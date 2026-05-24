package workspace

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/mount"
	"github.com/sufforest/drift/internal/storage"
	driftsync "github.com/sufforest/drift/internal/sync"
)

// TestLink_endToEnd drives a full pairing handshake against an in-memory
// provider. Two state dirs simulate two devices on the same machine; both
// share the same storage backend so the bucket-mediated handshake works.
func TestLink_endToEnd(t *testing.T) {
	ctx := context.Background()
	primary, prov := newPrimary(t)
	if err := primary.CompartmentCreate(ctx, "shared", domain.ModeMount); err != nil {
		t.Fatal(err)
	}

	// Phase 1: primary mints a pairing token.
	init, err := primary.LinkInit(ctx, 5*time.Minute)
	if err != nil {
		t.Fatalf("LinkInit: %v", err)
	}
	if init.Encoded == "" || init.PID == "" {
		t.Fatalf("LinkInit returned empty fields: %+v", init)
	}

	// Phase 2: new device LinkClaim runs in a goroutine, blocked on
	// awaitHandoff. We need primary's LinkConfirm to proceed before the
	// goroutine unblocks.
	newState, err := NewState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	claimNow := primary.now()
	providerFor := func(_ domain.S3Credential, _ domain.BucketInfo) (storage.Provider, error) {
		return prov, nil // in-memory backend ignores credentials
	}

	var claimRes *LinkClaimResult
	var claimErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		claimRes, claimErr = LinkClaim(ctx, init.Encoded, "desktop-tower", LinkClaimOptions{
			State:        newState,
			ProviderFor:  providerFor,
			Now:          func() time.Time { return claimNow },
			PollInterval: 5 * time.Millisecond,
			Timeout:      5 * time.Second,
		})
	}()

	// Give the claim goroutine a tick to upload its response, then
	// confirm.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if exists, _ := prov.Exists(ctx, domain.PairingResponseKey(init.PID)); exists {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	confirm, err := primary.LinkConfirm(ctx, init.PID, LinkConfirmOptions{})
	if err != nil {
		t.Fatalf("LinkConfirm: %v", err)
	}
	if confirm.ResealedCount != 1 {
		t.Fatalf("expected 1 compartment re-sealed, got %d", confirm.ResealedCount)
	}

	wg.Wait()
	if claimErr != nil {
		t.Fatalf("LinkClaim: %v", claimErr)
	}
	if claimRes.DeviceID != confirm.DeviceID {
		t.Fatalf("device id mismatch: claim=%s confirm=%s", claimRes.DeviceID, confirm.DeviceID)
	}

	// New device's local state must hold the device key + CPRK + a
	// config pinned to the right master fingerprint.
	if !newState.HasDevice() {
		t.Fatal("new device's device.json missing")
	}
	if _, err := newState.LoadCPRK(); err != nil {
		t.Fatalf("new device's cprk.key missing: %v", err)
	}
	cfg, err := newState.LoadConfig()
	if err != nil {
		t.Fatalf("new device's config.json: %v", err)
	}
	if cfg.WorkspaceID != primary.Config.WorkspaceID {
		t.Fatalf("workspace mismatch: %s vs %s", cfg.WorkspaceID, primary.Config.WorkspaceID)
	}
	if len(cfg.MasterFingerprint) != 32 {
		t.Fatalf("expected 32-byte master fingerprint, got %d", len(cfg.MasterFingerprint))
	}

	// Loading the new device as a Workspace should succeed and let it
	// read the manifest with its own CPRK (no master needed).
	secondary, err := Load(ctx, Options{
		State:    newState,
		Provider: prov,
		Writer:   storage.NewConditionalPutWriter(prov),
		Now:      func() time.Time { return claimNow },
	})
	if err != nil {
		t.Fatalf("Load on secondary: %v", err)
	}
	if secondary.Master != nil {
		t.Fatal("secondary device should not have a master")
	}
	m, err := secondary.Manifest(ctx)
	if err != nil {
		t.Fatalf("Manifest on secondary: %v", err)
	}
	if _, ok := m.Devices[claimRes.DeviceID]; !ok {
		t.Fatal("manifest should list the secondary device")
	}
	if _, ok := m.Enrollments[claimRes.DeviceID]; !ok {
		t.Fatal("manifest should hold an enrollment cert for the secondary device")
	}
	if _, ok := m.Compartments["shared"].EncryptedKeys[claimRes.DeviceID]; !ok {
		t.Fatal("shared compartment should be sealed for the secondary device")
	}
}

func TestLink_expiredPairingTokenRejected(t *testing.T) {
	ctx := context.Background()
	primary, prov := newPrimary(t)
	init, err := primary.LinkInit(ctx, 1*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)

	newState, _ := NewState(t.TempDir())
	_, err = LinkClaim(ctx, init.Encoded, "late", LinkClaimOptions{
		State:        newState,
		ProviderFor:  func(_ domain.S3Credential, _ domain.BucketInfo) (storage.Provider, error) { return prov, nil },
		Now:          time.Now,
		PollInterval: time.Millisecond,
		Timeout:      time.Second,
	})
	if err == nil {
		t.Fatal("expected expired pairing token to be rejected")
	}
}

func TestLink_tamperedPairingTokenRejected(t *testing.T) {
	ctx := context.Background()
	primary, prov := newPrimary(t)
	init, err := primary.LinkInit(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bad := init.Encoded[:len(init.Encoded)-2] + "11"

	newState, _ := NewState(t.TempDir())
	_, err = LinkClaim(ctx, bad, "imposter", LinkClaimOptions{
		State:        newState,
		ProviderFor:  func(_ domain.S3Credential, _ domain.BucketInfo) (storage.Provider, error) { return prov, nil },
		Now:          time.Now,
		PollInterval: time.Millisecond,
		Timeout:      time.Second,
	})
	if err == nil {
		t.Fatal("expected tampered pairing token to be rejected")
	}
	if !errors.Is(err, domain.ErrSignatureInvalid) && !errors.Is(err, domain.ErrTokenMalformed) {
		t.Fatalf("expected sig/malformed error, got %v", err)
	}
}

// TestLink_peerMode_sharesParentCred drives the full pairing handshake
// with PeerMode=true and asserts that the new device ends up with a
// parent.json equivalent to the primary's. This is the test that proves
// `drift link --peer` does what it claims: turns the secondary into a
// functional peer.
func TestLink_peerMode_sharesParentCred(t *testing.T) {
	ctx := context.Background()
	primary, prov := newPrimary(t)

	// Primary has a parent cred from newPrimary(); load it for comparison.
	primaryParent, err := primary.State.LoadParent()
	if err != nil {
		t.Fatalf("LoadParent on primary: %v", err)
	}

	// Phase 1: primary mints a peer pairing token.
	init, err := primary.LinkInit(ctx, 5*time.Minute, LinkInitOptions{PeerMode: true})
	if err != nil {
		t.Fatalf("LinkInit (peer): %v", err)
	}

	// Phase 2: secondary claims.
	newState, err := NewState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	claimNow := primary.now()
	providerFor := func(_ domain.S3Credential, _ domain.BucketInfo) (storage.Provider, error) {
		return prov, nil
	}

	var claimRes *LinkClaimResult
	var claimErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		claimRes, claimErr = LinkClaim(ctx, init.Encoded, "desktop-peer", LinkClaimOptions{
			State:        newState,
			ProviderFor:  providerFor,
			Now:          func() time.Time { return claimNow },
			PollInterval: 5 * time.Millisecond,
			Timeout:      5 * time.Second,
		})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if exists, _ := prov.Exists(ctx, domain.PairingResponseKey(init.PID)); exists {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if _, err := primary.LinkConfirm(ctx, init.PID, LinkConfirmOptions{}); err != nil {
		t.Fatalf("LinkConfirm: %v", err)
	}
	wg.Wait()
	if claimErr != nil {
		t.Fatalf("LinkClaim: %v", claimErr)
	}

	// Core peer-mode assertion: claimRes.PeerMode is true.
	if !claimRes.PeerMode {
		t.Fatal("claimRes.PeerMode = false; expected true for a --peer pairing")
	}

	// Secondary's local state should now hold a parent.json equivalent
	// to primary's.
	secondaryParent, err := newState.LoadParent()
	if err != nil {
		t.Fatalf("LoadParent on secondary: %v", err)
	}
	if secondaryParent.AccessKeyID != primaryParent.AccessKeyID {
		t.Errorf("secondary access key id = %q, want %q", secondaryParent.AccessKeyID, primaryParent.AccessKeyID)
	}
	if secondaryParent.SecretAccessKey != primaryParent.SecretAccessKey {
		t.Errorf("secondary secret access key did not match primary's")
	}
	if secondaryParent.Provider != primaryParent.Provider {
		t.Errorf("secondary provider = %q, want %q", secondaryParent.Provider, primaryParent.Provider)
	}
}

// TestLink_bearerMode_doesNotShareParentCred is the negative — when
// PeerMode is false (default), the secondary should NOT receive a
// parent cred. Critical for the trust-limited pairing path.
func TestLink_bearerMode_doesNotShareParentCred(t *testing.T) {
	ctx := context.Background()
	primary, prov := newPrimary(t)

	// Default behavior: PeerMode false.
	init, err := primary.LinkInit(ctx, 5*time.Minute)
	if err != nil {
		t.Fatalf("LinkInit: %v", err)
	}

	newState, err := NewState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	claimNow := primary.now()
	providerFor := func(_ domain.S3Credential, _ domain.BucketInfo) (storage.Provider, error) {
		return prov, nil
	}

	var claimRes *LinkClaimResult
	var claimErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		claimRes, claimErr = LinkClaim(ctx, init.Encoded, "desktop-bearer", LinkClaimOptions{
			State:        newState,
			ProviderFor:  providerFor,
			Now:          func() time.Time { return claimNow },
			PollInterval: 5 * time.Millisecond,
			Timeout:      5 * time.Second,
		})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if exists, _ := prov.Exists(ctx, domain.PairingResponseKey(init.PID)); exists {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if _, err := primary.LinkConfirm(ctx, init.PID, LinkConfirmOptions{}); err != nil {
		t.Fatalf("LinkConfirm: %v", err)
	}
	wg.Wait()
	if claimErr != nil {
		t.Fatalf("LinkClaim: %v", claimErr)
	}

	if claimRes.PeerMode {
		t.Fatal("claimRes.PeerMode = true; expected false for default (non-peer) pairing")
	}

	// Secondary's local state must NOT have a parent.json.
	if _, err := newState.LoadParent(); err == nil {
		t.Fatal("secondary device received a parent cred in non-peer mode; expected no parent.json")
	}
}

// TestLink_peerMode_secondaryCanMountDirect is the integration check
// that ties everything together: after a peer pairing, the secondary
// device should be able to call MountDirect (the no-token primary-style
// flow) without errors. This proves the parent cred handoff was
// useful, not just present.
func TestLink_peerMode_secondaryCanMountDirect(t *testing.T) {
	ctx := context.Background()
	primary, prov := newPrimary(t)
	if err := primary.CompartmentCreate(ctx, "shared", domain.ModeMount); err != nil {
		t.Fatal(err)
	}

	init, err := primary.LinkInit(ctx, 5*time.Minute, LinkInitOptions{PeerMode: true})
	if err != nil {
		t.Fatalf("LinkInit (peer): %v", err)
	}

	newState, err := NewState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	claimNow := primary.now()
	providerFor := func(_ domain.S3Credential, _ domain.BucketInfo) (storage.Provider, error) {
		return prov, nil
	}

	var claimErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, claimErr = LinkClaim(ctx, init.Encoded, "peer-desktop", LinkClaimOptions{
			State:        newState,
			ProviderFor:  providerFor,
			Now:          func() time.Time { return claimNow },
			PollInterval: 5 * time.Millisecond,
			Timeout:      5 * time.Second,
		})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if exists, _ := prov.Exists(ctx, domain.PairingResponseKey(init.PID)); exists {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if _, err := primary.LinkConfirm(ctx, init.PID, LinkConfirmOptions{}); err != nil {
		t.Fatalf("LinkConfirm: %v", err)
	}
	wg.Wait()
	if claimErr != nil {
		t.Fatalf("LinkClaim: %v", claimErr)
	}

	// Now load the secondary as a Workspace and run MountDirect through a
	// noop mounter/syncer. The peer should be able to mount its own
	// compartments using just the parent cred + its sealed CPRK; no
	// master key involved.
	secondary, err := Load(ctx, Options{
		State:    newState,
		Provider: prov,
		Writer:   storage.NewConditionalPutWriter(prov),
	})
	if err != nil {
		t.Fatalf("Load secondary: %v", err)
	}
	if secondary.Master != nil {
		t.Fatal("secondary should not hold the master key")
	}
	if _, err := secondary.State.LoadParent(); err != nil {
		t.Fatalf("secondary missing parent cred (peer mode failed to save it): %v", err)
	}
	tmp := t.TempDir()
	sess, err := secondary.MountDirect(ctx, DirectMountOptions{
		Mounter:   mount.NewNoopMounter(),
		Syncer:    driftsync.NewNoopSyncer(),
		MountBase: tmp,
		Vols:      []string{"shared"},
		Now:       func() time.Time { return claimNow },
	})
	if err != nil {
		t.Fatalf("MountDirect on peer secondary should have succeeded, got: %v", err)
	}
	if len(sess.Mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(sess.Mounts))
	}
	if sess.Mounts[0].Compartment() != "shared" {
		t.Fatalf("mounted wrong compartment: %s", sess.Mounts[0].Compartment())
	}
	_ = sess.Close()
}

// TestLink_peerMode_secondaryCanGrant is the payoff test: after a peer
// pairing, the secondary should be able to mint bearer tokens on its
// own (this is the killer differentiator from bearer-only pairing).
// Without parent cred, `drift grant` cannot mint, so this test fails if
// the peer-handoff didn't actually deliver the parent cred.
func TestLink_peerMode_secondaryCanGrant(t *testing.T) {
	ctx := context.Background()
	primary, prov := newPrimary(t)
	if err := primary.CompartmentCreate(ctx, "shared", domain.ModeMount); err != nil {
		t.Fatal(err)
	}

	init, err := primary.LinkInit(ctx, 5*time.Minute, LinkInitOptions{PeerMode: true})
	if err != nil {
		t.Fatalf("LinkInit (peer): %v", err)
	}

	newState, _ := NewState(t.TempDir())
	claimNow := primary.now()
	providerFor := func(_ domain.S3Credential, _ domain.BucketInfo) (storage.Provider, error) {
		return prov, nil
	}

	var claimErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, claimErr = LinkClaim(ctx, init.Encoded, "peer-grant", LinkClaimOptions{
			State:        newState,
			ProviderFor:  providerFor,
			Now:          func() time.Time { return claimNow },
			PollInterval: 5 * time.Millisecond,
			Timeout:      5 * time.Second,
		})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if exists, _ := prov.Exists(ctx, domain.PairingResponseKey(init.PID)); exists {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if _, err := primary.LinkConfirm(ctx, init.PID, LinkConfirmOptions{}); err != nil {
		t.Fatalf("LinkConfirm: %v", err)
	}
	wg.Wait()
	if claimErr != nil {
		t.Fatalf("LinkClaim: %v", claimErr)
	}

	// Load secondary as a Workspace and use its Grant method (this
	// exercises buildMinter which reads parent cred from state).
	secondary, err := Load(ctx, Options{
		State:    newState,
		Provider: prov,
		Writer:   storage.NewConditionalPutWriter(prov),
		Now:      func() time.Time { return claimNow },
	})
	if err != nil {
		t.Fatalf("Load secondary: %v", err)
	}

	res, err := secondary.Grant(ctx, GrantRequest{
		Scope: []string{"shared"},
		Mode:  domain.TokenModeRW,
		TTL:   time.Hour,
	})
	if err != nil {
		t.Fatalf("Grant on peer secondary failed (peer cred not received?): %v", err)
	}
	if res.Encoded == "" || res.TID == "" {
		t.Fatalf("Grant returned empty result: %+v", res)
	}

	// Token must be in the manifest now — verify by re-reading.
	m, err := secondary.Manifest(ctx)
	if err != nil {
		t.Fatalf("Manifest after Grant: %v", err)
	}
	if _, ok := m.ActiveTokens[res.TID]; !ok {
		t.Fatalf("manifest does not contain newly granted tid %s", res.TID)
	}
	// Audit attribution: the issued-by should be the SECONDARY's device id,
	// proving per-device audit attribution survives peer pairing.
	if m.ActiveTokens[res.TID].IssuedBy != secondary.Config.DeviceID {
		t.Errorf("expected issuer=%s, got %s", secondary.Config.DeviceID, m.ActiveTokens[res.TID].IssuedBy)
	}
}

// TestPairingHandoff_jsonRoundtripWithParent ensures the new Parent
// field serializes correctly without disrupting the existing CPRK +
// MasterPub fields. Schema-safety test.
func TestPairingHandoff_jsonRoundtripWithParent(t *testing.T) {
	original := domain.PairingHandoff{
		CPRK:      []byte("the-cprk"),
		MasterPub: []byte("the-master-pub"),
		Parent: &domain.PairingHandoffParent{
			Provider:        "r2",
			AccessKeyID:     "ak_123",
			SecretAccessKey: "sk_456",
		},
	}
	body, err := jsonMarshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back domain.PairingHandoff
	if err := jsonUnmarshal(body, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(back.CPRK) != string(original.CPRK) {
		t.Errorf("CPRK roundtrip mismatch")
	}
	if string(back.MasterPub) != string(original.MasterPub) {
		t.Errorf("MasterPub roundtrip mismatch")
	}
	if back.Parent == nil {
		t.Fatal("Parent dropped during roundtrip")
	}
	if back.Parent.AccessKeyID != "ak_123" || back.Parent.SecretAccessKey != "sk_456" || back.Parent.Provider != "r2" {
		t.Errorf("Parent fields garbled: %+v", back.Parent)
	}
}

// TestPairingHandoff_jsonRoundtripWithoutParent ensures that the
// omitempty tag works as intended: a handoff with no Parent field
// (bearer-mode pairing) doesn't emit "parent":null in the JSON, and
// roundtrips correctly with Parent == nil.
func TestPairingHandoff_jsonRoundtripWithoutParent(t *testing.T) {
	original := domain.PairingHandoff{
		CPRK:      []byte("the-cprk"),
		MasterPub: []byte("the-master-pub"),
	}
	body, err := jsonMarshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(body), `"parent"`) {
		t.Errorf("non-peer handoff should omit parent key from JSON: %s", string(body))
	}
	var back domain.PairingHandoff
	if err := jsonUnmarshal(body, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Parent != nil {
		t.Errorf("non-peer handoff roundtrip produced non-nil Parent")
	}
}

// TestPairingStub_backwardCompatibleJSON proves that a manifest from
// before the PeerMode field existed still deserializes cleanly. The
// PeerMode zero-value (false) is the safe default (bearer-mode).
func TestPairingStub_backwardCompatibleJSON(t *testing.T) {
	// Pre-PeerMode-field manifest JSON (omitting peer_mode entirely).
	oldJSON := []byte(`{
		"pid": "pair_abc",
		"issued_by": "master",
		"issued_at": "2026-05-20T12:00:00Z",
		"expires_at": "2026-05-20T12:15:00Z"
	}`)
	var stub domain.PairingStub
	if err := jsonUnmarshal(oldJSON, &stub); err != nil {
		t.Fatalf("legacy JSON unmarshal: %v", err)
	}
	if stub.PID != "pair_abc" {
		t.Errorf("PID = %q, want pair_abc", stub.PID)
	}
	if stub.PeerMode {
		t.Errorf("legacy stub should default to PeerMode=false, got true")
	}
}

// jsonMarshal/jsonUnmarshal are thin wrappers so we don't need to import
// "encoding/json" at the test scope just for the schema tests.
func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }
