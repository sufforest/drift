package workspace

import (
	"context"
	"testing"
	"time"

	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/storage"
	"github.com/sufforest/drift/internal/token"
)

func readRevocationsForTest(t *testing.T, ctx context.Context, p storage.Provider) *domain.RevocationList {
	t.Helper()
	body, err := p.Get(ctx, domain.RevocationsKey)
	if err != nil {
		t.Fatalf("read revocations: %v", err)
	}
	list, err := token.DecodeRevocations(body)
	if err != nil {
		t.Fatalf("decode revocations: %v", err)
	}
	return list
}

func revContains(list *domain.RevocationList, tid string) bool {
	for _, e := range list.Entries {
		if e.TID == tid {
			return true
		}
	}
	return false
}

func TestCompartmentRotate_keyChangesAndTokenIsRevoked(t *testing.T) {
	ctx := context.Background()
	ws, prov := newPrimary(t)
	if err := ws.CompartmentCreate(ctx, "secrets", domain.ModeMount); err != nil {
		t.Fatal(err)
	}

	issued, err := ws.Grant(ctx, GrantRequest{
		Scope: []string{"secrets"},
		Mode:  domain.TokenModeRW,
		TTL:   1 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	pre, _ := ws.Manifest(ctx)
	oldSealed := pre.Compartments["secrets"].EncryptedKeys[ws.Config.DeviceID]
	oldKV := pre.Compartments["secrets"].KeyVersion

	res, err := ws.CompartmentRotate(ctx, "secrets")
	if err != nil {
		t.Fatalf("CompartmentRotate: %v", err)
	}
	if res.NewKeyVersion != oldKV+1 {
		t.Fatalf("KeyVersion did not bump: %d → %d", oldKV, res.NewKeyVersion)
	}
	if len(res.RevokedTokens) != 1 || res.RevokedTokens[0] != issued.TID {
		t.Fatalf("expected outstanding token to be revoked: got %v", res.RevokedTokens)
	}

	post, _ := ws.Manifest(ctx)
	newSealed := post.Compartments["secrets"].EncryptedKeys[ws.Config.DeviceID]
	if string(oldSealed) == string(newSealed) {
		t.Fatal("sealed compartment key did not change after rotation")
	}
	if _, stillActive := post.ActiveTokens[issued.TID]; stillActive {
		t.Fatal("rotated-out token should be removed from active_tokens")
	}

	// Revocation entry should be appended (best-effort, but in-memory
	// provider always succeeds).
	rev := readRevocationsForTest(t, ctx, prov)
	if !revContains(rev, issued.TID) {
		t.Fatal("expected revocation entry for the rotated-out token")
	}
}

func TestCompartmentRotate_unknownCompartment(t *testing.T) {
	ws, _ := newPrimary(t)
	_, err := ws.CompartmentRotate(context.Background(), "nope")
	if err == nil {
		t.Fatal("expected error for unknown compartment")
	}
}

func TestRotateMaster_secondaryFollowsChain(t *testing.T) {
	ctx := context.Background()
	primary, prov := newPrimary(t)

	// Pair a secondary so the chain has someone to walk.
	init, err := primary.LinkInit(ctx, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	newState, _ := NewState(t.TempDir())
	providerFor := func(_ domain.S3Credential, _ domain.BucketInfo) (storage.Provider, error) {
		return prov, nil
	}
	claimDone := make(chan *LinkClaimResult, 1)
	go func() {
		res, _ := LinkClaim(ctx, init.Encoded, "sec", LinkClaimOptions{
			State:        newState,
			ProviderFor:  providerFor,
			Now:          primary.now,
			PollInterval: 5 * time.Millisecond,
			Timeout:      5 * time.Second,
		})
		claimDone <- res
	}()
	for i := 0; i < 100; i++ {
		if exists, _ := prov.Exists(ctx, domain.PairingResponseKey(init.PID)); exists {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := primary.LinkConfirm(ctx, init.PID, LinkConfirmOptions{}); err != nil {
		t.Fatal(err)
	}
	<-claimDone

	// Secondary records the original master fingerprint.
	cfgBefore, _ := newState.LoadConfig()
	originalFP := append([]byte(nil), cfgBefore.MasterFingerprint...)

	// Rotate master.
	res, err := primary.RotateMaster(ctx)
	if err != nil {
		t.Fatalf("RotateMaster: %v", err)
	}
	if res.RotationSequence != 1 {
		t.Fatalf("rotation seq = %d, want 1", res.RotationSequence)
	}
	if len(res.ReEnrolledDevices) != 2 {
		// primary + secondary both need fresh enrollment certs under the new master
		t.Fatalf("expected 2 re-enrolled devices (primary + secondary), got %v", res.ReEnrolledDevices)
	}

	// Secondary's next Manifest call must walk the rotation chain,
	// update its pinned fingerprint, and verify successfully.
	secondary, err := Load(ctx, Options{
		State:    newState,
		Provider: prov,
		Writer:   storage.NewConditionalPutWriter(prov),
		Now:      primary.now,
	})
	if err != nil {
		t.Fatalf("Load secondary: %v", err)
	}
	m, err := secondary.Manifest(ctx)
	if err != nil {
		t.Fatalf("secondary Manifest post-rotate-master: %v", err)
	}
	if m.MasterRotationSequence != 1 {
		t.Fatalf("secondary saw manifest rotation seq %d, want 1", m.MasterRotationSequence)
	}

	cfgAfter, _ := newState.LoadConfig()
	if cfgAfter.LastObservedRotation != 1 {
		t.Fatalf("secondary LastObservedRotation = %d, want 1", cfgAfter.LastObservedRotation)
	}
	if string(cfgAfter.MasterFingerprint) == string(originalFP) {
		t.Fatal("secondary's pinned fingerprint should have updated")
	}
	if string(cfgAfter.MasterFingerprint) != string(res.NewFingerprint) {
		t.Fatal("secondary's new pinned fingerprint should match rotation result")
	}
}

func TestRotateCPRK_primaryReDerivesAndSecondaryAutoRefreshes(t *testing.T) {
	ctx := context.Background()
	primary, prov := newPrimary(t)
	if err := primary.CompartmentCreate(ctx, "shared", domain.ModeMount); err != nil {
		t.Fatal(err)
	}

	// Pair a secondary device so the rotation has someone to write a
	// sealed handoff for.
	init, err := primary.LinkInit(ctx, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	newState, _ := NewState(t.TempDir())
	providerFor := func(_ domain.S3Credential, _ domain.BucketInfo) (storage.Provider, error) {
		return prov, nil
	}
	claimDone := make(chan *LinkClaimResult, 1)
	go func() {
		res, _ := LinkClaim(ctx, init.Encoded, "secondary", LinkClaimOptions{
			State:        newState,
			ProviderFor:  providerFor,
			Now:          primary.now,
			PollInterval: 5 * time.Millisecond,
			Timeout:      5 * time.Second,
		})
		claimDone <- res
	}()
	// Wait for response, confirm.
	for i := 0; i < 100; i++ {
		if exists, _ := prov.Exists(ctx, domain.PairingResponseKey(init.PID)); exists {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := primary.LinkConfirm(ctx, init.PID, LinkConfirmOptions{}); err != nil {
		t.Fatal(err)
	}
	claimRes := <-claimDone
	if claimRes == nil {
		t.Fatal("LinkClaim returned nil")
	}

	// Now rotate the CPRK.
	res, err := primary.RotateCPRK(ctx)
	if err != nil {
		t.Fatalf("RotateCPRK: %v", err)
	}
	if res.NewEpoch != 1 {
		t.Fatalf("expected new epoch 1, got %d", res.NewEpoch)
	}
	if len(res.SealedDevices) != 1 || res.SealedDevices[0] != claimRes.DeviceID {
		t.Fatalf("expected sealed for the secondary device, got %v", res.SealedDevices)
	}

	// Primary can still read the manifest (uses new key on its own).
	if _, err := primary.Manifest(ctx); err != nil {
		t.Fatalf("primary Manifest post-rotate: %v", err)
	}

	// Load the secondary. It has the stale CPRK cached from pairing;
	// the first Manifest call should auto-refresh from the sealed handoff.
	secondary, err := Load(ctx, Options{
		State:    newState,
		Provider: prov,
		Writer:   storage.NewConditionalPutWriter(prov),
		Now:      primary.now,
	})
	if err != nil {
		t.Fatalf("Load secondary: %v", err)
	}
	if _, err := secondary.Manifest(ctx); err != nil {
		t.Fatalf("secondary Manifest after rotate: %v (refresh path failed)", err)
	}
	// Secondary's local config must have the new epoch.
	cfg, _ := newState.LoadConfig()
	if cfg.CPRKEpoch != 1 {
		t.Fatalf("secondary cfg.CPRKEpoch = %d, want 1", cfg.CPRKEpoch)
	}
}
