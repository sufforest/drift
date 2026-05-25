package workspace

import (
	"context"
	"crypto/ed25519"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sufforest/drift/internal/credentials"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/storage"
)

// driveBearerHandshake pairs a peer with DD-9 bearer mode + the
// requested scope. Mirrors driveScopedHandshake but flips the
// BearerMode flag. Returns primary, secondary state, claim result,
// provider — same shape as the existing helpers for symmetry.
func driveBearerHandshake(t *testing.T, scope []string) (*Workspace, *State, *LinkClaimResult, *storage.MemoryProvider) {
	t.Helper()
	ctx := context.Background()
	primary, prov := newPrimary(t)
	for _, name := range scope {
		if _, exists := mustManifest(t, primary).Compartments[name]; !exists {
			if err := primary.CompartmentCreate(ctx, name, domain.ModeMount); err != nil {
				t.Fatal(err)
			}
		}
	}

	init, err := primary.LinkInit(ctx, 5*time.Minute, LinkInitOptions{
		BearerMode:       true,
		CompartmentScope: scope,
	})
	if err != nil {
		t.Fatalf("LinkInit (bearer): %v", err)
	}

	newState, _ := NewState(t.TempDir())
	var wg sync.WaitGroup
	var claim *LinkClaimResult
	var claimErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		claim, claimErr = LinkClaim(ctx, init.Encoded, "bearer-peer", LinkClaimOptions{
			State:        newState,
			ProviderFor:  func(_ domain.S3Credential, _ domain.BucketInfo) (storage.Provider, error) { return prov, nil },
			Now:          primary.now,
			PollInterval: 2 * time.Millisecond,
			Timeout:      5 * time.Second,
		})
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ok, _ := prov.Exists(ctx, domain.PairingResponseKey(init.PID)); ok {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := primary.LinkConfirm(ctx, init.PID, LinkConfirmOptions{}); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if claimErr != nil {
		t.Fatal(claimErr)
	}
	return primary, newState, claim, prov
}

func mustManifest(t *testing.T, ws *Workspace) *domain.Manifest {
	t.Helper()
	m, err := ws.Manifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestDD9Pairing_happyPath: full bearer-mode pairing. After:
//   - Secondary state holds peercred.json (NOT parent.json)
//   - PeerCred verifies under master pub
//   - Manifest has PeerCreds entry for the secondary
//   - Claim result reports BearerMode=true, PeerMode=false
func TestDD9Pairing_happyPath(t *testing.T) {
	primary, secondaryState, claim, _ := driveBearerHandshake(t, []string{"allowed"})

	if !claim.BearerMode {
		t.Error("claim result must report BearerMode=true")
	}
	if claim.PeerMode {
		t.Error("claim result must NOT report PeerMode=true (bearer != parent peer)")
	}

	// Secondary state: peercred.json present, parent.json absent.
	if !secondaryState.HasPeerCred() {
		t.Fatal("secondary must have peercred.json after bearer pairing")
	}
	if _, err := secondaryState.LoadParent(); err == nil {
		t.Error("secondary must NOT have a parent cred (bearer mode does not hand off parent)")
	}

	// Verify the PeerCred signature against the primary's master pubkey.
	pc, err := secondaryState.LoadPeerCred()
	if err != nil {
		t.Fatal(err)
	}
	masterPub := ed25519.PublicKey(primary.Master.SignPub())
	if err := credentials.VerifyPeerCred(*pc, masterPub); err != nil {
		t.Errorf("saved PeerCred must verify under primary's master pub: %v", err)
	}
	if pc.DeviceID != claim.DeviceID {
		t.Errorf("PeerCred DeviceID = %q, want %q", pc.DeviceID, claim.DeviceID)
	}
	if len(pc.Scope) != 1 || pc.Scope[0] != "allowed" {
		t.Errorf("PeerCred Scope = %v, want [allowed]", pc.Scope)
	}

	// Manifest tracks the issuance.
	m, _ := primary.Manifest(context.Background())
	rec, ok := m.PeerCreds[claim.DeviceID]
	if !ok {
		t.Fatal("manifest must record PeerCreds entry for bearer peer")
	}
	if rec.JTI != pc.JTI {
		t.Errorf("manifest JTI %q != PeerCred JTI %q", rec.JTI, pc.JTI)
	}
	if rec.Revoked {
		t.Error("fresh bearer peer must not be marked revoked")
	}
}

// TestDD9Pairing_linkInitRefusesBearerWithoutScope: opting into bearer
// mode without a CompartmentScope is refused at LinkInit. This is the
// scope-required boundary (DD-9 §2).
func TestDD9Pairing_linkInitRefusesBearerWithoutScope(t *testing.T) {
	ctx := context.Background()
	primary, _ := newPrimary(t)
	_, err := primary.LinkInit(ctx, 5*time.Minute, LinkInitOptions{
		BearerMode:       true,
		CompartmentScope: nil,
	})
	if err == nil {
		t.Fatal("LinkInit must refuse bearer mode without compartment scope")
	}
	if !strings.Contains(err.Error(), "requires --peer-compartments") {
		t.Errorf("error must mention scope requirement: %v", err)
	}
}

// TestDD9Pairing_linkInitRefusesBothModes: --peer + --peer-bearer at
// the same time is refused. Protocol-level mutex.
func TestDD9Pairing_linkInitRefusesBothModes(t *testing.T) {
	ctx := context.Background()
	primary, _ := newPrimary(t)
	if err := primary.CompartmentCreate(ctx, "x", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	_, err := primary.LinkInit(ctx, 5*time.Minute, LinkInitOptions{
		PeerMode:         true,
		BearerMode:       true,
		CompartmentScope: []string{"x"},
	})
	if err == nil {
		t.Fatal("LinkInit must refuse simultaneous PeerMode + BearerMode")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error must mention mutex: %v", err)
	}
}

// TestDD9Pairing_legacyV1PeerStillWorks: existing --peer pairing
// (DD-4 parent handoff) is unchanged. Backward-compat guarantee.
func TestDD9Pairing_legacyV1PeerStillWorks(t *testing.T) {
	ctx := context.Background()
	primary, prov := newPrimary(t)
	if err := primary.CompartmentCreate(ctx, "x", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	init, err := primary.LinkInit(ctx, 5*time.Minute, LinkInitOptions{PeerMode: true})
	if err != nil {
		t.Fatal(err)
	}
	newState, _ := NewState(t.TempDir())
	var wg sync.WaitGroup
	var claim *LinkClaimResult
	wg.Add(1)
	go func() {
		defer wg.Done()
		claim, _ = LinkClaim(ctx, init.Encoded, "legacy", LinkClaimOptions{
			State:        newState,
			ProviderFor:  func(_ domain.S3Credential, _ domain.BucketInfo) (storage.Provider, error) { return prov, nil },
			Now:          primary.now,
			PollInterval: 2 * time.Millisecond,
			Timeout:      5 * time.Second,
		})
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ok, _ := prov.Exists(ctx, domain.PairingResponseKey(init.PID)); ok {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := primary.LinkConfirm(ctx, init.PID, LinkConfirmOptions{}); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if !claim.PeerMode {
		t.Error("v1 --peer must still produce PeerMode=true")
	}
	if claim.BearerMode {
		t.Error("v1 --peer must NOT set BearerMode")
	}
	// parent.json present, peercred.json absent.
	if _, err := newState.LoadParent(); err != nil {
		t.Errorf("v1 peer must have parent.json: %v", err)
	}
	if newState.HasPeerCred() {
		t.Error("v1 peer must NOT have peercred.json")
	}
	// Manifest must NOT have a PeerCreds entry for this device.
	m, _ := primary.Manifest(ctx)
	if _, ok := m.PeerCreds[claim.DeviceID]; ok {
		t.Error("v1 peer must NOT appear in PeerCreds (that's bearer-mode only)")
	}
}

// TestDD9Pairing_scopeFlowsToPeerCred: the scope passed at LinkInit
// ends up on the issued PeerCred + on the manifest PeerCredRecord +
// on the secondary's Device.CompartmentScope entry. End-to-end scope
// integrity.
func TestDD9Pairing_scopeFlowsToPeerCred(t *testing.T) {
	primary, secondaryState, claim, _ := driveBearerHandshake(t, []string{"allowed"})

	pc, _ := secondaryState.LoadPeerCred()
	if len(pc.Scope) != 1 || pc.Scope[0] != "allowed" {
		t.Errorf("PeerCred scope on peer = %v, want [allowed]", pc.Scope)
	}

	m, _ := primary.Manifest(context.Background())
	rec := m.PeerCreds[claim.DeviceID]
	if len(rec.Scope) != 1 || rec.Scope[0] != "allowed" {
		t.Errorf("manifest PeerCredRecord.Scope = %v, want [allowed]", rec.Scope)
	}
	dev := m.Devices[claim.DeviceID]
	if len(dev.CompartmentScope) != 1 || dev.CompartmentScope[0] != "allowed" {
		t.Errorf("Device.CompartmentScope = %v, want [allowed]", dev.CompartmentScope)
	}
}

// TestDD9Pairing_peerCredTimingFields: IssuedAt/ExpiresAt/RefreshAt
// are populated and consistent. RefreshAt = IssuedAt + TTL/2.
func TestDD9Pairing_peerCredTimingFields(t *testing.T) {
	_, secondaryState, _, _ := driveBearerHandshake(t, []string{"allowed"})
	pc, _ := secondaryState.LoadPeerCred()

	if pc.IssuedAt.IsZero() || pc.ExpiresAt.IsZero() || pc.RefreshAt.IsZero() {
		t.Fatalf("timing fields must all be set: iat=%v exp=%v refresh=%v",
			pc.IssuedAt, pc.ExpiresAt, pc.RefreshAt)
	}
	wantExp := pc.IssuedAt.Add(PeerCredDefaultTTL)
	if !pc.ExpiresAt.Equal(wantExp) {
		t.Errorf("ExpiresAt = %v, want IssuedAt+24h = %v", pc.ExpiresAt, wantExp)
	}
	wantRefresh := pc.IssuedAt.Add(PeerCredDefaultTTL / 2)
	if !pc.RefreshAt.Equal(wantRefresh) {
		t.Errorf("RefreshAt = %v, want IssuedAt+12h = %v", pc.RefreshAt, wantRefresh)
	}
}
