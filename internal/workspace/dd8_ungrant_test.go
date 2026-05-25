package workspace

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/storage"
)

// driveMultiScopedHandshake is driveScopedHandshake but creates THREE
// vols (allowed, also-allowed, blocked) and lets the peer be scoped for
// the first two. Lets ungrant tests narrow from {allowed, also-allowed}
// to {also-allowed} without hitting the last-entry refuse-case.
func driveMultiScopedHandshake(t *testing.T) (*Workspace, *State, *LinkClaimResult, *storage.MemoryProvider) {
	t.Helper()
	ctx := context.Background()
	primary, prov := newPrimary(t)
	for _, name := range []string{"allowed", "also-allowed", "blocked"} {
		if err := primary.CompartmentCreate(ctx, name, domain.ModeMount); err != nil {
			t.Fatal(err)
		}
	}
	init, err := primary.LinkInit(ctx, 5*time.Minute, LinkInitOptions{
		PeerMode:         true,
		CompartmentScope: []string{"allowed", "also-allowed"},
	})
	if err != nil {
		t.Fatal(err)
	}
	newState, _ := NewState(t.TempDir())
	done := make(chan struct{})
	var claim *LinkClaimResult
	var cerr error
	go func() {
		claim, cerr = LinkClaim(ctx, init.Encoded, "multi-scoped", LinkClaimOptions{
			State:        newState,
			ProviderFor:  func(_ domain.S3Credential, _ domain.BucketInfo) (storage.Provider, error) { return prov, nil },
			Now:          primary.now,
			PollInterval: 2 * time.Millisecond,
			Timeout:      5 * time.Second,
		})
		close(done)
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
	<-done
	if cerr != nil {
		t.Fatal(cerr)
	}
	return primary, newState, claim, prov
}

// TestDD8_compartmentUngrant_happyPath: ungrant one vol from a
// multi-scoped peer. After the op:
//   - Peer's CompartmentScope no longer contains the ungranted vol.
//   - Peer's CompartmentScope still contains the other vol.
//   - The ungranted vol's KeyVersion has bumped.
//   - The ungranted vol's EncryptedKeys map no longer has an entry
//     for the peer.
//   - The primary's entry IS still present.
//   - The secondary's subsequent Grant for the ungranted vol is refused.
//   - The secondary's Grant for the still-in-scope vol still works.
func TestDD8_compartmentUngrant_happyPath(t *testing.T) {
	ctx := context.Background()
	primary, secondaryState, claim, prov := driveMultiScopedHandshake(t)

	m, _ := primary.Manifest(ctx)
	if !m.Devices[claim.DeviceID].HasCompartmentAccess("allowed") {
		t.Fatal("precondition: peer must be scoped for allowed")
	}
	if !m.Devices[claim.DeviceID].HasCompartmentAccess("also-allowed") {
		t.Fatal("precondition: peer must be scoped for also-allowed")
	}
	if _, ok := m.Compartments["allowed"].EncryptedKeys[claim.DeviceID]; !ok {
		t.Fatal("precondition: peer must have sealed CK for allowed")
	}
	oldKV := m.Compartments["allowed"].KeyVersion

	res, err := primary.CompartmentUngrant(ctx, claim.DeviceID, "allowed")
	if err != nil {
		t.Fatalf("CompartmentUngrant: %v", err)
	}
	if res.AlreadyRevoked {
		t.Fatal("first ungrant must not be already-revoked")
	}
	if res.NewKeyVersion != res.OldKeyVersion+1 {
		t.Errorf("key version must bump by 1: %d -> %d", res.OldKeyVersion, res.NewKeyVersion)
	}

	m, _ = primary.Manifest(ctx)
	if m.Devices[claim.DeviceID].HasCompartmentAccess("allowed") {
		t.Errorf("peer scope should NOT contain allowed after ungrant: %v",
			m.Devices[claim.DeviceID].CompartmentScope)
	}
	if !m.Devices[claim.DeviceID].HasCompartmentAccess("also-allowed") {
		t.Errorf("peer's other scope must remain: %v",
			m.Devices[claim.DeviceID].CompartmentScope)
	}
	if _, ok := m.Compartments["allowed"].EncryptedKeys[claim.DeviceID]; ok {
		t.Error("peer should not have sealed CK for allowed after ungrant")
	}
	if _, ok := m.Compartments["also-allowed"].EncryptedKeys[claim.DeviceID]; !ok {
		t.Error("peer must STILL have sealed CK for also-allowed after ungrant")
	}
	if _, ok := m.Compartments["allowed"].EncryptedKeys[primary.Config.DeviceID]; !ok {
		t.Error("primary must still be sealed for allowed after ungrant")
	}
	if m.Compartments["allowed"].KeyVersion != oldKV+1 {
		t.Errorf("manifest KeyVersion = %d, want %d", m.Compartments["allowed"].KeyVersion, oldKV+1)
	}

	// Secondary refused for ungranted vol, allowed for remaining.
	secondary, err := Load(ctx, Options{
		State:    secondaryState,
		Provider: prov,
		Writer:   storage.NewConditionalPutWriter(prov),
		Now:      primary.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = secondary.Grant(ctx, GrantRequest{
		Scope: []string{"allowed"},
		Mode:  domain.TokenModeRW,
		TTL:   time.Hour,
	})
	if err == nil {
		t.Fatal("after ungrant, secondary must NOT be able to mint for the ungranted vol")
	}
	if !strings.Contains(err.Error(), "not scoped for") {
		t.Errorf("expected scope-mismatch error, got: %v", err)
	}
	if _, err := secondary.Grant(ctx, GrantRequest{
		Scope: []string{"also-allowed"},
		Mode:  domain.TokenModeRW,
		TTL:   time.Hour,
	}); err != nil {
		t.Errorf("secondary must STILL be able to mint for in-scope vol: %v", err)
	}
}

// TestDD8_compartmentUngrant_refusesLastInScope: ungranting the only
// entry in a device's scope is refused — the operator must use device
// revoke instead. Without this guard, the device would end up with an
// empty scope, which our backward-compat semantics interpret as "full
// access" — the exact opposite of operator intent.
func TestDD8_compartmentUngrant_refusesLastInScope(t *testing.T) {
	ctx := context.Background()
	primary, _, claim, _, _ := driveScopedHandshake(t, []string{"allowed"})
	_, err := primary.CompartmentUngrant(ctx, claim.DeviceID, "allowed")
	if err == nil {
		t.Fatal("expected refusal — ungrant of last scope entry would silently elevate to full access")
	}
	if !strings.Contains(err.Error(), "device revoke") {
		t.Errorf("error must mention `device revoke` as the alternative, got: %v", err)
	}
}

// TestDD8_compartmentUngrant_idempotent: ungranting an already-not-
// scoped (device, vol) is a no-op. AlreadyRevoked is true, manifest
// sequence does not advance, KeyVersion does not bump.
func TestDD8_compartmentUngrant_idempotent(t *testing.T) {
	ctx := context.Background()
	primary, _, claim, _, _ := driveScopedHandshake(t, []string{"allowed"})

	beforeM, _ := primary.Manifest(ctx)
	beforeSeq := beforeM.Sequence
	beforeKV := beforeM.Compartments["blocked"].KeyVersion

	// Ungrant a vol the peer was never scoped for.
	res, err := primary.CompartmentUngrant(ctx, claim.DeviceID, "blocked")
	if err != nil {
		t.Fatalf("CompartmentUngrant: %v", err)
	}
	if !res.AlreadyRevoked {
		t.Error("ungrant of a never-scoped vol must be AlreadyRevoked")
	}

	afterM, _ := primary.Manifest(ctx)
	if afterM.Sequence != beforeSeq {
		t.Errorf("no-op ungrant must not advance manifest sequence: %d -> %d", beforeSeq, afterM.Sequence)
	}
	if afterM.Compartments["blocked"].KeyVersion != beforeKV {
		t.Errorf("no-op ungrant must not rotate the CK: %d -> %d", beforeKV, afterM.Compartments["blocked"].KeyVersion)
	}
}

// TestDD8_compartmentUngrant_refusesFullScopeDevice: ungranting from a
// full-scope (empty CompartmentScope) device is refused — operator
// must use device revoke. Ungrant is a narrowing tool, not a full
// revocation.
func TestDD8_compartmentUngrant_refusesFullScopeDevice(t *testing.T) {
	ctx := context.Background()
	primary, _, claim, _, _ := driveScopedHandshake(t, nil) // nil = full scope

	_, err := primary.CompartmentUngrant(ctx, claim.DeviceID, "allowed")
	if err == nil {
		t.Fatal("expected refusal for full-scope device")
	}
	if !strings.Contains(err.Error(), "no scope restriction") {
		t.Errorf("expected 'no scope restriction' in error, got: %v", err)
	}
}

// TestDD8_compartmentUngrant_errorsOnUnknownDevice
func TestDD8_compartmentUngrant_errorsOnUnknownDevice(t *testing.T) {
	ctx := context.Background()
	primary, _ := newPrimary(t)
	if err := primary.CompartmentCreate(ctx, "x", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	_, err := primary.CompartmentUngrant(ctx, "dev_nonexistent", "x")
	if err == nil {
		t.Fatal("expected unknown-device error")
	}
}

// TestDD8_compartmentUngrant_errorsOnUnknownCompartment
func TestDD8_compartmentUngrant_errorsOnUnknownCompartment(t *testing.T) {
	ctx := context.Background()
	primary, _, claim, _, _ := driveScopedHandshake(t, []string{"allowed"})
	_, err := primary.CompartmentUngrant(ctx, claim.DeviceID, "nonexistent")
	if err == nil {
		t.Fatal("expected unknown-compartment error")
	}
}

// TestDD8_compartmentUngrant_refusesMaster: ungranting from the master
// pseudo-device is meaningless (master has full access by definition).
func TestDD8_compartmentUngrant_refusesMaster(t *testing.T) {
	ctx := context.Background()
	primary, _ := newPrimary(t)
	if err := primary.CompartmentCreate(ctx, "x", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	_, err := primary.CompartmentUngrant(ctx, domain.MasterDeviceID, "x")
	if err == nil {
		t.Fatal("expected refusal to ungrant from master pseudo-device")
	}
}

// TestDD8_compartmentUngrant_rejectsInvalidName
func TestDD8_compartmentUngrant_rejectsInvalidName(t *testing.T) {
	ctx := context.Background()
	primary, _, claim, _, _ := driveScopedHandshake(t, []string{"allowed"})
	_, err := primary.CompartmentUngrant(ctx, claim.DeviceID, "$bad")
	if err == nil {
		t.Fatal("CompartmentUngrant must reject malformed compartment name")
	}
}

// TestDD8_compartmentUngrant_revokesTokens: tokens whose scope touches
// the ungranted vol must be revoked as part of the operation.
func TestDD8_compartmentUngrant_revokesTokens(t *testing.T) {
	ctx := context.Background()
	primary, _, claim, _ := driveMultiScopedHandshake(t)

	// Primary mints a token for "allowed". (Primary has full scope.)
	tok, err := primary.Grant(ctx, GrantRequest{
		Scope: []string{"allowed"},
		Mode:  domain.TokenModeRW,
		TTL:   time.Hour,
	})
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}

	res, err := primary.CompartmentUngrant(ctx, claim.DeviceID, "allowed")
	if err != nil {
		t.Fatalf("CompartmentUngrant: %v", err)
	}

	// The minted token's TID should be in the revoked list.
	found := false
	for _, tid := range res.RevokedTokens {
		if tid == tok.TID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ungrant should have revoked token %s touching the rotated vol; revoked list: %v",
			tok.TID, res.RevokedTokens)
	}
}

// TestDD8_compartmentUngrant_grantThenUngrantRoundtrip: grant a vol
// post-pairing, then ungrant it. Resulting scope matches the original
// pairing scope; rotation happened (KeyVersion bumped twice — once for
// the grant's seal, once for the ungrant's rotation). Sanity-checks
// the full grant/ungrant pair.
func TestDD8_compartmentUngrant_grantThenUngrantRoundtrip(t *testing.T) {
	ctx := context.Background()
	primary, _, claim, _, _ := driveScopedHandshake(t, []string{"allowed"})

	// Add blocked to scope.
	if _, err := primary.CompartmentGrant(ctx, claim.DeviceID, "blocked"); err != nil {
		t.Fatalf("CompartmentGrant: %v", err)
	}
	m, _ := primary.Manifest(ctx)
	if !m.Devices[claim.DeviceID].HasCompartmentAccess("blocked") {
		t.Fatal("after grant, peer must have access to blocked")
	}
	kvAfterGrant := m.Compartments["blocked"].KeyVersion
	// Grant doesn't rotate — it just adds a sealed entry. KeyVersion same.

	// Then ungrant it.
	res, err := primary.CompartmentUngrant(ctx, claim.DeviceID, "blocked")
	if err != nil {
		t.Fatalf("CompartmentUngrant: %v", err)
	}
	if res.AlreadyRevoked {
		t.Fatal("post-grant ungrant must not be already-revoked")
	}

	m, _ = primary.Manifest(ctx)
	// Scope back to original.
	if m.Devices[claim.DeviceID].HasCompartmentAccess("blocked") {
		t.Error("after ungrant, peer must NOT have access to blocked")
	}
	if !m.Devices[claim.DeviceID].HasCompartmentAccess("allowed") {
		t.Error("ungrant of blocked must not affect allowed")
	}
	// KeyVersion bumped due to ungrant rotation.
	if m.Compartments["blocked"].KeyVersion != kvAfterGrant+1 {
		t.Errorf("blocked KeyVersion should bump on ungrant: %d -> %d (want %d)",
			kvAfterGrant, m.Compartments["blocked"].KeyVersion, kvAfterGrant+1)
	}
	// Peer's sealed entry for blocked must be gone.
	if _, ok := m.Compartments["blocked"].EncryptedKeys[claim.DeviceID]; ok {
		t.Error("peer's sealed CK for blocked must be removed after ungrant")
	}
}
