package workspace

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/storage"
)

// driveScopedHandshake creates a pre-populated workspace with two
// compartments (allowed, blocked) and pairs in a peer device with the
// supplied scope. Returns (primary, secondary-state, claimResult,
// confirmResult, prov). Useful for tests that need the post-pairing
// state but not for testing the pairing itself.
func driveScopedHandshake(t *testing.T, scope []string) (*Workspace, *State, *LinkClaimResult, *LinkConfirmResult, *storage.MemoryProvider) {
	t.Helper()
	ctx := context.Background()
	primary, prov := newPrimary(t)
	if err := primary.CompartmentCreate(ctx, "allowed", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	if err := primary.CompartmentCreate(ctx, "blocked", domain.ModeMount); err != nil {
		t.Fatal(err)
	}

	init, err := primary.LinkInit(ctx, 5*time.Minute, LinkInitOptions{
		PeerMode:         true,
		CompartmentScope: scope,
	})
	if err != nil {
		t.Fatalf("LinkInit: %v", err)
	}
	newState, _ := NewState(t.TempDir())

	var claimRes *LinkClaimResult
	var claimErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		claimRes, claimErr = LinkClaim(ctx, init.Encoded, "scoped-peer", LinkClaimOptions{
			State:        newState,
			ProviderFor:  func(_ domain.S3Credential, _ domain.BucketInfo) (storage.Provider, error) { return prov, nil },
			Now:          primary.now,
			PollInterval: 2 * time.Millisecond,
			Timeout:      5 * time.Second,
		})
	}()
	respKey := domain.PairingResponseKey(init.PID)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ok, _ := prov.Exists(ctx, respKey); ok {
			break
		}
		time.Sleep(time.Millisecond)
	}
	confirm, err := primary.LinkConfirm(ctx, init.PID, LinkConfirmOptions{})
	if err != nil {
		t.Fatalf("LinkConfirm: %v", err)
	}
	wg.Wait()
	if claimErr != nil {
		t.Fatalf("LinkClaim: %v", claimErr)
	}
	return primary, newState, claimRes, confirm, prov
}

// TestDD8_pairing_writesScopeOntoDeviceEntry: peer paired with
// --peer-compartments has CompartmentScope written onto its Device
// entry in the manifest.
func TestDD8_pairing_writesScopeOntoDeviceEntry(t *testing.T) {
	primary, _, claim, _, _ := driveScopedHandshake(t, []string{"allowed"})
	m, err := primary.Manifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dev, ok := m.Devices[claim.DeviceID]
	if !ok {
		t.Fatalf("device %s missing from manifest", claim.DeviceID)
	}
	if len(dev.CompartmentScope) != 1 || dev.CompartmentScope[0] != "allowed" {
		t.Errorf("expected CompartmentScope=[allowed], got %v", dev.CompartmentScope)
	}
}

// TestDD8_pairing_sealsOnlyScopedCompartments: the manifest's blocked
// compartment must NOT have a sealed CK for the new device, but the
// allowed compartment must.
func TestDD8_pairing_sealsOnlyScopedCompartments(t *testing.T) {
	primary, _, claim, _, _ := driveScopedHandshake(t, []string{"allowed"})
	m, _ := primary.Manifest(context.Background())

	allowed := m.Compartments["allowed"]
	if _, ok := allowed.EncryptedKeys[claim.DeviceID]; !ok {
		t.Error("allowed compartment must be sealed for the scoped peer")
	}
	blocked := m.Compartments["blocked"]
	if _, ok := blocked.EncryptedKeys[claim.DeviceID]; ok {
		t.Error("blocked compartment must NOT be sealed for the scoped peer")
	}
}

// TestDD8_pairing_emptyScopeMeansFullAccess: peer with nil scope must
// receive sealed CKs for every compartment (the pre-DD-8 default).
func TestDD8_pairing_emptyScopeMeansFullAccess(t *testing.T) {
	primary, _, claim, _, _ := driveScopedHandshake(t, nil)
	m, _ := primary.Manifest(context.Background())

	dev := m.Devices[claim.DeviceID]
	if len(dev.CompartmentScope) != 0 {
		t.Errorf("nil scope should remain empty, got %v", dev.CompartmentScope)
	}
	for _, name := range []string{"allowed", "blocked"} {
		if _, ok := m.Compartments[name].EncryptedKeys[claim.DeviceID]; !ok {
			t.Errorf("compartment %s must be sealed for full-scope peer", name)
		}
	}
}

// TestDD8_compartmentCreate_skipsOutOfScopeDevices: a compartment
// created AFTER a scoped peer was paired must NOT be sealed for that
// peer (because the peer's scope is fixed at pairing time and doesn't
// include the new compartment).
func TestDD8_compartmentCreate_skipsOutOfScopeDevices(t *testing.T) {
	primary, _, claim, _, _ := driveScopedHandshake(t, []string{"allowed"})
	ctx := context.Background()
	if err := primary.CompartmentCreate(ctx, "newly-created", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	m, _ := primary.Manifest(ctx)
	newComp := m.Compartments["newly-created"]
	if _, ok := newComp.EncryptedKeys[claim.DeviceID]; ok {
		t.Error("scoped peer must NOT be sealed for newly-created compartment")
	}
	// Master must still get it.
	if _, ok := newComp.EncryptedKeys[primary.Config.DeviceID]; !ok {
		t.Error("primary device must be sealed for newly-created compartment")
	}
}

// TestDD8_compartmentCreate_sealsForFullScopeDevices: full-scope (nil
// CompartmentScope) devices keep receiving newly-created compartments.
func TestDD8_compartmentCreate_sealsForFullScopeDevices(t *testing.T) {
	primary, _, claim, _, _ := driveScopedHandshake(t, nil) // nil = full
	ctx := context.Background()
	if err := primary.CompartmentCreate(ctx, "another", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	m, _ := primary.Manifest(ctx)
	if _, ok := m.Compartments["another"].EncryptedKeys[claim.DeviceID]; !ok {
		t.Error("full-scope peer must be sealed for newly-created compartment")
	}
}

// TestDD8_grant_scopedPeerRefusesOutOfScopeMint: a scoped peer cannot
// mint bearer tokens for compartments outside its scope.
func TestDD8_grant_scopedPeerRefusesOutOfScopeMint(t *testing.T) {
	ctx := context.Background()
	primary, secondaryState, _, _, prov := driveScopedHandshake(t, []string{"allowed"})

	// Load secondary as a Workspace.
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
		Scope: []string{"blocked"},
		Mode:  domain.TokenModeRW,
		TTL:   time.Hour,
	})
	if err == nil {
		t.Fatal("scoped peer must NOT be allowed to mint tokens for out-of-scope compartments")
	}
	if !strings.Contains(err.Error(), "not scoped for") {
		t.Errorf("expected scope-mismatch error, got: %v", err)
	}
}

// TestDD8_grant_scopedPeerMintsInScope: the same scoped peer CAN mint
// tokens for compartments it's scoped for.
func TestDD8_grant_scopedPeerMintsInScope(t *testing.T) {
	ctx := context.Background()
	primary, secondaryState, _, _, prov := driveScopedHandshake(t, []string{"allowed"})

	secondary, err := Load(ctx, Options{
		State:    secondaryState,
		Provider: prov,
		Writer:   storage.NewConditionalPutWriter(prov),
		Now:      primary.now,
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := secondary.Grant(ctx, GrantRequest{
		Scope: []string{"allowed"},
		Mode:  domain.TokenModeRW,
		TTL:   time.Hour,
	})
	if err != nil {
		t.Fatalf("scoped peer should be able to mint for in-scope vol, got: %v", err)
	}
	if res == nil || res.Encoded == "" {
		t.Fatal("expected a valid token result")
	}
}

// TestDD8_grant_fullScopePeerMintsAny: full-scope peer can mint for
// any compartment (no regression on pre-DD-8 behavior).
func TestDD8_grant_fullScopePeerMintsAny(t *testing.T) {
	ctx := context.Background()
	primary, secondaryState, _, _, prov := driveScopedHandshake(t, nil)

	secondary, err := Load(ctx, Options{
		State:    secondaryState,
		Provider: prov,
		Writer:   storage.NewConditionalPutWriter(prov),
		Now:      primary.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"allowed", "blocked"} {
		res, err := secondary.Grant(ctx, GrantRequest{
			Scope: []string{name},
			Mode:  domain.TokenModeRW,
			TTL:   time.Hour,
		})
		if err != nil {
			t.Errorf("full-scope peer should mint for %s, got: %v", name, err)
		}
		if res == nil || res.Encoded == "" {
			t.Errorf("nil result for %s", name)
		}
	}
}

// TestDD8_compartmentGrant_addsScopeAndSeals: drift vol grant
// retroactively gives a scoped peer access to a new compartment;
// after the grant, the secondary CAN mint for it.
func TestDD8_compartmentGrant_addsScopeAndSeals(t *testing.T) {
	ctx := context.Background()
	primary, secondaryState, claim, _, prov := driveScopedHandshake(t, []string{"allowed"})

	res, err := primary.CompartmentGrant(ctx, claim.DeviceID, "blocked")
	if err != nil {
		t.Fatalf("CompartmentGrant: %v", err)
	}
	if res.AlreadyGranted {
		t.Fatal("first grant must not be already-granted")
	}
	if res.Sequence == 0 {
		t.Errorf("expected non-zero sequence after a real grant")
	}

	// Manifest must now show:
	//   - scope contains "blocked"
	//   - blocked.EncryptedKeys[device] present
	m, _ := primary.Manifest(ctx)
	dev := m.Devices[claim.DeviceID]
	if !dev.HasCompartmentAccess("blocked") {
		t.Errorf("scope must now include blocked: %v", dev.CompartmentScope)
	}
	if _, ok := m.Compartments["blocked"].EncryptedKeys[claim.DeviceID]; !ok {
		t.Error("blocked compartment must be sealed for the granted peer")
	}

	// Secondary should now be able to mint for "blocked".
	secondary, err := Load(ctx, Options{
		State:    secondaryState,
		Provider: prov,
		Writer:   storage.NewConditionalPutWriter(prov),
		Now:      primary.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secondary.Grant(ctx, GrantRequest{
		Scope: []string{"blocked"},
		Mode:  domain.TokenModeRW,
		TTL:   time.Hour,
	}); err != nil {
		t.Errorf("after CompartmentGrant, secondary must be able to mint for blocked; got: %v", err)
	}
}

// TestDD8_compartmentGrant_idempotent: granting an already-granted
// (device, vol) is a no-op — does NOT advance the manifest sequence.
func TestDD8_compartmentGrant_idempotent(t *testing.T) {
	ctx := context.Background()
	primary, _, claim, _, _ := driveScopedHandshake(t, []string{"allowed"})

	beforeM, _ := primary.Manifest(ctx)
	beforeSeq := beforeM.Sequence

	// Already in scope.
	res, err := primary.CompartmentGrant(ctx, claim.DeviceID, "allowed")
	if err != nil {
		t.Fatalf("CompartmentGrant: %v", err)
	}
	if !res.AlreadyGranted {
		t.Error("second grant for the same (device, vol) must be already-granted")
	}

	afterM, _ := primary.Manifest(ctx)
	if afterM.Sequence != beforeSeq {
		t.Errorf("idempotent grant must NOT advance sequence: %d -> %d", beforeSeq, afterM.Sequence)
	}
}

// TestDD8_compartmentGrant_nopForFullScopeDevice: granting to a
// full-scope device is a no-op (it already has all access).
func TestDD8_compartmentGrant_nopForFullScopeDevice(t *testing.T) {
	ctx := context.Background()
	primary, _, claim, _, _ := driveScopedHandshake(t, nil)

	beforeM, _ := primary.Manifest(ctx)
	beforeSeq := beforeM.Sequence

	res, err := primary.CompartmentGrant(ctx, claim.DeviceID, "allowed")
	if err != nil {
		t.Fatalf("CompartmentGrant on full-scope device: %v", err)
	}
	if !res.AlreadyGranted {
		t.Error("granting to a full-scope device must be already-granted")
	}
	afterM, _ := primary.Manifest(ctx)
	if afterM.Sequence != beforeSeq {
		t.Errorf("no-op grant must not advance sequence: %d -> %d", beforeSeq, afterM.Sequence)
	}
}

// TestDD8_compartmentGrant_errorsOnUnknownDevice
func TestDD8_compartmentGrant_errorsOnUnknownDevice(t *testing.T) {
	ctx := context.Background()
	primary, _ := newPrimary(t)
	if err := primary.CompartmentCreate(ctx, "x", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	_, err := primary.CompartmentGrant(ctx, "dev_nonexistent", "x")
	if err == nil {
		t.Fatal("expected unknown-device error")
	}
}

// TestDD8_compartmentGrant_errorsOnUnknownCompartment
func TestDD8_compartmentGrant_errorsOnUnknownCompartment(t *testing.T) {
	ctx := context.Background()
	primary, _, claim, _, _ := driveScopedHandshake(t, []string{"allowed"})
	_, err := primary.CompartmentGrant(ctx, claim.DeviceID, "nonexistent-vol")
	if err == nil {
		t.Fatal("expected unknown-compartment error")
	}
}

// TestDD8_compartmentGrant_refusesMaster: trying to grant scope to the
// master pseudo-device is an error (master always has full access by
// definition).
func TestDD8_compartmentGrant_refusesMaster(t *testing.T) {
	ctx := context.Background()
	primary, _ := newPrimary(t)
	if err := primary.CompartmentCreate(ctx, "x", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	_, err := primary.CompartmentGrant(ctx, domain.MasterDeviceID, "x")
	if err == nil {
		t.Fatal("expected refusal to grant scope to master pseudo-device")
	}
}

// TestDD8_normalizeScope_sortsAndDedupes: documents the canonical
// stable order used in PairingStub + Device entries.
func TestDD8_normalizeScope_sortsAndDedupes(t *testing.T) {
	got := normalizeScope([]string{"c", "a", "b", "a", "", "b"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("idx %d: got %q want %q", i, got[i], want[i])
		}
	}
	if normalizeScope(nil) != nil {
		t.Error("nil input must return nil output")
	}
	if normalizeScope([]string{"", ""}) != nil {
		t.Error("all-empty input must return nil output")
	}
}

// TestDD8_linkInit_rejectsInvalidCompartmentName: a typo or bad name
// must error at LinkInit rather than silently producing a useless scope.
func TestDD8_linkInit_rejectsInvalidCompartmentName(t *testing.T) {
	ctx := context.Background()
	primary, _ := newPrimary(t)
	for _, bad := range []string{"$$broken", "has space", "../escape", "UPPER"} {
		_, err := primary.LinkInit(ctx, 5*time.Minute, LinkInitOptions{
			CompartmentScope: []string{bad},
		})
		if err == nil {
			t.Errorf("LinkInit must reject malformed compartment name %q", bad)
		}
	}
}

// TestDD8_compartmentGrant_rejectsInvalidName
func TestDD8_compartmentGrant_rejectsInvalidName(t *testing.T) {
	ctx := context.Background()
	primary, _, claim, _, _ := driveScopedHandshake(t, []string{"allowed"})
	_, err := primary.CompartmentGrant(ctx, claim.DeviceID, "$bad")
	if err == nil {
		t.Fatal("CompartmentGrant must reject malformed compartment name")
	}
}

// TestDD8_linkInit_endToEndScopeNormalization: un-normalized input to
// LinkInit (out-of-order + duplicates) results in a sorted, deduped
// scope on the new device's Device entry.
func TestDD8_linkInit_endToEndScopeNormalization(t *testing.T) {
	ctx := context.Background()
	primary, _ := newPrimary(t)
	for _, name := range []string{"alpha", "bravo", "charlie"} {
		if err := primary.CompartmentCreate(ctx, name, domain.ModeMount); err != nil {
			t.Fatal(err)
		}
	}
	init, err := primary.LinkInit(ctx, 5*time.Minute, LinkInitOptions{
		PeerMode:         true,
		CompartmentScope: []string{"charlie", "alpha", "bravo", "alpha"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Inspect the stub directly via the manifest.
	m, _ := primary.Manifest(ctx)
	stub := m.Pairings[init.PID]
	want := []string{"alpha", "bravo", "charlie"}
	if len(stub.CompartmentScope) != len(want) {
		t.Fatalf("stub scope = %v, want %v", stub.CompartmentScope, want)
	}
	for i, w := range want {
		if stub.CompartmentScope[i] != w {
			t.Errorf("stub scope[%d] = %q, want %q", i, stub.CompartmentScope[i], w)
		}
	}
}

// TestDD8_secondarySeesOwnScopeAfterLoad: after pairing with scope, the
// freshly-Loaded secondary's Manifest() read shows its own Device entry
// with the expected CompartmentScope. Confirms the scope is visible to
// the secondary itself (not just the primary), which it needs in order
// to honor scope at its own Grant() calls.
func TestDD8_secondarySeesOwnScopeAfterLoad(t *testing.T) {
	ctx := context.Background()
	primary, secondaryState, claim, _, prov := driveScopedHandshake(t, []string{"allowed"})

	secondary, err := Load(ctx, Options{
		State:    secondaryState,
		Provider: prov,
		Writer:   storage.NewConditionalPutWriter(prov),
		Now:      primary.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	m, err := secondary.Manifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	me := m.Devices[claim.DeviceID]
	if len(me.CompartmentScope) != 1 || me.CompartmentScope[0] != "allowed" {
		t.Errorf("secondary's view of own scope = %v, want [allowed]", me.CompartmentScope)
	}
	if !me.HasCompartmentAccess("allowed") {
		t.Error("secondary's HasCompartmentAccess(allowed) should be true")
	}
	if me.HasCompartmentAccess("blocked") {
		t.Error("secondary's HasCompartmentAccess(blocked) should be false")
	}
}
