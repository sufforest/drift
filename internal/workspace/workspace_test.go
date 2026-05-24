package workspace

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/credentials"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/manifest"
	"github.com/sufforest/drift/internal/mount"
	"github.com/sufforest/drift/internal/storage"
)

// newPrimary spins up an Init'd workspace on a per-test temp dir + memory
// provider. Returns the workspace plus a frozen "now" the test can advance.
func newPrimary(t *testing.T) (*Workspace, *storage.MemoryProvider) {
	t.Helper()
	ctx := context.Background()

	state, err := NewState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prov := storage.NewMemoryProvider()
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)

	ws, err := Init(ctx, Options{
		State:    state,
		Provider: prov,
		Writer:   storage.NewConditionalPutWriter(prov),
		Now:      func() time.Time { return now },
	}, InitParams{
		Bucket: domain.BucketInfo{
			Provider: domain.ProviderR2,
			Endpoint: "https://example.r2.cloudflarestorage.com",
			Name:     "test-bucket",
			Region:   "auto",
		},
		Parent: &credentials.Parent{
			Provider:        domain.ProviderR2,
			AccessKeyID:     "AK",
			SecretAccessKey: "SK",
		},
		DeviceName: "test-laptop",
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	return ws, prov
}

func TestInit_writesStateAndUploadsManifest(t *testing.T) {
	ws, prov := newPrimary(t)

	// State files exist with the right modes.
	if !ws.State.HasMaster() {
		t.Fatal("master.json not saved")
	}
	if _, err := ws.State.LoadDevice(); err != nil {
		t.Fatalf("LoadDevice: %v", err)
	}
	if _, err := ws.State.LoadParent(); err != nil {
		t.Fatalf("LoadParent: %v", err)
	}

	// Manifest is encrypted + signed + verifiable.
	m, err := ws.Manifest(context.Background())
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if m.WorkspaceID != ws.Config.WorkspaceID {
		t.Fatalf("workspace id mismatch: %s vs %s", m.WorkspaceID, ws.Config.WorkspaceID)
	}
	if _, ok := m.Devices[ws.Config.DeviceID]; !ok {
		t.Fatal("initializing device not in manifest")
	}

	// Init refuses to overwrite.
	state, _ := NewState(ws.State.BaseDir)
	_, err = Init(context.Background(), Options{
		State: state, Provider: prov, Writer: storage.NewConditionalPutWriter(prov),
	}, InitParams{
		Bucket: ws.Config.Bucket,
		Parent: &credentials.Parent{AccessKeyID: "x", SecretAccessKey: "y"},
	})
	if err == nil {
		t.Fatal("expected re-Init to fail")
	}
}

func TestLoad_recoversWorkspace(t *testing.T) {
	ws, prov := newPrimary(t)
	want := ws.Config.WorkspaceID

	loaded, err := Load(context.Background(), Options{
		State: ws.State, Provider: prov, Writer: storage.NewConditionalPutWriter(prov),
	})
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Config.WorkspaceID != want {
		t.Fatalf("loaded wid %s != saved %s", loaded.Config.WorkspaceID, want)
	}
	if loaded.Master == nil {
		t.Fatal("loaded master is nil")
	}
}

func TestCompartmentCreate_sealsKeyForEveryDevice(t *testing.T) {
	ws, _ := newPrimary(t)
	if err := ws.CompartmentCreate(context.Background(), "models", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	m, err := ws.Manifest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c, ok := m.Compartments["models"]
	if !ok {
		t.Fatal("compartment not in manifest")
	}
	// Sealed for the device and the master pseudo-device.
	if len(c.EncryptedKeys) != 2 {
		t.Fatalf("expected 2 sealed keys, got %d (keys=%v)", len(c.EncryptedKeys), c.EncryptedKeys)
	}
	if _, ok := c.EncryptedKeys[ws.Config.DeviceID]; !ok {
		t.Fatal("compartment not sealed for primary device")
	}

	// Re-creating fails.
	if err := ws.CompartmentCreate(context.Background(), "models", domain.ModeMount); err == nil {
		t.Fatal("expected duplicate compartment create to fail")
	}
}

// --- End-to-end: init → compartment → grant → redeem → revoke ---

func TestEndToEnd_grantRedeemRevoke(t *testing.T) {
	ctx := context.Background()
	ws, prov := newPrimary(t)

	if err := ws.CompartmentCreate(ctx, "project-x", domain.ModeMount); err != nil {
		t.Fatal(err)
	}

	issued, err := ws.Grant(ctx, GrantRequest{
		Scope: []string{"project-x"},
		Mode:  domain.TokenModeRW,
		TTL:   time.Hour,
	})
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}

	// Bearer side: redeem against the same in-memory provider.
	mnt := mount.NewNoopMounter()
	sess, err := Redeem(ctx, issued.Encoded, RedeemOptions{
		Provider:     prov,
		Mounter:      mnt,
		MountBase:    "/tmp/test-workspace",
		PollInterval: 10 * time.Millisecond,
		Now:          ws.now,
	})
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if sess.TID != issued.TID {
		t.Fatalf("session tid %s != issued %s", sess.TID, issued.TID)
	}
	if got := mnt.Active(); len(got) != 1 {
		t.Fatalf("expected 1 active mount, got %d (%v)", len(got), got)
	}

	// Revoke from the primary device.
	if err := ws.Revoke(ctx, issued.TID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// The session's poller picks it up; Wait returns ErrTokenRevoked.
	err = sess.Wait()
	if !errors.Is(err, domain.ErrTokenRevoked) {
		t.Fatalf("Wait expected ErrTokenRevoked, got %v", err)
	}
	if got := mnt.Active(); len(got) != 0 {
		t.Fatalf("mounts should be torn down on revoke, got %v", got)
	}

	// A subsequent Redeem against the revoked token fails up front.
	_, err = Redeem(ctx, issued.Encoded, RedeemOptions{
		Provider:     prov,
		Mounter:      mount.NewNoopMounter(),
		MountBase:    "/tmp/test-workspace-2",
		PollInterval: time.Second,
		Now:          ws.now,
	})
	if !errors.Is(err, domain.ErrTokenRevoked) {
		t.Fatalf("Redeem after revoke expected ErrTokenRevoked, got %v", err)
	}
}

func TestStatus_reportsTokensAndCompartments(t *testing.T) {
	ctx := context.Background()
	ws, _ := newPrimary(t)
	_ = ws.CompartmentCreate(ctx, "a", domain.ModeMount)
	_, _ = ws.Grant(ctx, GrantRequest{Scope: []string{"a"}, Mode: domain.TokenModeRO, TTL: 30 * time.Minute})

	s, err := ws.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Compartments) != 1 || s.Compartments[0].Name != "a" {
		t.Fatalf("compartments: %+v", s.Compartments)
	}
	if len(s.Tokens) != 1 {
		t.Fatalf("tokens: %+v", s.Tokens)
	}
}

func TestDevices_marksThisDevice(t *testing.T) {
	ws, _ := newPrimary(t)
	devs, err := ws.Devices(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Two devices: the running one + the master pseudo-device.
	if len(devs) != 2 {
		t.Fatalf("expected 2 devices, got %d: %+v", len(devs), devs)
	}
	hits := 0
	for _, d := range devs {
		if d.IsThis {
			hits++
			if d.ID != ws.Config.DeviceID {
				t.Fatalf("IsThis on wrong id: %s vs %s", d.ID, ws.Config.DeviceID)
			}
		}
	}
	if hits != 1 {
		t.Fatalf("exactly one device should be IsThis, got %d", hits)
	}
}

func TestVerify_happyPath(t *testing.T) {
	ctx := context.Background()
	ws, _ := newPrimary(t)
	_ = ws.CompartmentCreate(ctx, "c1", domain.ModeMount)

	report, err := ws.Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !report.ManifestSignature {
		t.Fatal("manifest signature should verify")
	}
	if !report.ProviderReachable || !report.ConditionalPut {
		t.Fatalf("provider reachable/cap mismatch: %+v", report)
	}
	if report.NumCompartments != 1 {
		t.Fatalf("compartments = %d, want 1", report.NumCompartments)
	}
}

func TestCompartmentDelete_removesFromManifest(t *testing.T) {
	ctx := context.Background()
	ws, _ := newPrimary(t)
	if err := ws.CompartmentCreate(ctx, "kill-me", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	if err := ws.CompartmentDelete(ctx, "kill-me"); err != nil {
		t.Fatal(err)
	}
	m, _ := ws.Manifest(ctx)
	if _, ok := m.Compartments["kill-me"]; ok {
		t.Fatal("compartment should have been removed")
	}
	// Deleting again surfaces ErrCompartmentUnknown.
	if err := ws.CompartmentDelete(ctx, "kill-me"); !errors.Is(err, domain.ErrCompartmentUnknown) {
		t.Fatalf("expected ErrCompartmentUnknown on re-delete, got %v", err)
	}
}

func TestDeviceRevoke_rotatesKeysAndInvalidatesTokens(t *testing.T) {
	ctx := context.Background()
	ws, _ := newPrimary(t)
	if err := ws.CompartmentCreate(ctx, "shared", domain.ModeMount); err != nil {
		t.Fatal(err)
	}

	// Pre-condition: shared compartment is sealed for both the primary
	// device and the master pseudo-entry.
	m0, _ := ws.Manifest(ctx)
	v0 := m0.Compartments["shared"].KeyVersion

	// Add a second device to the manifest manually so we have something
	// to revoke. We mutate via the same RMW path the workspace uses.
	addedID := "dev_extra"
	err := ws.Writer.ReadModifyWrite(ctx, domain.ManifestKey, func(cur []byte) ([]byte, error) {
		mm, err := manifest.Decrypt(cur, ws.CPRK, ws.Config.WorkspaceID)
		if err != nil {
			return nil, err
		}
		extra, _ := dcrypto.GenerateDeviceKey()
		extraPub, _ := extra.BoxPub()
		mm.Devices[addedID] = domain.Device{
			ID:         addedID,
			Name:       "extra",
			PublicKey:  extra.SignPub(),
			EncryptKey: extraPub[:],
			EnrolledAt: ws.now(),
			LastSeen:   ws.now(),
		}
		// Seal the existing compartment key for the new device.
		c := mm.Compartments["shared"]
		c.EncryptedKeys[addedID] = []byte("dummy-sealed-key-for-test")
		mm.Compartments["shared"] = c
		mm.UpdatedAt = ws.now()
		if err := manifest.Sign(mm, ws.Config.DeviceID, ws.Device.SignPriv); err != nil {
			return nil, err
		}
		return manifest.Encrypt(mm, ws.CPRK)
	})
	if err != nil {
		t.Fatal(err)
	}

	// Revoke with rotation.
	result, err := ws.DeviceRevoke(ctx, addedID, true)
	if err != nil {
		t.Fatalf("DeviceRevoke: %v", err)
	}
	if !result.RemovedFromDevices {
		t.Fatal("expected RemovedFromDevices=true")
	}
	if len(result.RotatedCompartments) != 1 || result.RotatedCompartments[0] != "shared" {
		t.Fatalf("expected to rotate [shared], got %v", result.RotatedCompartments)
	}

	// Post-condition: device gone, KeyVersion bumped, sealed-keys map
	// no longer contains the revoked device.
	m1, _ := ws.Manifest(ctx)
	if _, ok := m1.Devices[addedID]; ok {
		t.Fatal("revoked device still in Devices map")
	}
	if m1.Compartments["shared"].KeyVersion != v0+1 {
		t.Fatalf("KeyVersion = %d, want %d", m1.Compartments["shared"].KeyVersion, v0+1)
	}
	if _, ok := m1.Compartments["shared"].EncryptedKeys[addedID]; ok {
		t.Fatal("revoked device still in EncryptedKeys")
	}
}

func TestDeviceRevoke_refusesSelfRevoke(t *testing.T) {
	ws, _ := newPrimary(t)
	_, err := ws.DeviceRevoke(context.Background(), ws.Config.DeviceID, true)
	if err == nil || !contains(err.Error(), "running device") {
		t.Fatalf("expected self-revoke refusal, got %v", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestGC_sweepsOrphanedCompartmentChunks(t *testing.T) {
	ctx := context.Background()
	ws, prov := newPrimary(t)
	// Place chunks under a compartment that never existed in the manifest.
	_ = prov.Put(ctx, "compartments/ghost/chunk-1", []byte("x"))
	_ = prov.Put(ctx, "compartments/ghost/chunk-2", []byte("x"))

	// Also a live compartment with chunks — should NOT be swept.
	if err := ws.CompartmentCreate(ctx, "live", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	_ = prov.Put(ctx, "compartments/live/chunk-1", []byte("y"))

	report, err := ws.GC(ctx, GCOptions{})
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if len(report.OrphanedCompartmentChunks) != 2 {
		t.Fatalf("expected 2 orphans, got %d: %v", len(report.OrphanedCompartmentChunks), report.OrphanedCompartmentChunks)
	}
	// Live chunks survive.
	if ok, _ := prov.Exists(ctx, "compartments/live/chunk-1"); !ok {
		t.Fatal("live compartment chunk was deleted by gc")
	}
}

func TestGC_dryRunDoesNotDelete(t *testing.T) {
	ctx := context.Background()
	ws, prov := newPrimary(t)
	_ = prov.Put(ctx, "compartments/ghost/x", []byte("x"))

	report, err := ws.GC(ctx, GCOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.OrphanedCompartmentChunks) != 1 {
		t.Fatalf("expected 1 orphan, got %d", len(report.OrphanedCompartmentChunks))
	}
	if ok, _ := prov.Exists(ctx, "compartments/ghost/x"); !ok {
		t.Fatal("dry-run should not have deleted")
	}
}

func TestGC_sweepsExpiredCredentialBlobs(t *testing.T) {
	ctx := context.Background()
	ws, prov := newPrimary(t)
	_ = ws.CompartmentCreate(ctx, "c", domain.ModeMount)

	// Issue a token that will be expired by the time GC runs.
	issued, err := ws.Grant(ctx, GrantRequest{
		Scope: []string{"c"},
		Mode:  domain.TokenModeRW,
		TTL:   time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	credKey := domain.CredentialsKeyFor(issued.TID)
	if ok, _ := prov.Exists(ctx, credKey); !ok {
		t.Fatal("credentials blob should exist after grant")
	}

	// Advance the workspace clock far past the grace window.
	ws.now = func() time.Time { return time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC) }
	report, err := ws.GC(ctx, GCOptions{CredentialsGracePeriod: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.OrphanedCredentialBlobs) != 1 {
		t.Fatalf("expected 1 expired blob, got %d (%v)", len(report.OrphanedCredentialBlobs), report.OrphanedCredentialBlobs)
	}
	if ok, _ := prov.Exists(ctx, credKey); ok {
		t.Fatal("expired credentials blob should have been deleted")
	}
}

func TestManifest_rejectsForgedDeviceWithoutEnrollment(t *testing.T) {
	// A bucket-write attacker inserts a fake device into m.Devices and
	// re-signs the manifest with that device's key. Without a matching
	// master-signed enrollment cert, the attacker can't forge a valid
	// chain — Verify rejects on the missing/invalid enrollment.
	ctx := context.Background()
	ws, prov := newPrimary(t)

	body, err := prov.Get(ctx, domain.ManifestKey)
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Decrypt(body, ws.CPRK, ws.Config.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}

	// Insert a fresh attacker device with no enrollment cert. Re-sign
	// the manifest with the attacker's key so the top-level signature
	// passes.
	rogue, _ := dcrypto.GenerateDeviceKey()
	rogueBox, _ := rogue.BoxPub()
	m.Devices["rogue"] = domain.Device{
		ID:         "rogue",
		Name:       "attacker",
		PublicKey:  rogue.SignPub(),
		EncryptKey: rogueBox[:],
		EnrolledAt: ws.now(),
		LastSeen:   ws.now(),
	}
	if err := manifest.Sign(m, "rogue", rogue.SignPriv); err != nil {
		t.Fatal(err)
	}
	cipher, err := manifest.Encrypt(m, ws.CPRK)
	if err != nil {
		t.Fatal(err)
	}
	if err := prov.Put(ctx, domain.ManifestKey, cipher); err != nil {
		t.Fatal(err)
	}

	_, err = ws.Manifest(ctx)
	if !errors.Is(err, domain.ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid for forged device, got %v", err)
	}
}

func TestManifest_rejectsRollback(t *testing.T) {
	// H1: a bucket-write attacker replays an older signed manifest. The
	// workspace remembers the highest Sequence and refuses lower ones.
	ctx := context.Background()
	ws, prov := newPrimary(t)

	// Capture the initial manifest body (seq=1).
	original, _ := prov.Get(ctx, domain.ManifestKey)

	// Bump the manifest by creating a compartment — seq goes to 2.
	if err := ws.CompartmentCreate(ctx, "later", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	if _, err := ws.Manifest(ctx); err != nil {
		t.Fatalf("Manifest after legitimate bump: %v", err)
	}

	// Attacker replays the older signed manifest.
	if err := prov.Put(ctx, domain.ManifestKey, original); err != nil {
		t.Fatal(err)
	}
	_, err := ws.Manifest(ctx)
	if !errors.Is(err, domain.ErrManifestConflict) {
		t.Fatalf("expected ErrManifestConflict on manifest rollback, got %v", err)
	}
}

func TestInit_refusesToOverwriteExistingManifest(t *testing.T) {
	// Round-2 audit #13: a user with a fresh ~/.config/drift but a
	// bucket that already holds a manifest should not silently clobber.
	ctx := context.Background()
	first, prov := newPrimary(t)

	state, _ := NewState(t.TempDir()) // fresh state dir
	_, err := Init(ctx, Options{
		State:    state,
		Provider: prov,
		Writer:   storage.NewConditionalPutWriter(prov),
	}, InitParams{
		Bucket: first.Config.Bucket,
		Parent: &credentials.Parent{
			Provider:        domain.ProviderR2,
			AccessKeyID:     "AK",
			SecretAccessKey: "SK",
		},
	})
	if err == nil {
		t.Fatal("expected second Init to refuse overwriting existing manifest")
	}
}

func TestCompartmentCreate_rejectsBadName(t *testing.T) {
	ctx := context.Background()
	ws, _ := newPrimary(t)
	for _, bad := range []string{"", "..", "../foo", "FOO", "x/y", "x y", "-leading-hyphen"} {
		if err := ws.CompartmentCreate(ctx, bad, domain.ModeMount); err == nil {
			t.Errorf("expected rejection for compartment name %q", bad)
		}
	}
}

func TestSessionFile_roundTrip(t *testing.T) {
	dir := t.TempDir()
	rec := SessionRecord{
		PID:         os.Getpid(), // alive by definition
		TID:         "tok_test",
		WorkspaceID: "wks_test",
		MountPoints: []string{"/mnt/x"},
		StartedAt:   time.Now().UTC().Truncate(time.Second),
	}
	if err := SaveSession(dir, rec); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSession(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.PID != rec.PID || got.TID != rec.TID {
		t.Fatalf("roundtrip mismatch: %+v vs %+v", got, rec)
	}
	if !got.SignalAlive() {
		t.Fatal("own pid should be alive")
	}
	if err := ClearSession(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSession(dir); !os.IsNotExist(err) {
		t.Fatalf("LoadSession after Clear: want NotExist, got %v", err)
	}
}

func TestSessionFile_deadPID(t *testing.T) {
	dir := t.TempDir()
	rec := SessionRecord{PID: 999999999, TID: "tok"} // unlikely to be live
	if err := SaveSession(dir, rec); err != nil {
		t.Fatal(err)
	}
	got, _ := LoadSession(dir)
	if got.SignalAlive() {
		t.Fatal("pid 999999999 should not be alive")
	}
}

func TestSession_closeIsIdempotent(t *testing.T) {
	ctx := context.Background()
	ws, prov := newPrimary(t)
	_ = ws.CompartmentCreate(ctx, "x", domain.ModeMount)
	issued, _ := ws.Grant(ctx, GrantRequest{Scope: []string{"x"}, Mode: domain.TokenModeRW, TTL: time.Hour})

	sess, err := Redeem(ctx, issued.Encoded, RedeemOptions{
		Provider:     prov,
		Mounter:      mount.NewNoopMounter(),
		MountBase:    t.TempDir(),
		PollInterval: time.Second,
		Now:          ws.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sess.Close(); err != nil {
		t.Fatalf("second Close should be idempotent, got %v", err)
	}
}
