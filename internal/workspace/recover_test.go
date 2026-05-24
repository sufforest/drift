package workspace

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sufforest/drift/internal/credentials"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/recovery"
	"github.com/sufforest/drift/internal/storage"
)

const testPassphrase = "correct horse battery staple test 42"

// weakArgon returns Argon parameters fast enough for unit tests.
func weakArgon() recovery.WrapOptions {
	return recovery.WrapOptions{Time: 1, MemoryKiB: 8 * 1024, Threads: 1, AllowWeakPassphrase: true}
}

func TestSaveRecovery_writesBlob(t *testing.T) {
	ws, prov := newPrimary(t)
	ctx := context.Background()

	if err := ws.SaveRecovery(ctx, testPassphrase, weakArgon()); err != nil {
		t.Fatalf("SaveRecovery: %v", err)
	}
	exists, err := prov.Exists(ctx, domain.RecoveryKey)
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !exists {
		t.Fatal("recovery blob not uploaded")
	}
}

func TestDisableRecovery_removesBlob(t *testing.T) {
	ws, prov := newPrimary(t)
	ctx := context.Background()

	if err := ws.SaveRecovery(ctx, testPassphrase, weakArgon()); err != nil {
		t.Fatalf("SaveRecovery: %v", err)
	}
	if err := ws.DisableRecovery(ctx); err != nil {
		t.Fatalf("DisableRecovery: %v", err)
	}
	exists, _ := prov.Exists(ctx, domain.RecoveryKey)
	if exists {
		t.Fatal("recovery blob still present after disable")
	}

	// Double-disable is idempotent.
	if err := ws.DisableRecovery(ctx); err != nil {
		t.Fatalf("second DisableRecovery: %v", err)
	}
}

func TestRecover_fullFlow(t *testing.T) {
	ctx := context.Background()
	primary, prov := newPrimary(t)

	// Create a couple of compartments so we exercise re-sealing.
	if err := primary.CompartmentCreate(ctx, "models", domain.ModeMount); err != nil {
		t.Fatalf("CompartmentCreate models: %v", err)
	}
	if err := primary.CompartmentCreate(ctx, "code", domain.ModeSync); err != nil {
		t.Fatalf("CompartmentCreate code: %v", err)
	}

	if err := primary.SaveRecovery(ctx, testPassphrase, weakArgon()); err != nil {
		t.Fatalf("SaveRecovery: %v", err)
	}

	// Pretend the laptop died — bootstrap a fresh state dir against the
	// SAME bucket (memory provider keeps state).
	freshState, err := NewState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 5, 22, 9, 0, 0, 0, time.UTC)
	recovered, err := Recover(ctx, Options{
		State:    freshState,
		Provider: prov,
		Writer:   storage.NewConditionalPutWriter(prov),
		Now:      func() time.Time { return now },
	}, RecoverParams{
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
		Passphrase: testPassphrase,
		DeviceName: "test-replacement",
	})
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}

	// New device id must be different from original.
	if recovered.Config.DeviceID == primary.Config.DeviceID {
		t.Fatal("recovered device id collides with original — should be fresh")
	}
	// Workspace id must match.
	if recovered.Config.WorkspaceID != primary.Config.WorkspaceID {
		t.Fatalf("workspace id mismatch: %s vs %s", recovered.Config.WorkspaceID, primary.Config.WorkspaceID)
	}
	// Master fingerprint pinned identically.
	if string(recovered.Config.MasterFingerprint) != string(primary.Config.MasterFingerprint) {
		t.Fatal("master fingerprint pin mismatch after recovery")
	}

	// Sanity: manifest fetched + each compartment has a seal for the new device.
	m, err := recovered.Manifest(ctx)
	if err != nil {
		t.Fatalf("Manifest after recovery: %v", err)
	}
	for _, name := range []string{"models", "code"} {
		c, ok := m.Compartments[name]
		if !ok {
			t.Fatalf("compartment %q gone from manifest", name)
		}
		if _, ok := c.EncryptedKeys[recovered.Config.DeviceID]; !ok {
			t.Errorf("compartment %q has no seal for recovered device %s", name, recovered.Config.DeviceID)
		}
	}

	// Primary's device is still enrolled too (we didn't remove it).
	if _, ok := m.Devices[primary.Config.DeviceID]; !ok {
		t.Error("primary device dropped from manifest during recovery")
	}
}

func TestRecover_wrongPassphrase(t *testing.T) {
	ctx := context.Background()
	primary, prov := newPrimary(t)
	if err := primary.SaveRecovery(ctx, testPassphrase, weakArgon()); err != nil {
		t.Fatalf("SaveRecovery: %v", err)
	}
	freshState, _ := NewState(t.TempDir())
	_, err := Recover(ctx, Options{
		State:    freshState,
		Provider: prov,
		Writer:   storage.NewConditionalPutWriter(prov),
	}, RecoverParams{
		Bucket: domain.BucketInfo{Name: "test-bucket"},
		Parent: &credentials.Parent{Provider: domain.ProviderR2},
		Passphrase: "wrong passphrase entirely",
	})
	if !errors.Is(err, recovery.ErrPassphrase) {
		t.Fatalf("expected ErrPassphrase, got %v", err)
	}
}

func TestRecover_noBlobInBucket(t *testing.T) {
	ctx := context.Background()
	_, prov := newPrimary(t)
	// Note: did NOT call SaveRecovery, so no blob.
	freshState, _ := NewState(t.TempDir())
	_, err := Recover(ctx, Options{
		State:    freshState,
		Provider: prov,
		Writer:   storage.NewConditionalPutWriter(prov),
	}, RecoverParams{
		Bucket:     domain.BucketInfo{Name: "test-bucket"},
		Parent:     &credentials.Parent{Provider: domain.ProviderR2},
		Passphrase: testPassphrase,
	})
	if !errors.Is(err, recovery.ErrNoBlob) {
		t.Fatalf("expected ErrNoBlob, got %v", err)
	}
}
