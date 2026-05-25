package workspace

import (
	"context"
	"errors"
	"strings"
	"testing"

	driftcreds "github.com/sufforest/drift/internal/credentials"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/storage"
)

// TestParentSet_happyPath: SkipVerify path saves the new cred and
// emits the audit entry. State.LoadParent returns the new cred after.
func TestParentSet_happyPath(t *testing.T) {
	ctx := context.Background()
	ws, _ := newPrimary(t)

	res, err := ws.ParentSet(ctx, ParentSetOptions{
		AccessKeyID:     "NEW_AK",
		SecretAccessKey: "NEW_SK",
		SkipVerify:      true,
	})
	if err != nil {
		t.Fatalf("ParentSet: %v", err)
	}
	if res.OldAccessKeyID != "AK" {
		t.Errorf("OldAccessKeyID = %q, want AK (from newPrimary fixture)", res.OldAccessKeyID)
	}
	if res.NewAccessKeyID != "NEW_AK" {
		t.Errorf("NewAccessKeyID = %q, want NEW_AK", res.NewAccessKeyID)
	}
	if res.Verified {
		t.Error("SkipVerify=true must not set Verified=true")
	}
	if res.Provider != domain.ProviderR2 {
		t.Errorf("Provider = %q, want r2 (preserved from existing)", res.Provider)
	}

	got, err := ws.State.LoadParent()
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessKeyID != "NEW_AK" || got.SecretAccessKey != "NEW_SK" {
		t.Errorf("LoadParent after Set: AK=%q SK=%q, want NEW_AK / NEW_SK", got.AccessKeyID, got.SecretAccessKey)
	}
	if got.Provider != domain.ProviderR2 {
		t.Errorf("Provider on disk = %q, want r2", got.Provider)
	}
}

// TestParentSet_verifyHappyPath: a verifier that succeeds (in-memory
// provider, Exists is fine) lets the save proceed and Verified=true.
func TestParentSet_verifyHappyPath(t *testing.T) {
	ctx := context.Background()
	ws, prov := newPrimary(t)

	res, err := ws.ParentSet(ctx, ParentSetOptions{
		AccessKeyID:     "NEW_AK",
		SecretAccessKey: "NEW_SK",
		ProviderFor: func(_ context.Context, _ domain.BucketInfo, _ *driftcreds.Parent) (storage.Provider, error) {
			// Pretend the new cred works — return the same in-memory
			// provider the workspace was Init'd with so Exists succeeds.
			return prov, nil
		},
	})
	if err != nil {
		t.Fatalf("ParentSet (verify): %v", err)
	}
	if !res.Verified {
		t.Error("Verified must be true when SkipVerify=false and probe succeeds")
	}
}

// TestParentSet_verifyFailureRefusesSave: a verifier that returns a
// provider whose Exists fails must abort the save, leaving the old cred
// in place. Critical for "user typo'd the secret" recovery — we don't
// want to silently brick the device.
func TestParentSet_verifyFailureRefusesSave(t *testing.T) {
	ctx := context.Background()
	ws, _ := newPrimary(t)

	_, err := ws.ParentSet(ctx, ParentSetOptions{
		AccessKeyID:     "BAD_AK",
		SecretAccessKey: "BAD_SK",
		ProviderFor: func(_ context.Context, _ domain.BucketInfo, _ *driftcreds.Parent) (storage.Provider, error) {
			return &failingProvider{}, nil
		},
	})
	if err == nil {
		t.Fatal("expected verification failure to abort save")
	}
	if !strings.Contains(err.Error(), "verification failed") {
		t.Errorf("expected 'verification failed' in error, got: %v", err)
	}

	// The old cred must be intact.
	got, _ := ws.State.LoadParent()
	if got.AccessKeyID != "AK" {
		t.Errorf("old cred should remain after failed verify: got AK=%q, want AK", got.AccessKeyID)
	}
}

// TestParentSet_refusesWithoutMaster: only the primary can replace
// the parent cred.
func TestParentSet_refusesWithoutMaster(t *testing.T) {
	ctx := context.Background()
	ws, _ := newPrimary(t)
	ws.Master = nil // simulate a peer-loaded workspace

	_, err := ws.ParentSet(ctx, ParentSetOptions{
		AccessKeyID:     "X",
		SecretAccessKey: "Y",
		SkipVerify:      true,
	})
	if err == nil {
		t.Fatal("expected refusal without master")
	}
	if !strings.Contains(err.Error(), "primary") {
		t.Errorf("expected 'primary' in error, got: %v", err)
	}
}

// TestParentSet_rejectsMissingFields
func TestParentSet_rejectsMissingFields(t *testing.T) {
	ctx := context.Background()
	ws, _ := newPrimary(t)

	cases := []ParentSetOptions{
		{AccessKeyID: "", SecretAccessKey: "Y"},
		{AccessKeyID: "X", SecretAccessKey: ""},
	}
	for i, opts := range cases {
		if _, err := ws.ParentSet(ctx, opts); err == nil {
			t.Errorf("case %d: missing field should error", i)
		}
	}
}

// TestParentSet_providerOverride: passing Provider replaces the
// stored provider id; omitting it preserves the existing value.
func TestParentSet_providerOverride(t *testing.T) {
	ctx := context.Background()
	ws, _ := newPrimary(t)

	// Preserve default.
	_, err := ws.ParentSet(ctx, ParentSetOptions{
		AccessKeyID: "K", SecretAccessKey: "S", SkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := ws.State.LoadParent()
	if got.Provider != domain.ProviderR2 {
		t.Errorf("default-preserve: provider = %q, want r2", got.Provider)
	}

	// Now override to b2.
	_, err = ws.ParentSet(ctx, ParentSetOptions{
		Provider:    "b2",
		AccessKeyID: "K2", SecretAccessKey: "S2", SkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ = ws.State.LoadParent()
	if got.Provider != "b2" {
		t.Errorf("override: provider = %q, want b2", got.Provider)
	}
}

// failingProvider implements storage.Provider with every method
// returning an error. Used to simulate auth failure in tests.
type failingProvider struct{}

func (f *failingProvider) Get(ctx context.Context, key string) ([]byte, error) {
	return nil, errors.New("simulated auth failure")
}
func (f *failingProvider) GetWithETag(ctx context.Context, key string) ([]byte, string, error) {
	return nil, "", errors.New("simulated auth failure")
}
func (f *failingProvider) Put(ctx context.Context, key string, body []byte) error {
	return errors.New("simulated auth failure")
}
func (f *failingProvider) PutIfNotExists(ctx context.Context, key string, body []byte) (string, error) {
	return "", errors.New("simulated auth failure")
}
func (f *failingProvider) PutConditional(ctx context.Context, key string, body []byte, etag string) (string, error) {
	return "", errors.New("simulated auth failure")
}
func (f *failingProvider) Delete(ctx context.Context, key string) error {
	return errors.New("simulated auth failure")
}
func (f *failingProvider) Exists(ctx context.Context, key string) (bool, error) {
	return false, errors.New("simulated auth failure")
}
func (f *failingProvider) List(ctx context.Context, prefix string) ([]string, error) {
	return nil, errors.New("simulated auth failure")
}
func (f *failingProvider) Capabilities(ctx context.Context) (storage.Capabilities, error) {
	return storage.Capabilities{}, errors.New("simulated auth failure")
}
