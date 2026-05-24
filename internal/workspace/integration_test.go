//go:build integration

// End-to-end workspace lifecycle against MinIO. Exercises the same code
// path the CLI uses: BuildS3Provider → ProbeCapabilities → SelectWriter →
// Init → CompartmentCreate → Grant → Redeem → Revoke.
//
// Run with: `make test-integration`.
package workspace

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sufforest/drift/internal/credentials"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/mount"
	"github.com/sufforest/drift/internal/storage"
)

const (
	minioEndpoint  = "http://127.0.0.1:9000"
	minioAccessKey = "drift-test"
	minioSecretKey = "drift-test-secret"
	minioBucket    = "drift-test"
)

// freshMinIOBucket clears every Drift-owned key under .drift/ and
// compartments/ from a previous run so each integration test starts from
// a clean slate without recreating the bucket.
func freshMinIOBucket(t *testing.T) *storage.S3Provider {
	t.Helper()
	ctx := context.Background()
	bucket := domain.BucketInfo{
		Provider: domain.ProviderMinIO,
		Endpoint: minioEndpoint,
		Name:     minioBucket,
		Region:   "us-east-1",
	}
	p, err := BuildS3Provider(ctx, bucket, minioAccessKey, minioSecretKey, "")
	if err != nil {
		t.Fatalf("BuildS3Provider: %v", err)
	}
	for _, prefix := range []string{".drift/", "compartments/"} {
		keys, err := p.List(ctx, prefix)
		if err != nil {
			t.Fatalf("List %s: %v", prefix, err)
		}
		for _, k := range keys {
			_ = p.Delete(ctx, k)
		}
	}
	return p
}

// TestIntegration_FullLifecycle drives the entire Drift v1 MVR flow against
// MinIO. If any part of this test fails, the corresponding CLI command will
// not work in production either.
func TestIntegration_FullLifecycle(t *testing.T) {
	ctx := context.Background()
	provider := freshMinIOBucket(t)

	state, err := NewState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()

	caps, err := storage.ProbeCapabilities(ctx, provider)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !caps.ConditionalPut {
		t.Fatal("expected MinIO to support conditional PUT")
	}
	writer := storage.SelectWriter(provider, caps, "")

	bucket := domain.BucketInfo{
		Provider: domain.ProviderMinIO,
		Endpoint: minioEndpoint,
		Name:     minioBucket,
		Region:   "us-east-1",
	}
	parent := &credentials.Parent{
		Provider:        domain.ProviderMinIO,
		AccessKeyID:     minioAccessKey,
		SecretAccessKey: minioSecretKey,
	}

	ws, err := Init(ctx, Options{
		State:    state,
		Provider: provider,
		Writer:   writer,
		Now:      func() time.Time { return now },
	}, InitParams{
		Bucket:     bucket,
		Parent:     parent,
		DeviceName: "integration-laptop",
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Manifest decrypts + verifies after the round trip through MinIO.
	m, err := ws.Manifest(ctx)
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if m.WorkspaceID != ws.Config.WorkspaceID {
		t.Fatalf("workspace id mismatch")
	}

	if err := ws.CompartmentCreate(ctx, "datasets", domain.ModeMount); err != nil {
		t.Fatalf("CompartmentCreate: %v", err)
	}

	// Issue a token...
	issued, err := ws.Grant(ctx, GrantRequest{
		Scope: []string{"datasets"},
		Mode:  domain.TokenModeRW,
		TTL:   30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if issued.Encoded == "" {
		t.Fatal("empty encoded token")
	}

	// ...and redeem it. Bearer's S3 calls run through the *same* MinIO
	// provider here because MinIO is the only backend in the test;
	// the JWT we mint isn't validated by MinIO. That's fine — this test
	// exercises Drift's flow, not R2's enforcement.
	mnt := mount.NewNoopMounter()
	sess, err := Redeem(ctx, issued.Encoded, RedeemOptions{
		Provider:     provider,
		Mounter:      mnt,
		MountBase:    t.TempDir(),
		PollInterval: 50 * time.Millisecond,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if sess.TID != issued.TID {
		t.Fatalf("session tid %s != issued %s", sess.TID, issued.TID)
	}

	// Revoke from the primary device; the bearer's poller should observe
	// it and tear the session down.
	if err := ws.Revoke(ctx, issued.TID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := sess.Wait(); !errors.Is(err, domain.ErrTokenRevoked) {
		t.Fatalf("Wait expected ErrTokenRevoked, got %v", err)
	}

	// A fresh Redeem against the now-revoked token must fail immediately.
	_, err = Redeem(ctx, issued.Encoded, RedeemOptions{
		Provider:     provider,
		Mounter:      mount.NewNoopMounter(),
		MountBase:    t.TempDir(),
		PollInterval: time.Second,
		Now:          func() time.Time { return now },
	})
	if !errors.Is(err, domain.ErrTokenRevoked) {
		t.Fatalf("post-revoke Redeem expected ErrTokenRevoked, got %v", err)
	}

	// Verify / Devices / Status all touch the manifest; they should pass.
	report, err := ws.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !report.ManifestSignature || !report.ProviderReachable || !report.ConditionalPut {
		t.Fatalf("Verify report: %+v", report)
	}
}

// TestIntegration_TamperedManifest confirms that a bucket admin overwriting
// the manifest body cannot trick a client into trusting it.
func TestIntegration_TamperedManifest(t *testing.T) {
	ctx := context.Background()
	provider := freshMinIOBucket(t)

	state, _ := NewState(t.TempDir())
	caps, _ := storage.ProbeCapabilities(ctx, provider)
	writer := storage.SelectWriter(provider, caps, "")

	ws, err := Init(ctx, Options{
		State:    state,
		Provider: provider,
		Writer:   writer,
	}, InitParams{
		Bucket: domain.BucketInfo{
			Provider: domain.ProviderMinIO,
			Endpoint: minioEndpoint,
			Name:     minioBucket,
			Region:   "us-east-1",
		},
		Parent: &credentials.Parent{
			Provider:        domain.ProviderMinIO,
			AccessKeyID:     minioAccessKey,
			SecretAccessKey: minioSecretKey,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Bucket admin overwrites the manifest with garbage.
	if err := provider.Put(ctx, domain.ManifestKey, []byte("not a valid ciphertext")); err != nil {
		t.Fatal(err)
	}
	_, err = ws.Manifest(ctx)
	if err == nil {
		t.Fatal("expected error after manifest tampering")
	}
}
