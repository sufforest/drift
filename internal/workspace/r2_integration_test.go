//go:build r2

// R2 integration tests. These run against a real Cloudflare R2 bucket, so
// they're gated behind both the `r2` build tag AND the presence of the
// expected environment variables. Without those, the suite skips cleanly
// so it's safe to enable in CI.
//
// To run locally:
//
//	export DRIFT_R2_ACCESS_KEY_ID=...
//	export DRIFT_R2_SECRET_ACCESS_KEY=...
//	export DRIFT_R2_ENDPOINT=https://<account>.r2.cloudflarestorage.com
//	export DRIFT_R2_BUCKET=drift-integration-test
//	go test -tags=r2 -count=1 ./internal/workspace/
//
// The bucket must already exist. The tests clean up the .drift/ and
// compartments/ prefixes around each run.
package workspace

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/sufforest/drift/internal/credentials"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/mount"
	"github.com/sufforest/drift/internal/storage"
)

type r2Env struct {
	AccessKey string
	Secret    string
	Endpoint  string
	Bucket    string
}

func r2EnvOrSkip(t *testing.T) r2Env {
	t.Helper()
	env := r2Env{
		AccessKey: os.Getenv("DRIFT_R2_ACCESS_KEY_ID"),
		Secret:    os.Getenv("DRIFT_R2_SECRET_ACCESS_KEY"),
		Endpoint:  os.Getenv("DRIFT_R2_ENDPOINT"),
		Bucket:    os.Getenv("DRIFT_R2_BUCKET"),
	}
	missing := []string{}
	if env.AccessKey == "" {
		missing = append(missing, "DRIFT_R2_ACCESS_KEY_ID")
	}
	if env.Secret == "" {
		missing = append(missing, "DRIFT_R2_SECRET_ACCESS_KEY")
	}
	if env.Endpoint == "" {
		missing = append(missing, "DRIFT_R2_ENDPOINT")
	}
	if env.Bucket == "" {
		missing = append(missing, "DRIFT_R2_BUCKET")
	}
	if len(missing) > 0 {
		t.Skipf("R2 integration tests skipped — set %v", missing)
	}
	return env
}

// freshR2Bucket cleans Drift's prefixes so each test starts from scratch.
// Caller is responsible for the bucket itself existing.
func freshR2Bucket(t *testing.T, env r2Env) *storage.S3Provider {
	t.Helper()
	ctx := context.Background()
	bucket := domain.BucketInfo{
		Provider: domain.ProviderR2,
		Endpoint: env.Endpoint,
		Name:     env.Bucket,
		Region:   "auto",
	}
	p, err := BuildS3Provider(ctx, bucket, env.AccessKey, env.Secret, "")
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

// TestR2_FullLifecycle mirrors TestIntegration_FullLifecycle but against
// real R2. Confirms our S3Provider + manifest encryption + token issuance
// + revocation poller all work against Cloudflare's production semantics.
func TestR2_FullLifecycle(t *testing.T) {
	env := r2EnvOrSkip(t)
	ctx := context.Background()
	provider := freshR2Bucket(t, env)

	state, err := NewState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	caps, err := storage.ProbeCapabilities(ctx, provider)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	// R2 supports conditional PUT; if this assertion fires it's a real
	// regression worth catching.
	if !caps.ConditionalPut {
		t.Fatal("expected R2 to support conditional PUT")
	}
	writer := storage.SelectWriter(provider, caps, "")

	bucket := domain.BucketInfo{
		Provider: domain.ProviderR2,
		Endpoint: env.Endpoint,
		Name:     env.Bucket,
		Region:   "auto",
	}
	parent := &credentials.Parent{
		Provider:        domain.ProviderR2,
		AccessKeyID:     env.AccessKey,
		SecretAccessKey: env.Secret,
	}

	now := time.Now().UTC()
	ws, err := Init(ctx, Options{
		State:    state,
		Provider: provider,
		Writer:   writer,
		Now:      func() time.Time { return now },
	}, InitParams{
		Bucket:     bucket,
		Parent:     parent,
		DeviceName: "r2-integration-laptop",
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	if err := ws.CompartmentCreate(ctx, "datasets", domain.ModeMount); err != nil {
		t.Fatalf("CompartmentCreate: %v", err)
	}

	issued, err := ws.Grant(ctx, GrantRequest{
		Scope: []string{"datasets"},
		Mode:  domain.TokenModeRW,
		TTL:   30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Grant: %v", err)
	}

	sess, err := Redeem(ctx, issued.Encoded, RedeemOptions{
		Provider:     provider,
		Mounter:      mount.NewNoopMounter(),
		MountBase:    t.TempDir(),
		PollInterval: 250 * time.Millisecond,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}

	if err := ws.Revoke(ctx, issued.TID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := sess.Wait(); !errors.Is(err, domain.ErrTokenRevoked) {
		t.Fatalf("Wait expected ErrTokenRevoked, got %v", err)
	}

	// Final cleanup so the next run starts clean.
	_ = freshR2Bucket(t, env)
}

// TestR2_R2TokenScoping confirms that the JWT we mint actually enforces
// scope on R2's side. If R2 ever changes their JWT semantics, this catches
// it. Mints a DataCred with prefixes=[compartments/x/] and verifies that a
// PUT outside that prefix is rejected by R2.
//
// (Requires the parent provider has scoping enabled on the R2 API token;
// some R2 tokens are full-bucket.)
func TestR2_DataCredCannotWriteOutsideScope(t *testing.T) {
	env := r2EnvOrSkip(t)
	ctx := context.Background()
	provider := freshR2Bucket(t, env)

	state, _ := NewState(t.TempDir())
	caps, _ := storage.ProbeCapabilities(ctx, provider)
	writer := storage.SelectWriter(provider, caps, "")
	now := time.Now().UTC()

	bucket := domain.BucketInfo{
		Provider: domain.ProviderR2,
		Endpoint: env.Endpoint,
		Name:     env.Bucket,
		Region:   "auto",
	}
	parent := &credentials.Parent{
		Provider:        domain.ProviderR2,
		AccessKeyID:     env.AccessKey,
		SecretAccessKey: env.Secret,
	}

	ws, err := Init(ctx, Options{
		State:    state,
		Provider: provider,
		Writer:   writer,
		Now:      func() time.Time { return now },
	}, InitParams{Bucket: bucket, Parent: parent})
	if err != nil {
		t.Fatal(err)
	}
	if err := ws.CompartmentCreate(ctx, "scope-test", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	issued, err := ws.Grant(ctx, GrantRequest{
		Scope: []string{"scope-test"},
		Mode:  domain.TokenModeRW,
		TTL:   15 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Build a Provider authenticated with DataCred and try writing OUTSIDE
	// the authorized prefix. R2 should reject with 403.
	mnt := mount.NewNoopMounter()
	sess, err := Redeem(ctx, issued.Encoded, RedeemOptions{
		Provider:     provider,
		Mounter:      mnt,
		MountBase:    t.TempDir(),
		PollInterval: time.Second,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	bearerProvider, err := BuildS3Provider(ctx, sess.Result().BucketInfo,
		sess.Result().DataCred.AccessKeyID,
		sess.Result().DataCred.SecretAccessKey,
		sess.Result().DataCred.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	// Try to write to a path outside compartments/scope-test/
	err = bearerProvider.Put(ctx, "compartments/some-other-compartment/evil", []byte("nope"))
	if err == nil {
		t.Fatal("expected R2 to reject write outside scope, got nil error")
	}
	t.Logf("write outside scope correctly rejected: %v", err)
}
