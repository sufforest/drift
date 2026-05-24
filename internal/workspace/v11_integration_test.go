//go:build integration

// v1.1 surface integration tests against MinIO:
//
//   - drift link end-to-end
//   - drift rotate cprk (primary + secondary refresh)
//   - drift rotate master (chain walk on secondary)
//   - drift audit emit + list + verify
//
// Each test starts from a freshly-cleaned bucket so they're independent.
package workspace

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/sufforest/drift/internal/audit"
	"github.com/sufforest/drift/internal/credentials"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/mount"
	"github.com/sufforest/drift/internal/storage"
)

func bootstrapPrimary(t *testing.T) *Workspace {
	t.Helper()
	ctx := context.Background()
	provider := freshMinIOBucket(t)

	state, err := NewState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	caps, err := storage.ProbeCapabilities(ctx, provider)
	if err != nil {
		t.Fatal(err)
	}
	writer := storage.SelectWriter(provider, caps, "")

	ws, err := Init(ctx, Options{
		State:    state,
		Provider: provider,
		Writer:   writer,
		Now:      time.Now,
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
		DeviceName: "integration-primary",
	})
	if err != nil {
		t.Fatal(err)
	}
	return ws
}

// TestIntegration_v11_LinkRoundTrip drives the full pairing handshake
// against MinIO: primary issues, secondary claims, primary confirms,
// secondary loads as a real Workspace and reads the manifest.
func TestIntegration_v11_LinkRoundTrip(t *testing.T) {
	ctx := context.Background()
	primary := bootstrapPrimary(t)
	if err := primary.CompartmentCreate(ctx, "shared", domain.ModeMount); err != nil {
		t.Fatal(err)
	}

	init, err := primary.LinkInit(ctx, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	secState, err := NewState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// MinIO doesn't accept R2's locally-signed JWTs (they're a CF-specific
	// shape). For integration testing we substitute the parent
	// credential everywhere a minted cred would be used; the threat-model
	// properties of the cred-split are validated separately in the
	// unit-level token tests against an in-memory provider.
	providerFor := func(_ domain.S3Credential, bucket domain.BucketInfo) (storage.Provider, error) {
		return BuildS3Provider(ctx, bucket, minioAccessKey, minioSecretKey, "")
	}

	claimDone := make(chan *LinkClaimResult, 1)
	claimErr := make(chan error, 1)
	go func() {
		res, err := LinkClaim(ctx, init.Encoded, "integration-secondary", LinkClaimOptions{
			State:        secState,
			ProviderFor:  providerFor,
			Now:          time.Now,
			PollInterval: 200 * time.Millisecond,
			Timeout:      30 * time.Second,
		})
		claimDone <- res
		claimErr <- err
	}()

	// Wait briefly for response to land.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if exists, _ := primary.Provider.Exists(ctx, domain.PairingResponseKey(init.PID)); exists {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	confirm, err := primary.LinkConfirm(ctx, init.PID, LinkConfirmOptions{})
	if err != nil {
		t.Fatalf("LinkConfirm: %v", err)
	}

	res := <-claimDone
	if err := <-claimErr; err != nil {
		t.Fatalf("LinkClaim: %v", err)
	}
	if res.DeviceID != confirm.DeviceID {
		t.Fatalf("device ids disagree: %s vs %s", res.DeviceID, confirm.DeviceID)
	}

	// Load the secondary against MinIO and read the manifest.
	secProvider, err := BuildProviderFromParent(ctx, primary.Config.Bucket, &credentials.Parent{
		AccessKeyID:     minioAccessKey,
		SecretAccessKey: minioSecretKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	secCaps, _ := storage.ProbeCapabilities(ctx, secProvider)
	secondary, err := Load(ctx, Options{
		State:    secState,
		Provider: secProvider,
		Writer:   storage.SelectWriter(secProvider, secCaps, res.DeviceID),
		Now:      time.Now,
	})
	if err != nil {
		t.Fatalf("Load secondary: %v", err)
	}
	m, err := secondary.Manifest(ctx)
	if err != nil {
		t.Fatalf("secondary Manifest: %v", err)
	}
	if _, ok := m.Devices[res.DeviceID]; !ok {
		t.Fatal("manifest does not list secondary device after handshake")
	}
}

// TestIntegration_v11_RotateCPRK pairs a secondary, rotates CPRK on the
// primary, and confirms the secondary's auto-refresh path picks up the
// new key via the sealed handoff at .drift/cprk/<did>.enc.
func TestIntegration_v11_RotateCPRK(t *testing.T) {
	ctx := context.Background()
	primary := bootstrapPrimary(t)

	init, err := primary.LinkInit(ctx, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	secState, _ := NewState(t.TempDir())
	// MinIO doesn't accept R2's locally-signed JWTs (they're a CF-specific
	// shape). For integration testing we substitute the parent
	// credential everywhere a minted cred would be used; the threat-model
	// properties of the cred-split are validated separately in the
	// unit-level token tests against an in-memory provider.
	providerFor := func(_ domain.S3Credential, bucket domain.BucketInfo) (storage.Provider, error) {
		return BuildS3Provider(ctx, bucket, minioAccessKey, minioSecretKey, "")
	}
	claimDone := make(chan *LinkClaimResult, 1)
	go func() {
		res, _ := LinkClaim(ctx, init.Encoded, "rotate-cprk-secondary", LinkClaimOptions{
			State:        secState,
			ProviderFor:  providerFor,
			Now:          time.Now,
			PollInterval: 200 * time.Millisecond,
			Timeout:      30 * time.Second,
		})
		claimDone <- res
	}()
	for i := 0; i < 200; i++ {
		if exists, _ := primary.Provider.Exists(ctx, domain.PairingResponseKey(init.PID)); exists {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := primary.LinkConfirm(ctx, init.PID, LinkConfirmOptions{}); err != nil {
		t.Fatal(err)
	}
	claimRes := <-claimDone

	res, err := primary.RotateCPRK(ctx)
	if err != nil {
		t.Fatalf("RotateCPRK: %v", err)
	}
	if res.NewEpoch != 1 {
		t.Fatalf("new epoch = %d, want 1", res.NewEpoch)
	}

	// Secondary loads, manifest read triggers refresh, epoch should land at 1.
	secProvider, _ := BuildProviderFromParent(ctx, primary.Config.Bucket, &credentials.Parent{
		AccessKeyID:     minioAccessKey,
		SecretAccessKey: minioSecretKey,
	})
	secCaps, _ := storage.ProbeCapabilities(ctx, secProvider)
	secondary, err := Load(ctx, Options{
		State:    secState,
		Provider: secProvider,
		Writer:   storage.SelectWriter(secProvider, secCaps, claimRes.DeviceID),
		Now:      time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secondary.Manifest(ctx); err != nil {
		t.Fatalf("secondary Manifest after RotateCPRK: %v", err)
	}
	cfg, _ := secState.LoadConfig()
	if cfg.CPRKEpoch != 1 {
		t.Fatalf("secondary CPRKEpoch = %d, want 1", cfg.CPRKEpoch)
	}
}

// TestIntegration_v11_RotateMasterChainWalk confirms a paired secondary
// follows the master-rotation announcement chain to update its pinned
// fingerprint.
func TestIntegration_v11_RotateMasterChainWalk(t *testing.T) {
	ctx := context.Background()
	primary := bootstrapPrimary(t)

	init, err := primary.LinkInit(ctx, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	secState, _ := NewState(t.TempDir())
	// MinIO doesn't accept R2's locally-signed JWTs (they're a CF-specific
	// shape). For integration testing we substitute the parent
	// credential everywhere a minted cred would be used; the threat-model
	// properties of the cred-split are validated separately in the
	// unit-level token tests against an in-memory provider.
	providerFor := func(_ domain.S3Credential, bucket domain.BucketInfo) (storage.Provider, error) {
		return BuildS3Provider(ctx, bucket, minioAccessKey, minioSecretKey, "")
	}
	claimDone := make(chan *LinkClaimResult, 1)
	go func() {
		res, _ := LinkClaim(ctx, init.Encoded, "rotate-master-secondary", LinkClaimOptions{
			State:        secState,
			ProviderFor:  providerFor,
			Now:          time.Now,
			PollInterval: 200 * time.Millisecond,
			Timeout:      30 * time.Second,
		})
		claimDone <- res
	}()
	for i := 0; i < 200; i++ {
		if exists, _ := primary.Provider.Exists(ctx, domain.PairingResponseKey(init.PID)); exists {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := primary.LinkConfirm(ctx, init.PID, LinkConfirmOptions{}); err != nil {
		t.Fatal(err)
	}
	claimRes := <-claimDone

	preCfg, _ := secState.LoadConfig()
	originalFP := append([]byte(nil), preCfg.MasterFingerprint...)

	rotateRes, err := primary.RotateMaster(ctx)
	if err != nil {
		t.Fatalf("RotateMaster: %v", err)
	}

	secProvider, _ := BuildProviderFromParent(ctx, primary.Config.Bucket, &credentials.Parent{
		AccessKeyID:     minioAccessKey,
		SecretAccessKey: minioSecretKey,
	})
	secCaps, _ := storage.ProbeCapabilities(ctx, secProvider)
	secondary, err := Load(ctx, Options{
		State:    secState,
		Provider: secProvider,
		Writer:   storage.SelectWriter(secProvider, secCaps, claimRes.DeviceID),
		Now:      time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secondary.Manifest(ctx); err != nil {
		t.Fatalf("secondary Manifest after RotateMaster: %v (chain walk failed)", err)
	}
	postCfg, _ := secState.LoadConfig()
	if string(postCfg.MasterFingerprint) == string(originalFP) {
		t.Fatal("secondary's pinned fingerprint did not update")
	}
	if string(postCfg.MasterFingerprint) != string(rotateRes.NewFingerprint) {
		t.Fatal("secondary fingerprint does not match new master")
	}
}

// TestIntegration_v11_AuditChainVerifies confirms emit-on-mutation +
// chain verification all work against real S3 semantics.
func TestIntegration_v11_AuditChainVerifies(t *testing.T) {
	ctx := context.Background()
	primary := bootstrapPrimary(t)

	if err := primary.CompartmentCreate(ctx, "audited", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	issued, err := primary.Grant(ctx, GrantRequest{
		Scope: []string{"audited"},
		Mode:  domain.TokenModeRW,
		TTL:   30 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := primary.Revoke(ctx, issued.TID); err != nil {
		t.Fatal(err)
	}

	m, err := primary.Manifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(did string) ed25519.PublicKey {
		if d, ok := m.Devices[did]; ok {
			return ed25519.PublicKey(d.PublicKey)
		}
		return nil
	}
	entries, skipped, err := audit.List(ctx, primary.Provider, primary.Config.WorkspaceID, primary.CPRK, resolve)
	if err != nil {
		t.Fatal(err)
	}
	if skipped > 0 {
		t.Fatalf("skipped = %d, expected 0 on freshly-bootstrapped workspace", skipped)
	}
	if len(entries) < 4 {
		t.Fatalf("expected at least 4 entries (init + compartment.create + grant + revoke), got %d", len(entries))
	}
	for _, e := range entries {
		if e.VerifyErr != nil {
			t.Fatalf("entry %s verify error: %v", e.Entry.EntryID, e.VerifyErr)
		}
	}
	if err := audit.VerifyChain(entries); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

// TestIntegration_v11_TokenRedeemEnforcesMasterFingerprint confirms a
// post-master-rotation token redemption refuses old tokens.
func TestIntegration_v11_TokenRedeemEnforcesMasterFingerprint(t *testing.T) {
	ctx := context.Background()
	primary := bootstrapPrimary(t)
	if err := primary.CompartmentCreate(ctx, "bearer-test", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	issued, err := primary.Grant(ctx, GrantRequest{
		Scope: []string{"bearer-test"},
		Mode:  domain.TokenModeRW,
		TTL:   30 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	mountBase := t.TempDir()
	mounter := mount.NewNoopMounter()
	// Sanity: token should redeem against MinIO (same provider).
	sess, err := Redeem(ctx, issued.Encoded, RedeemOptions{
		Provider:     primary.Provider,
		Mounter:      mounter,
		MountBase:    mountBase,
		PollInterval: time.Hour,
		Now:          time.Now,
	})
	if err != nil {
		t.Fatalf("first Redeem: %v", err)
	}
	if sess.TID != issued.TID {
		t.Fatal("tid mismatch")
	}
	_ = sess.Close()

	// Rotate the master and confirm the OLD token fails redemption
	// (it carries the OLD MasterFingerprint).
	if _, err := primary.RotateMaster(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = Redeem(ctx, issued.Encoded, RedeemOptions{
		Provider:     primary.Provider,
		Mounter:      mount.NewNoopMounter(),
		MountBase:    t.TempDir(),
		PollInterval: time.Hour,
		Now:          time.Now,
	})
	if err == nil {
		t.Fatal("expected old-master-fingerprint token to fail after rotation")
	}
	if !errors.Is(err, domain.ErrSignatureInvalid) && !errors.Is(err, domain.ErrTokenRevoked) {
		t.Logf("redemption refused with: %v (acceptable)", err)
	}
}
