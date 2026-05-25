package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufforest/drift/internal/credentials"
	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/storage"
	"github.com/sufforest/drift/internal/workspace"
)

func mustGenerateDeviceKey(t *testing.T) *dcrypto.DeviceKey {
	t.Helper()
	d, err := dcrypto.GenerateDeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// makeStateDir builds a minimal valid state directory the CLI bootstrap
// can load against. Doesn't make a real R2 cred — uses placeholder
// values. BuildS3Provider doesn't connect on construction, so the
// load succeeds; runtime R2 operations would fail but loadWorkspace
// itself doesn't perform any.
func makeStateDir(t *testing.T, withParent bool, withPeerCred bool) string {
	t.Helper()
	dir := t.TempDir()
	state, err := workspace.NewState(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := workspace.LocalConfig{
		WorkspaceID:       "wks_test",
		DeviceID:          "dev_test",
		Bucket:            domain.BucketInfo{Provider: domain.ProviderR2, Endpoint: "https://abc.r2.cloudflarestorage.com", Name: "bucket", Region: "auto"},
		MasterFingerprint: []byte("0123456789abcdef0123456789abcdef"),
		// Concurrency must be set so selectWriter's fall-back path runs
		// when the capability probe fails (no real R2 reachable in test).
		Concurrency: domain.ConcurrencyConditionalPut,
	}
	if err := state.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	// Device key needed by LoadDevice in loadWorkspace.
	dev := mustGenerateDeviceKey(t)
	if err := state.SaveDevice(dev); err != nil {
		t.Fatal(err)
	}
	if withParent {
		if err := state.SaveParent(&credentials.Parent{Provider: "r2", AccessKeyID: "AK", SecretAccessKey: "SK"}); err != nil {
			t.Fatal(err)
		}
	}
	if withPeerCred {
		pc := &credentials.PeerCred{
			Version:  credentials.PeerCredVersion,
			DeviceID: "dev_test",
			JTI:      "pc_test",
			Scope:    []string{"main"},
			Mode:     "rw",
			Data: credentials.ScopedCredSet{
				AccessKeyID:     "AK",
				SecretAccessKey: "SK_HEX",
				SessionToken:    "anNvbi9mYWtl",
				Endpoint:        "https://abc.r2.cloudflarestorage.com",
				Bucket:          "bucket",
			},
			// Control nil for now — bootstrap test only exercises the
			// Data-cred path for loadWorkspace's existence checks.
			// DD-10 phase 4 will add a split-provider test.
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(time.Hour),
			RefreshAt: time.Now().Add(30 * time.Minute),
		}
		if err := state.SavePeerCred(pc); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func cmdWithConfig(dir string) *cobra.Command {
	c := &cobra.Command{}
	// stateDir() reads cmd.Flags() not PersistentFlags() — for a
	// standalone command in a test (no parent), use Flags() directly
	// so the value is actually visible.
	c.Flags().String("config", dir, "")
	c.Flags().String("workspace", "", "")
	return c
}

// TestLoadWorkspace_bearerModeWorksWithoutParent: regression for
// the bug where `drift peer status` (and any other read-only command)
// failed on a bearer-mode peer because loadWorkspace unconditionally
// called LoadParent. With peercred.json present, parent.json absent,
// loadWorkspace must succeed.
func TestLoadWorkspace_bearerModeWorksWithoutParent(t *testing.T) {
	dir := makeStateDir(t, false /*withParent*/, true /*withPeerCred*/)
	cmd := cmdWithConfig(dir)

	ws, err := loadWorkspace(context.Background(), cmd)
	if err != nil {
		t.Fatalf("loadWorkspace must succeed on bearer-mode state, got: %v", err)
	}
	if !ws.State.HasPeerCred() {
		t.Errorf("loaded workspace should still report HasPeerCred=true")
	}
}

// TestLoadWorkspace_legacyParentStillWorks: same load path on a
// parent-only state dir (primary or DD-4 v1 peer).
func TestLoadWorkspace_legacyParentStillWorks(t *testing.T) {
	dir := makeStateDir(t, true /*withParent*/, false /*withPeerCred*/)
	cmd := cmdWithConfig(dir)

	if _, err := loadWorkspace(context.Background(), cmd); err != nil {
		t.Fatalf("loadWorkspace on legacy parent state must succeed: %v", err)
	}
}

// TestLoadWorkspace_bearerModeWithControl_wrapsSplitProvider: a v2
// PeerCred with Control populated must cause loadWorkspace to wrap
// the S3 client in a SplitProvider so control-plane reads use the
// RO cred. Without the wrap, the over-grant model from before DD-10
// would still be active. (Tested by inspecting the loaded
// workspace.Provider's concrete type.)
func TestLoadWorkspace_bearerModeWithControl_wrapsSplitProvider(t *testing.T) {
	dir := t.TempDir()
	state, err := workspace.NewState(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := workspace.LocalConfig{
		WorkspaceID:       "wks_test",
		DeviceID:          "dev_test",
		Bucket:            domain.BucketInfo{Provider: domain.ProviderR2, Endpoint: "https://abc.r2.cloudflarestorage.com", Name: "bucket", Region: "auto"},
		MasterFingerprint: []byte("0123456789abcdef0123456789abcdef"),
		Concurrency:       domain.ConcurrencyConditionalPut,
	}
	if err := state.SaveConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if err := state.SaveDevice(mustGenerateDeviceKey(t)); err != nil {
		t.Fatal(err)
	}
	pc := &credentials.PeerCred{
		Version:  credentials.PeerCredVersion,
		DeviceID: "dev_test",
		JTI:      "pc_test",
		Scope:    []string{"main"},
		Mode:     "rw",
		Data: credentials.ScopedCredSet{
			AccessKeyID: "AK", SecretAccessKey: "SK_data", SessionToken: "data-jwt",
			Endpoint: "https://abc.r2.cloudflarestorage.com", Bucket: "bucket",
		},
		Control: &credentials.ScopedCredSet{
			AccessKeyID: "AK", SecretAccessKey: "SK_ctrl", SessionToken: "ctrl-jwt",
			Endpoint: "https://abc.r2.cloudflarestorage.com", Bucket: "bucket",
		},
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		RefreshAt: time.Now().Add(30 * time.Minute),
	}
	if err := state.SavePeerCred(pc); err != nil {
		t.Fatal(err)
	}

	cmd := cmdWithConfig(dir)
	ws, err := loadWorkspace(context.Background(), cmd)
	if err != nil {
		t.Fatalf("loadWorkspace: %v", err)
	}
	if _, ok := ws.Provider.(*storage.SplitProvider); !ok {
		t.Errorf("loaded workspace.Provider type = %T, want *storage.SplitProvider — bearer-mode with Control must wrap", ws.Provider)
	}
}

// TestLoadWorkspace_bearerModeWithoutControl_noSplitProvider: a v2
// PeerCred with Control=nil (AWS-STS / R2-server-mint shape) must
// NOT wrap with SplitProvider — there's no second cred to route to.
// This is the AWS-future-compat path.
func TestLoadWorkspace_bearerModeWithoutControl_noSplitProvider(t *testing.T) {
	dir := t.TempDir()
	state, _ := workspace.NewState(dir)
	cfg := workspace.LocalConfig{
		WorkspaceID:       "wks_test",
		DeviceID:          "dev_test",
		Bucket:            domain.BucketInfo{Provider: domain.ProviderR2, Endpoint: "https://abc.r2.cloudflarestorage.com", Name: "bucket", Region: "auto"},
		MasterFingerprint: []byte("0123456789abcdef0123456789abcdef"),
		Concurrency:       domain.ConcurrencyConditionalPut,
	}
	_ = state.SaveConfig(cfg)
	_ = state.SaveDevice(mustGenerateDeviceKey(t))
	pc := &credentials.PeerCred{
		Version:  credentials.PeerCredVersion,
		DeviceID: "dev_test",
		JTI:      "pc_test",
		Scope:    []string{"main"},
		Mode:     "rw",
		Data: credentials.ScopedCredSet{
			AccessKeyID: "AK", SecretAccessKey: "SK", SessionToken: "jwt",
			Endpoint: "https://abc.r2.cloudflarestorage.com", Bucket: "bucket",
		},
		Control:   nil, // AWS-STS / R2-server-mint shape
		IssuedAt:  time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
		RefreshAt: time.Now().Add(30 * time.Minute),
	}
	_ = state.SavePeerCred(pc)

	cmd := cmdWithConfig(dir)
	ws, err := loadWorkspace(context.Background(), cmd)
	if err != nil {
		t.Fatalf("loadWorkspace: %v", err)
	}
	if _, ok := ws.Provider.(*storage.SplitProvider); ok {
		t.Error("with Control=nil, Provider should NOT be SplitProvider — Data covers everything in the AWS-future shape")
	}
}

// TestLoadWorkspace_v1PeerCredErrorsActionably: a peer paired before
// DD-10 has a v1-shaped peercred.json on disk. loadWorkspace must
// detect the version mismatch and emit a specific re-pair instruction
// rather than failing later with a confusing signature error.
func TestLoadWorkspace_v1PeerCredErrorsActionably(t *testing.T) {
	dir := t.TempDir()
	state, _ := workspace.NewState(dir)
	cfg := workspace.LocalConfig{
		WorkspaceID:       "wks_test",
		DeviceID:          "dev_test",
		Bucket:            domain.BucketInfo{Provider: domain.ProviderR2, Endpoint: "https://abc.r2.cloudflarestorage.com", Name: "bucket", Region: "auto"},
		MasterFingerprint: []byte("0123456789abcdef0123456789abcdef"),
		Concurrency:       domain.ConcurrencyConditionalPut,
	}
	_ = state.SaveConfig(cfg)
	_ = state.SaveDevice(mustGenerateDeviceKey(t))

	// Write a v1-shaped peercred.json directly. The v2 decoder ignores
	// the flat AccessKeyID/SecretAccessKey/SessionToken fields (they're
	// unknown to the new struct), but the Version field decodes as 1.
	// That's the trigger the loadWorkspace gate watches for.
	v1Bytes := []byte(`{
		"v": 1,
		"did": "dev_test",
		"jti": "pc_old",
		"scope": ["main"],
		"mode": "rw",
		"ak": "AK", "sk": "SK_HEX", "session": "old-jwt",
		"endpoint": "https://abc.r2.cloudflarestorage.com",
		"bucket": "bucket",
		"iat": "2026-05-24T00:00:00Z",
		"exp": "2026-05-25T00:00:00Z",
		"refresh_at": "2026-05-24T12:00:00Z",
		"sig": "AAAA"
	}`)
	if err := os.WriteFile(filepath.Join(dir, "peercred.json"), v1Bytes, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := cmdWithConfig(dir)
	_, err := loadWorkspace(context.Background(), cmd)
	if err == nil {
		t.Fatal("loadWorkspace must error on v1 PeerCred (DD-10 added split-cred shape)")
	}
	// Must mention the migration path: drift link / re-pair / version
	// numbers — all signals to the user about what to do.
	msg := err.Error()
	if !strings.Contains(msg, "drift link") {
		t.Errorf("error must instruct re-pair via drift link, got: %v", err)
	}
	if !strings.Contains(msg, "older schema") {
		t.Errorf("error must explain version mismatch, got: %v", err)
	}
}

// TestLoadWorkspace_neitherCredErrors: a state dir with no cred at
// all should error with a clear message pointing to drift init or
// drift link.
func TestLoadWorkspace_neitherCredErrors(t *testing.T) {
	dir := makeStateDir(t, false, false)
	cmd := cmdWithConfig(dir)

	_, err := loadWorkspace(context.Background(), cmd)
	if err == nil {
		t.Fatal("loadWorkspace must error when neither parent.json nor peercred.json is present")
	}
	if !strings.Contains(err.Error(), "drift link") && !strings.Contains(err.Error(), "drift init") {
		t.Errorf("error should point user at drift init/link, got: %v", err)
	}
}
