package mount

import (
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sufforest/drift/internal/domain"
)

func sampleRequest() Request {
	return Request{
		WorkspaceID:    "wks_abc",
		Compartment:    "project-x",
		CompartmentKey: []byte("0123456789abcdef0123456789abcdef"),
		Cred: domain.S3Credential{
			AccessKeyID:     "AK",
			SecretAccessKey: "SK",
			SessionToken:    "jwt/tok",
		},
		Bucket: domain.BucketInfo{
			Provider: domain.ProviderR2,
			Endpoint: "https://example.r2.cloudflarestorage.com",
			Name:     "my-bucket",
			Region:   "auto",
		},
		MountPoint: "/mnt/x",
		Mode:       "rw",
	}
}

func TestBuildRcloneEnv_setsAllRequiredFields(t *testing.T) {
	cryptName, env, err := BuildRcloneEnv(sampleRequest(), "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cryptName, "drift_crypt_") {
		t.Fatalf("crypt name %q does not start with drift_crypt_", cryptName)
	}

	want := []string{
		"_TYPE=s3",
		"_PROVIDER=Cloudflare",
		"_REGION=auto",
		"_ACCESS_KEY_ID=AK",
		"_SECRET_ACCESS_KEY=SK",
		"_SESSION_TOKEN=jwt/tok",
		"_ENDPOINT=https://example.r2.cloudflarestorage.com",
		"_TYPE=crypt",
		"_REMOTE=", // crypt remote points at s3 + bucket + compartment prefix
		"_PASSWORD=",
		"_PASSWORD2=",
		"_FILENAME_ENCRYPTION=standard",
		"_DIRECTORY_NAME_ENCRYPTION=true",
	}
	for _, w := range want {
		if !envContainsSuffix(env, w) {
			t.Errorf("env missing line ending with %q. full env:\n%s", w, strings.Join(env, "\n"))
		}
	}

	// The crypt REMOTE must point at the right S3 path: compartments/<name>.
	if !envContains(env, "REMOTE=", "/compartments/project-x") {
		t.Errorf("crypt REMOTE must reference compartments/project-x; got env:\n%s", strings.Join(env, "\n"))
	}
}

func TestBuildRcloneEnv_omitsSessionTokenWhenEmpty(t *testing.T) {
	req := sampleRequest()
	req.Cred.SessionToken = ""
	_, env, err := BuildRcloneEnv(req, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range env {
		if strings.Contains(e, "_SESSION_TOKEN=") {
			t.Fatalf("env should not include SESSION_TOKEN when empty, got %q", e)
		}
	}
}

func TestBuildRcloneEnv_requiresKeyMaterial(t *testing.T) {
	req := sampleRequest()
	req.CompartmentKey = nil
	if _, _, err := BuildRcloneEnv(req, ""); err == nil {
		t.Fatal("expected error for empty compartment key")
	}
}

func TestBuildRcloneArgs_includesVFSCacheMode(t *testing.T) {
	args := BuildRcloneArgs(sampleRequest(), "crypt:", "/tmp/cache", "full")
	if len(args) == 0 || args[0] != "mount" {
		t.Fatalf("first arg should be 'mount', got %v", args)
	}
	if !containsPair(args, "--vfs-cache-mode", "full") {
		t.Errorf("missing --vfs-cache-mode full: %v", args)
	}
	if !containsPair(args, "--cache-dir", "/tmp/cache") {
		t.Errorf("missing --cache-dir /tmp/cache: %v", args)
	}
}

func TestBuildRcloneArgs_readOnlyFlag(t *testing.T) {
	req := sampleRequest()
	req.Mode = "ro"
	args := BuildRcloneArgs(req, "crypt:", "/tmp/cache", "full")
	if !contains(args, "--read-only") {
		t.Errorf("ro mode should add --read-only, got %v", args)
	}
}

func TestBuildRcloneArgs_ephemeralUsesWritesMode(t *testing.T) {
	// Audit #8: ephemeral must pin a tmpfs cache-dir (caller's
	// responsibility) AND use "writes" mode so rclone keeps everything
	// in memory or in the spool we control.
	req := sampleRequest()
	req.Ephemeral = true
	args := BuildRcloneArgs(req, "crypt:", "/dev/shm/drift", "full")
	if !containsPair(args, "--vfs-cache-mode", "writes") {
		t.Errorf("ephemeral should set --vfs-cache-mode writes, got %v", args)
	}
	if !containsPair(args, "--cache-dir", "/dev/shm/drift") {
		t.Errorf("ephemeral must still pin a --cache-dir (callers pass a tmpfs path), got %v", args)
	}
}

func TestRcloneObscure_runsAgainstRealRclone(t *testing.T) {
	// rcloneObscure subprocesses `rclone obscure`. If rclone isn't in
	// PATH we skip; otherwise we just confirm we got a non-empty
	// base64url string back. Round-trip vs `rclone reveal` lives in
	// rclone_smoke_test.go (integration build tag).
	if _, err := exec.LookPath("rclone"); err != nil {
		t.Skip("rclone not in PATH")
	}
	obscured, err := rcloneObscure([]byte("hello-drift"), "")
	if err != nil {
		t.Fatal(err)
	}
	if obscured == "" {
		t.Fatal("expected non-empty obscured output")
	}
	if _, err := base64.RawURLEncoding.DecodeString(obscured); err != nil {
		t.Fatalf("obscured is not base64url: %v", err)
	}
}

func TestSecureWipeDir_overwritesAndRemoves(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.bin")
	b := filepath.Join(dir, "sub", "b.bin")
	_ = os.MkdirAll(filepath.Dir(b), 0o755)
	mustWrite(t, a, []byte("secret-A"))
	mustWrite(t, b, []byte("secret-B"))

	if err := SecureWipeDir(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("dir should be removed, got %v", err)
	}
}

// --- helpers ---

func envContains(env []string, substrA, substrB string) bool {
	for _, e := range env {
		if strings.Contains(e, substrA) && strings.Contains(e, substrB) {
			return true
		}
	}
	return false
}

func envContainsSuffix(env []string, suffix string) bool {
	for _, e := range env {
		// suffix may include "=" so we check that the substring appears.
		if strings.Contains(e, suffix) {
			return true
		}
	}
	return false
}

func containsPair(args []string, key, value string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == key && args[i+1] == value {
			return true
		}
	}
	return false
}

func contains(args []string, needle string) bool {
	for _, a := range args {
		if a == needle {
			return true
		}
	}
	return false
}

func mustWrite(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}
