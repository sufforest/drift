//go:build integration

// Smoke test for the rclone subprocess path. Verifies that:
//
//   - rclone accepts the env vars produced by BuildRcloneEnv,
//   - the obscured passwords decode round-trip via `rclone reveal`,
//   - the configured crypt+S3 remote can `ls` an empty bucket through MinIO.
//
// Does NOT attempt a FUSE mount — that requires macFUSE/fuse3 + interactive
// setup and is the right job for an end-to-end manual smoke run.
//
// Run with `make test-integration` (MinIO must be up).
package mount

import (
	"bytes"
	"context"
	"encoding/base64"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/sufforest/drift/internal/domain"
)

func smokeRequest() Request {
	// 32-byte key for the crypt remote — same shape Drift's compartment
	// keys use.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	return Request{
		WorkspaceID:    "wks_smoke",
		Compartment:    "smoke",
		CompartmentKey: key,
		Cred: domain.S3Credential{
			AccessKeyID:     "drift-test",
			SecretAccessKey: "drift-test-secret",
		},
		Bucket: domain.BucketInfo{
			Provider: domain.ProviderMinIO,
			Endpoint: "http://127.0.0.1:9000",
			Name:     "drift-test",
			Region:   "us-east-1",
		},
		MountPoint: "/tmp/drift-smoke-mp",
		Mode:       "rw",
	}
}

// TestRcloneSmoke_obscureRevealRoundTrip pipes our obscured password
// through `rclone reveal` and confirms the plaintext matches what we sent.
// Since rcloneObscure now base64-encodes the raw key first, the round-trip
// landed value is the b64 string, not the key bytes.
func TestRcloneSmoke_obscureRevealRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("rclone"); err != nil {
		t.Skip("rclone not in PATH; skipping smoke test")
	}
	key := []byte("hello-from-drift-smoke-test-1234")
	obscured, err := rcloneObscure(key, "")
	if err != nil {
		t.Fatal(err)
	}
	out, err := runRclone(t, nil, 3*time.Second, "reveal", obscured)
	if err != nil {
		t.Fatalf("rclone reveal: %v\nstdout: %s", err, out)
	}
	got := strings.TrimRight(out, "\n")
	want := base64.RawURLEncoding.EncodeToString(key)
	if got != want {
		t.Fatalf("reveal mismatch:\n  got=%q\n  want=%q (b64 of %q)", got, want, key)
	}
}

// TestRcloneSmoke_listsCryptRemoteAgainstMinIO uses our env-based config
// to ask rclone to ls the configured crypt remote. The bucket is empty so
// the output should be empty; the absence of an error proves the config
// shape is valid and the auth chain works.
func TestRcloneSmoke_listsCryptRemoteAgainstMinIO(t *testing.T) {
	if _, err := exec.LookPath("rclone"); err != nil {
		t.Skip("rclone not in PATH; skipping smoke test")
	}
	req := smokeRequest()
	cryptName, env, err := BuildRcloneEnv(req, "")
	if err != nil {
		t.Fatal(err)
	}
	out, err := runRclone(t, env, 10*time.Second, "ls", cryptName+":")
	if err != nil {
		t.Fatalf("rclone ls %s: %v\nstdout:\n%s", cryptName, err, out)
	}
	// Empty output is fine; anything we accidentally wrote during prior
	// tests would also be acceptable for this smoke check.
	_ = out
}

// runRclone is a small helper that runs `rclone <args>` with the given
// extra env vars and a deadline, returning the merged stdout/stderr.
func runRclone(t *testing.T, extraEnv []string, timeout time.Duration, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "rclone", args...)
	cmd.Env = append(cmd.Environ(), extraEnv...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}
