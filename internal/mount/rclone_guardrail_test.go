package mount

import (
	"strings"
	"testing"

	"github.com/sufforest/drift/internal/domain"
)

// These tests guard against rclone-vs-R2 discoveries from the May 2026
// debug session. The two rclone-side gotchas that took hours to find:
//
//   1. rclone's S3 backend does HeadObject on `compartments/<vol>`
//      (no trailing slash) as part of its init probe. Without an
//      objectPath grant covering that exact key, R2 returns 403.
//      Tested via guardrail in internal/token/issue_guardrail_test.go.
//
//   2. rclone's S3 backend tries CreateBucket on first upload unless
//      explicitly told not to via NO_CHECK_BUCKET=true. Without this
//      env var, bearer creds (which don't have bucket-level perms)
//      get rejected with 403 AccessDenied. We assert presence below.

func newReq() Request {
	return Request{
		WorkspaceID:    "wks_abc",
		Compartment:    "main",
		CompartmentKey: bytes32("compartment-key-32-bytes-padding"),
		Cred: domain.S3Credential{
			AccessKeyID:     "ak",
			SecretAccessKey: "sk",
			SessionToken:    "session",
		},
		Bucket: domain.BucketInfo{
			Provider: domain.ProviderR2,
			Endpoint: "https://abc.r2.cloudflarestorage.com",
			Name:     "drift",
			Region:   "auto",
		},
		MountPoint: "/tmp/whatever",
		Mode:       "rw",
	}
}

func bytes32(s string) []byte {
	b := make([]byte, 32)
	copy(b, s)
	return b
}

// TestRcloneGuardrail_S3HasNoCheckBucket asserts the BuildRcloneEnv
// output contains NO_CHECK_BUCKET=true for the S3 remote. Without it
// rclone tries CreateBucket before any PUT, and bearer creds get 403.
// This was wall #3 in the R2 debug session.
func TestRcloneGuardrail_S3HasNoCheckBucket(t *testing.T) {
	_, env, err := BuildRcloneEnv(newReq(), "")
	if err != nil {
		t.Fatalf("BuildRcloneEnv: %v", err)
	}
	if !envHasSuffix(env, "_NO_CHECK_BUCKET=true") {
		t.Fatal("rclone S3 env missing *_NO_CHECK_BUCKET=true; CreateBucket probe will 403 with scoped bearer creds")
	}
}

// TestRcloneGuardrail_CryptWrapsS3 asserts the crypt remote's REMOTE
// pointer references the s3 remote name + "/<bucket>/compartments/<vol>".
// rclone needs this exact shape to know which prefix to layer crypt over.
func TestRcloneGuardrail_CryptWrapsS3(t *testing.T) {
	cryptName, env, err := BuildRcloneEnv(newReq(), "")
	if err != nil {
		t.Fatalf("BuildRcloneEnv: %v", err)
	}
	if cryptName == "" {
		t.Fatal("BuildRcloneEnv returned empty crypt name")
	}
	if !envEntryContains(env, "_REMOTE=", "compartments/main") {
		t.Fatal("crypt REMOTE env doesn't point at compartments/<vol>")
	}
	if !envEntryContains(env, "_REMOTE=", ":drift/compartments/main") {
		t.Fatal("crypt REMOTE env doesn't include the bucket name in the path")
	}
}

// TestRcloneGuardrail_CredentialsPropagated asserts the bearer's
// AK/SK/SessionToken all make it into the s3 env. Missing any of these
// causes silent auth failure or wrong-creds errors that look unrelated.
func TestRcloneGuardrail_CredentialsPropagated(t *testing.T) {
	_, env, err := BuildRcloneEnv(newReq(), "")
	if err != nil {
		t.Fatalf("BuildRcloneEnv: %v", err)
	}
	for _, want := range []string{
		"_ACCESS_KEY_ID=ak",
		"_SECRET_ACCESS_KEY=sk",
		"_SESSION_TOKEN=session",
		"_ENDPOINT=https://abc.r2.cloudflarestorage.com",
	} {
		if !envHasSuffix(env, want) {
			t.Errorf("rclone env missing entry with suffix %q", want)
		}
	}
}

// TestRcloneGuardrail_FilenameEncryptionEnabled asserts the crypt
// remote uses standard filename encryption + directory name encryption.
// Without these, filenames leak the workspace structure to bucket admins.
func TestRcloneGuardrail_FilenameEncryptionEnabled(t *testing.T) {
	_, env, err := BuildRcloneEnv(newReq(), "")
	if err != nil {
		t.Fatalf("BuildRcloneEnv: %v", err)
	}
	if !envHasSuffix(env, "_FILENAME_ENCRYPTION=standard") {
		t.Error("crypt remote missing FILENAME_ENCRYPTION=standard; filenames would leak")
	}
	if !envHasSuffix(env, "_DIRECTORY_NAME_ENCRYPTION=true") {
		t.Error("crypt remote missing DIRECTORY_NAME_ENCRYPTION=true; dir names would leak")
	}
}

// TestRcloneGuardrail_BuildRcloneEnv_emptyKey errors cleanly when no
// compartment key is provided. Without this guard, rclone would be
// configured with an empty crypt key and silently produce unencrypted
// blobs.
func TestRcloneGuardrail_BuildRcloneEnv_emptyKey(t *testing.T) {
	req := newReq()
	req.CompartmentKey = nil
	_, _, err := BuildRcloneEnv(req, "")
	if err == nil {
		t.Fatal("BuildRcloneEnv must refuse empty CompartmentKey")
	}
}

// envHasSuffix returns true if any env entry ends with suffix.
func envHasSuffix(env []string, suffix string) bool {
	for _, e := range env {
		if strings.HasSuffix(e, suffix) {
			return true
		}
	}
	return false
}

// envEntryContains returns true if any env entry contains both substrings.
func envEntryContains(env []string, parts ...string) bool {
	for _, e := range env {
		ok := true
		for _, p := range parts {
			if !strings.Contains(e, p) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
