package token

import (
	"testing"
	"time"

	"github.com/sufforest/drift/internal/domain"
)

// TestIssueGuardrail_DataCredGrantsObjectPathWithoutSlash asserts that
// buildDataMintRequest emits BOTH a prefixPath ending in "/" AND an
// objectPath for the same prefix WITHOUT the trailing slash. The
// second one matters because rclone's S3 backend does HeadObject on
// `compartments/<vol>` (no slash) as part of its init probe, and R2's
// prefix-matching is strict: "compartments/main" doesn't start with
// "compartments/main/".
//
// Without this exact pair, drift open fails with:
//   "S3: HeadObject ... 403 Forbidden"
// which is what happened during the May 2026 debug session.
func TestIssueGuardrail_DataCredGrantsObjectPathWithoutSlash(t *testing.T) {
	req := IssueRequest{
		BucketInfo: domain.BucketInfo{Name: "drift"},
		Scope:      []string{"main"},
		Mode:       domain.TokenModeRW,
	}
	mr := buildDataMintRequest(req, time.Hour)

	// Prefix WITH trailing slash for actual data ops.
	foundPrefix := false
	for _, p := range mr.Prefixes {
		if p == "compartments/main/" {
			foundPrefix = true
		}
	}
	if !foundPrefix {
		t.Errorf("DataCred missing prefixPath 'compartments/main/' for actual data ops; got: %v", mr.Prefixes)
	}

	// Object WITHOUT trailing slash for rclone's HeadObject probe.
	foundObject := false
	for _, p := range mr.ObjectPaths {
		if p == "compartments/main" {
			foundObject = true
		}
	}
	if !foundObject {
		t.Errorf("DataCred missing objectPath 'compartments/main' (no slash) for rclone init probe; got: %v", mr.ObjectPaths)
	}
}

// TestIssueGuardrail_DataCredMultiVolScope asserts the prefix+object
// duality holds for every vol in the scope.
func TestIssueGuardrail_DataCredMultiVolScope(t *testing.T) {
	req := IssueRequest{
		BucketInfo: domain.BucketInfo{Name: "drift"},
		Scope:      []string{"main", "code", "models"},
		Mode:       domain.TokenModeRW,
	}
	mr := buildDataMintRequest(req, time.Hour)

	for _, name := range req.Scope {
		wantPrefix := "compartments/" + name + "/"
		wantObject := "compartments/" + name
		if !contains(mr.Prefixes, wantPrefix) {
			t.Errorf("scope %q missing prefixPath %q", name, wantPrefix)
		}
		if !contains(mr.ObjectPaths, wantObject) {
			t.Errorf("scope %q missing objectPath %q", name, wantObject)
		}
	}
}

// TestIssueGuardrail_ControlCredGrantsExactlyThreeObjects asserts
// the ControlCred's objectPaths are the EXACT three control-plane
// files the bearer needs and nothing more. Drift's security model
// depends on this — see DD-3 + the token issuance docs.
func TestIssueGuardrail_ControlCredGrantsExactlyThreeObjects(t *testing.T) {
	tid := "tok_abc123"
	req := IssueRequest{
		BucketInfo: domain.BucketInfo{Name: "drift"},
	}
	mr := buildControlMintRequest(req, tid, time.Hour)

	want := []string{
		domain.ManifestKey,
		domain.RevocationsKey,
		domain.CredentialsKeyFor(tid),
	}
	if len(mr.ObjectPaths) != len(want) {
		t.Fatalf("ControlCred objectPaths count = %d, want %d (%v vs %v)", len(mr.ObjectPaths), len(want), mr.ObjectPaths, want)
	}
	for _, w := range want {
		if !contains(mr.ObjectPaths, w) {
			t.Errorf("ControlCred missing expected objectPath %q", w)
		}
	}
	if len(mr.Prefixes) != 0 {
		t.Errorf("ControlCred must have NO prefixPaths; got %v", mr.Prefixes)
	}
}

// TestIssueGuardrail_DataCredROModeUsesObjectReadOnlyScope asserts
// that the mode → scope mapping is correct. RO tokens should never
// get object-read-write scope (which would silently allow writes).
func TestIssueGuardrail_DataCredROModeUsesObjectReadOnlyScope(t *testing.T) {
	req := IssueRequest{
		BucketInfo: domain.BucketInfo{Name: "drift"},
		Scope:      []string{"main"},
		Mode:       domain.TokenModeRO,
	}
	mr := buildDataMintRequest(req, time.Hour)
	if mr.Scope != "object-read-only" {
		t.Errorf("RO mode should produce scope=object-read-only, got %q", mr.Scope)
	}

	req.Mode = domain.TokenModeRW
	mr = buildDataMintRequest(req, time.Hour)
	if mr.Scope != "object-read-write" {
		t.Errorf("RW mode should produce scope=object-read-write, got %q", mr.Scope)
	}
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
