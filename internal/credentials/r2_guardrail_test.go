package credentials

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func hexSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// These tests guard against the hard-won R2 minter discoveries from
// the May 2026 debug session. Every assertion here corresponds to a
// real R2 behavior that took hours to find. If any of these break in
// a future refactor, drift-on-R2 will silently fail again.
//
// Reference: dist/R2-DEBUG-LOG.md, dist/r2-refs/cf-docs-*.md.

const (
	guardEndpoint = "https://abc123.r2.cloudflarestorage.com"
	guardAK       = "ak-abc"
	guardSK       = "sk-xyz"
	guardBucket   = "drift-test"
)

func newGuardMinter() *R2LocalSignMinter {
	return &R2LocalSignMinter{
		AccessKeyID:     guardAK,
		SecretAccessKey: guardSK,
		Endpoint:        guardEndpoint,
		Now:             func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}
}

// TestR2Guardrail_JWTOmitsActions is the #1 critical regression test:
// R2's local-sign validator REJECTS any JWT containing the `actions`
// claim, despite CF docs claiming it's supported. If a future refactor
// re-adds actions serialization, drift's bearer flow will silently
// break on R2 again. This test catches that immediately.
func TestR2Guardrail_JWTOmitsActions(t *testing.T) {
	m := newGuardMinter()
	cred, err := m.Mint(context.Background(), MintRequest{
		Bucket:  guardBucket,
		Scope:   R2ScopeObjectReadOnly,
		Actions: []string{"GetObject", "HeadObject"}, // explicitly request actions
		TTL:     time.Hour,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	jwt, err := DecodeR2SessionToken(cred.SessionToken)
	if err != nil {
		t.Fatalf("DecodeR2SessionToken: %v", err)
	}
	// Inspect the raw payload JSON bytes — not the decoded struct.
	// A future regression could re-add an Actions field to the struct
	// without changing serialization (or vice versa); the wire bytes
	// are what R2 actually validates.
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed JWT")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("payload b64: %v", err)
	}
	_ = json.RawMessage(body) // ensure json import retained
	if strings.Contains(string(body), `"actions"`) {
		t.Fatalf("JWT contains `actions` claim — R2 will reject. JWT body: %s", string(body))
	}
}

// TestR2Guardrail_SessionTokenIsBase64OfJwtSlashPrefix asserts the
// exact session-token wire format: base64("jwt/" + signed-jwt).
// R2 expects this; "jwt/" alone, urlsafe base64, or unwrapped jwt
// all fail differently.
func TestR2Guardrail_SessionTokenIsBase64OfJwtSlashPrefix(t *testing.T) {
	m := newGuardMinter()
	cred, err := m.Mint(context.Background(), MintRequest{
		Bucket: guardBucket,
		Scope:  R2ScopeObjectReadOnly,
		TTL:    time.Hour,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(cred.SessionToken)
	if err != nil {
		t.Fatalf("session token not standard base64: %v", err)
	}
	if !strings.HasPrefix(string(decoded), "jwt/") {
		t.Fatalf("decoded session token must start with 'jwt/', got %q (first 8: %q)",
			"...", string(decoded[:min(8, len(decoded))]))
	}
}

// TestR2Guardrail_TempSecretIsSHA256HexOfJWT asserts the temporary
// secret access key derivation rule from CF docs: hex(SHA-256(jwt)).
// R2 server-side recomputes this; mismatch breaks SigV4 signing.
func TestR2Guardrail_TempSecretIsSHA256HexOfJWT(t *testing.T) {
	m := newGuardMinter()
	cred, err := m.Mint(context.Background(), MintRequest{
		Bucket: guardBucket,
		Scope:  R2ScopeObjectReadOnly,
		TTL:    time.Hour,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	jwt, _ := DecodeR2SessionToken(cred.SessionToken)
	// Recompute and compare.
	want := hexSHA256(jwt)
	if cred.SecretAccessKey != want {
		t.Fatalf("SecretAccessKey != hex(SHA-256(jwt))\n  got:  %s\n  want: %s", cred.SecretAccessKey, want)
	}
	if len(cred.SecretAccessKey) != 64 {
		t.Errorf("temp secret must be 64 hex chars, got %d", len(cred.SecretAccessKey))
	}
}

// TestR2Guardrail_RequiredClaimsPresent asserts the JWT contains every
// claim R2's validator inspects. Missing any of these → InvalidArgument.
func TestR2Guardrail_RequiredClaimsPresent(t *testing.T) {
	m := newGuardMinter()
	cred, err := m.Mint(context.Background(), MintRequest{
		Bucket:      guardBucket,
		Scope:       R2ScopeObjectReadOnly,
		Prefixes:    []string{"compartments/foo/"},
		ObjectPaths: []string{".drift/manifest.enc"},
		TTL:         time.Hour,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	jwt, _ := DecodeR2SessionToken(cred.SessionToken)
	claims, _, _, err := DecodeR2JWT(jwt)
	if err != nil {
		t.Fatalf("DecodeR2JWT: %v", err)
	}

	checks := map[string]any{
		"Bucket":    claims.Bucket,
		"Scope":     claims.Scope,
		"Subject":   claims.Subject,
		"Issuer":    claims.Issuer,
		"Audience":  claims.Audience,
		"IssuedAt":  claims.IssuedAt,
		"ExpiresAt": claims.ExpiresAt,
		"Paths":     claims.Paths,
	}
	for k, v := range checks {
		switch vv := v.(type) {
		case string:
			if vv == "" {
				t.Errorf("required claim %s is empty", k)
			}
		case int64:
			if vv == 0 {
				t.Errorf("required claim %s is zero", k)
			}
		case *R2Paths:
			if vv == nil {
				t.Errorf("required claim %s is nil", k)
			}
		}
	}
	if claims.Audience != "abc123.r2.cloudflarestorage.com" {
		t.Errorf("aud must be endpoint HOST, got %q", claims.Audience)
	}
	if claims.Subject != "abc123" {
		t.Errorf("sub must be account-id (leftmost label of endpoint host), got %q", claims.Subject)
	}
	if claims.Issuer != guardAK {
		t.Errorf("iss must be parent access key ID, got %q", claims.Issuer)
	}
}

// TestR2Guardrail_PathsAlwaysSerializeBothKeys asserts that the nested
// paths object always contains both prefixPaths and objectPaths keys,
// even when one is empty. The CF reference impl does this; we match
// it to avoid parser-strictness surprises.
func TestR2Guardrail_PathsAlwaysSerializeBothKeys(t *testing.T) {
	m := newGuardMinter()
	cred, err := m.Mint(context.Background(), MintRequest{
		Bucket:      guardBucket,
		Scope:       R2ScopeObjectReadOnly,
		ObjectPaths: []string{".drift/manifest.enc"}, // only objects, no prefixes
		TTL:         time.Hour,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	jwt, _ := DecodeR2SessionToken(cred.SessionToken)
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed JWT (parts=%d)", len(parts))
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("base64 payload: %v", err)
	}
	pj := string(payloadRaw)
	if !strings.Contains(pj, `"prefixPaths"`) {
		t.Errorf("paths missing prefixPaths key: %s", pj)
	}
	if !strings.Contains(pj, `"objectPaths"`) {
		t.Errorf("paths missing objectPaths key: %s", pj)
	}
}

// TestR2Guardrail_ParseR2Endpoint covers the host + account-id derivation
// for normal, jurisdiction-specific, and edge-case endpoints.
func TestR2Guardrail_ParseR2Endpoint(t *testing.T) {
	cases := []struct {
		endpoint string
		wantHost string
		wantAcct string
		wantErr  bool
	}{
		{"https://abc123.r2.cloudflarestorage.com", "abc123.r2.cloudflarestorage.com", "abc123", false},
		{"https://abc123.eu.r2.cloudflarestorage.com", "abc123.eu.r2.cloudflarestorage.com", "abc123", false},
		{"https://abc123.r2.cloudflarestorage.com/some/path", "abc123.r2.cloudflarestorage.com", "abc123", false},
		{"http://abc123.r2.cloudflarestorage.com", "abc123.r2.cloudflarestorage.com", "abc123", false},
		{"", "", "", true},
		{"https://", "", "", true},
		{"https://nodotpath", "", "", true},
	}
	for _, c := range cases {
		host, acct, err := parseR2Endpoint(c.endpoint)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseR2Endpoint(%q) = (%q, %q, nil), want err", c.endpoint, host, acct)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseR2Endpoint(%q): %v", c.endpoint, err)
			continue
		}
		if host != c.wantHost {
			t.Errorf("parseR2Endpoint(%q) host = %q, want %q", c.endpoint, host, c.wantHost)
		}
		if acct != c.wantAcct {
			t.Errorf("parseR2Endpoint(%q) acct = %q, want %q", c.endpoint, acct, c.wantAcct)
		}
	}
}

func min(a, b int) int { if a < b { return a }; return b }
