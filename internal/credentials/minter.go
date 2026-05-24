// Package credentials mints scoped S3 credentials for embedding into tokens
// and loads parent provider credentials from the user's config.
//
// The headline implementation is R2 local signing: the issuing device
// signs a JWT with the parent R2 secret key, derives a temporary secret
// via SHA-256, and prefixes the JWT with "jwt/" to form the sessionToken.
// No API call to Cloudflare is required.
package credentials

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sufforest/drift/internal/domain"
)

// MintRequest describes the scoped credential to mint for a token.
type MintRequest struct {
	Bucket      string        // bucket name (R2/B2/AWS/etc.)
	Scope       string        // R2 preset: "object-read-only", "object-read-write", "admin-read-only", "admin-read-write"
	Prefixes    []string      // e.g. ["compartments/project-sdxl/", "compartments/models/"]
	ObjectPaths []string      // read-only control-plane objects (".drift/revocations.enc")
	Actions     []string      // ["GetObject", "PutObject", ...] — further restricts beyond Scope
	TTL         time.Duration // typically <= 24h
}

// R2 scope presets — see https://developers.cloudflare.com/r2/api/s3/temporary-credentials/#scope
const (
	R2ScopeObjectReadOnly  = "object-read-only"
	R2ScopeObjectReadWrite = "object-read-write"
	R2ScopeAdminReadOnly   = "admin-read-only"
	R2ScopeAdminReadWrite  = "admin-read-write"
)

// Minter mints scoped S3 credentials for a given MintRequest. The interface
// is small so non-R2 backends (B2 b2_create_key, AWS STS) can plug in later.
type Minter interface {
	Mint(ctx context.Context, req MintRequest) (*domain.S3Credential, error)
}

// DefaultActions is the set of S3 actions a read-write Drift session needs.
// Multipart actions are included so files >5GB upload correctly.
var DefaultActions = []string{
	"GetObject",
	"HeadObject",
	"PutObject",
	"DeleteObject",
	"ListBucket",
	"ListObjectsV2",
	"CreateMultipartUpload",
	"UploadPart",
	"CompleteMultipartUpload",
	"AbortMultipartUpload",
	"CopyObject",
	"ListMultipartUploads",
	"ListParts",
}

// ReadOnlyActions are used for objects the bearer should only read (e.g. the
// shared revocations file).
var ReadOnlyActions = []string{"GetObject", "HeadObject"}

// R2LocalSignMinter mints credentials by client-side-signing a JWT with the
// parent R2 secret key. Per Cloudflare docs the issuing environment must be
// trusted — in Drift's model that's the user's primary device.
//
// Endpoint is required because R2 binds the JWT's audience to the
// endpoint host (e.g. <account>.r2.cloudflarestorage.com) and the
// subject to the account ID. Both are derived from Endpoint at mint
// time.
type R2LocalSignMinter struct {
	AccessKeyID     string // parent R2 access key ID (reused for derived creds)
	SecretAccessKey string // parent R2 secret access key — never transmitted
	Endpoint        string // bucket endpoint URL: https://<account>.r2.cloudflarestorage.com
	Now             func() time.Time
}

// R2Claims matches the JWT body shape that R2's local-sign validator
// actually accepts. Verified by comparing against the JWT produced by
// CF's server-side `/r2/temp-access-credentials` API endpoint.
//
// Two non-obvious things that differ from the published spec at
// https://developers.cloudflare.com/r2/api/s3/temporary-credentials/:
//
//  1. The `actions` claim — though the docs say it's "supported via
//     local signing only", R2's local-sign validator REJECTS any JWT
//     that contains it. We omit it entirely; scope alone gates which
//     operations are allowed.
//  2. Field order: the on-the-wire JSON keys come out as
//     {bucket, paths, scope, sub, iat, iss, aud, exp}. The jose
//     TypeScript example in CF's docs would produce a different order;
//     CF's API mint matches the order above, which we mirror for safety
//     even though JSON parsers shouldn't care about order.
type R2Claims struct {
	// R2 custom claims first (matching CF API output)
	Bucket string   `json:"bucket"`
	Paths  *R2Paths `json:"paths,omitempty"`
	Scope  string   `json:"scope,omitempty"`

	// Standard JWT claims in CF API's order: sub, iat, iss, aud, exp
	Subject   string `json:"sub"`
	IssuedAt  int64  `json:"iat"`
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	ExpiresAt int64  `json:"exp"`
}

// R2Paths is the nested scoping object inside R2Claims. R2's spec uses
// prefixPaths / objectPaths (NOT top-level "prefixes" / "objects"). The
// reference JS implementation always serializes both keys even when one
// is empty — we match that to avoid any parser-strictness surprises.
type R2Paths struct {
	PrefixPaths []string `json:"prefixPaths"`
	ObjectPaths []string `json:"objectPaths"`
}

// Mint produces a temporary credential triple via R2 local JWT signing.
func (m *R2LocalSignMinter) Mint(_ context.Context, req MintRequest) (*domain.S3Credential, error) {
	if m.AccessKeyID == "" || m.SecretAccessKey == "" {
		return nil, errors.New("credentials: R2LocalSignMinter requires parent AccessKeyID and SecretAccessKey")
	}
	if m.Endpoint == "" {
		return nil, errors.New("credentials: R2LocalSignMinter requires Endpoint (e.g. https://<account>.r2.cloudflarestorage.com)")
	}
	if req.Bucket == "" {
		return nil, errors.New("credentials: MintRequest.Bucket is required")
	}
	if req.Scope == "" && len(req.Actions) == 0 {
		return nil, errors.New("credentials: MintRequest needs at least one of Scope or Actions")
	}
	if req.TTL <= 0 {
		return nil, errors.New("credentials: MintRequest.TTL must be > 0")
	}

	host, accountID, err := parseR2Endpoint(m.Endpoint)
	if err != nil {
		return nil, err
	}

	now := m.now()
	claims := R2Claims{
		Bucket:    req.Bucket,
		Scope:     req.Scope,
		Subject:   accountID,
		IssuedAt:  now.Unix(),
		Issuer:    m.AccessKeyID,
		Audience:  host,
		ExpiresAt: now.Add(req.TTL).Unix(),
	}
	// NOTE: req.Actions is intentionally NOT propagated to claims.
	// Empirically R2's local-sign validator rejects any JWT containing
	// an `actions` claim, despite CF docs claiming local-sign supports
	// it. See dist/R2-DEBUG-LOG.md for the isolation evidence.
	_ = req.Actions
	if len(req.Prefixes) > 0 || len(req.ObjectPaths) > 0 {
		// Always serialize both keys (the JS reference impl does this
		// even when one is empty). Convert nil slices to [] so JSON
		// emits "[]" rather than "null".
		prefixes := req.Prefixes
		if prefixes == nil {
			prefixes = []string{}
		}
		objects := req.ObjectPaths
		if objects == nil {
			objects = []string{}
		}
		claims.Paths = &R2Paths{
			PrefixPaths: prefixes,
			ObjectPaths: objects,
		}
	}

	jwt, err := signR2JWT(claims, m.SecretAccessKey)
	if err != nil {
		return nil, err
	}

	// Per CF spec:
	//   secretAccessKey = hex(SHA-256(signed-jwt))
	//   sessionToken    = base64("jwt/" + signed-jwt)
	sum := sha256.Sum256([]byte(jwt))
	tempSecret := hex.EncodeToString(sum[:])
	sessionToken := base64.StdEncoding.EncodeToString([]byte("jwt/" + jwt))

	return &domain.S3Credential{
		AccessKeyID:     m.AccessKeyID, // reused
		SecretAccessKey: tempSecret,
		SessionToken:    sessionToken,
		Expires:         time.Unix(claims.ExpiresAt, 0).UTC(),
	}, nil
}

func (m *R2LocalSignMinter) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// parseR2Endpoint extracts (host, accountID) from a URL like
// https://abc123.r2.cloudflarestorage.com or
// https://abc123.eu.r2.cloudflarestorage.com.
func parseR2Endpoint(endpoint string) (host, accountID string, err error) {
	// Trim scheme if present.
	s := endpoint
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(s, prefix) {
			s = s[len(prefix):]
			break
		}
	}
	// Drop path / query suffix.
	if i := strings.IndexAny(s, "/?"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return "", "", fmt.Errorf("credentials: empty R2 endpoint host")
	}
	host = s
	// Account ID is the leftmost dot-separated label.
	if i := strings.Index(s, "."); i > 0 {
		accountID = s[:i]
	} else {
		return "", "", fmt.Errorf("credentials: cannot extract account ID from endpoint %q", endpoint)
	}
	if accountID == "" {
		return "", "", fmt.Errorf("credentials: empty account ID in endpoint %q", endpoint)
	}
	return host, accountID, nil
}

// signR2JWT produces a base64url-encoded JWT signed with HS256.
//
// Format: base64url(header) "." base64url(payload) "." base64url(HMAC-SHA256(secret, header.payload))
func signR2JWT(claims R2Claims, secret string) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64url(header) + "." + b64url(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	return signingInput + "." + b64url(mac.Sum(nil)), nil
}

func b64url(b []byte) string {
	// JWT uses base64url WITHOUT padding (RFC 7515 §2).
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

// DecodeR2JWT decodes the payload from an R2 JWT for inspection. It does NOT
// verify the signature — callers verify by re-signing with the parent secret
// and comparing. Exported because tests and `drift verify` want to inspect a
// minted credential's claims.
func DecodeR2JWT(jwt string) (claims R2Claims, signingInput, signature string, err error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return R2Claims{}, "", "", fmt.Errorf("jwt: expected 3 parts, got %d", len(parts))
	}
	payload, err := decodeB64URL(parts[1])
	if err != nil {
		return R2Claims{}, "", "", fmt.Errorf("jwt payload b64: %w", err)
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return R2Claims{}, "", "", fmt.Errorf("jwt payload json: %w", err)
	}
	return claims, parts[0] + "." + parts[1], parts[2], nil
}

// DecodeR2SessionToken takes the SessionToken value (base64("jwt/" + jwt))
// and returns the inner JWT. Use this when you have the cred from a token
// blob and want to inspect the underlying JWT claims.
func DecodeR2SessionToken(sessionToken string) (jwt string, err error) {
	raw, err := base64.StdEncoding.DecodeString(sessionToken)
	if err != nil {
		return "", fmt.Errorf("session token b64: %w", err)
	}
	const prefix = "jwt/"
	if !strings.HasPrefix(string(raw), prefix) {
		return "", fmt.Errorf("session token: missing %q prefix after base64 decode", prefix)
	}
	return string(raw)[len(prefix):], nil
}

func decodeB64URL(s string) ([]byte, error) {
	if pad := len(s) % 4; pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}
	return base64.URLEncoding.DecodeString(s)
}
