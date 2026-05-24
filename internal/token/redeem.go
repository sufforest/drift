package token

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/credentials"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/manifest"
	"github.com/sufforest/drift/internal/storage"
)

// Redeemer turns an encoded token string into a verified RedeemResult ready
// for the mount layer. It is the inverse of Issuer.
//
// Provider should be authenticated with the token's ControlCred so it can
// GET (and only GET) the three control-plane objects this code reads. The
// workspace layer wires this up; tests use MemoryProvider, which ignores
// authentication.
type Redeemer struct {
	Provider storage.Provider
	Now      func() time.Time
}

// RedeemResult is the verified, decrypted view of a token.
//
// DataCred is the credential the mount layer uses for compartment R/W. It
// has no .drift/* access by construction. Keep ControlCred handy in case
// the caller wants to refresh the revocation poller's Provider.
type RedeemResult struct {
	TID          string
	WorkspaceID  string
	BucketInfo   domain.BucketInfo
	DataCred     domain.S3Credential
	ControlCred  domain.S3Credential
	Compartments map[string]domain.CompartmentGrant
	CPRK         []byte
	Manifest     *domain.Manifest
	ExpiresAt    time.Time
	IssuedBy     string
}

// Redeem turns an encoded token string into a verified RedeemResult.
// Verify-before-use ordering:
//
//  1. Decode the token string.
//  2. Verify the Ed25519 signature OVER THE PAYLOAD BYTES against the
//     token's self-asserted IssuerPub. This must happen before any field
//     of the token is used to drive network behavior, because Bucket and
//     ControlCred direct outbound HTTP — a tampered Bucket.Endpoint would
//     otherwise be an SSRF / credential-exfiltration vector.
//  3. Fetch + decrypt .drift/credentials/<tid>.enc using RedemptionCode.
//  4. Fetch + decrypt the manifest with CPRK.
//  5. Verify the manifest signature.
//  6. Cross-check that IssuerPub matches the issuing device's pubkey
//     recorded in the manifest — confirms the signer is actually a known
//     device, not just a self-asserted one.
//  7. Check active_tokens record + revocations + TTL.
func (r *Redeemer) Redeem(ctx context.Context, encoded string) (*RedeemResult, error) {
	// 1. Decode wire format.
	payload, sig, err := dcrypto.DecodeToken(encoded)
	if err != nil {
		return nil, err
	}
	var tok domain.Token
	if err := json.Unmarshal(payload, &tok); err != nil {
		return nil, fmt.Errorf("%w: %v", domain.ErrTokenMalformed, err)
	}
	if tok.Version != domain.TokenVersion {
		return nil, fmt.Errorf("%w: unsupported token version %d", domain.ErrTokenMalformed, tok.Version)
	}

	// 2. Verify the signature against the token's IssuerPub BEFORE
	//    using any field of the token. This is the trust gate.
	if len(tok.IssuerPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: missing or malformed IssuerPub", domain.ErrTokenMalformed)
	}
	if err := dcrypto.Verify(ed25519.PublicKey(tok.IssuerPub), payload, sig); err != nil {
		return nil, err
	}

	// 3. Fetch + decrypt the credentials blob using the redemption code.
	//    AAD binds the ciphertext to this specific tid + wid, so a bucket
	//    admin swapping blob bytes between tids is detected by the AEAD.
	credCipher, err := r.Provider.Get(ctx, domain.CredentialsKeyFor(tok.TID))
	if err != nil {
		if errors.Is(err, domain.ErrObjectNotFound) {
			return nil, fmt.Errorf("%w: credentials blob missing for %s", domain.ErrTokenRevoked, tok.TID)
		}
		return nil, fmt.Errorf("fetch credentials: %w", err)
	}
	tcBody, err := dcrypto.Decrypt(tok.RedemptionCode, credCipher, CredentialsAADFor(tok.TID, tok.WorkspaceID))
	if err != nil {
		return nil, fmt.Errorf("decrypt credentials: %w", err)
	}
	var tc domain.TokenCredentials
	if err := json.Unmarshal(tcBody, &tc); err != nil {
		return nil, fmt.Errorf("parse credentials: %w", err)
	}

	now := r.now()
	if now.After(tc.ExpiresAt) {
		return nil, fmt.Errorf("%w: credentials expired at %s", domain.ErrTokenExpired, tc.ExpiresAt.UTC().Format(time.RFC3339))
	}

	// 4. Fetch + decrypt the manifest with the CPRK we just unlocked.
	manifestCipher, err := r.Provider.Get(ctx, domain.ManifestKey)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	m, err := manifest.Decrypt(manifestCipher, tc.CPRK, tok.WorkspaceID)
	if err != nil {
		return nil, err
	}

	// 5. Verify the manifest signature + enrollment chain. Refusing to
	//    operate on an unsignable manifest closes the
	//    bucket-admin-rewrites-control-plane attack vector.
	if err := manifest.Verify(m); err != nil {
		return nil, err
	}
	// Pin check: the master pseudo-device's pubkey must hash to the
	// fingerprint the token committed to. A bucket admin who forks the
	// workspace by inserting their own master fails here.
	if len(tok.MasterFingerprint) > 0 {
		master, ok := m.Devices[domain.MasterDeviceID]
		if !ok {
			return nil, fmt.Errorf("%w: manifest has no master entry", domain.ErrDeviceUnknown)
		}
		gotFP := sha256.Sum256(master.PublicKey)
		if !bytes.Equal(gotFP[:], tok.MasterFingerprint) {
			return nil, fmt.Errorf("%w: master fingerprint mismatch", domain.ErrSignatureInvalid)
		}
	}

	// 6. Cross-check IssuerPub against the manifest's device record. The
	//    sig already verified against IssuerPub in step 2; this step
	//    confirms the issuer is actually an authorized device.
	issuingDev, ok := m.Devices[tc.IssuedBy]
	if !ok {
		return nil, fmt.Errorf("%w: token issued by unknown device %s", domain.ErrDeviceUnknown, tc.IssuedBy)
	}
	if !bytes.Equal(issuingDev.PublicKey, tok.IssuerPub) {
		return nil, fmt.Errorf("%w: token IssuerPub does not match manifest record for %s", domain.ErrSignatureInvalid, tc.IssuedBy)
	}
	// Confirm the tid is still listed in active_tokens. If a device
	// was revoked + re-enrolled with a fresh keypair, old token signatures
	// would fail above; this catches the case where the manifest dropped
	// the record explicitly (cleanup or admin action).
	rec, ok := m.ActiveTokens[tok.TID]
	if !ok {
		return nil, fmt.Errorf("%w: tid not in manifest active_tokens", domain.ErrTokenRevoked)
	}
	if now.After(rec.ExpiresAt) {
		return nil, fmt.Errorf("%w: manifest records expired at %s", domain.ErrTokenExpired, rec.ExpiresAt.UTC().Format(time.RFC3339))
	}

	// Cross-check that the scope embedded in the credentials blob
	// matches the manifest's authoritative record AND the actual prefixes
	// claimed by the minted JWT. Protects against an issuing-device or
	// upstream-tampering attack that swaps in a DataCred scoped to a
	// different compartment than the manifest record advertises.
	if err := verifyScopeConsistency(rec, &tc); err != nil {
		return nil, err
	}

	// 7. Check the revocation list.
	if err := r.checkRevoked(ctx, tok.TID, m); err != nil {
		return nil, err
	}

	return &RedeemResult{
		TID:          tok.TID,
		WorkspaceID:  tok.WorkspaceID,
		BucketInfo:   tok.Bucket,
		DataCred:     tc.DataCred,
		ControlCred:  tok.ControlCred,
		Compartments: tc.Compartments,
		CPRK:         tc.CPRK,
		Manifest:     m,
		ExpiresAt:    tc.ExpiresAt,
		IssuedBy:     tc.IssuedBy,
	}, nil
}

// verifyScopeConsistency requires the recorded Scope in the manifest's
// TokenRecord, the keys in the credentials blob's Compartments map, and
// the prefixes claim inside the DataCred R2 JWT to describe the same set
// of compartments AND each name to pass ValidCompartmentName so a
// downstream filepath.Join can't traverse out of the mount root.
//
// Caveat: the JWT prefixes check is best-effort because non-R2 minters
// produce credentials whose session token isn't a JWT. We skip the JWT
// claim verification when SessionToken doesn't start with "jwt/".
func verifyScopeConsistency(rec domain.TokenRecord, tc *domain.TokenCredentials) error {
	scopeSet := make(map[string]struct{}, len(rec.Scope))
	for _, name := range rec.Scope {
		if err := domain.ValidCompartmentName(name); err != nil {
			return fmt.Errorf("%w: manifest scope: %v", domain.ErrSignatureInvalid, err)
		}
		scopeSet[name] = struct{}{}
	}
	if len(tc.Compartments) != len(scopeSet) {
		return fmt.Errorf("%w: credentials blob has %d compartments, manifest record has %d",
			domain.ErrSignatureInvalid, len(tc.Compartments), len(scopeSet))
	}
	for name := range tc.Compartments {
		if err := domain.ValidCompartmentName(name); err != nil {
			return fmt.Errorf("%w: credentials compartment: %v", domain.ErrSignatureInvalid, err)
		}
		if _, ok := scopeSet[name]; !ok {
			return fmt.Errorf("%w: credentials blob includes %q, not in manifest scope",
				domain.ErrSignatureInvalid, name)
		}
	}

	// JWT prefixes cross-check (R2 only).
	jwt, err := credentials.DecodeR2SessionToken(tc.DataCred.SessionToken)
	if err != nil {
		// Not an R2-signed cred (e.g. AWS STS in the future); skip
		// this defense-in-depth check — caller still validates the
		// scope at S3 enforcement level.
		return nil
	}
	claims, _, _, err := credentials.DecodeR2JWT(jwt)
	if err != nil {
		return fmt.Errorf("%w: cannot decode DataCred JWT: %v", domain.ErrSignatureInvalid, err)
	}
	expected := make(map[string]struct{}, len(scopeSet))
	for name := range scopeSet {
		expected[domain.CompartmentPrefix(name)] = struct{}{}
	}
	var prefixes []string
	if claims.Paths != nil {
		prefixes = claims.Paths.PrefixPaths
	}
	if len(prefixes) != len(expected) {
		return fmt.Errorf("%w: DataCred has %d prefixes, manifest scope describes %d",
			domain.ErrSignatureInvalid, len(prefixes), len(expected))
	}
	for _, p := range prefixes {
		if _, ok := expected[p]; !ok {
			return fmt.Errorf("%w: DataCred prefix %q outside manifest scope", domain.ErrSignatureInvalid, p)
		}
	}
	return nil
}

func (r *Redeemer) checkRevoked(ctx context.Context, tid string, m *domain.Manifest) error {
	body, err := r.Provider.Get(ctx, domain.RevocationsKey)
	if errors.Is(err, domain.ErrObjectNotFound) {
		return nil // no revocations yet
	}
	if err != nil {
		return fmt.Errorf("fetch revocations: %w", err)
	}
	list, err := DecodeRevocations(body)
	if err != nil {
		return err
	}
	for _, e := range list.Entries {
		if e.TID != tid {
			continue
		}
		// Verify the revocation signature against the revoking device's
		// pubkey. An unsignable revocation is ignored — a bucket admin
		// cannot forge revocations any more than they can forge a manifest.
		dev, ok := m.Devices[e.RevokedBy]
		if !ok {
			continue
		}
		if err := VerifyRevocationEntry(e, ed25519.PublicKey(dev.PublicKey)); err != nil {
			continue
		}
		return fmt.Errorf("%w: %s", domain.ErrTokenRevoked, tid)
	}
	return nil
}

func (r *Redeemer) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}
