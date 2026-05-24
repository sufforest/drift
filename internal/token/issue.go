// Package token implements `drift grant`, `drift open`, and `drift revoke`.
package token

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/credentials"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/manifest"
	"github.com/sufforest/drift/internal/storage"
)

// CredentialsAADFor returns the AAD bound into the per-token credentials
// blob's AEAD. Including tid + wid means a bucket admin who swaps blob
// bytes between tids (or between workspaces) is detected on Decrypt —
// the AEAD tag won't verify against the wrong context.
func CredentialsAADFor(tid, workspaceID string) []byte {
	return []byte("drift/v2/credentials|" + workspaceID + "|" + tid)
}

// Issuer mints a new token and registers it in the manifest. One Issuer is
// constructed per `drift grant` invocation.
type Issuer struct {
	Provider   storage.Provider
	Writer     storage.ReadModifyWriter
	Minter     credentials.Minter
	DeviceID   string
	DeviceSign ed25519.PrivateKey
	MasterPub  ed25519.PublicKey // workspace master pubkey; embedded into tokens as MasterFingerprint
	Now        func() time.Time
}

// IssueRequest is the input to Issuer.Issue. The caller (CLI / workspace
// layer) is responsible for reading + decrypting the manifest and gathering
// the compartment keys for the scoped compartments.
type IssueRequest struct {
	WorkspaceID string
	BucketInfo  domain.BucketInfo

	// CPRK is the workspace's Control Plane Read Key, re-embedded into the
	// credentials blob so the bearer can decrypt the manifest + revocations.
	CPRK []byte

	// Compartments is the set of plaintext compartment keys for everything
	// in Scope. Missing entries are an error.
	Compartments map[string][]byte

	Scope []string      // compartment names to grant
	Mode  string        // TokenModeRW / TokenModeRO
	TTL   time.Duration // <= 24h recommended
}

// IssueResult is what Issue returns to the caller. Both scoped creds are
// included so the CLI / workspace layer can show their expiry, etc.
type IssueResult struct {
	Encoded     string
	TID         string
	ExpiresAt   time.Time
	DataCred    domain.S3Credential
	ControlCred domain.S3Credential
}

// Issue performs the full grant flow:
//
//  1. Mint two scoped S3 credentials: ControlCred (GET-only on the three
//     control-plane objects the bearer needs) and DataCred (RW or RO on the
//     authorized compartment prefixes, with NO .drift/* access).
//  2. Build TokenCredentials with DataCred inside; encrypt with redemption code.
//  3. Upload to .drift/credentials/<tid>.enc.
//  4. Build + sign the small Token (carries ControlCred); encode wire format.
//  5. Register the tid in the manifest (RMW).
//
// The two-credential split is the privacy-preserving fix for R2's
// single-actions-list JWT: the bearer literally cannot write to .drift/*.
func (i *Issuer) Issue(ctx context.Context, req IssueRequest) (*IssueResult, error) {
	if err := validateIssue(req); err != nil {
		return nil, err
	}
	now := i.now()
	exp := now.Add(req.TTL)

	// 1. Generate tid + redemption code.
	tid, err := newTID()
	if err != nil {
		return nil, fmt.Errorf("tid: %w", err)
	}
	redemptionCode, err := dcrypto.GenerateRedemptionCode()
	if err != nil {
		return nil, fmt.Errorf("redemption code: %w", err)
	}

	// 2. Mint the two scoped creds.
	ttl := exp.Sub(now)
	dataCred, err := i.Minter.Mint(ctx, buildDataMintRequest(req, ttl))
	if err != nil {
		return nil, fmt.Errorf("mint data cred: %w", err)
	}
	controlCred, err := i.Minter.Mint(ctx, buildControlMintRequest(req, tid, ttl))
	if err != nil {
		return nil, fmt.Errorf("mint control cred: %w", err)
	}

	// 3. Encrypt + upload TokenCredentials blob (carries DataCred only).
	tc := &domain.TokenCredentials{
		DataCred:     *dataCred,
		Compartments: buildGrants(req),
		CPRK:         req.CPRK,
		ExpiresAt:    exp,
		IssuedAt:     now,
		IssuedBy:     i.DeviceID,
	}
	tcBody, err := json.Marshal(tc)
	if err != nil {
		return nil, fmt.Errorf("marshal credentials: %w", err)
	}
	tcCipher, err := dcrypto.Encrypt(redemptionCode, tcBody, CredentialsAADFor(tid, req.WorkspaceID))
	if err != nil {
		return nil, fmt.Errorf("encrypt credentials: %w", err)
	}
	if err := i.Provider.Put(ctx, domain.CredentialsKeyFor(tid), tcCipher); err != nil {
		return nil, fmt.Errorf("upload credentials: %w", err)
	}

	// 4. Build + sign the small Token. IssuerPub is the self-contained
	//    pubkey the bearer verifies the signature against BEFORE doing
	//    anything else; MasterFingerprint pins the workspace trust root
	//    so a forged manifest with attacker-inserted enrollments fails.
	if len(i.MasterPub) == 0 {
		return nil, errors.New("token: Issuer.MasterPub required")
	}
	masterFP := sha256.Sum256(i.MasterPub)
	tok := &domain.Token{
		Version:           domain.TokenVersion,
		TID:               tid,
		WorkspaceID:       req.WorkspaceID,
		Bucket:            req.BucketInfo,
		RedemptionCode:    redemptionCode,
		ControlCred:       *controlCred,
		IssuerPub:         []byte(i.DeviceSign.Public().(ed25519.PublicKey)),
		MasterFingerprint: masterFP[:],
	}
	payload, err := json.Marshal(tok)
	if err != nil {
		return nil, fmt.Errorf("marshal token: %w", err)
	}
	sig := dcrypto.Sign(i.DeviceSign, payload)
	encoded := dcrypto.EncodeToken(payload, sig)

	// 5. Register the tid in the manifest. This is the only mutation that
	//    must be serialized w.r.t. other manifest writers.
	record := domain.TokenRecord{
		TID:       tid,
		IssuedBy:  i.DeviceID,
		Scope:     append([]string(nil), req.Scope...),
		Mode:      req.Mode,
		ExpiresAt: exp,
		IssuedAt:  now,
	}
	err = i.Writer.ReadModifyWrite(ctx, domain.ManifestKey, func(cur []byte) ([]byte, error) {
		m, err := manifest.Decrypt(cur, req.CPRK, req.WorkspaceID)
		if err != nil {
			return nil, fmt.Errorf("decrypt manifest: %w", err)
		}
		if m.ActiveTokens == nil {
			m.ActiveTokens = make(map[string]domain.TokenRecord)
		}
		m.ActiveTokens[tid] = record
		m.UpdatedAt = now
		m.Sequence++
		if err := manifest.Sign(m, i.DeviceID, i.DeviceSign); err != nil {
			return nil, err
		}
		return manifest.Encrypt(m, req.CPRK)
	})
	if err != nil {
		// We already uploaded the credentials blob; best-effort cleanup
		// so a half-issued tid doesn't linger.
		_ = i.Provider.Delete(ctx, domain.CredentialsKeyFor(tid))
		return nil, fmt.Errorf("register token in manifest: %w", err)
	}

	return &IssueResult{
		Encoded:     encoded,
		TID:         tid,
		ExpiresAt:   exp,
		DataCred:    *dataCred,
		ControlCred: *controlCred,
	}, nil
}

func (i *Issuer) now() time.Time {
	if i.Now != nil {
		return i.Now()
	}
	return time.Now()
}

func validateIssue(req IssueRequest) error {
	if req.WorkspaceID == "" {
		return errors.New("token: WorkspaceID required")
	}
	if len(req.CPRK) == 0 {
		return errors.New("token: CPRK required")
	}
	if len(req.Scope) == 0 {
		return errors.New("token: Scope must list at least one compartment")
	}
	if req.Mode != domain.TokenModeRW && req.Mode != domain.TokenModeRO {
		return fmt.Errorf("token: Mode must be %q or %q, got %q", domain.TokenModeRW, domain.TokenModeRO, req.Mode)
	}
	if req.TTL <= 0 {
		return errors.New("token: TTL must be > 0")
	}
	for _, name := range req.Scope {
		if err := domain.ValidCompartmentName(name); err != nil {
			return err
		}
		if _, ok := req.Compartments[name]; !ok {
			return fmt.Errorf("%w: %s", domain.ErrCompartmentUnknown, name)
		}
	}
	return nil
}

func buildGrants(req IssueRequest) map[string]domain.CompartmentGrant {
	out := make(map[string]domain.CompartmentGrant, len(req.Scope))
	for _, name := range req.Scope {
		out[name] = domain.CompartmentGrant{
			Key:  append([]byte(nil), req.Compartments[name]...),
			Mode: req.Mode,
		}
	}
	return out
}

// buildDataMintRequest produces the mint params for DataCred: read or
// read/write on the authorized compartment prefixes, with NO .drift/* access.
// The bearer's data-plane credential is therefore unable to touch the
// control plane no matter how it's used (rclone, boto3, raw HTTP).
//
// We grant TWO scopes for each compartment:
//   - prefix "compartments/<name>/" — all data ops on contents
//   - object "compartments/<name>"  — rclone's file/folder probe HEADs
//     this exact key during remote init; without this entry R2 returns
//     403 Forbidden and `drift open` fails with "bucket sentinel: exit
//     status 1". The object grant doesn't widen practical access since
//     "compartments/<name>" as a literal key has no value.
func buildDataMintRequest(req IssueRequest, ttl time.Duration) credentials.MintRequest {
	prefixes := make([]string, 0, len(req.Scope))
	objects := make([]string, 0, len(req.Scope))
	for _, name := range req.Scope {
		prefix := domain.CompartmentPrefix(name)
		prefixes = append(prefixes, prefix)
		objects = append(objects, strings.TrimSuffix(prefix, "/"))
	}
	actions := credentials.DefaultActions
	scope := credentials.R2ScopeObjectReadWrite
	if req.Mode == domain.TokenModeRO {
		actions = credentials.ReadOnlyActions
		scope = credentials.R2ScopeObjectReadOnly
	}
	return credentials.MintRequest{
		Bucket:      req.BucketInfo.Name,
		Scope:       scope,
		Prefixes:    prefixes,
		ObjectPaths: objects,
		Actions:     actions,
		TTL:         ttl,
	}
}

// buildControlMintRequest produces the mint params for ControlCred:
// GET/HEAD-only on exactly the three control-plane objects the bearer must
// be able to read — the manifest, the revocations list, and its own
// credentials blob. No prefixes, no write actions.
func buildControlMintRequest(req IssueRequest, tid string, ttl time.Duration) credentials.MintRequest {
	return credentials.MintRequest{
		Bucket: req.BucketInfo.Name,
		Scope:  credentials.R2ScopeObjectReadOnly,
		ObjectPaths: []string{
			domain.ManifestKey,
			domain.RevocationsKey,
			domain.CredentialsKeyFor(tid),
		},
		Actions: credentials.ReadOnlyActions,
		TTL:     ttl,
	}
}

// newTID returns a random "tok_<12 hex>" identifier. 48 bits of entropy is
// collision-safe within a workspace's token universe (tids never leave it).
func newTID() (string, error) {
	b, err := dcrypto.GenerateRedemptionCode()
	if err != nil {
		return "", err
	}
	return "tok_" + hex.EncodeToString(b[:6]), nil
}
