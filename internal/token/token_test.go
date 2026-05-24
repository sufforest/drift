package token

import (
	"context"
	"errors"
	"testing"
	"time"

	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/credentials"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/manifest"
	"github.com/sufforest/drift/internal/storage"
)

// --- bootstrap ---

type fixture struct {
	ctx          context.Context
	provider     *storage.MemoryProvider
	writer       storage.ReadModifyWriter
	minter       credentials.Minter
	master       *dcrypto.MasterKey
	device       *dcrypto.DeviceKey
	deviceID     string
	cprk         []byte
	workspaceID  string
	bucket       domain.BucketInfo
	compartments map[string][]byte
	now          time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	prov := storage.NewMemoryProvider()
	master, err := dcrypto.GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	dev, err := dcrypto.GenerateDeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	wid := "wks_test"
	cprk, err := dcrypto.DeriveCPRK(master.Root, wid, 0)
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "dev-test"
	now := time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC)

	// Construct an initial signed + encrypted manifest with one device and
	// one compartment.
	compartments := map[string][]byte{}
	compKey, _ := dcrypto.GenerateCompartmentKey()
	compartments["project-x"] = compKey

	masterBox, _ := master.BoxPub()
	devBox, _ := dev.BoxPub()
	primaryEnroll := manifest.SignEnrollment(deviceID, now.UnixNano(),
		dev.SignPub(), devBox[:], master.SignPriv)

	m := &domain.Manifest{
		Version:     1,
		WorkspaceID: wid,
		Concurrency: domain.ConcurrencyConditionalPut,
		Devices: map[string]domain.Device{
			deviceID: {
				ID:         deviceID,
				Name:       "laptop",
				PublicKey:  dev.SignPub(),
				EncryptKey: devBox[:],
				EnrolledAt: now,
				LastSeen:   now,
			},
			domain.MasterDeviceID: {
				ID:         domain.MasterDeviceID,
				Name:       "master",
				PublicKey:  master.SignPub(),
				EncryptKey: masterBox[:],
				EnrolledAt: now,
				LastSeen:   now,
			},
		},
		Compartments: map[string]domain.Compartment{
			"project-x": {Name: "project-x", Mode: domain.ModeMount, KeyVersion: 1, CreatedAt: now},
		},
		ActiveTokens: map[string]domain.TokenRecord{},
		Enrollments: map[string]domain.Enrollment{
			deviceID: primaryEnroll,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := manifest.Sign(m, deviceID, dev.SignPriv); err != nil {
		t.Fatal(err)
	}
	body, err := manifest.Encrypt(m, cprk)
	if err != nil {
		t.Fatal(err)
	}
	if err := prov.Put(ctx, domain.ManifestKey, body); err != nil {
		t.Fatal(err)
	}

	return &fixture{
		ctx:         ctx,
		provider:    prov,
		writer:      storage.NewConditionalPutWriter(prov),
		minter:      &credentials.R2LocalSignMinter{AccessKeyID: "AK", SecretAccessKey: "SK", Endpoint: "https://abc123.r2.cloudflarestorage.com", Now: func() time.Time { return now }},
		master:      master,
		device:      dev,
		deviceID:    deviceID,
		cprk:        cprk,
		workspaceID: wid,
		bucket: domain.BucketInfo{
			Provider: domain.ProviderR2,
			Endpoint: "https://example.r2.cloudflarestorage.com",
			Name:     "my-bucket",
			Region:   "auto",
		},
		compartments: compartments,
		now:          now,
	}
}

func (f *fixture) issuer() *Issuer {
	return &Issuer{
		Provider:   f.provider,
		Writer:     f.writer,
		Minter:     f.minter,
		DeviceID:   f.deviceID,
		DeviceSign: f.device.SignPriv,
		MasterPub:  f.master.SignPub(),
		Now:        func() time.Time { return f.now },
	}
}

func (f *fixture) redeemer() *Redeemer {
	return &Redeemer{
		Provider: f.provider,
		Now:      func() time.Time { return f.now },
	}
}

func (f *fixture) issueDefault(t *testing.T) *IssueResult {
	t.Helper()
	res, err := f.issuer().Issue(f.ctx, IssueRequest{
		WorkspaceID:  f.workspaceID,
		BucketInfo:   f.bucket,
		CPRK:         f.cprk,
		Compartments: f.compartments,
		Scope:        []string{"project-x"},
		Mode:         domain.TokenModeRW,
		TTL:          1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return res
}

// --- Issue + Redeem happy path ---

func TestIssueRedeem_roundTrip(t *testing.T) {
	f := newFixture(t)
	issued := f.issueDefault(t)

	if issued.Encoded == "" || issued.TID == "" {
		t.Fatal("Issue did not populate Encoded / TID")
	}

	got, err := f.redeemer().Redeem(f.ctx, issued.Encoded)
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if got.TID != issued.TID {
		t.Fatalf("TID mismatch: %s vs %s", got.TID, issued.TID)
	}
	if got.WorkspaceID != f.workspaceID {
		t.Fatalf("workspace mismatch")
	}
	if got.DataCred.SessionToken == "" || got.DataCred.AccessKeyID == "" {
		t.Fatal("DataCred missing")
	}
	if got.ControlCred.SessionToken == "" || got.ControlCred.AccessKeyID == "" {
		t.Fatal("ControlCred missing")
	}
	grant, ok := got.Compartments["project-x"]
	if !ok {
		t.Fatal("compartment key not in redemption")
	}
	if grant.Mode != domain.TokenModeRW {
		t.Fatalf("mode = %s, want rw", grant.Mode)
	}

	// Manifest should now record the new tid in ActiveTokens.
	cipher, _ := f.provider.Get(f.ctx, domain.ManifestKey)
	m, err := manifest.Decrypt(cipher, f.cprk, f.workspaceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.ActiveTokens[issued.TID]; !ok {
		t.Fatal("manifest does not record issued tid")
	}
}

// --- Issue rejects bad inputs ---

func TestIssue_validationFailures(t *testing.T) {
	f := newFixture(t)
	base := IssueRequest{
		WorkspaceID:  f.workspaceID,
		BucketInfo:   f.bucket,
		CPRK:         f.cprk,
		Compartments: f.compartments,
		Scope:        []string{"project-x"},
		Mode:         domain.TokenModeRW,
		TTL:          time.Hour,
	}
	cases := map[string]func(r *IssueRequest){
		"empty scope":     func(r *IssueRequest) { r.Scope = nil },
		"unknown comp":    func(r *IssueRequest) { r.Scope = []string{"nope"} },
		"empty cprk":      func(r *IssueRequest) { r.CPRK = nil },
		"empty wid":       func(r *IssueRequest) { r.WorkspaceID = "" },
		"zero ttl":        func(r *IssueRequest) { r.TTL = 0 },
		"bad mode":        func(r *IssueRequest) { r.Mode = "execute" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			req := base
			mutate(&req)
			if _, err := f.issuer().Issue(f.ctx, req); err == nil {
				t.Fatalf("expected error for %s, got nil", name)
			}
		})
	}
}

// --- Redeem rejects tampered tokens ---

func TestRedeem_malformedToken(t *testing.T) {
	f := newFixture(t)
	_, err := f.redeemer().Redeem(f.ctx, "drift1.notbase58!.also-bad")
	if !errors.Is(err, domain.ErrTokenMalformed) {
		t.Fatalf("expected ErrTokenMalformed, got %v", err)
	}
}

func TestRedeem_tamperedSignatureFails(t *testing.T) {
	f := newFixture(t)
	issued := f.issueDefault(t)

	// Mutate the encoded token's signature segment.
	bad := issued.Encoded[:len(issued.Encoded)-2] + "11"
	if bad == issued.Encoded {
		t.Fatal("did not mutate token")
	}
	_, err := f.redeemer().Redeem(f.ctx, bad)
	if err == nil {
		t.Fatal("expected error for tampered signature")
	}
}

func TestRedeem_wrongRedemptionCodeFails(t *testing.T) {
	f := newFixture(t)
	issued := f.issueDefault(t)

	// Overwrite the credentials blob with garbage so the redemption-code
	// decrypt fails.
	if err := f.provider.Put(f.ctx, domain.CredentialsKeyFor(issued.TID), []byte("garbage-not-a-ciphertext")); err != nil {
		t.Fatal(err)
	}
	_, err := f.redeemer().Redeem(f.ctx, issued.Encoded)
	if err == nil {
		t.Fatal("expected decrypt failure")
	}
}

func TestRedeem_expiredCredsRejected(t *testing.T) {
	f := newFixture(t)
	issued, err := f.issuer().Issue(f.ctx, IssueRequest{
		WorkspaceID:  f.workspaceID,
		BucketInfo:   f.bucket,
		CPRK:         f.cprk,
		Compartments: f.compartments,
		Scope:        []string{"project-x"},
		Mode:         domain.TokenModeRO,
		TTL:          1 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	r := f.redeemer()
	r.Now = func() time.Time { return f.now.Add(2 * time.Hour) }
	_, err = r.Redeem(f.ctx, issued.Encoded)
	if !errors.Is(err, domain.ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

// --- Revoke flow ---

func TestRevoke_thenRedeemFails(t *testing.T) {
	f := newFixture(t)
	issued := f.issueDefault(t)

	rev := &Revoker{
		Provider:   f.provider,
		Writer:     f.writer,
		DeviceID:   f.deviceID,
		DeviceSign: f.device.SignPriv,
		Now:        func() time.Time { return f.now },
	}
	if _, err := rev.Revoke(f.ctx, issued.TID); err != nil {
		t.Fatal(err)
	}
	// Second revoke is idempotent.
	if _, err := rev.Revoke(f.ctx, issued.TID); err != nil {
		t.Fatalf("second revoke should be idempotent, got %v", err)
	}

	_, err := f.redeemer().Redeem(f.ctx, issued.Encoded)
	if !errors.Is(err, domain.ErrTokenRevoked) {
		t.Fatalf("expected ErrTokenRevoked, got %v", err)
	}
}

func TestRevoke_unauthorizedSignerIgnored(t *testing.T) {
	f := newFixture(t)
	issued := f.issueDefault(t)

	// Sign a revocation with a device that is NOT in the manifest.
	rogue, _ := dcrypto.GenerateDeviceKey()
	roguer := &Revoker{
		Provider:   f.provider,
		Writer:     f.writer,
		DeviceID:   "rogue-device",
		DeviceSign: rogue.SignPriv,
		Now:        func() time.Time { return f.now },
	}
	if _, err := roguer.Revoke(f.ctx, issued.TID); err != nil {
		t.Fatal(err)
	}

	// Redeem should still succeed because the rogue revocation isn't
	// verifiable.
	if _, err := f.redeemer().Redeem(f.ctx, issued.Encoded); err != nil {
		t.Fatalf("rogue revocation should be ignored, got %v", err)
	}
}

// --- Audit C1+C2: verify-before-use ---

func TestRedeem_signatureVerifiedBeforeNetworkCall(t *testing.T) {
	// A token whose signature does NOT validate against its embedded
	// IssuerPub must be rejected up front — before fetching the
	// credentials blob, before touching the manifest. Verified by setting
	// up a provider whose Get() panics if called, then redeeming a
	// signature-broken token.
	f := newFixture(t)
	issued := f.issueDefault(t)

	bad := issued.Encoded[:len(issued.Encoded)-2] + "11"
	r := &Redeemer{Provider: &panicProvider{}, Now: func() time.Time { return f.now }}
	_, err := r.Redeem(f.ctx, bad)
	if !errors.Is(err, domain.ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid before any I/O, got %v", err)
	}
}

func TestRedeem_missingIssuerPubRejected(t *testing.T) {
	f := newFixture(t)
	// Build a token by hand without IssuerPub.
	payload := []byte(`{"v":1,"tid":"tok_x","wid":"wks_x","bucket":{},"rc":"AAAA","cc":{}}`)
	sig := make([]byte, 64)
	encoded := dcrypto.EncodeToken(payload, sig)

	_, err := f.redeemer().Redeem(f.ctx, encoded)
	if !errors.Is(err, domain.ErrTokenMalformed) {
		t.Fatalf("expected ErrTokenMalformed for missing IssuerPub, got %v", err)
	}
}

func TestRedeem_issuerPubMustMatchManifest(t *testing.T) {
	f := newFixture(t)
	// Issue a real token, then surreptitiously swap the manifest's
	// device pubkey for a different one. After this, IssuerPub on the
	// token no longer matches the manifest's record.
	issued := f.issueDefault(t)

	err := f.writer.ReadModifyWrite(f.ctx, domain.ManifestKey, func(cur []byte) ([]byte, error) {
		m, err := manifest.Decrypt(cur, f.cprk, f.workspaceID)
		if err != nil {
			return nil, err
		}
		// Replace the device's pubkey with one we just made up.
		rogue, _ := dcrypto.GenerateDeviceKey()
		dev := m.Devices[f.deviceID]
		dev.PublicKey = rogue.SignPub()
		m.Devices[f.deviceID] = dev
		if err := manifest.Sign(m, f.deviceID, f.device.SignPriv); err != nil {
			// This will produce a manifest whose signature doesn't verify
			// against the new pubkey — that's intentional for the test;
			// we'll trip on the IssuerPub cross-check first either way.
			return nil, err
		}
		return manifest.Encrypt(m, f.cprk)
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = f.redeemer().Redeem(f.ctx, issued.Encoded)
	if err == nil {
		t.Fatal("expected error when IssuerPub no longer matches manifest record")
	}
}

// panicProvider lets a test prove no I/O happened during a code path: if
// any method is called, the test fails with a panic message naming the call.
type panicProvider struct{}

func (panicProvider) Put(ctx context.Context, k string, d []byte) error { panic("Put called: " + k) }
func (panicProvider) Get(ctx context.Context, k string) ([]byte, error) { panic("Get called: " + k) }
func (panicProvider) Delete(ctx context.Context, k string) error        { panic("Delete called: " + k) }
func (panicProvider) List(ctx context.Context, p string) ([]string, error) {
	panic("List called: " + p)
}
func (panicProvider) Exists(ctx context.Context, k string) (bool, error) {
	panic("Exists called: " + k)
}
func (panicProvider) GetWithETag(ctx context.Context, k string) ([]byte, string, error) {
	panic("GetWithETag called: " + k)
}
func (panicProvider) PutConditional(ctx context.Context, k string, d []byte, e string) (string, error) {
	panic("PutConditional called: " + k)
}
func (panicProvider) PutIfNotExists(ctx context.Context, k string, d []byte) (string, error) {
	panic("PutIfNotExists called: " + k)
}

// --- Audit C3: AAD bound to tid + workspace ---

func TestRedeem_credentialsBlobSwapRejected(t *testing.T) {
	// Issue two tokens; swap their credentials blob bytes; both must fail
	// to decrypt because the AAD includes tid.
	f := newFixture(t)
	a := f.issueDefault(t)
	b := f.issueDefault(t)
	if a.TID == b.TID {
		t.Fatal("tid collision in test setup")
	}

	bytesA, _ := f.provider.Get(f.ctx, domain.CredentialsKeyFor(a.TID))
	bytesB, _ := f.provider.Get(f.ctx, domain.CredentialsKeyFor(b.TID))

	// Swap.
	_ = f.provider.Put(f.ctx, domain.CredentialsKeyFor(a.TID), bytesB)
	_ = f.provider.Put(f.ctx, domain.CredentialsKeyFor(b.TID), bytesA)

	if _, err := f.redeemer().Redeem(f.ctx, a.Encoded); err == nil {
		t.Fatal("expected swapped credentials blob to fail decryption")
	}
	if _, err := f.redeemer().Redeem(f.ctx, b.Encoded); err == nil {
		t.Fatal("expected swapped credentials blob to fail decryption")
	}
}

// --- Privacy property: bearer's creds cannot write to .drift/* ---

func TestIssue_credentialScoping(t *testing.T) {
	f := newFixture(t)
	issued := f.issueDefault(t)

	got, err := f.redeemer().Redeem(f.ctx, issued.Encoded)
	if err != nil {
		t.Fatal(err)
	}

	// DataCred: prefixPaths only on compartments/<scope>/, NO .drift/* objects.
	dataClaims, _, _, err := credentials.DecodeR2JWT(stripJWTPrefix(t, got.DataCred.SessionToken))
	if err != nil {
		t.Fatalf("decode data jwt: %v", err)
	}
	if dataClaims.Paths != nil {
		for _, obj := range dataClaims.Paths.ObjectPaths {
			if startsWith(obj, ".drift/") {
				t.Fatalf("DataCred must NOT include .drift/* objects, got %q", obj)
			}
		}
		for _, p := range dataClaims.Paths.PrefixPaths {
			if startsWith(p, ".drift/") {
				t.Fatalf("DataCred must NOT include .drift/ prefix, got %q", p)
			}
			if !startsWith(p, "compartments/") {
				t.Fatalf("DataCred prefix outside compartments/: %q", p)
			}
		}
		// Sanity: scope is what we asked for.
		if len(dataClaims.Paths.PrefixPaths) != 1 || dataClaims.Paths.PrefixPaths[0] != "compartments/project-x/" {
			t.Fatalf("DataCred prefixPaths = %v", dataClaims.Paths.PrefixPaths)
		}
	} else {
		t.Fatal("DataCred missing paths claim")
	}

	// ControlCred: GET/HEAD only, on exactly the 3 control-plane objects.
	ctrlClaims, _, _, err := credentials.DecodeR2JWT(stripJWTPrefix(t, got.ControlCred.SessionToken))
	if err != nil {
		t.Fatalf("decode control jwt: %v", err)
	}
	if ctrlClaims.Paths == nil || len(ctrlClaims.Paths.PrefixPaths) != 0 {
		t.Fatalf("ControlCred must have no prefixPaths, got %v", ctrlClaims.Paths)
	}
	wantObjects := map[string]bool{
		".drift/manifest.enc":                          true,
		".drift/revocations.enc":                       true,
		".drift/credentials/" + issued.TID + ".enc":   true,
	}
	if len(ctrlClaims.Paths.ObjectPaths) != len(wantObjects) {
		t.Fatalf("ControlCred objectPaths = %v, want %v", ctrlClaims.Paths.ObjectPaths, wantObjects)
	}
	for _, obj := range ctrlClaims.Paths.ObjectPaths {
		if !wantObjects[obj] {
			t.Fatalf("ControlCred has unexpected object %q", obj)
		}
	}
	// NOTE: actions claim is NOT serialized — R2's local-sign validator
	// rejects JWTs that contain it. Read-vs-write is enforced via Scope.
}

// stripJWTPrefix decodes the base64-encoded session token and strips the
// "jwt/" prefix to return the inner signed JWT.
func stripJWTPrefix(t *testing.T, sessionToken string) string {
	t.Helper()
	jwt, err := credentials.DecodeR2SessionToken(sessionToken)
	if err != nil {
		t.Fatalf("decode session token: %v", err)
	}
	return jwt
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// --- R2 minter unit tests ---

func TestR2Minter_jwtStructure(t *testing.T) {
	m := &credentials.R2LocalSignMinter{
		AccessKeyID:     "acct-ak",
		SecretAccessKey: "acct-sk",
		Endpoint:        "https://abc123.r2.cloudflarestorage.com",
		Now:             func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	}
	cred, err := m.Mint(context.Background(), credentials.MintRequest{
		Bucket:      "my-bucket",
		Scope:       credentials.R2ScopeObjectReadOnly,
		Prefixes:    []string{"compartments/x/"},
		ObjectPaths: []string{".drift/revocations.enc"},
		Actions:     credentials.ReadOnlyActions,
		TTL:         time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	if cred.AccessKeyID != "acct-ak" {
		t.Fatalf("R2 minter must reuse parent access key id, got %s", cred.AccessKeyID)
	}
	jwt, err := credentials.DecodeR2SessionToken(cred.SessionToken)
	if err != nil {
		t.Fatalf("decode session token: %v", err)
	}
	claims, _, _, err := credentials.DecodeR2JWT(jwt)
	if err != nil {
		t.Fatalf("decode JWT: %v", err)
	}
	if claims.Audience != "abc123.r2.cloudflarestorage.com" {
		t.Errorf("aud = %q, want endpoint host", claims.Audience)
	}
	if claims.Subject != "abc123" {
		t.Errorf("sub = %q, want account ID 'abc123'", claims.Subject)
	}
	if claims.Issuer != "acct-ak" {
		t.Errorf("iss = %q, want parent access key id", claims.Issuer)
	}
	if claims.Bucket != "my-bucket" {
		t.Errorf("bucket = %q, want my-bucket", claims.Bucket)
	}
	if claims.Scope != credentials.R2ScopeObjectReadOnly {
		t.Errorf("scope = %q, want object-read-only", claims.Scope)
	}
	if claims.Paths == nil || len(claims.Paths.PrefixPaths) != 1 || claims.Paths.PrefixPaths[0] != "compartments/x/" {
		t.Errorf("paths.prefixPaths mismatch: %v", claims.Paths)
	}
	// `actions` claim is intentionally omitted from the JWT (R2 rejects
	// JWTs with this claim). MintRequest.Actions is still accepted by
	// the minter API for forward-compat but doesn't appear in the cred.
	if claims.ExpiresAt-claims.IssuedAt != int64(time.Hour.Seconds()) {
		t.Errorf("exp-iat = %d, want %d", claims.ExpiresAt-claims.IssuedAt, int64(time.Hour.Seconds()))
	}
}

func TestR2Minter_requiresParentSecret(t *testing.T) {
	m := &credentials.R2LocalSignMinter{AccessKeyID: "ak"}
	_, err := m.Mint(context.Background(), credentials.MintRequest{Bucket: "b", TTL: time.Hour})
	if err == nil {
		t.Fatal("expected error when SecretAccessKey is empty")
	}
}
