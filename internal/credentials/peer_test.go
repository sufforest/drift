package credentials

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

// goodPeerCred builds a fully-populated PeerCred for testing. Unsigned;
// caller signs before passing to Verify-side tests.
func goodPeerCred(t *testing.T) PeerCred {
	t.Helper()
	now := time.Unix(1_700_000_000, 0).UTC()
	return PeerCred{
		Version:  PeerCredVersion,
		DeviceID: "dev_abcdef12",
		JTI:      "jti_12345",
		Scope:    []string{"main", "docs"},
		Mode:     "rw",
		Data: ScopedCredSet{
			AccessKeyID:     "AK_parent",
			SecretAccessKey: "deadbeefcafe", // hex(SHA-256(jwt)) in production
			SessionToken:    "anNvbi9hbnktanc=",
			Endpoint:        "https://acct.r2.cloudflarestorage.com",
			Bucket:          "drift-test",
		},
		Control: &ScopedCredSet{
			AccessKeyID:     "AK_parent",
			SecretAccessKey: "ctrl-secret-hex",
			SessionToken:    "anNvbi9jdHJsLWp3dA==",
			Endpoint:        "https://acct.r2.cloudflarestorage.com",
			Bucket:          "drift-test",
		},
		IssuedAt:  now,
		ExpiresAt: now.Add(24 * time.Hour),
		RefreshAt: now.Add(12 * time.Hour),
	}
}

func TestPeerCred_signVerifyRoundtrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed := SignPeerCred(goodPeerCred(t), priv)
	if err := VerifyPeerCred(signed, pub); err != nil {
		t.Fatalf("Verify failed on freshly-signed cred: %v", err)
	}
}

// TestPeerCred_verifyFailsUnderWrongMaster: signing with one master and
// verifying under a different pubkey must fail. Catches the case where
// a bucket-side attacker substitutes a forged PeerCred — the peer's
// pinned masterPub won't verify it.
func TestPeerCred_verifyFailsUnderWrongMaster(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	signed := SignPeerCred(goodPeerCred(t), priv1)
	if err := VerifyPeerCred(signed, pub2); err == nil {
		t.Fatal("Verify must fail under a different master pubkey")
	}
}

// TestPeerCred_verifyFailsOnTampering: flipping any field of a signed
// cred must invalidate the signature. We test each transcript-included
// field to make sure all of them are bound by the signature.
func TestPeerCred_verifyFailsOnTampering(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	cases := map[string]func(p *PeerCred){
		"DeviceID":              func(p *PeerCred) { p.DeviceID = "dev_attacker" },
		"JTI":                   func(p *PeerCred) { p.JTI = "jti_attacker" },
		"Mode":                  func(p *PeerCred) { p.Mode = "ro" },
		"Data.AccessKeyID":      func(p *PeerCred) { p.Data.AccessKeyID = "AK_attacker" },
		"Data.SecretAccessKey":  func(p *PeerCred) { p.Data.SecretAccessKey = "00" },
		"Data.SessionToken":     func(p *PeerCred) { p.Data.SessionToken = "ZmFrZQ==" },
		"Data.Endpoint":         func(p *PeerCred) { p.Data.Endpoint = "https://evil.example/" },
		"Data.Bucket":           func(p *PeerCred) { p.Data.Bucket = "attacker-bucket" },
		"Control.SessionToken":  func(p *PeerCred) { p.Control.SessionToken = "ZmFrZQ==" },
		"Control.SecretAccess":  func(p *PeerCred) { p.Control.SecretAccessKey = "00" },
		"IssuedAt":              func(p *PeerCred) { p.IssuedAt = p.IssuedAt.Add(time.Hour) },
		"ExpiresAt":             func(p *PeerCred) { p.ExpiresAt = p.ExpiresAt.Add(100 * 24 * time.Hour) },
		"RefreshAt":             func(p *PeerCred) { p.RefreshAt = p.RefreshAt.Add(100 * 24 * time.Hour) },
		"Scope":                 func(p *PeerCred) { p.Scope = []string{"secret"} },
		// CRITICAL: dropping Control entirely (to coerce drift into
		// routing control-plane reads through Data) must also fail
		// signature verification. The hasControl bit binds presence.
		"DropControl":           func(p *PeerCred) { p.Control = nil },
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			signed := SignPeerCred(goodPeerCred(t), priv)
			tamper(&signed)
			if err := VerifyPeerCred(signed, pub); err == nil {
				t.Errorf("tampering with %s did NOT invalidate the signature", name)
			}
		})
	}
}

// TestPeerCred_signVerify_nilControl: a PeerCred minted with
// Control=nil (the AWS-STS / R2-server-mint shape) must sign and
// verify cleanly. The hasControl=0 byte is canonicalized into the
// signing body, so adding Control later (or sign-without-verify-with)
// would still fail — but the matched-pair nil case is the happy path.
func TestPeerCred_signVerify_nilControl(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	p := goodPeerCred(t)
	p.Control = nil
	signed := SignPeerCred(p, priv)
	if err := VerifyPeerCred(signed, pub); err != nil {
		t.Fatalf("nil-Control PeerCred should sign+verify cleanly: %v", err)
	}
}

// TestPeerCred_addControlAfterSigning_fails: signing with Control=nil
// then later setting Control to a value (e.g., attacker tries to add
// a control cred they minted) must invalidate the signature. The
// hasControl bit was 0 at sign time; flipping to 1 changes the
// signing body.
func TestPeerCred_addControlAfterSigning_fails(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	p := goodPeerCred(t)
	p.Control = nil
	signed := SignPeerCred(p, priv)
	// Attacker substitutes a Control cred post-signing.
	signed.Control = &ScopedCredSet{
		AccessKeyID:     "AK_attacker",
		SecretAccessKey: "attacker",
		SessionToken:    "attacker-jwt",
		Endpoint:        "https://evil.example/",
		Bucket:          "drift-test",
	}
	if err := VerifyPeerCred(signed, pub); err == nil {
		t.Fatal("adding Control to a nil-Control-signed PeerCred must invalidate signature")
	}
}

// TestPeerCred_verifyFailsOnMissingFields: a PeerCred whose required
// fields are empty must be refused even with a valid-looking signature.
// Defense in depth — an attacker-built "blank" cred shouldn't pass.
func TestPeerCred_verifyFailsOnMissingFields(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	blank := PeerCred{Version: PeerCredVersion}
	signed := SignPeerCred(blank, priv)
	if err := VerifyPeerCred(signed, pub); err == nil {
		t.Error("Verify must refuse blank/incomplete creds")
	}
}

// TestPeerCred_verifyFailsOnUnknownVersion: a future schema bump must
// not be silently accepted by older code.
func TestPeerCred_verifyFailsOnUnknownVersion(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	p := goodPeerCred(t)
	p.Version = PeerCredVersion + 100
	signed := SignPeerCred(p, priv)
	err := VerifyPeerCred(signed, pub)
	if err == nil {
		t.Fatal("Verify must refuse unknown PeerCred version")
	}
	if !strings.Contains(err.Error(), "unsupported PeerCred version") {
		t.Errorf("error must mention version: %v", err)
	}
}

// TestPeerCred_signingBytesAreLengthPrefixed: two different field
// splits that would concatenate to the same byte stream must NOT
// produce the same signing body. Catches concat-collision attacks.
func TestPeerCred_signingBytesAreLengthPrefixed(t *testing.T) {
	a := goodPeerCred(t)
	a.DeviceID = "AB"
	a.JTI = "CD"
	b := goodPeerCred(t)
	b.DeviceID = "ABC"
	b.JTI = "D"
	bytesA := PeerCredSigningBytes(a)
	bytesB := PeerCredSigningBytes(b)
	if string(bytesA) == string(bytesB) {
		t.Fatal("signing-bytes should differ when length-prefix should disambiguate")
	}
}

// TestPeerCred_IsExpired
func TestPeerCred_IsExpired(t *testing.T) {
	p := goodPeerCred(t)
	if p.IsExpired(p.IssuedAt) {
		t.Error("at IssuedAt, cred should not be expired")
	}
	if p.IsExpired(p.ExpiresAt.Add(-time.Second)) {
		t.Error("just before ExpiresAt, cred should not be expired")
	}
	if !p.IsExpired(p.ExpiresAt) {
		t.Error("at ExpiresAt exactly, cred should be expired (inclusive)")
	}
	if !p.IsExpired(p.ExpiresAt.Add(time.Hour)) {
		t.Error("after ExpiresAt, cred should be expired")
	}
}

// TestPeerCred_NeedsRefresh
func TestPeerCred_NeedsRefresh(t *testing.T) {
	p := goodPeerCred(t)
	if p.NeedsRefresh(p.IssuedAt) {
		t.Error("at IssuedAt, refresh not yet needed")
	}
	if p.NeedsRefresh(p.RefreshAt.Add(-time.Second)) {
		t.Error("just before RefreshAt, no refresh")
	}
	if !p.NeedsRefresh(p.RefreshAt) {
		t.Error("at RefreshAt exactly, needs refresh")
	}
	if !p.NeedsRefresh(p.RefreshAt.Add(time.Hour)) {
		t.Error("after RefreshAt, needs refresh")
	}
}

// TestPeerCred_scopeBoundaryMarker: the scope-end marker (__scope_end__)
// prevents an attacker from confusing the signing body by appending
// "scope" entries that bleed into the next field. Test that prepending
// a value to scope changes the signed bytes meaningfully.
func TestPeerCred_scopeBoundaryMarker(t *testing.T) {
	a := goodPeerCred(t)
	b := goodPeerCred(t)
	b.Scope = append([]string{"injected"}, a.Scope...)
	if string(PeerCredSigningBytes(a)) == string(PeerCredSigningBytes(b)) {
		t.Error("appending to scope must change signing bytes")
	}
}
