package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/sufforest/drift/internal/domain"
)

// --- keys ---

func TestGenerateMasterKey_distinctMaterial(t *testing.T) {
	m, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	if len(m.SignPriv) == 0 || bytes.Equal(m.BoxPriv[:], m.Root[:]) {
		t.Fatalf("master key roles share material: sign=%d, boxPriv==root=%v", len(m.SignPriv), bytes.Equal(m.BoxPriv[:], m.Root[:]))
	}
	// Verify public keys are derivable and non-zero.
	if _, err := m.BoxPub(); err != nil {
		t.Fatalf("BoxPub: %v", err)
	}
	if m.SignPub() == nil || len(m.SignPub()) == 0 {
		t.Fatal("SignPub returned empty key")
	}
}

func TestGenerateMasterKey_freshEachCall(t *testing.T) {
	a, _ := GenerateMasterKey()
	b, _ := GenerateMasterKey()
	if bytes.Equal(a.Root[:], b.Root[:]) {
		t.Fatal("two master keys collided on root secret — randomness broken")
	}
}

func TestDeriveCPRK_deterministic(t *testing.T) {
	m, err := GenerateMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	k1, err := DeriveCPRK(m.Root, "wks_abc", 0)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveCPRK(m.Root, "wks_abc", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatal("DeriveCPRK is not deterministic for same inputs")
	}
	if len(k1) != SymmetricKeySize {
		t.Fatalf("CPRK length = %d, want %d", len(k1), SymmetricKeySize)
	}
}

func TestDeriveCPRK_workspaceSeparation(t *testing.T) {
	m, _ := GenerateMasterKey()
	k1, _ := DeriveCPRK(m.Root, "wks_a", 0)
	k2, _ := DeriveCPRK(m.Root, "wks_b", 0)
	if bytes.Equal(k1, k2) {
		t.Fatal("CPRK collided across workspace IDs")
	}
}

// --- AEAD ---

func TestEncryptDecrypt_roundTrip(t *testing.T) {
	key := mustRandom(t, SymmetricKeySize)
	plaintext := []byte("the quick brown fox jumps over the lazy dog")
	aad := []byte("context:manifest:v1")

	ct, err := Encrypt(key, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := Decrypt(key, ct, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", pt, plaintext)
	}
}

func TestEncryptDecrypt_freshNonces(t *testing.T) {
	key := mustRandom(t, SymmetricKeySize)
	a, _ := Encrypt(key, []byte("hello"), nil)
	b, _ := Encrypt(key, []byte("hello"), nil)
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions of identical input produced identical ciphertext — nonce not random")
	}
}

func TestDecrypt_wrongKeyFails(t *testing.T) {
	k1 := mustRandom(t, SymmetricKeySize)
	k2 := mustRandom(t, SymmetricKeySize)
	ct, _ := Encrypt(k1, []byte("secret"), nil)
	if _, err := Decrypt(k2, ct, nil); err == nil {
		t.Fatal("decrypt with wrong key should fail")
	}
}

func TestDecrypt_aadBindingFails(t *testing.T) {
	key := mustRandom(t, SymmetricKeySize)
	ct, _ := Encrypt(key, []byte("secret"), []byte("aad-A"))
	if _, err := Decrypt(key, ct, []byte("aad-B")); err == nil {
		t.Fatal("decrypt with wrong AAD should fail")
	}
}

func TestDecrypt_tamperedCiphertextFails(t *testing.T) {
	key := mustRandom(t, SymmetricKeySize)
	ct, _ := Encrypt(key, []byte("secret-payload"), nil)
	ct[len(ct)-1] ^= 0x01 // flip a tag bit
	if _, err := Decrypt(key, ct, nil); err == nil {
		t.Fatal("decrypt of tampered ciphertext should fail")
	}
}

func TestDecrypt_shortCiphertext(t *testing.T) {
	key := mustRandom(t, SymmetricKeySize)
	_, err := Decrypt(key, []byte{0x01, 0x02}, nil)
	if !errors.Is(err, ErrCiphertextTooShort) {
		t.Fatalf("expected ErrCiphertextTooShort, got %v", err)
	}
}

// --- signing ---

func TestSignVerify_roundTrip(t *testing.T) {
	d, err := GenerateDeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("manifest v3 sha256=abc")
	sig := Sign(d.SignPriv, msg)
	if err := Verify(d.SignPub(), msg, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerify_tamperedMessageFails(t *testing.T) {
	d, _ := GenerateDeviceKey()
	sig := Sign(d.SignPriv, []byte("trust me"))
	err := Verify(d.SignPub(), []byte("trust me NOT"), sig)
	if !errors.Is(err, domain.ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid, got %v", err)
	}
}

func TestVerify_wrongKeyFails(t *testing.T) {
	d1, _ := GenerateDeviceKey()
	d2, _ := GenerateDeviceKey()
	msg := []byte("hello")
	sig := Sign(d1.SignPriv, msg)
	err := Verify(d2.SignPub(), msg, sig)
	if !errors.Is(err, domain.ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid, got %v", err)
	}
}

// --- sealed box ---

func TestSealOpen_roundTrip(t *testing.T) {
	d, err := GenerateDeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := d.BoxPub()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("the compartment key bytes")

	ct, err := SealFor(pub, msg)
	if err != nil {
		t.Fatalf("SealFor: %v", err)
	}
	if bytes.Equal(ct, msg) {
		t.Fatal("ciphertext equals plaintext")
	}

	pt, err := Open(pub, d.BoxPriv, ct)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatalf("plaintext mismatch: got %q want %q", pt, msg)
	}
}

func TestOpen_wrongRecipientFails(t *testing.T) {
	d1, _ := GenerateDeviceKey()
	d2, _ := GenerateDeviceKey()
	pub1, _ := d1.BoxPub()
	pub2, _ := d2.BoxPub()
	ct, _ := SealFor(pub1, []byte("for d1"))
	if _, err := Open(pub2, d2.BoxPriv, ct); err == nil {
		t.Fatal("Open with wrong recipient should fail")
	}
}

// --- token encoding ---

func TestEncodeDecodeToken_roundTrip(t *testing.T) {
	payload := []byte(`{"v":1,"tid":"tok_abc","wid":"wks_x"}`)
	sig := mustRandom(t, 64)

	encoded := EncodeToken(payload, sig)
	if !strings.HasPrefix(encoded, domain.TokenPrefix+".") {
		t.Fatalf("encoded token missing prefix: %q", encoded)
	}
	if strings.Count(encoded, ".") != 2 {
		t.Fatalf("expected 2 dots, got %d in %q", strings.Count(encoded, "."), encoded)
	}

	gotPayload, gotSig, err := DecodeToken(encoded)
	if err != nil {
		t.Fatalf("DecodeToken: %v", err)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("payload mismatch: %q vs %q", gotPayload, payload)
	}
	if !bytes.Equal(gotSig, sig) {
		t.Fatal("signature mismatch")
	}
}

func TestDecodeToken_malformed(t *testing.T) {
	cases := map[string]string{
		"empty":         "",
		"no prefix":     "abc.def.ghi",
		"two parts":     "drift1.abc",
		"four parts":    "drift1.abc.def.ghi",
		"bad base58 #1": "drift1.0OIl.abc",       // 0/O/I/l are excluded from base58
		"bad base58 #2": "drift1.abc.0OIl",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := DecodeToken(input)
			if !errors.Is(err, domain.ErrTokenMalformed) {
				t.Fatalf("expected ErrTokenMalformed for %q, got %v", input, err)
			}
		})
	}
}

// --- end-to-end: sign + encode + decode + verify ---

func TestTokenSignVerify_endToEnd(t *testing.T) {
	d, _ := GenerateDeviceKey()
	payload := []byte(`{"v":1,"tid":"tok_e2e"}`)
	sig := Sign(d.SignPriv, payload)
	encoded := EncodeToken(payload, sig)

	gotPayload, gotSig, err := DecodeToken(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(d.SignPub(), gotPayload, gotSig); err != nil {
		t.Fatalf("Verify failed after encode/decode round trip: %v", err)
	}
}

// --- helpers ---

func mustRandom(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}
