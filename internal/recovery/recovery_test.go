package recovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	dcrypto "github.com/sufforest/drift/internal/crypto"
)

func TestWrapUnwrap_roundtrip(t *testing.T) {
	mk, err := dcrypto.GenerateMasterKey()
	if err != nil {
		t.Fatalf("genMaster: %v", err)
	}
	const pass = "correct horse battery staple winch"
	const wid = "wks_abc12345"
	// Lower the Argon cost so the test runs in milliseconds.
	opts := WrapOptions{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}
	blob, err := Wrap(mk, wid, pass, opts)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if blob.Version != BlobVersion {
		t.Fatalf("blob version = %d, want %d", blob.Version, BlobVersion)
	}
	if len(blob.Salt) != SaltSize {
		t.Fatalf("blob salt = %d bytes, want %d", len(blob.Salt), SaltSize)
	}

	got, gotWID, err := Unwrap(blob, pass)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if gotWID != wid {
		t.Errorf("wid = %q, want %q", gotWID, wid)
	}
	if !bytes.Equal(got.SignPriv, mk.SignPriv) {
		t.Errorf("SignPriv differs after roundtrip")
	}
	if got.BoxPriv != mk.BoxPriv {
		t.Errorf("BoxPriv differs after roundtrip")
	}
	if got.Root != mk.Root {
		t.Errorf("Root differs after roundtrip")
	}
}

func TestUnwrap_wrongPassphrase(t *testing.T) {
	mk, _ := dcrypto.GenerateMasterKey()
	opts := WrapOptions{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}
	blob, err := Wrap(mk, "wks_x", "the right passphrase value here ok", opts)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	_, _, err = Unwrap(blob, "wrong passphrase guess")
	if !errors.Is(err, ErrPassphrase) {
		t.Fatalf("expected ErrPassphrase, got %v", err)
	}
}

func TestUnwrap_tamperedBlob(t *testing.T) {
	mk, _ := dcrypto.GenerateMasterKey()
	opts := WrapOptions{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}
	blob, err := Wrap(mk, "wks_x", "robust passphrase choice 42!!", opts)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	// Flip a byte in the ciphertext.
	blob.Cipher[len(blob.Cipher)/2] ^= 0x01
	_, _, err = Unwrap(blob, "robust passphrase choice 42!!")
	if !errors.Is(err, ErrPassphrase) {
		t.Fatalf("expected ErrPassphrase on tamper, got %v", err)
	}
}

func TestWeakPassphrase_rejected(t *testing.T) {
	mk, _ := dcrypto.GenerateMasterKey()
	opts := WrapOptions{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}
	_, err := Wrap(mk, "wks_x", "password", opts)
	var weak *ErrWeakPassphrase
	if !errors.As(err, &weak) {
		t.Fatalf("expected ErrWeakPassphrase for 'password', got %v", err)
	}
}

func TestWeakPassphrase_allowOverride(t *testing.T) {
	mk, _ := dcrypto.GenerateMasterKey()
	opts := WrapOptions{Time: 1, MemoryKiB: 8 * 1024, Threads: 1, AllowWeakPassphrase: true}
	if _, err := Wrap(mk, "wks_x", "weak", opts); err != nil {
		t.Fatalf("AllowWeakPassphrase did not bypass gate: %v", err)
	}
}

func TestStrength(t *testing.T) {
	cases := []struct {
		name string
		pw   string
		// require strict thresholds rather than exact values — the
		// estimator is intentionally rough.
		atLeast float64
		atMost  float64
	}{
		{"empty", "", 0, 0},
		{"weak short", "abc", 0, 30},
		{"common word", "password", 0, MinPassphraseBits},
		{"diceware four words", "correct horse battery staple", MinPassphraseBits, 200},
		{"random mixed long", "Xg7!q9zR$wL2pAv0Bh", MinPassphraseBits, 200},
	}
	for _, tc := range cases {
		got := Strength(tc.pw)
		if got < tc.atLeast || got > tc.atMost {
			t.Errorf("%s: Strength(%q) = %.1f, want in [%.1f, %.1f]", tc.name, tc.pw, got, tc.atLeast, tc.atMost)
		}
	}
}

func TestBlob_JSONRoundtrip(t *testing.T) {
	mk, _ := dcrypto.GenerateMasterKey()
	opts := WrapOptions{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}
	blob, err := Wrap(mk, "wks_x", "robust passphrase choice 42!!", opts)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	body, err := json.Marshal(blob)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Blob
	if err := json.Unmarshal(body, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got, _, err := Unwrap(&back, "robust passphrase choice 42!!")
	if err != nil {
		t.Fatalf("Unwrap after JSON roundtrip: %v", err)
	}
	if !bytes.Equal(got.SignPriv, mk.SignPriv) {
		t.Errorf("SignPriv differs after JSON roundtrip")
	}
}
