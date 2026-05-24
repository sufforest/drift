// Package recovery wraps the workspace master key under a user passphrase
// so a single-device user can restore access after losing their device.
//
// The wrapped blob is uploaded to the workspace bucket. Without the
// passphrase the blob is unreadable. With it, plus the bucket coordinates
// and a valid parent S3 credential, a fresh machine can reconstruct the
// master key, re-enroll itself as a new device, and resume operating on
// the workspace.
//
// The blob contains only the master key material and a workspace ID.
// Parent S3 credentials are deliberately NOT stored — the user maintains
// those separately (their cloud provider's dashboard). This keeps the
// blob's blast radius bounded.
package recovery

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"time"
	"unicode"

	"golang.org/x/crypto/argon2"

	dcrypto "github.com/sufforest/drift/internal/crypto"
)

const (
	// BlobVersion is the on-bucket envelope version. Bump when the field
	// layout changes incompatibly.
	BlobVersion = 1

	// Argon2id defaults. 256 MiB / 3 iterations / 4 threads is the OWASP
	// "second choice" recommendation for password hashing as of 2024;
	// strong enough to make offline brute force costly given a passphrase
	// above the strength gate.
	DefaultArgonTime    uint32 = 3
	DefaultArgonMemKiB  uint32 = 256 * 1024
	DefaultArgonThreads uint8  = 4

	SaltSize = 32
	KeySize  = 32

	// MinPassphraseBits is the strength gate. ~60 bits ≈ NIST L1; an
	// attacker who scrapes the blob still has to spend >$10K of cloud
	// compute to brute-force, given the Argon2 cost. Tunable via
	// AllowWeakPassphrase.
	MinPassphraseBits = 60.0

	// AAD label binds ciphertexts to "recovery v1", preventing confusion
	// with other drift-encrypted blobs.
	aadLabel = "drift/recovery/v1"
)

// ErrNoBlob means the bucket has no recovery blob to unwrap.
var ErrNoBlob = errors.New("recovery: no blob in bucket (not configured)")

// ErrPassphrase means the supplied passphrase did not decrypt the blob.
var ErrPassphrase = errors.New("recovery: passphrase did not decrypt blob")

// ErrWeakPassphrase means the supplied passphrase is below MinPassphraseBits.
type ErrWeakPassphrase struct {
	Bits float64
}

func (e *ErrWeakPassphrase) Error() string {
	return fmt.Sprintf("recovery: passphrase too weak (%.0f bits, need >= %.0f). Try a longer passphrase, a four-word random phrase, or a 20+ character mix.", e.Bits, MinPassphraseBits)
}

// Blob is the on-bucket envelope. Stored as JSON at domain.RecoveryKey.
type Blob struct {
	Version int    `json:"version"`
	Salt    []byte `json:"salt"`
	Time    uint32 `json:"argon_time"`
	Memory  uint32 `json:"argon_memory_kib"`
	Threads uint8  `json:"argon_threads"`
	Cipher  []byte `json:"cipher"` // dcrypto.Encrypt output: nonce || ciphertext || tag
	WrappedAt time.Time `json:"wrapped_at"`
}

// payload is the cleartext under Blob.Cipher.
type payload struct {
	Version       int       `json:"version"`
	WorkspaceID   string    `json:"workspace_id"`
	MasterSignPriv []byte   `json:"master_sign_priv"`  // ed25519 64-byte priv
	MasterBoxPriv []byte    `json:"master_box_priv"`   // x25519 32-byte priv
	MasterRoot    []byte    `json:"master_root"`       // 32-byte root for CPRK derivation
	CreatedAt     time.Time `json:"created_at"`
}

// WrapOptions tunes the Argon2id cost. Zero values fall back to defaults.
type WrapOptions struct {
	Time              uint32
	MemoryKiB         uint32
	Threads           uint8
	AllowWeakPassphrase bool
}

// Wrap builds a passphrase-encrypted blob containing the master key
// material and workspace ID. The blob can be safely persisted on the
// bucket — without the passphrase it reveals nothing.
func Wrap(master *dcrypto.MasterKey, workspaceID, passphrase string, opts WrapOptions) (*Blob, error) {
	if master == nil {
		return nil, errors.New("recovery: master key required")
	}
	if workspaceID == "" {
		return nil, errors.New("recovery: workspace id required")
	}
	if !opts.AllowWeakPassphrase {
		if bits := Strength(passphrase); bits < MinPassphraseBits {
			return nil, &ErrWeakPassphrase{Bits: bits}
		}
	}

	argTime := opts.Time
	if argTime == 0 {
		argTime = DefaultArgonTime
	}
	mem := opts.MemoryKiB
	if mem == 0 {
		mem = DefaultArgonMemKiB
	}
	threads := opts.Threads
	if threads == 0 {
		threads = DefaultArgonThreads
	}

	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("recovery: salt: %w", err)
	}
	kek := argon2.IDKey([]byte(passphrase), salt, argTime, mem, threads, KeySize)

	pl := payload{
		Version:        1,
		WorkspaceID:    workspaceID,
		MasterSignPriv: append([]byte(nil), master.SignPriv...),
		MasterBoxPriv:  append([]byte(nil), master.BoxPriv[:]...),
		MasterRoot:     append([]byte(nil), master.Root[:]...),
		CreatedAt:      time2(),
	}
	plBytes, err := json.Marshal(&pl)
	if err != nil {
		return nil, fmt.Errorf("recovery: marshal: %w", err)
	}
	cipher, err := dcrypto.Encrypt(kek, plBytes, []byte(aadLabel))
	if err != nil {
		return nil, fmt.Errorf("recovery: encrypt: %w", err)
	}
	return &Blob{
		Version:   BlobVersion,
		Salt:      salt,
		Time:      argTime,
		Memory:    mem,
		Threads:   threads,
		Cipher:    cipher,
		WrappedAt: time2(),
	}, nil
}

// Unwrap decrypts a blob with the supplied passphrase, returning the
// master key + workspace ID. ErrPassphrase if the passphrase is wrong.
func Unwrap(b *Blob, passphrase string) (*dcrypto.MasterKey, string, error) {
	if b == nil {
		return nil, "", errors.New("recovery: nil blob")
	}
	if b.Version != BlobVersion {
		return nil, "", fmt.Errorf("recovery: blob version %d not supported", b.Version)
	}
	if len(b.Salt) != SaltSize {
		return nil, "", fmt.Errorf("recovery: salt length %d, want %d", len(b.Salt), SaltSize)
	}
	kek := argon2.IDKey([]byte(passphrase), b.Salt, b.Time, b.Memory, b.Threads, KeySize)
	plBytes, err := dcrypto.Decrypt(kek, b.Cipher, []byte(aadLabel))
	if err != nil {
		return nil, "", ErrPassphrase
	}
	var pl payload
	if err := json.Unmarshal(plBytes, &pl); err != nil {
		return nil, "", fmt.Errorf("recovery: parse payload: %w", err)
	}
	if pl.Version != 1 {
		return nil, "", fmt.Errorf("recovery: payload version %d not supported", pl.Version)
	}
	if len(pl.MasterSignPriv) != ed25519.PrivateKeySize {
		return nil, "", fmt.Errorf("recovery: master sign priv length %d, want %d", len(pl.MasterSignPriv), ed25519.PrivateKeySize)
	}
	if len(pl.MasterBoxPriv) != dcrypto.X25519KeySize {
		return nil, "", fmt.Errorf("recovery: master box priv length %d, want %d", len(pl.MasterBoxPriv), dcrypto.X25519KeySize)
	}
	if len(pl.MasterRoot) != dcrypto.RootSecretSize {
		return nil, "", fmt.Errorf("recovery: master root length %d, want %d", len(pl.MasterRoot), dcrypto.RootSecretSize)
	}
	mk := &dcrypto.MasterKey{
		SignPriv: append(ed25519.PrivateKey(nil), pl.MasterSignPriv...),
	}
	copy(mk.BoxPriv[:], pl.MasterBoxPriv)
	copy(mk.Root[:], pl.MasterRoot)
	return mk, pl.WorkspaceID, nil
}

// Strength returns a rough entropy estimate in bits. Not zxcvbn — we use
// a deliberately simple model (Shannon-style on character classes,
// length-multiplied, with a penalty for common patterns) to avoid a heavy
// dictionary dependency. False positives on weak passphrases are
// acceptable; an attacker still has to clear the Argon2id cost.
func Strength(p string) float64 {
	if p == "" {
		return 0
	}
	var hasLower, hasUpper, hasDigit, hasSpace, hasSymbol bool
	for _, r := range p {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsSpace(r):
			hasSpace = true
		default:
			hasSymbol = true
		}
	}
	classes := 0
	if hasLower {
		classes += 26
	}
	if hasUpper {
		classes += 26
	}
	if hasDigit {
		classes += 10
	}
	if hasSpace {
		classes += 1
	}
	if hasSymbol {
		classes += 32
	}
	if classes == 0 {
		return 0
	}
	bits := float64(len([]rune(p))) * math.Log2(float64(classes))

	// Penalty for common substrings. Not exhaustive — meant to catch
	// "password123" / "letmein" / "drift!" style choices, not a full
	// dictionary attack.
	lc := lowerASCII(p)
	for _, bad := range []string{
		"password", "passw0rd", "qwerty", "letmein", "iloveyou",
		"welcome", "abc123", "111111", "123456", "admin", "secret",
		"drift", "master", "rclone",
	} {
		if containsASCII(lc, bad) {
			bits -= 20
		}
	}
	if bits < 0 {
		bits = 0
	}
	return bits
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func containsASCII(haystack, needle string) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// time2 is a hook for test injection. Today it just returns time.Now()
// — production callers don't need to mock it.
var time2 = func() time.Time { return time.Now().UTC() }
