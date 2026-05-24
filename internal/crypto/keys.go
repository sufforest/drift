// Package crypto contains Drift's cryptographic primitives.
//
// Key hierarchy:
//
//	MasterKey (per workspace, on primary device only)
//	  ├── Ed25519 keypair      — signs initial manifest, top-level revocations
//	  ├── X25519 keypair       — receives sealed-box messages (recovery, key rotation)
//	  └── Root secret          — HKDF IKM for deriving the CPRK
//	        └── CPRK           — symmetric, encrypts manifest / revocations
//	DeviceKey (per device)
//	  ├── Ed25519 keypair      — signs manifest updates, tokens, revocation entries
//	  └── X25519 keypair       — receives compartment keys via sealed box
//	CompartmentKey (per compartment)
//	  └── 32-byte symmetric    — used by rclone crypt for data-plane encryption
//
// All randomness comes from crypto/rand. No deterministic key derivation across
// algorithm boundaries (each role gets its own random source).
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// Key sizes (bytes).
const (
	X25519KeySize    = 32
	SymmetricKeySize = 32
	RootSecretSize   = 32
)

// HKDF labels are versioned so a future v2 hierarchy can coexist with v1 keys.
const (
	hkdfLabelCPRK = "drift/v1/cprk"
)

// MasterKey is the root of trust for a workspace. Generated at `drift init`.
// Stored only in the primary device's keychain (file-based for v1 per the
// open-decisions resolution).
type MasterKey struct {
	SignPriv ed25519.PrivateKey
	BoxPriv  [X25519KeySize]byte
	Root     [RootSecretSize]byte
}

// DeviceKey is per-device key material generated at `drift init` or `drift link`.
// The public halves are written to the manifest; the private halves stay in the
// device keychain.
type DeviceKey struct {
	SignPriv ed25519.PrivateKey
	BoxPriv  [X25519KeySize]byte
}

// GenerateMasterKey creates a fresh MasterKey with independent random material
// for each role.
func GenerateMasterKey() (*MasterKey, error) {
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519: %w", err)
	}
	_ = signPub // returned by GenerateKey but available via signPriv.Public()

	var boxPriv [X25519KeySize]byte
	if _, err := io.ReadFull(rand.Reader, boxPriv[:]); err != nil {
		return nil, fmt.Errorf("x25519 priv: %w", err)
	}
	// Clamp per RFC 7748 §5 to ensure a valid scalar.
	clampX25519(&boxPriv)

	var root [RootSecretSize]byte
	if _, err := io.ReadFull(rand.Reader, root[:]); err != nil {
		return nil, fmt.Errorf("root secret: %w", err)
	}

	return &MasterKey{SignPriv: signPriv, BoxPriv: boxPriv, Root: root}, nil
}

// GenerateDeviceKey creates a fresh DeviceKey. Has no Root because device keys
// derive nothing — they only sign and receive sealed boxes.
func GenerateDeviceKey() (*DeviceKey, error) {
	_, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ed25519: %w", err)
	}
	var boxPriv [X25519KeySize]byte
	if _, err := io.ReadFull(rand.Reader, boxPriv[:]); err != nil {
		return nil, fmt.Errorf("x25519 priv: %w", err)
	}
	clampX25519(&boxPriv)
	return &DeviceKey{SignPriv: signPriv, BoxPriv: boxPriv}, nil
}

// SignPub returns the device's Ed25519 public key (32 bytes).
func (d *DeviceKey) SignPub() ed25519.PublicKey {
	return d.SignPriv.Public().(ed25519.PublicKey)
}

// BoxPub returns the device's X25519 public key (32 bytes).
func (d *DeviceKey) BoxPub() ([X25519KeySize]byte, error) {
	return x25519Pub(d.BoxPriv)
}

// SignPub returns the master Ed25519 public key.
func (m *MasterKey) SignPub() ed25519.PublicKey {
	return m.SignPriv.Public().(ed25519.PublicKey)
}

// BoxPub returns the master X25519 public key.
func (m *MasterKey) BoxPub() ([X25519KeySize]byte, error) {
	return x25519Pub(m.BoxPriv)
}

// DeriveCPRK derives the workspace's Control Plane Read Key from the master
// root secret. The workspace ID + epoch are mixed in via HKDF "info" so
// (a) two workspaces sharing a master yield distinct CPRKs and
// (b) rotating epoch yields a fresh CPRK without changing the root secret.
func DeriveCPRK(root [RootSecretSize]byte, workspaceID string, epoch uint64) ([]byte, error) {
	info := []byte(hkdfLabelCPRK + ":" + workspaceID + ":" + strconvU(epoch))
	h := hkdf.New(sha3.New256, root[:], nil, info)
	key := make([]byte, SymmetricKeySize)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, fmt.Errorf("hkdf cprk: %w", err)
	}
	return key, nil
}

// strconvU avoids pulling strconv into this file for a single conversion.
func strconvU(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// GenerateCompartmentKey returns a fresh random 32-byte symmetric key suitable
// for rclone crypt.
func GenerateCompartmentKey() ([]byte, error) {
	k := make([]byte, SymmetricKeySize)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, fmt.Errorf("compartment key: %w", err)
	}
	return k, nil
}

// GenerateRedemptionCode returns a fresh 32-byte random redemption code.
func GenerateRedemptionCode() ([]byte, error) {
	k := make([]byte, SymmetricKeySize)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, fmt.Errorf("redemption code: %w", err)
	}
	return k, nil
}

// x25519Pub derives the X25519 public key from a private scalar.
func x25519Pub(priv [X25519KeySize]byte) ([X25519KeySize]byte, error) {
	pubBytes, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return [X25519KeySize]byte{}, fmt.Errorf("x25519 pub: %w", err)
	}
	var out [X25519KeySize]byte
	copy(out[:], pubBytes)
	return out, nil
}

// clampX25519 applies the RFC 7748 scalar clamp.
func clampX25519(k *[X25519KeySize]byte) {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
}
