package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEAD is XChaCha20-Poly1305: 256-bit key, 192-bit (24-byte) nonce, 128-bit tag.
// XChaCha20 is preferred over ChaCha20 here because the 24-byte nonce is large
// enough that uniform random selection is collision-safe across many messages
// without per-key counters — important because Drift writes the manifest and
// credentials files from multiple devices that share an encryption key.

// ErrCiphertextTooShort is returned when a ciphertext is smaller than the
// minimum (nonce + tag). Indicates corruption or a malformed input.
var ErrCiphertextTooShort = errors.New("crypto: ciphertext too short")

// Encrypt encrypts plaintext with XChaCha20-Poly1305 and prepends a random
// nonce. aad is authenticated but not encrypted (use it for headers, version,
// or context bytes that must bind to the ciphertext).
//
// Output layout: nonce(24) || ciphertext || tag(16).
func Encrypt(key, plaintext, aad []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("crypto: key must be %d bytes, got %d", chacha20poly1305.KeySize, len(key))
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("xchacha20: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	// Seal appends to its first argument, so passing `nonce` makes the result
	// begin with the nonce.
	return aead.Seal(nonce, nonce, plaintext, aad), nil
}

// Decrypt is the inverse of Encrypt. Returns an error (without partial output)
// if the tag does not verify against (key, nonce, aad).
func Decrypt(key, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("crypto: key must be %d bytes, got %d", chacha20poly1305.KeySize, len(key))
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("xchacha20: %w", err)
	}
	if len(ciphertext) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrCiphertextTooShort
	}
	nonce, body := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, body, aad)
	if err != nil {
		return nil, fmt.Errorf("aead open: %w", err)
	}
	return pt, nil
}
