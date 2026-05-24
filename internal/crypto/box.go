package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/nacl/box"
)

// SealFor encrypts plaintext to a recipient X25519 public key using NaCl's
// anonymous sealed-box construction (ephemeral sender keypair, X25519 ECDH,
// XSalsa20-Poly1305 with a derived nonce).
//
// Used to wrap compartment keys per device: the manifest stores one sealed
// blob per (compartment, device) pair.
func SealFor(recipientPub [X25519KeySize]byte, plaintext []byte) ([]byte, error) {
	pub := recipientPub
	ct, err := box.SealAnonymous(nil, plaintext, &pub, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("box seal: %w", err)
	}
	return ct, nil
}

// Open decrypts a sealed box for the holder of (recipientPub, recipientPriv).
// Both halves are required because box.OpenAnonymous needs the public key to
// derive the same shared secret the sender used.
func Open(recipientPub, recipientPriv [X25519KeySize]byte, ciphertext []byte) ([]byte, error) {
	pub, priv := recipientPub, recipientPriv
	pt, ok := box.OpenAnonymous(nil, ciphertext, &pub, &priv)
	if !ok {
		return nil, errors.New("crypto: sealed box open failed")
	}
	return pt, nil
}
