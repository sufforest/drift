package crypto

import (
	"crypto/ed25519"

	"github.com/sufforest/drift/internal/domain"
)

// Sign signs message with the given Ed25519 private key. Returns the raw
// 64-byte signature.
func Sign(priv ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(priv, message)
}

// Verify checks an Ed25519 signature. Returns domain.ErrSignatureInvalid on
// any verification failure so callers can errors.Is against a stable sentinel.
func Verify(pub ed25519.PublicKey, message, signature []byte) error {
	if len(pub) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return domain.ErrSignatureInvalid
	}
	if !ed25519.Verify(pub, message, signature) {
		return domain.ErrSignatureInvalid
	}
	return nil
}
