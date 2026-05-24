package domain

import "errors"

// Sentinel errors returned across package boundaries. Callers should compare
// with errors.Is rather than string-matching.
var (
	// ErrManifestConflict is returned by a ManifestWriter when the underlying
	// conditional PUT loses a race after retries are exhausted.
	ErrManifestConflict = errors.New("drift: manifest write conflict")

	// ErrLockHeld is returned by the lock-object writer when another device
	// holds the manifest lock and it has not yet expired.
	ErrLockHeld = errors.New("drift: manifest lock held by another writer")

	// ErrTokenRevoked is returned when a token's tid appears in revocations.enc.
	ErrTokenRevoked = errors.New("drift: token revoked")

	// ErrTokenExpired is returned when a token's exp has passed.
	ErrTokenExpired = errors.New("drift: token expired")

	// ErrSignatureInvalid is returned when an Ed25519 verification fails
	// (manifest, token, or revocation entry).
	ErrSignatureInvalid = errors.New("drift: signature verification failed")

	// ErrProviderUnavailable is returned when the storage provider is
	// unreachable or returns an unexpected error during a probe.
	ErrProviderUnavailable = errors.New("drift: storage provider unavailable")

	// ErrObjectNotFound is returned by Get/GetWithETag/Delete when the key
	// does not exist in the backing store.
	ErrObjectNotFound = errors.New("drift: object not found")

	// ErrPreconditionFailed is returned when a conditional PUT loses the
	// precondition (412 from S3-compatible providers).
	ErrPreconditionFailed = errors.New("drift: precondition failed")

	// ErrConditionalUnsupported is returned when the provider rejects the
	// conditional headers themselves (501 from Backblaze B2). Used by the
	// capability probe to select the lock-object fallback.
	ErrConditionalUnsupported = errors.New("drift: conditional writes not supported")

	// ErrTokenMalformed is returned when a token cannot be decoded.
	ErrTokenMalformed = errors.New("drift: token malformed")

	// ErrCompartmentUnknown is returned when a token references a compartment
	// not present in the manifest.
	ErrCompartmentUnknown = errors.New("drift: compartment unknown")

	// ErrDeviceUnknown is returned when a token is signed by a device whose
	// public key is not in the manifest.
	ErrDeviceUnknown = errors.New("drift: signing device unknown")
)
