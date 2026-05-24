package domain

import "time"

// RevocationListVersion is the wire-format version of revocations.enc.
const RevocationListVersion = 1

// RevocationList is the body of .drift/revocations.enc. Unlike the manifest
// it is NOT encrypted — token bearers must be able to read it without holding
// the CPRK. Authentication is per-entry via Ed25519 signatures.
//
// Sequence is monotonically incremented on every revocation write. Bearers
// remember the Sequence they observed at redemption and reject any
// later-fetched list with a lower one to detect rollback.
type RevocationList struct {
	Version  int               `json:"version"`
	Sequence uint64            `json:"sequence"`
	Entries  []RevocationEntry `json:"entries"`
}

// RevocationEntry revokes a single token id. Verified using the revoking
// device's public key from the manifest.
type RevocationEntry struct {
	TID       string    `json:"tid"`
	RevokedAt time.Time `json:"revoked_at"`
	RevokedBy string    `json:"revoked_by"` // device_id
	Signature []byte    `json:"signature"`  // Ed25519 over (tid || revoked_at_unix || revoked_by)
}
