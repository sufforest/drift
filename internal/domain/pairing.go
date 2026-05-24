package domain

import "time"

// PairingVersion is the current pairing-token wire format.
const PairingVersion = 1

// PairingPrefix is the human-readable scheme prefix written by encoders.
// Distinct from TokenPrefix so capability redeemers immediately reject
// pairing tokens and vice-versa.
const PairingPrefix = "driftpair1"

// PairingToken is the master-signed credential a new device needs to join a
// workspace. It carries TWO scoped creds:
//
//   - ReadCred:  GET-only on the manifest, the new device's response
//                slot, and its handoff slot.
//   - WriteCred: PUT-only on the new device's response slot.
//
// R2's JWT semantics are actions × objects (Cartesian product), so a
// single cred granting both PUT (needed for response.json) and inclusion
// of ManifestKey in objects would let any token-holder PUT garbage over
// the manifest — DoS the workspace. Splitting into two creds with
// disjoint action sets makes the workspace-DoS path impossible.
type PairingToken struct {
	Version     int          `json:"v"`
	PID         string       `json:"pid"` // pairing id, "pair_<hex>", random
	WorkspaceID string       `json:"wid"`
	Bucket      BucketInfo   `json:"bucket"`
	ReadCred    S3Credential `json:"rcred"` // GET/HEAD on read-only objects (manifest, response, handoff)
	WriteCred   S3Credential `json:"wcred"` // PUT on response.json only
	Challenge   []byte       `json:"chal"`  // 32 random bytes
	ExpiresAt   time.Time    `json:"exp"`
	IssuerPub   []byte       `json:"ipub"` // master Ed25519 pubkey (also the trust root)
	MasterFP    []byte       `json:"mfp"`  // SHA-256 of IssuerPub; pinned by new device on accept
}

// PairingStub is the in-flight pairing record stored in Manifest.Pairings.
// Lets other enrolled devices see what handshakes are mid-flight.
type PairingStub struct {
	PID       string    `json:"pid"`
	IssuedBy  string    `json:"issued_by"` // device id of the issuer (master == MasterDeviceID)
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// PeerMode toggles whether the pairing should hand the parent S3
	// credential to the new device. True = the new device becomes a
	// functional peer (can `drift mount`, `drift grant`, etc.) without
	// going through the bearer flow. False = identity-only; the new
	// device must use `drift open <token>` for daily access.
	//
	// Choose true for solo dev with multiple personal machines (same
	// human owns both). Choose false for less-trusted devices.
	PeerMode bool `json:"peer_mode,omitempty"`
	// CompartmentScope, when non-empty, restricts the new device to the
	// listed compartments (DD-8). nil / empty means "no restriction".
	// Captured in LinkConfirm and written onto the new device's Device
	// entry in the manifest.
	CompartmentScope []string `json:"compartment_scope,omitempty"`
}

// PairingResponse is what the new device writes to
// .drift/pairings/<pid>/response.json so the primary can complete enrollment.
type PairingResponse struct {
	PID           string `json:"pid"`
	DeviceID      string `json:"device_id"`
	Name          string `json:"name"`
	DeviceSignPub []byte `json:"device_sign_pub"` // Ed25519
	DeviceBoxPub  []byte `json:"device_box_pub"`  // X25519
	ChallengeSig  []byte `json:"challenge_sig"`   // Ed25519(DeviceSignPriv, PairingToken.Challenge)
}

// PairingsDir is the bucket prefix under which pairing artifacts live.
const PairingsDir = ".drift/pairings/"

// PairingResponseKey returns the bucket key for a pid's response object.
func PairingResponseKey(pid string) string {
	return PairingsDir + pid + "/response.json"
}

// PairingChallengeKey returns the bucket key for a pid's challenge marker
// (existence indicates an in-flight pairing).
func PairingChallengeKey(pid string) string {
	return PairingsDir + pid + "/challenge"
}

// PairingHandoffKey returns the bucket key where the primary writes a
// sealed CPRK + master-pubkey blob for the new device to consume after
// the primary confirms the pairing.
func PairingHandoffKey(pid string) string {
	return PairingsDir + pid + "/handoff.enc"
}

// PairingAbortKey returns the bucket key where the primary writes an
// abort marker when the SAS verification fails (user said "no" at the
// confirm prompt). Existence of this object causes the secondary's
// awaitHandoff to fail fast with a clear message instead of timing
// out after 10 minutes.
func PairingAbortKey(pid string) string {
	return PairingsDir + pid + "/aborted.flag"
}

// PairingHandoff is the plaintext payload (before sealed-box encryption)
// the primary device hands off to the new device after confirming.
//
// Parent is included only in peer-mode pairings (see PairingStub.PeerMode).
// When present, the new device saves it as its own parent S3 cred and
// becomes a functional peer; when nil, the new device has identity only.
type PairingHandoff struct {
	CPRK      []byte                `json:"cprk"`
	MasterPub []byte                `json:"master_pub"`
	Parent    *PairingHandoffParent `json:"parent,omitempty"`
}

// PairingHandoffParent is the subset of credentials.Parent that's safe
// to transmit. We don't import internal/credentials here because that
// would create a layering cycle (credentials depends on domain).
type PairingHandoffParent struct {
	Provider        string `json:"provider"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
}
