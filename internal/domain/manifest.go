// Package domain contains the core Drift types: manifests, tokens, config.
// These types have no I/O and no dependencies on other internal packages.
package domain

import "time"

// Concurrency strategies recorded in the manifest.
const (
	ConcurrencyConditionalPut = "conditional_put"
	ConcurrencyLockObject     = "lock_object"
)

// Compartment modes.
const (
	ModeMount = "mount"
	ModeSync  = "sync"
)

// Token modes.
const (
	TokenModeRW = "rw"
	TokenModeRO = "ro"
)

// MasterDeviceID is the well-known device id under which the workspace's
// master signing + box pubkeys are recorded in Manifest.Devices. The master
// is not a "real" device — it never signs runtime manifest updates — but
// its public keys live here so every reader can recover the trust root
// without a separate lookup.
const MasterDeviceID = "master"

// Manifest is the encrypted control-plane document at .drift/manifest.enc.
//
// Sequence is a monotonically-increasing counter incremented on every
// successful write. Clients track the highest Sequence they've observed
// and refuse to load any manifest with a lower one — this defends against
// a bucket-write attacker replaying an older signed manifest (e.g. to
// resurrect a removed device).
type Manifest struct {
	Version      int                    `json:"version"`
	WorkspaceID  string                 `json:"workspace_id"`
	Sequence     uint64                 `json:"sequence"`
	Concurrency  string                 `json:"concurrency"`
	Devices      map[string]Device      `json:"devices"`
	Compartments map[string]Compartment `json:"compartments"`
	ActiveTokens map[string]TokenRecord `json:"active_tokens"`
	Enrollments  map[string]Enrollment  `json:"enrollments"`
	Pairings     map[string]PairingStub `json:"pairings"` // in-flight `drift link` handshakes
	// MasterRotationSequence is the highest sequence number among
	// announcements under .drift/master-rotations/. Devices use this to
	// decide whether to fetch + follow the rotation chain to update
	// their pinned master fingerprint.
	MasterRotationSequence uint64    `json:"master_rotation_seq"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	Signature    []byte                 `json:"signature"`
	SignedBy     string                 `json:"signed_by"`
}

// Enrollment is a master-signed certificate proving a device's signing +
// box public keys were authorized by the workspace's master at SignedAt.
// One entry per device in Manifest.Devices (excluding the master pseudo-
// device). A bucket-write attacker who inserts an unrecognized device into
// Devices cannot fabricate a matching Enrollment without the master
// signing key, so manifest verification rejects the forgery.
type Enrollment struct {
	DeviceID  string    `json:"device_id"`
	SignedAt  time.Time `json:"signed_at"`
	MasterSig []byte    `json:"master_sig"`
}

// Device is a registered installation of the Drift client.
type Device struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	PublicKey  []byte    `json:"public_key"`  // Ed25519, for signing verification
	EncryptKey []byte    `json:"encrypt_key"` // X25519, for sealed-box encryption
	EnrolledAt time.Time `json:"enrolled_at"`
	LastSeen   time.Time `json:"last_seen"`

	// CompartmentScope, when non-empty, restricts this device to the listed
	// compartments (DD-8). nil / empty means "no restriction" — the device
	// can decrypt every compartment in the workspace. Pre-DD-8 manifests
	// omit this field entirely; on read, missing == nil == full access,
	// which preserves backward compatibility.
	CompartmentScope []string `json:"compartment_scope,omitempty"`
}

// HasCompartmentAccess reports whether the device is permitted to hold a
// sealed copy of the named compartment's key. Devices with no explicit
// scope (the pre-DD-8 default) have access to every compartment.
func (d Device) HasCompartmentAccess(name string) bool {
	if len(d.CompartmentScope) == 0 {
		return true
	}
	for _, c := range d.CompartmentScope {
		if c == name {
			return true
		}
	}
	return false
}

// Compartment is a named, independently-keyed subspace of the workspace.
type Compartment struct {
	Name          string            `json:"name"`
	Mode          string            `json:"mode"`
	KeyVersion    int               `json:"key_version"`
	EncryptedKeys map[string][]byte `json:"encrypted_keys"` // device_id -> key sealed for device
	CreatedAt     time.Time         `json:"created_at"`
}

// TokenRecord is the manifest entry for an outstanding token.
type TokenRecord struct {
	TID       string    `json:"tid"`
	IssuedBy  string    `json:"issued_by"`
	Scope     []string  `json:"scope"`
	Mode      string    `json:"mode"`
	ExpiresAt time.Time `json:"expires_at"`
	IssuedAt  time.Time `json:"issued_at"`
}
