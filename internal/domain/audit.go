package domain

import "time"

// Audit event kinds. The list is closed in v1; new kinds added later via
// the entry's Version field. Readers ignore entries with unknown kinds
// (forward-compat).
const (
	AuditKindWorkspaceInit       = "workspace.init"
	AuditKindDeviceLink          = "device.link"
	AuditKindDeviceRevoke        = "device.revoke"
	AuditKindCompartmentCreate   = "compartment.create"
	AuditKindCompartmentDelete   = "compartment.delete"
	AuditKindCompartmentRotate   = "compartment.rotate"
	AuditKindCompartmentGrant    = "compartment.grant"   // DD-8 scope grant
	AuditKindCompartmentUngrant  = "compartment.ungrant" // DD-8 scope ungrant + targeted rotation
	AuditKindTokenGrant          = "token.grant"
	AuditKindTokenRevoke         = "token.revoke"
	AuditKindCPRKRotate          = "cprk.rotate"
	AuditKindMasterRotate        = "master.rotate"
	AuditKindRecoveryConfigured  = "recovery.configured"
	AuditKindRecoveryDisabled    = "recovery.disabled"
	AuditKindRecoveryRestored    = "recovery.restored"
	AuditKindParentSet           = "parent.set"      // device's parent S3 credential was replaced
	AuditKindPeerCredIssued      = "peer.cred.issued"    // DD-9 bearer-mode cred minted for a peer
	AuditKindPeerCredRevoked     = "peer.cred.revoked"   // DD-9 bearer-mode peer revoked workspace-side
	AuditKindPeerCredRefreshed   = "peer.cred.refreshed" // DD-9 bearer-mode cred re-minted for a peer
)

// AuditDir is the bucket prefix that holds audit entry objects.
const AuditDir = ".drift/audit/"

// AuditEntry is one signed, encrypted control-plane event. Entries are
// stored as separate objects (not appended to a single log file) so
// concurrent writers do not collide and so a bucket-admin delete leaves
// detectable gaps in the per-device hash chain.
type AuditEntry struct {
	Version     int       `json:"v"`
	EntryID     string    `json:"id"`        // "<unix_nano>-<device_id>-<nonce_hex>"
	WorkspaceID string    `json:"wid"`
	DeviceID    string    `json:"did"`       // emitting device
	Sequence    uint64    `json:"seq"`       // per-device monotonic
	PrevHash    []byte    `json:"prev_hash"` // SHA-256 of previous entry from this device (canonical bytes)
	OccurredAt  time.Time `json:"at"`
	Kind        string    `json:"kind"`
	Subject     string    `json:"subject"`   // tid / compartment name / device id (kind-dependent)
	Details     []byte    `json:"details,omitempty"` // opaque JSON bytes, kind-specific
	Signature   []byte    `json:"sig"`
}

// AuditEntryKey returns the bucket key for an entry.
func AuditEntryKey(entryID string) string {
	return AuditDir + entryID + ".enc"
}

// AuditAADFor binds the AEAD envelope to the entry's id + workspace so a
// bucket admin who swaps body bytes between entries fails decryption.
func AuditAADFor(workspaceID, entryID string) []byte {
	return []byte("drift/v1/audit|" + workspaceID + "|" + entryID)
}
