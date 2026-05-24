package domain

import "time"

// MasterRotationsDir is the bucket prefix that holds per-sequence rotation
// announcements. One JSON object per rotation, keyed by sequence number.
// Devices walking forward from a pre-rotation pinned fingerprint read this
// directory in sequence order to update their pin.
const MasterRotationsDir = ".drift/master-rotations/"

// MasterRotationAnnouncement is the doubly-signed record produced by
// `drift rotate master`. Stored under MasterRotationsDir keyed by
// Sequence. Devices reading a manifest with MasterRotationSequence > N
// fetch announcements N+1..M and verify each against the previous master's
// pubkey, updating their pinned fingerprint step by step.
type MasterRotationAnnouncement struct {
	Version      int       `json:"v"`
	WorkspaceID  string    `json:"wid"`
	Sequence     uint64    `json:"seq"`
	OldMasterPub []byte    `json:"old_mpub"` // pubkey of the retiring master; SHA-256 of this is the verifier's pre-pin
	NewMasterPub []byte    `json:"new_mpub"` // pubkey of the incoming master; SHA-256 of this becomes the post-pin
	AnnouncedAt  time.Time `json:"announced_at"`

	OldMasterSig []byte `json:"old_sig"` // signature by the retiring master
	NewMasterSig []byte `json:"new_sig"` // signature by the incoming master
}

// MasterRotationKey returns the bucket key for a rotation announcement
// at the given sequence number.
func MasterRotationKey(seq uint64) string {
	return MasterRotationsDir + formatRotationSeq(seq) + ".json"
}

// formatRotationSeq zero-pads so lexicographic List order matches numeric
// order (16 hex digits handles every uint64).
func formatRotationSeq(seq uint64) string {
	const hex = "0123456789abcdef"
	var buf [16]byte
	for i := 15; i >= 0; i-- {
		buf[i] = hex[seq&0xf]
		seq >>= 4
	}
	return string(buf[:])
}
