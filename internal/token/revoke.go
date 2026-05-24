package token

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/storage"
)

// Revoker appends a signed revocation entry to .drift/revocations.enc.
//
// The revocations file is signed-but-not-encrypted: token bearers must be
// able to read it without holding the CPRK. Authentication of each entry
// is via Ed25519 signature with the revoking device's key.
//
// MinSeq is the monotonic-sequence floor: if the bucket's revocations list
// presents a Sequence below MinSeq, the mutator refuses to write (treating
// the bucket as rolled-back). The caller must read this back from the
// returned RevokeResult and persist it so a fresh process inherits the
// floor. Without this, idempotent re-revoke after a bucket-side rollback
// silently re-publishes the rolled-back state.
type Revoker struct {
	Provider   storage.Provider
	Writer     storage.ReadModifyWriter
	DeviceID   string
	DeviceSign ed25519.PrivateKey
	Now        func() time.Time
	MinSeq     uint64
}

// RevokeResult tells the caller what the persisted Sequence is now and
// whether the tid was already-revoked. Use NewSequence to update the
// caller's persistent floor.
type RevokeResult struct {
	NewSequence uint64
	Idempotent  bool
}

// Revoke adds tid to the revocation list. Idempotent: a second Revoke for the
// same tid still bumps Sequence (so a bucket-side rollback to a snapshot
// before this revoke is detectable later). Honest clients pick up the
// change within their poll interval.
func (r *Revoker) Revoke(ctx context.Context, tid string) (*RevokeResult, error) {
	if tid == "" {
		return nil, errors.New("token: tid required")
	}
	now := r.now()
	var result RevokeResult
	err := r.Writer.ReadModifyWrite(ctx, domain.RevocationsKey, func(cur []byte) ([]byte, error) {
		list, err := DecodeRevocations(cur)
		if err != nil {
			return nil, err
		}
		if list.Sequence < r.MinSeq {
			return nil, fmt.Errorf("%w: revocations sequence %d below floor %d (possible bucket rollback)",
				domain.ErrManifestConflict, list.Sequence, r.MinSeq)
		}
		alreadyRevoked := false
		for _, e := range list.Entries {
			if e.TID == tid {
				alreadyRevoked = true
				break
			}
		}
		if !alreadyRevoked {
			entry := domain.RevocationEntry{
				TID:       tid,
				RevokedAt: now,
				RevokedBy: r.DeviceID,
			}
			entry.Signature = dcrypto.Sign(r.DeviceSign, RevocationSigningBytes(entry))
			list.Entries = append(list.Entries, entry)
		}
		// Always bump — idempotent re-revoke still moves the floor
		// forward so a future rollback to a pre-revoke snapshot trips
		// the MinSeq check.
		list.Version = domain.RevocationListVersion
		list.Sequence++
		result.NewSequence = list.Sequence
		result.Idempotent = alreadyRevoked
		return json.Marshal(list)
	})
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (r *Revoker) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// DecodeRevocations parses the JSON body of .drift/revocations.enc. A nil or
// empty body is treated as an empty list (cold start).
func DecodeRevocations(body []byte) (*domain.RevocationList, error) {
	if len(body) == 0 {
		return &domain.RevocationList{Version: domain.RevocationListVersion}, nil
	}
	var list domain.RevocationList
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("parse revocations: %w", err)
	}
	if list.Entries == nil {
		list.Entries = []domain.RevocationEntry{}
	}
	return &list, nil
}

// RevocationSigningBytes returns the canonical byte string signed for an
// entry. Layout: "drift/v1/rev|" || tid || "|" || revoked_by || "|" || unix_nano.
//
// Plain text rather than JSON so a future shuffle of the JSON marshaller
// does not invalidate existing signatures. Exported because the revocation
// poller (in workspace) needs to verify entries without re-implementing
// this layout.
func RevocationSigningBytes(e domain.RevocationEntry) []byte {
	buf := make([]byte, 0, 64+len(e.TID)+len(e.RevokedBy))
	buf = append(buf, "drift/v1/rev|"...)
	buf = append(buf, e.TID...)
	buf = append(buf, '|')
	buf = append(buf, e.RevokedBy...)
	buf = append(buf, '|')
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(e.RevokedAt.UnixNano()))
	buf = append(buf, ts[:]...)
	return buf
}

// VerifyRevocationEntry checks the Ed25519 signature on a revocation entry
// against the revoking device's public key.
func VerifyRevocationEntry(e domain.RevocationEntry, pub ed25519.PublicKey) error {
	return dcrypto.Verify(pub, RevocationSigningBytes(e), e.Signature)
}
