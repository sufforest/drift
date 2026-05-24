package workspace

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/manifest"
	"github.com/sufforest/drift/internal/storage"
)

// MasterRotateResult summarizes a master rotation for the CLI.
type MasterRotateResult struct {
	OldFingerprint     []byte
	NewFingerprint     []byte
	RotationSequence   uint64
	ReEnrolledDevices  []string
	RevokedTokens      []string
	ManifestSequence   uint64
}

// RotateMaster generates a fresh master keypair, signs an announcement
// chained to the previous fingerprint with BOTH old and new master
// signatures, re-signs every enrollment cert under the new master, and
// updates the manifest.
//
// Other enrolled devices pick up the new master fingerprint on their
// next Manifest() read — the manifest's MasterRotationSequence advances,
// they fetch the announcement chain, verify each step, and update their
// pinned MasterFingerprint accordingly.
//
// All outstanding capability tokens are revoked: they carry the OLD
// MasterFingerprint and would fail bearer-side verification anyway.
func (w *Workspace) RotateMaster(ctx context.Context) (*MasterRotateResult, error) {
	if w.Master == nil {
		return nil, errors.New("workspace: only the primary device can rotate master in v1")
	}
	// Re-probe the provider rather than trusting the cached label —
	// otherwise a user who re-pointed the bucket between Init and now
	// could bypass this guard with a stale "conditional_put" value.
	caps, err := storage.ProbeCapabilities(ctx, w.Provider)
	if err != nil {
		return nil, fmt.Errorf("probe capabilities for rotation: %w", err)
	}
	if !caps.ConditionalPut {
		return nil, errors.New("workspace: master rotation requires conditional-PUT support; current provider does not")
	}
	now := w.now()

	newMaster, err := dcrypto.GenerateMasterKey()
	if err != nil {
		return nil, fmt.Errorf("generate new master: %w", err)
	}
	newMasterPub := newMaster.SignPub()
	oldMasterPub := w.Master.SignPub()
	newFP := sha256.Sum256(newMasterPub)
	oldFP := sha256.Sum256(oldMasterPub)

	result := &MasterRotateResult{
		OldFingerprint: oldFP[:],
		NewFingerprint: newFP[:],
	}

	// Build + doubly-sign the announcement at the next rotation seq.
	w.configMu.Lock()
	nextRotSeq := w.Config.LastObservedRotation + 1
	w.configMu.Unlock()

	announcement := domain.MasterRotationAnnouncement{
		Version:      1,
		WorkspaceID:  w.Config.WorkspaceID,
		Sequence:     nextRotSeq,
		OldMasterPub: oldMasterPub,
		NewMasterPub: newMasterPub,
		AnnouncedAt:  now,
	}
	signBody := MasterRotationSigningBytes(announcement)
	announcement.OldMasterSig = dcrypto.Sign(w.Master.SignPriv, signBody)
	announcement.NewMasterSig = dcrypto.Sign(newMaster.SignPriv, signBody)
	announcementBody, err := json.Marshal(announcement)
	if err != nil {
		return nil, fmt.Errorf("marshal announcement: %w", err)
	}
	// PutIfNotExists at the sequence key — refuses to overwrite a prior
	// announcement at this seq. Concurrent rotations from two primaries
	// (post drift link) collide here and only the winner publishes.
	//
	// The probe at line ~50 already established ConditionalPut=true; if
	// the provider now claims it's unsupported, that's a regression we
	// must NOT paper over with a plain Put (the whole point of M2 + M5-1
	// was to close this exact race). Hard error instead.
	if _, err := w.Provider.PutIfNotExists(ctx, domain.MasterRotationKey(nextRotSeq), announcementBody); err != nil {
		if errors.Is(err, domain.ErrPreconditionFailed) {
			return nil, fmt.Errorf("a rotation announcement already exists at sequence %d", nextRotSeq)
		}
		if errors.Is(err, domain.ErrConditionalUnsupported) {
			return nil, fmt.Errorf("provider returned conditional-PUT-unsupported after probing positive — refusing to fall back to plain PUT (atomicity guarantee would be lost)")
		}
		return nil, fmt.Errorf("upload announcement: %w", err)
	}
	result.RotationSequence = nextRotSeq

	// Pre-compute new enrollment certs for every existing non-master
	// device. The mutator inside RMW just stitches them in.
	newCert := func(did string, dev domain.Device) domain.Enrollment {
		return manifest.SignEnrollment(did, now.UnixNano(),
			dev.PublicKey, dev.EncryptKey, newMaster.SignPriv)
	}

	newMasterBox, err := newMaster.BoxPub()
	if err != nil {
		return nil, err
	}

	err = w.Writer.ReadModifyWrite(ctx, domain.ManifestKey, func(cur []byte) ([]byte, error) {
		m, err := manifest.Decrypt(cur, w.CPRK, w.Config.WorkspaceID)
		if err != nil {
			return nil, err
		}
		// Replace the master pseudo-device entry.
		m.Devices[domain.MasterDeviceID] = domain.Device{
			ID:         domain.MasterDeviceID,
			Name:       "master",
			PublicKey:  newMasterPub,
			EncryptKey: newMasterBox[:],
			EnrolledAt: now,
			LastSeen:   now,
		}
		// Re-issue enrollment certs under the new master for every
		// non-master device that still has one.
		if m.Enrollments == nil {
			m.Enrollments = map[string]domain.Enrollment{}
		}
		var reEnrolled []string
		for did, dev := range m.Devices {
			if did == domain.MasterDeviceID {
				continue
			}
			m.Enrollments[did] = newCert(did, dev)
			reEnrolled = append(reEnrolled, did)
		}
		result.ReEnrolledDevices = reEnrolled

		// Drop every outstanding token — they carry the OLD master
		// fingerprint and would fail bearer-side pin check.
		for tid := range m.ActiveTokens {
			result.RevokedTokens = append(result.RevokedTokens, tid)
			delete(m.ActiveTokens, tid)
		}

		m.MasterRotationSequence = nextRotSeq
		m.UpdatedAt = now
		m.Sequence++
		result.ManifestSequence = m.Sequence
		if err := manifest.Sign(m, w.Config.DeviceID, w.Device.SignPriv); err != nil {
			return nil, err
		}
		return manifest.Encrypt(m, w.CPRK)
	})
	if err != nil {
		return nil, err
	}

	// Persist the new master locally. Write to a versioned filename so
	// the user can recover the old master.json if they panic — we don't
	// delete it.
	if err := w.State.RotateMaster(newMaster, now); err != nil {
		return result, fmt.Errorf("persist new master: %w", err)
	}

	// Update workspace + config state in-memory.
	w.configMu.Lock()
	w.Master = newMaster
	w.Config.MasterFingerprint = newFP[:]
	w.Config.LastObservedRotation = nextRotSeq
	saveErr := w.State.SaveConfig(*w.Config)
	w.configMu.Unlock()
	if saveErr != nil {
		return result, fmt.Errorf("persist config: %w", saveErr)
	}

	// Revoke outstanding tokens explicitly so honest bearers see
	// "revoked" not "signature mismatch".
	for _, tid := range result.RevokedTokens {
		if err := w.Revoke(ctx, tid); err != nil {
			return result, fmt.Errorf("append revocation for %s: %w", tid, err)
		}
	}
	_ = w.auditEmitter().Emit(ctx, domain.AuditKindMasterRotate, w.Config.WorkspaceID, map[string]any{
		"old_fingerprint":   fmt.Sprintf("%x", result.OldFingerprint),
		"new_fingerprint":   fmt.Sprintf("%x", result.NewFingerprint),
		"rotation_sequence": result.RotationSequence,
		"re_enrolled":       result.ReEnrolledDevices,
		"revoked_tokens":    result.RevokedTokens,
	})
	return result, nil
}

// MasterRotationSigningBytes is the canonical byte form signed by both
// old + new master. Plain text so a future JSON marshaller change does
// not invalidate existing signatures.
func MasterRotationSigningBytes(a domain.MasterRotationAnnouncement) []byte {
	buf := make([]byte, 0, 256)
	buf = append(buf, "drift/v1/master-rotation|"...)
	buf = append(buf, a.WorkspaceID...)
	buf = append(buf, '|')
	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], a.Sequence)
	buf = append(buf, seqBuf[:]...)
	buf = append(buf, '|')
	buf = append(buf, base64.RawURLEncoding.EncodeToString(a.OldMasterPub)...)
	buf = append(buf, '|')
	buf = append(buf, base64.RawURLEncoding.EncodeToString(a.NewMasterPub)...)
	buf = append(buf, '|')
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(a.AnnouncedAt.UnixNano()))
	buf = append(buf, tsBuf[:]...)
	return buf
}

// VerifyMasterRotation checks an announcement's doubly-signed chain link.
// previousFP is the fingerprint the verifying device currently trusts;
// SHA-256(announcement.OldMasterPub) must equal previousFP, both
// signatures must verify under their respective pubkeys.
func VerifyMasterRotation(a domain.MasterRotationAnnouncement, previousFP []byte) error {
	if len(a.OldMasterPub) != ed25519.PublicKeySize || len(a.NewMasterPub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: malformed master pubkey", domain.ErrSignatureInvalid)
	}
	gotOldFP := sha256.Sum256(a.OldMasterPub)
	if !bytes.Equal(gotOldFP[:], previousFP) {
		return fmt.Errorf("%w: announcement OldMasterPub does not match our pinned fingerprint", domain.ErrSignatureInvalid)
	}
	body := MasterRotationSigningBytes(a)
	if err := dcrypto.Verify(ed25519.PublicKey(a.OldMasterPub), body, a.OldMasterSig); err != nil {
		return fmt.Errorf("old master sig: %w", err)
	}
	if err := dcrypto.Verify(ed25519.PublicKey(a.NewMasterPub), body, a.NewMasterSig); err != nil {
		return fmt.Errorf("new master sig: %w", err)
	}
	return nil
}
