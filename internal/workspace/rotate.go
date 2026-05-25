package workspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/manifest"
	"github.com/sufforest/drift/internal/storage"
)

// CompartmentRotateResult summarizes a compartment rotation for the CLI.
type CompartmentRotateResult struct {
	Compartment    string
	OldKeyVersion  int
	NewKeyVersion  int
	RevokedTokens  []string
	Sequence       uint64
}

// CompartmentRotate generates a fresh symmetric key for the named
// compartment, re-seals it for every enrolled device, bumps KeyVersion,
// and revokes every outstanding token whose Scope includes this
// compartment (their embedded compartment key is now stale).
//
// Existing chunks under compartments/<name>/ remain decryptable with the
// OLD key. Anyone with that key keeps read access to existing data until
// `drift gc --reencrypt` (v2) sweeps; new writes use only the new key.
func (w *Workspace) CompartmentRotate(ctx context.Context, name string) (*CompartmentRotateResult, error) {
	if w.Master == nil {
		return nil, errors.New("workspace: only the primary device can rotate compartments in v1")
	}
	if err := domain.ValidCompartmentName(name); err != nil {
		return nil, err
	}

	result := &CompartmentRotateResult{Compartment: name}

	err := w.Writer.ReadModifyWrite(ctx, domain.ManifestKey, func(cur []byte) ([]byte, error) {
		m, err := manifest.Decrypt(cur, w.CPRK, w.Config.WorkspaceID)
		if err != nil {
			return nil, err
		}
		c, ok := m.Compartments[name]
		if !ok {
			return nil, fmt.Errorf("%w: %s", domain.ErrCompartmentUnknown, name)
		}

		newKey, err := dcrypto.GenerateCompartmentKey()
		if err != nil {
			return nil, err
		}
		sealed := map[string][]byte{}
		for did, dev := range m.Devices {
			if len(dev.EncryptKey) != dcrypto.X25519KeySize {
				continue
			}
			// DD-8: don't re-seal the new CK for devices whose
			// CompartmentScope excludes this vol. Without this check, a
			// rotation would silently re-grant access to previously-
			// scoped-out peers — exactly the security boundary DD-8
			// promises to maintain.
			if !dev.HasCompartmentAccess(name) {
				continue
			}
			var pub [dcrypto.X25519KeySize]byte
			copy(pub[:], dev.EncryptKey)
			ct, err := dcrypto.SealFor(pub, newKey)
			if err != nil {
				return nil, fmt.Errorf("seal new key for %s: %w", did, err)
			}
			sealed[did] = ct
		}

		result.OldKeyVersion = c.KeyVersion
		c.EncryptedKeys = sealed
		c.KeyVersion++
		m.Compartments[name] = c
		result.NewKeyVersion = c.KeyVersion

		// Drop every active token whose scope touches this compartment —
		// they embed the OLD key in their credentials blob and would
		// produce unreadable data if they continued to mount.
		for tid, rec := range m.ActiveTokens {
			for _, s := range rec.Scope {
				if s == name {
					delete(m.ActiveTokens, tid)
					result.RevokedTokens = append(result.RevokedTokens, tid)
					break
				}
			}
		}

		m.UpdatedAt = w.now()
		m.Sequence++
		result.Sequence = m.Sequence
		if err := manifest.Sign(m, w.Config.DeviceID, w.Device.SignPriv); err != nil {
			return nil, err
		}
		return manifest.Encrypt(m, w.CPRK)
	})
	if err != nil {
		return nil, err
	}

	// Best-effort: also append explicit revocation entries so honest
	// clients hit ErrTokenRevoked rather than the more confusing
	// "manifest doesn't list your tid". Failure here is benign because
	// the tokens are functionally dead — they hold the old compartment
	// key and can't decrypt any new chunks.
	for _, tid := range result.RevokedTokens {
		if err := w.Revoke(ctx, tid); err != nil {
			// Stop on first error rather than silently continue; user
			// can re-run individual `drift revoke` calls if needed.
			return result, fmt.Errorf("append revocation for %s: %w", tid, err)
		}
	}
	_ = w.auditEmitter().Emit(ctx, domain.AuditKindCompartmentRotate, name, map[string]any{
		"old_key_version": result.OldKeyVersion,
		"new_key_version": result.NewKeyVersion,
		"revoked_tokens":  result.RevokedTokens,
	})
	return result, nil
}

// CPRKRotateResult summarizes a CPRK rotation for the CLI.
type CPRKRotateResult struct {
	OldEpoch       uint64
	NewEpoch       uint64
	SealedDevices  []string
	FailedDevices  []string // sealing or upload failed for these — re-running `drift rotate cprk` bumps the epoch again and re-attempts every device
	RevokedTokens  []string
	Sequence       uint64
}

// RotateCPRK derives a fresh Control Plane Read Key under a new HKDF
// epoch, re-encrypts the manifest under the new key, writes per-device
// sealed handoff blobs for every non-master device, and revokes all
// outstanding tokens (their credentials blob embeds the OLD CPRK).
//
// Primary device updates its own LocalConfig.CPRKEpoch on success.
// Secondary devices pick up the new key on their next Manifest() call —
// the AEAD failure under the old key triggers an automatic refresh from
// the sealed handoff blob.
func (w *Workspace) RotateCPRK(ctx context.Context) (*CPRKRotateResult, error) {
	if w.Master == nil {
		return nil, errors.New("workspace: only the primary device can rotate CPRK in v1")
	}
	w.configMu.Lock()
	oldEpoch := w.Config.CPRKEpoch
	w.configMu.Unlock()
	newEpoch := oldEpoch + 1

	newCPRK, err := dcrypto.DeriveCPRK(w.Master.Root, w.Config.WorkspaceID, newEpoch)
	if err != nil {
		return nil, fmt.Errorf("derive new cprk: %w", err)
	}

	result := &CPRKRotateResult{
		OldEpoch: oldEpoch,
		NewEpoch: newEpoch,
	}

	// Read the current manifest under the OLD key, mutate, write back
	// under the NEW key. Both the read and the write use the same
	// ReadModifyWrite call — the writer doesn't know about CPRKs, so
	// we wrap the mutate closure to switch keys mid-flight.
	err = w.Writer.ReadModifyWrite(ctx, domain.ManifestKey, func(cur []byte) ([]byte, error) {
		m, err := manifest.Decrypt(cur, w.CPRK, w.Config.WorkspaceID)
		if err != nil {
			return nil, err
		}
		// Drop every outstanding token — their credentials blob holds
		// the old CPRK and can no longer decrypt the manifest.
		for tid := range m.ActiveTokens {
			result.RevokedTokens = append(result.RevokedTokens, tid)
			delete(m.ActiveTokens, tid)
		}
		m.UpdatedAt = w.now()
		m.Sequence++
		result.Sequence = m.Sequence
		if err := manifest.Sign(m, w.Config.DeviceID, w.Device.SignPriv); err != nil {
			return nil, err
		}
		return manifest.Encrypt(m, newCPRK)
	})
	if err != nil {
		return nil, err
	}

	// Manifest now lives under newCPRK. Read it (under the new key) so
	// we can seal the new CPRK for every secondary device.
	cipher, err := w.Provider.Get(ctx, domain.ManifestKey)
	if err != nil {
		return nil, fmt.Errorf("re-fetch manifest after rotation: %w", err)
	}
	m, err := manifest.Decrypt(cipher, newCPRK, w.Config.WorkspaceID)
	if err != nil {
		return nil, fmt.Errorf("re-decrypt manifest after rotation: %w", err)
	}

	written, failed := writeCPRKHandoffs(ctx, w.Provider, m, newEpoch, newCPRK, w.Master.SignPub(), w.Config.DeviceID)
	result.SealedDevices = written
	result.FailedDevices = failed

	// Update primary's own state: cache the new CPRK + bump epoch in
	// LocalConfig. Persist cprk.key BEFORE the config — Load() prefers
	// the on-disk CPRK over re-deriving, so a stale cprk.key paired
	// with the new epoch would deadlock the primary out of its own
	// manifest.
	if err := w.State.SaveCPRK(newCPRK); err != nil {
		return result, fmt.Errorf("persist new cprk: %w", err)
	}
	w.configMu.Lock()
	w.CPRK = newCPRK
	w.Config.CPRKEpoch = newEpoch
	saveErr := w.State.SaveConfig(*w.Config)
	w.configMu.Unlock()
	if saveErr != nil {
		return result, fmt.Errorf("persist new epoch: %w", saveErr)
	}

	// Best-effort: emit revocation entries for the dropped tokens so the
	// bearer-side error is "revoked" rather than "tid not in manifest".
	for _, tid := range result.RevokedTokens {
		if err := w.Revoke(ctx, tid); err != nil {
			return result, fmt.Errorf("append revocation for %s: %w", tid, err)
		}
	}
	_ = w.auditEmitter().Emit(ctx, domain.AuditKindCPRKRotate, w.Config.WorkspaceID, map[string]any{
		"old_epoch":      result.OldEpoch,
		"new_epoch":      result.NewEpoch,
		"sealed_devices": result.SealedDevices,
		"revoked_tokens": result.RevokedTokens,
	})
	return result, nil
}

// writeCPRKHandoffs seals newCPRK for every non-master, non-self device's
// X25519 pubkey and uploads the blob at .drift/cprk/<did>.enc. The running
// (primary) device's own ID is skipped — it re-derives CPRK directly from
// master.Root. Returns the list of devices written for and a separate
// list of devices that FAILED (so the caller can surface partial
// progress instead of aborting after the manifest has already moved to
// the new key).
func writeCPRKHandoffs(ctx context.Context, p storage.Provider, m *domain.Manifest, epoch uint64, newCPRK, masterPub []byte, selfID string) (written, failed []string) {
	body, err := json.Marshal(domain.CPRKHandoff{
		Epoch:     epoch,
		CPRK:      newCPRK,
		MasterPub: masterPub,
	})
	if err != nil {
		// Per-marshal error means EVERY device handoff fails. List them
		// as failed so the caller can surface.
		for did, dev := range m.Devices {
			if did == domain.MasterDeviceID || did == selfID {
				continue
			}
			if len(dev.EncryptKey) == dcrypto.X25519KeySize {
				failed = append(failed, did)
			}
		}
		return written, failed
	}
	for did, dev := range m.Devices {
		if did == domain.MasterDeviceID || did == selfID {
			continue
		}
		if len(dev.EncryptKey) != dcrypto.X25519KeySize {
			continue
		}
		var pub [dcrypto.X25519KeySize]byte
		copy(pub[:], dev.EncryptKey)
		sealed, err := dcrypto.SealFor(pub, body)
		if err != nil {
			failed = append(failed, did)
			continue
		}
		if err := p.Put(ctx, domain.CPRKKeyFor(did), sealed); err != nil {
			failed = append(failed, did)
			continue
		}
		written = append(written, did)
	}
	return written, failed
}
