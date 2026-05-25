package workspace

import (
	"context"
	"errors"
	"fmt"

	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/manifest"
)

// CompartmentUngrantResult summarizes a scope removal + rotation.
type CompartmentUngrantResult struct {
	DeviceID    string
	Compartment string
	// AlreadyRevoked is true when the operation was a no-op: the device
	// wasn't scoped for this compartment to begin with.
	AlreadyRevoked bool
	OldKeyVersion  int
	NewKeyVersion  int
	// RevokedTokens lists every token whose Scope touched this
	// compartment. After rotation those tokens' embedded CKs are stale;
	// we drop them from ActiveTokens AND append explicit revocation
	// entries so honest clients hit ErrTokenRevoked instead of a
	// confusing "no such token" error.
	RevokedTokens []string
	// Sequence is the manifest sequence after the write. Zero when
	// AlreadyRevoked is true (no mutation).
	Sequence uint64
}

// CompartmentUngrant atomically (a) removes a compartment from a
// device's CompartmentScope AND (b) rotates the compartment's CK so the
// ungranted device cannot decrypt FUTURE data written to it.
//
// Master-only — the rotation step needs primary's box priv to read the
// current CK before generating its replacement.
//
// Important: this does NOT take back the plaintext CK the ungranted
// device may have cached in memory or pinned to disk. That CK still
// decrypts every blob written BEFORE this operation. Going forward, the
// vol uses a new CK and the ungranted device is not sealed for it.
//
// Refuses with a clear error if:
//   - The device has empty/nil CompartmentScope (full-access). The
//     operator must use `drift device revoke` for full revocation;
//     ungrant is a per-compartment narrowing tool, not a substitute.
//   - The device id is the master pseudo-device (master never has a
//     scope — full access by definition).
//   - The device or compartment doesn't exist.
//
// Idempotent: if the device is already not scoped for the compartment,
// returns AlreadyRevoked=true with no manifest write.
func (w *Workspace) CompartmentUngrant(ctx context.Context, deviceID, compartment string) (*CompartmentUngrantResult, error) {
	if w.Master == nil {
		return nil, errors.New("workspace: only the primary device can ungrant compartment access (master key required to rotate)")
	}
	if deviceID == "" {
		return nil, errors.New("workspace: device id required")
	}
	if compartment == "" {
		return nil, errors.New("workspace: compartment name required")
	}
	if err := domain.ValidCompartmentName(compartment); err != nil {
		return nil, fmt.Errorf("workspace: %w", err)
	}
	if deviceID == domain.MasterDeviceID {
		return nil, errors.New("workspace: cannot ungrant scope from the master pseudo-device (it always has full access)")
	}

	result := &CompartmentUngrantResult{DeviceID: deviceID, Compartment: compartment}

	// Pre-check (TOCTOU with the RMW that follows is benign; the RMW is
	// authoritative). Lets us short-circuit the no-op + full-scope cases
	// without entering the RMW + paying for a rotation.
	m, err := w.Manifest(ctx)
	if err != nil {
		return nil, err
	}
	dev, ok := m.Devices[deviceID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", domain.ErrDeviceUnknown, deviceID)
	}
	if _, ok := m.Compartments[compartment]; !ok {
		return nil, fmt.Errorf("%w: %s", domain.ErrCompartmentUnknown, compartment)
	}
	if len(dev.CompartmentScope) == 0 {
		// Full-scope device — ungrant doesn't apply. Operator wants a
		// stronger primitive (device revoke) for full removal.
		return nil, fmt.Errorf("workspace: device %s has no scope restriction (full access) — use `drift device revoke` for full removal, ungrant is for narrowing scoped peers", deviceID)
	}
	if !scopeContains(dev.CompartmentScope, compartment) {
		result.AlreadyRevoked = true
		return result, nil
	}
	// CRITICAL: refuse to ungrant the LAST entry in a device's scope.
	// Our backward-compat semantics treat empty/nil CompartmentScope as
	// "no restriction = full access" (so pre-DD-8 manifests decode into
	// devices with full access). If ungrant left scope as []string{},
	// the device would silently upgrade to full access — the exact
	// opposite of operator intent.
	//
	// Operators who want a device to have NO access should `drift
	// device revoke` instead. Ungrant is a narrowing tool, not a full
	// revocation primitive.
	if len(dev.CompartmentScope) == 1 {
		return nil, fmt.Errorf("workspace: refusing to ungrant the only vol in device %s's scope — that would leave the device with empty scope, which our model treats as full access. Use `drift device revoke %s` to fully revoke this device's enrollment", deviceID, deviceID)
	}

	// RMW: remove the compartment from the device's scope AND rotate the
	// CK in one atomic update. Doing both in a single transaction means
	// there's no window where the device is unscoped but the CK hasn't
	// been rotated (which would leave the device's still-cached CK
	// effective for new writes until the rotation completes).
	err = w.Writer.ReadModifyWrite(ctx, domain.ManifestKey, func(cur []byte) ([]byte, error) {
		m, err := manifest.Decrypt(cur, w.CPRK, w.Config.WorkspaceID)
		if err != nil {
			return nil, err
		}
		dev, ok := m.Devices[deviceID]
		if !ok {
			return nil, fmt.Errorf("%w: %s", domain.ErrDeviceUnknown, deviceID)
		}
		c, ok := m.Compartments[compartment]
		if !ok {
			return nil, fmt.Errorf("%w: %s", domain.ErrCompartmentUnknown, compartment)
		}
		// Re-check (the manifest might have shifted under us between
		// Manifest() and the RMW). If the state has converged to
		// already-revoked, treat as no-op.
		if len(dev.CompartmentScope) == 0 {
			return nil, fmt.Errorf("workspace: device %s has no scope restriction (full access)", deviceID)
		}
		if !scopeContains(dev.CompartmentScope, compartment) {
			result.AlreadyRevoked = true
			return cur, nil
		}

		// 1) Remove the compartment from the device's scope.
		newScope := make([]string, 0, len(dev.CompartmentScope)-1)
		for _, s := range dev.CompartmentScope {
			if s != compartment {
				newScope = append(newScope, s)
			}
		}
		dev.CompartmentScope = newScope
		m.Devices[deviceID] = dev

		// 2) Rotate the CK. New key sealed only for devices whose
		// post-mutation scope still includes this compartment. The
		// just-ungranted device is excluded because we removed it
		// from scope above.
		newKey, err := dcrypto.GenerateCompartmentKey()
		if err != nil {
			return nil, err
		}
		sealed := map[string][]byte{}
		for did, d := range m.Devices {
			if len(d.EncryptKey) != dcrypto.X25519KeySize {
				continue
			}
			if !d.HasCompartmentAccess(compartment) {
				continue
			}
			var pub [dcrypto.X25519KeySize]byte
			copy(pub[:], d.EncryptKey)
			ct, err := dcrypto.SealFor(pub, newKey)
			if err != nil {
				return nil, fmt.Errorf("seal new key for %s: %w", did, err)
			}
			sealed[did] = ct
		}
		result.OldKeyVersion = c.KeyVersion
		c.EncryptedKeys = sealed
		c.KeyVersion++
		m.Compartments[compartment] = c
		result.NewKeyVersion = c.KeyVersion

		// 3) Drop every active token whose scope touches this
		// compartment — they embed the OLD key and would produce
		// unreadable data if redeemed against newly-written chunks.
		for tid, rec := range m.ActiveTokens {
			for _, s := range rec.Scope {
				if s == compartment {
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

	if result.AlreadyRevoked {
		return result, nil
	}

	// Append explicit revocation entries so honest clients redeeming
	// tokens that touched this compartment get a clear ErrTokenRevoked
	// rather than a manifest-doesn't-have-you error.
	for _, tid := range result.RevokedTokens {
		if err := w.Revoke(ctx, tid); err != nil {
			return result, fmt.Errorf("append revocation for %s: %w", tid, err)
		}
	}

	_ = w.auditEmitter().Emit(ctx, domain.AuditKindCompartmentUngrant, deviceID, map[string]any{
		"compartment":     compartment,
		"old_key_version": result.OldKeyVersion,
		"new_key_version": result.NewKeyVersion,
		"revoked_tokens":  result.RevokedTokens,
	})

	return result, nil
}
