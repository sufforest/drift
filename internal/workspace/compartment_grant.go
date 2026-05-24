package workspace

import (
	"context"
	"errors"
	"fmt"

	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/manifest"
)

// CompartmentGrantResult summarizes what CompartmentGrant changed.
type CompartmentGrantResult struct {
	DeviceID    string
	Compartment string
	// AlreadyGranted is true when the grant was a no-op: either the
	// device had nil/empty scope (full access) or the compartment was
	// already in its scope.
	AlreadyGranted bool
	// Sequence is the manifest sequence after the write. Zero if
	// AlreadyGranted was true (no mutation).
	Sequence uint64
}

// CompartmentGrant retroactively grants a device access to a compartment.
// Master-only — only the primary holds enough material to seal the CK
// for the target device (it decrypts CK with its own X25519 priv, then
// re-seals for the target).
//
// The operation:
//
//  1. Validates the device + compartment exist.
//  2. If the device's CompartmentScope is empty (full access), the grant
//     is a logical no-op — the device already has every compartment
//     sealed for it. Returns AlreadyGranted=true with no manifest write.
//  3. If the compartment is already in the device's scope, also no-op.
//  4. Otherwise: unseals the CK using the primary's box priv, seals it
//     for the target device's X25519 pub, adds the compartment to the
//     device's CompartmentScope, and re-signs the manifest.
//
// Idempotent: re-running on an already-granted (device, compartment) is
// a no-op and does not advance the manifest sequence.
func (w *Workspace) CompartmentGrant(ctx context.Context, deviceID, compartment string) (*CompartmentGrantResult, error) {
	if w.Master == nil {
		return nil, errors.New("workspace: only the primary device can grant compartment access (master key required to re-seal)")
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
		return nil, errors.New("workspace: cannot grant scope to the master pseudo-device (it always has full access)")
	}

	result := &CompartmentGrantResult{DeviceID: deviceID, Compartment: compartment}

	// Pre-check for no-op cases (full-scope device, already-granted) so we
	// can short-circuit before entering the RMW and avoid a wasted PUT of
	// identical manifest bytes. The pre-check has a TOCTOU window with the
	// RMW that follows, but both possible races are benign: (a) primary
	// concurrently re-scopes the target → next CompartmentGrant call
	// converges, (b) compartment deleted between check and RMW → the RMW
	// catches it and errors. The RMW is still the authoritative writer.
	m, err := w.Manifest(ctx)
	if err != nil {
		return nil, err
	}
	if dev, ok := m.Devices[deviceID]; !ok {
		return nil, fmt.Errorf("%w: %s", domain.ErrDeviceUnknown, deviceID)
	} else if _, ok := m.Compartments[compartment]; !ok {
		return nil, fmt.Errorf("%w: %s", domain.ErrCompartmentUnknown, compartment)
	} else if len(dev.CompartmentScope) == 0 {
		// Full-scope device — already has access; no manifest mutation needed.
		result.AlreadyGranted = true
		return result, nil
	} else if scopeContains(dev.CompartmentScope, compartment) {
		// Already explicitly scoped. Check the sealed key is also present
		// (so a self-repair grant can still proceed if it isn't); if both
		// are present, it's a no-op.
		if _, hasSeal := m.Compartments[compartment].EncryptedKeys[deviceID]; hasSeal {
			result.AlreadyGranted = true
			return result, nil
		}
	}

	err = w.Writer.ReadModifyWrite(ctx, domain.ManifestKey, func(cur []byte) ([]byte, error) {
		m, err := manifest.Decrypt(cur, w.CPRK, w.Config.WorkspaceID)
		if err != nil {
			return nil, err
		}
		dev, ok := m.Devices[deviceID]
		if !ok {
			return nil, fmt.Errorf("%w: %s", domain.ErrDeviceUnknown, deviceID)
		}
		comp, ok := m.Compartments[compartment]
		if !ok {
			return nil, fmt.Errorf("%w: %s", domain.ErrCompartmentUnknown, compartment)
		}

		// The full-scope and already-granted no-op cases were caught by the
		// pre-RMW check. Reaching here means we're either (a) adding a new
		// compartment to a scoped device or (b) repairing a missing sealed
		// CK for an already-scoped device. Both call for a real mutation.

		// Mutation: unseal the CK with primary's box priv, seal for the
		// target device. The primary always has a sealed copy of every
		// compartment's CK (it created them).
		myBoxPub, err := w.Device.BoxPub()
		if err != nil {
			return nil, err
		}
		sealedForMe, ok := comp.EncryptedKeys[w.Config.DeviceID]
		if !ok {
			return nil, fmt.Errorf("workspace: primary lacks a sealed CK for compartment %q — manifest is inconsistent", compartment)
		}
		plainCK, err := dcrypto.Open(myBoxPub, w.Device.BoxPriv, sealedForMe)
		if err != nil {
			return nil, fmt.Errorf("unseal CK for %q: %w", compartment, err)
		}
		if len(dev.EncryptKey) != dcrypto.X25519KeySize {
			return nil, fmt.Errorf("workspace: target device %s has no valid X25519 pubkey", deviceID)
		}
		var targetBoxPub [dcrypto.X25519KeySize]byte
		copy(targetBoxPub[:], dev.EncryptKey)
		sealedForTarget, err := dcrypto.SealFor(targetBoxPub, plainCK)
		if err != nil {
			return nil, fmt.Errorf("seal CK for %s: %w", deviceID, err)
		}
		if comp.EncryptedKeys == nil {
			comp.EncryptedKeys = map[string][]byte{}
		}
		comp.EncryptedKeys[deviceID] = sealedForTarget
		m.Compartments[compartment] = comp

		// Add to device's CompartmentScope, sorted+deduped for canonical
		// manifest bytes.
		if !scopeContains(dev.CompartmentScope, compartment) {
			dev.CompartmentScope = normalizeScope(append(dev.CompartmentScope, compartment))
		}
		m.Devices[deviceID] = dev

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

	if !result.AlreadyGranted {
		_ = w.auditEmitter().Emit(ctx, domain.AuditKindCompartmentGrant, deviceID, map[string]any{
			"compartment": compartment,
		})
	}
	return result, nil
}
