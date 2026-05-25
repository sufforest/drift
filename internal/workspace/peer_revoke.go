package workspace

import (
	"context"
	"errors"
	"fmt"

	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/manifest"
	"github.com/sufforest/drift/internal/token"
)

// PeerRevokeResult summarizes a bearer-peer revocation.
type PeerRevokeResult struct {
	DeviceID string
	JTI      string
	// AlreadyRevoked is true when the device's PeerCredRecord was
	// already marked revoked at the time of the call — operation is
	// idempotent and the manifest sequence does not advance.
	AlreadyRevoked bool
	Sequence       uint64
}

// PeerRevoke flips Manifest.PeerCreds[deviceID].Revoked to true AND
// appends the device's current JTI to revocations.enc. Both halves are
// needed for full revocation:
//
//   - Manifest gate (PeerCreds[did].Revoked): drift mount on the peer
//     checks this BEFORE doing any R2 work. Fast-fail without needing
//     to talk to the network.
//   - Revocations.enc entry: the existing token-redemption poller
//     watches this object; in-flight rclone sessions notice within one
//     poll cycle and start refusing. This catches the case where the
//     peer is already mounted with a still-valid JWT.
//
// Master-only — the revocation entry in revocations.enc is signed by
// this device's priv (which chains via Enrollment to the master),
// matching the existing token-revocation gate.
//
// Idempotent. Refusing a device that has never been issued a PeerCred
// errors clearly so operators don't silently apply revoke to the wrong
// device id.
//
// After revoke, the peer's locally-stored PeerCred bytes are unchanged
// — but the peer's next MountDirect attempt notices the Revoked flag
// and refuses. The underlying R2 JWT still works against R2 itself
// until its embedded ExpiresAt (typically 24h max under DD-9 defaults).
// For tighter cutoff, follow up with `drift parent set` to rotate the
// R2 token, which invalidates every JWT signed under the old secret.
func (w *Workspace) PeerRevoke(ctx context.Context, deviceID string) (*PeerRevokeResult, error) {
	if w.Master == nil {
		return nil, errors.New("workspace: only the primary device can revoke bearer-mode peers")
	}
	if deviceID == "" {
		return nil, errors.New("workspace: device id required")
	}

	result := &PeerRevokeResult{DeviceID: deviceID}

	// Phase 1: flip the manifest record. The mount-side gate reads
	// Manifest.PeerCreds[did].Revoked on every operation, so this is
	// the fast-fail channel.
	err := w.Writer.ReadModifyWrite(ctx, domain.ManifestKey, func(cur []byte) ([]byte, error) {
		m, err := manifest.Decrypt(cur, w.CPRK, w.Config.WorkspaceID)
		if err != nil {
			return nil, err
		}
		rec, ok := m.PeerCreds[deviceID]
		if !ok {
			return nil, fmt.Errorf("workspace: device %s has no bearer PeerCred record — nothing to revoke", deviceID)
		}
		result.JTI = rec.JTI
		if rec.Revoked {
			result.AlreadyRevoked = true
			return cur, nil
		}
		rec.Revoked = true
		m.PeerCreds[deviceID] = rec
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
		// No further state change needed; the manifest already gates,
		// and revocations.enc presumably already has the JTI from a
		// prior call. Still emit an audit entry for the attempted
		// re-revoke so forensics has a record.
		_ = w.auditEmitter().Emit(ctx, domain.AuditKindPeerCredRevoked, deviceID, map[string]any{
			"jti":          result.JTI,
			"already_revoked": true,
		})
		return result, nil
	}

	// Phase 2: append the JTI to revocations.enc via the existing
	// token-revocation primitive. We reuse it because the wire format
	// + signing protocol are exactly what we want here: a master-
	// chained signed entry containing the JTI as the subject. The
	// existing redeem-time poller will treat the JTI like any other
	// revoked TID (it doesn't differentiate kinds).
	w.configMu.Lock()
	floor := w.Config.MinRevocationsSequence
	w.configMu.Unlock()
	revoker := &token.Revoker{
		Provider:   w.Provider,
		Writer:     w.Writer,
		DeviceID:   w.Config.DeviceID,
		DeviceSign: w.Device.SignPriv,
		Now:        w.now,
		MinSeq:     floor,
	}
	revRes, err := revoker.Revoke(ctx, result.JTI)
	if err != nil {
		return result, fmt.Errorf("append JTI %s to revocations.enc: %w (manifest flag is set but in-flight sessions will not notice until this is retried)", result.JTI, err)
	}
	w.configMu.Lock()
	if revRes.NewSequence > w.Config.MinRevocationsSequence {
		w.Config.MinRevocationsSequence = revRes.NewSequence
		_ = w.State.SaveConfig(*w.Config)
	}
	w.configMu.Unlock()

	_ = w.auditEmitter().Emit(ctx, domain.AuditKindPeerCredRevoked, deviceID, map[string]any{
		"jti": result.JTI,
	})
	return result, nil
}
