package workspace

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/sufforest/drift/internal/credentials"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/manifest"
)

// PeerCredDefaultTTL is the standard lifetime of a freshly-issued
// bearer-mode PeerCred. Short enough that revocation propagates within
// a workday even if the peer never connects back to refresh; long
// enough that an always-on peer doesn't need to refresh more than
// twice a day.
const PeerCredDefaultTTL = 24 * time.Hour

// PeerCredMaxTTL caps how long an operator can request a single
// PeerCred to live. The cap exists because R2 has no way to honor
// drift's revocations.enc — a leaked PeerCred is usable against R2
// until its embedded JWT expires. The shorter we keep PeerCred TTLs,
// the smaller the post-revoke window of exposure. 7 days matches the
// typical "I'm on vacation, don't want to refresh" tolerance without
// stretching the leak-recovery window past most incident-response SLAs.
const PeerCredMaxTTL = 7 * 24 * time.Hour

// IssuePeerCred mints a DD-9 bearer-mode credential for the named
// enrolled device. Returns the fully-signed PeerCred ready to seal for
// the peer (via the pairing or refresh handshake) and atomically
// updates the manifest's PeerCreds record.
//
// Master-only: signing the cred + writing the PeerCreds record both
// require the master key. The R2 JWT inside is minted using the
// primary's parent secret as the HMAC key (R2's local-sign mechanism),
// so the primary necessarily has both halves at hand.
//
// Scope semantics:
//   - scope must be non-empty. We deliberately do NOT support
//     full-bucket bearer creds — every bearer-mode peer must declare
//     which compartments it can touch. The blast radius of a leaked
//     full-scope bearer would defeat the point of bearer-mode.
//   - every entry must name a compartment that currently exists in
//     the manifest. We refuse to issue for "future" compartments.
//   - if the target device has a CompartmentScope set in its Device
//     entry (DD-8), the issued scope must be a subset. The Device
//     entry is the authority on what the peer is allowed to see; this
//     primitive can't elevate.
//
// TTL semantics:
//   - ttl <= 0 → use PeerCredDefaultTTL.
//   - ttl > PeerCredMaxTTL → error.
//   - RefreshAt = IssuedAt + ttl/2 (half-life).
func (w *Workspace) IssuePeerCred(ctx context.Context, deviceID string, scope []string, ttl time.Duration) (*credentials.PeerCred, error) {
	if w.Master == nil {
		return nil, errors.New("workspace: only the primary device can issue bearer-mode PeerCreds")
	}
	if deviceID == "" {
		return nil, errors.New("workspace: device id required")
	}
	if deviceID == domain.MasterDeviceID {
		return nil, errors.New("workspace: cannot issue PeerCred for the master pseudo-device")
	}
	if len(scope) == 0 {
		return nil, errors.New("workspace: PeerCred scope must be non-empty (bearer-mode peers cannot have full-bucket access)")
	}
	for _, name := range scope {
		if err := domain.ValidCompartmentName(name); err != nil {
			return nil, fmt.Errorf("workspace: invalid compartment in scope: %w", err)
		}
	}
	if ttl <= 0 {
		ttl = PeerCredDefaultTTL
	}
	if ttl > PeerCredMaxTTL {
		return nil, fmt.Errorf("workspace: PeerCred TTL %s exceeds max %s — pick a shorter ttl or rotate more often", ttl, PeerCredMaxTTL)
	}

	parent, err := w.State.LoadParent()
	if err != nil {
		return nil, fmt.Errorf("workspace: cannot issue PeerCred — no parent S3 credential on this device (load: %w)", err)
	}

	// Pre-flight against the manifest so we error before any cred
	// minting (which is more expensive). The RMW later re-checks under
	// lock; this is just for fast error messages.
	m, err := w.Manifest(ctx)
	if err != nil {
		return nil, err
	}
	dev, ok := m.Devices[deviceID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", domain.ErrDeviceUnknown, deviceID)
	}
	for _, name := range scope {
		if _, ok := m.Compartments[name]; !ok {
			return nil, fmt.Errorf("workspace: scope refers to non-existent compartment %q", name)
		}
		if !dev.HasCompartmentAccess(name) {
			return nil, fmt.Errorf("workspace: device %s is not scoped for compartment %q (device scope: %v) — cannot issue a PeerCred that exceeds the device's own bounds", deviceID, name, dev.CompartmentScope)
		}
	}

	signed, err := w.buildSignedPeerCred(ctx, deviceID, scope, ttl, parent)
	if err != nil {
		return nil, err
	}
	now := signed.IssuedAt
	exp := signed.ExpiresAt
	jti := signed.JTI

	// Atomically update the manifest record under RMW. The record is
	// what enforces workspace-side revocation: subsequent reads notice
	// .Revoked=true and refuse to use the cred even if the embedded
	// JWT is still valid against R2.
	err = w.Writer.ReadModifyWrite(ctx, domain.ManifestKey, func(cur []byte) ([]byte, error) {
		m, err := manifest.Decrypt(cur, w.CPRK, w.Config.WorkspaceID)
		if err != nil {
			return nil, err
		}
		dev, ok := m.Devices[deviceID]
		if !ok {
			return nil, fmt.Errorf("%w: %s (raced with revoke?)", domain.ErrDeviceUnknown, deviceID)
		}
		// Re-validate scope under lock. The pre-check ran before we
		// minted the R2 cred and could be stale by now: a concurrent
		// vol delete or vol ungrant could have invalidated entries we
		// already baked into the signed PeerCred. Aborting here is
		// safer than persisting a cred whose scope no longer matches
		// the live manifest.
		for _, name := range scope {
			if _, ok := m.Compartments[name]; !ok {
				return nil, fmt.Errorf("workspace: scope refers to compartment %q that was removed during issuance — retry", name)
			}
			if !dev.HasCompartmentAccess(name) {
				return nil, fmt.Errorf("workspace: device %s scope changed during issuance (no longer covers %q) — retry", deviceID, name)
			}
		}
		if m.PeerCreds == nil {
			m.PeerCreds = map[string]domain.PeerCredRecord{}
		}
		m.PeerCreds[deviceID] = domain.PeerCredRecord{
			DeviceID:  deviceID,
			JTI:       jti,
			IssuedAt:  now,
			ExpiresAt: exp,
			Scope:     append([]string(nil), signed.Scope...),
			Mode:      signed.Mode,
			// Revoked left false. Re-issuance for an already-revoked
			// device is allowed: ops may want to re-enable a peer they
			// previously revoked without going through the full pairing
			// flow again. The new JTI is fresh and the .Revoked flag
			// resets to false here.
		}
		m.UpdatedAt = now
		m.Sequence++
		if err := manifest.Sign(m, w.Config.DeviceID, w.Device.SignPriv); err != nil {
			return nil, err
		}
		return manifest.Encrypt(m, w.CPRK)
	})
	if err != nil {
		return nil, err
	}

	_ = w.auditEmitter().Emit(ctx, domain.AuditKindPeerCredIssued, deviceID, map[string]any{
		"jti":   jti,
		"scope": signed.Scope,
		"mode":  signed.Mode,
		"ttl":   ttl.String(),
	})

	return &signed, nil
}

// buildSignedPeerCred is the pure mint-and-sign step, factored out so
// it can be called both from the standalone IssuePeerCred (which then
// does its own RMW to record the issuance) and from inside LinkConfirm's
// RMW (which integrates the PeerCreds write with the rest of the
// pairing-completion manifest mutations into a single atomic write).
//
// Performs validation, JWT minting, PeerCred wrapping, and Ed25519
// signing — does NOT touch the manifest or audit log. The caller is
// responsible for writing the PeerCredRecord (under RMW) and emitting
// the audit entry.
//
// Caller-supplied scope must already satisfy: non-empty, every name
// names an existing compartment, every name is in the target device's
// CompartmentScope (if it has one). The validation happens inside
// IssuePeerCred and inside LinkConfirm separately; this helper trusts
// its inputs and only validates TTL bounds + scope name shape.
func (w *Workspace) buildSignedPeerCred(ctx context.Context, deviceID string, scope []string, ttl time.Duration, parent *credentials.Parent) (credentials.PeerCred, error) {
	if ttl <= 0 {
		ttl = PeerCredDefaultTTL
	}
	if ttl > PeerCredMaxTTL {
		return credentials.PeerCred{}, fmt.Errorf("workspace: PeerCred TTL %s exceeds max %s", ttl, PeerCredMaxTTL)
	}
	for _, name := range scope {
		if err := domain.ValidCompartmentName(name); err != nil {
			return credentials.PeerCred{}, fmt.Errorf("workspace: invalid compartment in scope: %w", err)
		}
	}
	now := w.now()
	exp := now.Add(ttl)
	refresh := now.Add(ttl / 2)
	jti, err := newPeerCredJTI()
	if err != nil {
		return credentials.PeerCred{}, fmt.Errorf("generate JTI: %w", err)
	}

	// DD-10: mint TWO scoped JWTs on R2 local-sign. Both share the
	// same TTL + IssuedAt so they expire as a matched pair (no half-
	// broken states where data works but control has expired or vice
	// versa).
	minter := w.buildMinter(parent)

	// Data cred: RW on compartments/<vol>/* and compartments/<vol>
	// (the without-slash variant is required for rclone's S3 init
	// HEAD probe — see r2_guardrail_test).
	dataPrefixes := make([]string, 0, len(scope))
	dataObjects := make([]string, 0, len(scope))
	for _, name := range scope {
		dataPrefixes = append(dataPrefixes, "compartments/"+name+"/")
		dataObjects = append(dataObjects, "compartments/"+name)
	}
	dataR2, err := minter.Mint(ctx, credentials.MintRequest{
		Bucket:      w.Config.Bucket.Name,
		Scope:       credentials.R2ScopeObjectReadWrite,
		Prefixes:    dataPrefixes,
		ObjectPaths: dataObjects,
		TTL:         ttl,
	})
	if err != nil {
		return credentials.PeerCred{}, fmt.Errorf("mint Data cred: %w", err)
	}

	// Control cred: RO on workspace control-plane paths the peer needs:
	//   - manifest.enc       (every Manifest() read)
	//   - revocations.enc    (mount-session revocation poller)
	//   - peers/<id>/refresh.enc (the peer's own refresh-handoff blob)
	// R2 itself enforces read-only on these. A drift code bug that
	// tried to PUT here from a bearer peer would hit 403 — fail-loud,
	// not silent over-grant.
	ctrlObjects := []string{
		domain.ManifestKey,
		domain.RevocationsKey,
		domain.PeerCredRefreshKey(deviceID),
	}
	ctrlR2, err := minter.Mint(ctx, credentials.MintRequest{
		Bucket:      w.Config.Bucket.Name,
		Scope:       credentials.R2ScopeObjectReadOnly,
		ObjectPaths: ctrlObjects,
		TTL:         ttl,
	})
	if err != nil {
		return credentials.PeerCred{}, fmt.Errorf("mint Control cred: %w", err)
	}

	pc := credentials.PeerCred{
		Version:  credentials.PeerCredVersion,
		DeviceID: deviceID,
		JTI:      jti,
		Scope:    normalizeScope(scope),
		Mode:     "rw",
		Data: credentials.ScopedCredSet{
			AccessKeyID:     dataR2.AccessKeyID,
			SecretAccessKey: dataR2.SecretAccessKey,
			SessionToken:    dataR2.SessionToken,
			Endpoint:        w.Config.Bucket.Endpoint,
			Bucket:          w.Config.Bucket.Name,
		},
		Control: &credentials.ScopedCredSet{
			AccessKeyID:     ctrlR2.AccessKeyID,
			SecretAccessKey: ctrlR2.SecretAccessKey,
			SessionToken:    ctrlR2.SessionToken,
			Endpoint:        w.Config.Bucket.Endpoint,
			Bucket:          w.Config.Bucket.Name,
		},
		IssuedAt:  now,
		ExpiresAt: exp,
		RefreshAt: refresh,
	}
	return credentials.SignPeerCred(pc, w.Master.SignPriv), nil
}

// newPeerCredJTI returns a fresh "pc_<16 hex>" identifier. 64 bits of
// entropy is sufficient: collisions would require ~2^32 issuances
// before becoming likely (birthday bound), and the JTI namespace is
// per-workspace.
func newPeerCredJTI() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "pc_" + hex.EncodeToString(b), nil
}
