package workspace

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"github.com/sufforest/drift/internal/credentials"
	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/mount"
	driftsync "github.com/sufforest/drift/internal/sync"
)

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// DirectMountOptions describes a primary-device direct mount that
// bypasses the bearer/token flow entirely. The primary already holds
// the parent S3 credential, the master key, and the CPRK locally, so
// there's no need to mint a scoped JWT and round-trip through the
// token redemption path.
type DirectMountOptions struct {
	Mounter   mount.Mounter
	Syncer    driftsync.Syncer
	MountBase string
	Ephemeral bool

	// Vols selects which compartments to mount. Empty = all compartments
	// in the manifest.
	Vols []string

	// SyncInterval applies to sync-mode vols. 0 = let the Syncer pick.
	SyncInterval time.Duration

	// Now is a clock injection point for tests.
	Now func() time.Time
}

// DirectMountSession mirrors the bearer Session but with no TID and no
// revocation poller — the primary device is the authority for its own
// workspace.
type DirectMountSession struct {
	WorkspaceID string
	Mounts      []mount.Handle
	Syncs       []driftsync.Handle

	closer func() error
	done   chan struct{}
}

// Wait blocks until ctx is canceled. On cancellation it tears down the
// mounts and syncers cleanly.
func (s *DirectMountSession) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		_ = s.Close()
		return ctx.Err()
	case <-s.done:
		return nil
	}
}

// Close stops all mounts and syncs. Idempotent.
func (s *DirectMountSession) Close() error {
	if s.closer == nil {
		return nil
	}
	c := s.closer
	s.closer = nil
	err := c()
	close(s.done)
	return err
}

// MountDirect spins up rclone mounts/syncs for the selected vols using
// the device's local credential, whichever shape it takes:
//   - primary or DD-4 v1 peer: parent.json (raw AK/SK)
//   - DD-9 bearer peer: peercred.json (PeerCred with AK/SK/SessionToken)
//   - identity-only: NEITHER — those devices must use `drift open <token>`
//
// MountDirect needs three things, all of which exist on both primary
// and DD-9 bearer peer:
//   - An S3 credential (parent or bearer) to give rclone
//   - The device's own X25519 priv (to unwrap CKs from the manifest)
//   - A sealed-for-this-device CK for every requested vol (the pairing
//     flow's re-seal step puts these in place)
//
// On a bearer peer we additionally enforce:
//   - PeerCred signature verifies under the pinned master FP (defense
//     against a bucket-side substitution that somehow reached the
//     keychain)
//   - PeerCred is not past expiry
//   - Manifest.PeerCreds[deviceID].Revoked is false (workspace-side
//     revocation gate; the existing JWT may still work against R2
//     until its own expiry but drift refuses to use it)
//   - Each requested vol is in the PeerCred's declared Scope (defense
//     in depth; the sealed-CK check below would also catch it but the
//     error message here is clearer)
func (w *Workspace) MountDirect(ctx context.Context, o DirectMountOptions) (*DirectMountSession, error) {
	if o.MountBase == "" {
		return nil, errors.New("MountDirect: MountBase required")
	}

	m, err := w.Manifest(ctx)
	if err != nil {
		return nil, err
	}

	// Determine credential mode.
	var s3Cred domain.S3Credential
	var bearerScope map[string]bool
	if w.State.HasPeerCred() {
		// DD-9 bearer mode.
		pc, err := w.State.LoadPeerCred()
		if err != nil {
			return nil, fmt.Errorf("MountDirect: load bearer PeerCred: %w", err)
		}
		// Verify the cred's signature under the manifest's master
		// pubkey. The manifest's master pseudo-device entry is already
		// pinned-FP-verified at Manifest() time, so trusting it as the
		// PeerCred verifier is consistent with the rest of the trust
		// chain.
		masterDev, ok := m.Devices[domain.MasterDeviceID]
		if !ok {
			return nil, errors.New("MountDirect: manifest missing master pseudo-device — cannot verify PeerCred")
		}
		if err := credentials.VerifyPeerCred(*pc, ed25519.PublicKey(masterDev.PublicKey)); err != nil {
			return nil, fmt.Errorf("MountDirect: bearer PeerCred failed verification: %w", err)
		}
		now := w.now()
		if pc.IsExpired(now) {
			return nil, fmt.Errorf("MountDirect: bearer PeerCred expired at %s — run `drift peer refresh` from this device or `drift peer refresh %s` from the primary", pc.ExpiresAt.UTC().Format(time.RFC3339), w.Config.DeviceID)
		}
		// Workspace-side revocation: manifest record gates use of the
		// cred even while its JWT might still be valid against R2.
		rec, ok := m.PeerCreds[w.Config.DeviceID]
		if !ok {
			return nil, fmt.Errorf("MountDirect: no PeerCreds record for this device in the manifest — device may have been revoked")
		}
		if rec.Revoked {
			return nil, fmt.Errorf("MountDirect: this device's bearer cred is marked revoked in the manifest — `drift peer refresh` will only succeed if the primary clears the revocation")
		}
		// Mismatch between local JTI and manifest JTI = primary issued
		// a newer cred for us we haven't pulled yet. Refresh.
		if rec.JTI != pc.JTI {
			return nil, fmt.Errorf("MountDirect: local PeerCred JTI %s does not match manifest record %s — run `drift peer refresh`", pc.JTI, rec.JTI)
		}
		// Scope guard.
		bearerScope = make(map[string]bool, len(pc.Scope))
		for _, name := range pc.Scope {
			bearerScope[name] = true
		}
		// DD-10: rclone (data plane) always uses the Data cred. Control
		// cred, when present, is used only by drift's own Go code via
		// SplitProvider — never handed to rclone.
		s3Cred = domain.S3Credential{
			AccessKeyID:     pc.Data.AccessKeyID,
			SecretAccessKey: pc.Data.SecretAccessKey,
			SessionToken:    pc.Data.SessionToken,
			Expires:         pc.ExpiresAt,
		}
	} else {
		parent, err := w.State.LoadParent()
		if err != nil {
			return nil, fmt.Errorf("MountDirect: no parent S3 credential or bearer PeerCred on this device — only primary / v1 peer / DD-9 bearer peer can MountDirect (load: %w)", err)
		}
		s3Cred = domain.S3Credential{
			AccessKeyID:     parent.AccessKeyID,
			SecretAccessKey: parent.SecretAccessKey,
			Expires:         time.Time{},
		}
	}

	requested := o.Vols
	if len(requested) == 0 {
		requested = make([]string, 0, len(m.Compartments))
		for name := range m.Compartments {
			requested = append(requested, name)
		}
	}

	devBoxPub, err := w.Device.BoxPub()
	if err != nil {
		return nil, err
	}

	sess := &DirectMountSession{
		WorkspaceID: w.Config.WorkspaceID,
		done:        make(chan struct{}),
	}
	cleanup := func() {
		ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, h := range sess.Mounts {
			_ = o.Mounter.Unmount(ctx2, h)
		}
		if o.Syncer != nil {
			for _, h := range sess.Syncs {
				_ = o.Syncer.Stop(ctx2, h)
			}
		}
	}
	sess.closer = func() error {
		cleanup()
		return nil
	}

	for _, name := range requested {
		comp, ok := m.Compartments[name]
		if !ok {
			cleanup()
			return nil, fmt.Errorf("no vol named %q in workspace", name)
		}
		// DD-9 bearer mode: refuse vols outside the cred's declared
		// scope. The sealed-CK check below would also catch out-of-
		// scope (peer doesn't have a seal for non-scoped vols), but
		// this earlier check gives a clearer error and short-circuits
		// before unwrap.
		if bearerScope != nil && !bearerScope[name] {
			cleanup()
			return nil, fmt.Errorf("vol %q is not in this bearer device's scope (scoped for: %v)", name, sortedKeys(bearerScope))
		}
		sealed, ok := comp.EncryptedKeys[w.Config.DeviceID]
		if !ok {
			cleanup()
			return nil, fmt.Errorf("vol %s has no sealed key for this device", name)
		}
		compKey, err := dcrypto.Open(devBoxPub, w.Device.BoxPriv, sealed)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("unwrap vol %s key: %w", name, err)
		}

		dst := filepath.Join(o.MountBase, name)
		switch comp.Mode {
		case domain.ModeSync:
			if o.Syncer == nil {
				cleanup()
				return nil, fmt.Errorf("vol %s is sync-mode but DirectMountOptions.Syncer is nil", name)
			}
			h, sErr := o.Syncer.Sync(ctx, driftsync.Request{
				WorkspaceID:    w.Config.WorkspaceID,
				Compartment:    name,
				CompartmentKey: compKey,
				Cred:           s3Cred,
				Bucket:         w.Config.Bucket,
				LocalPath:      dst,
				Mode:           "rw", // primary always has full RW on its own vols
				Interval:       o.SyncInterval,
			})
			if sErr != nil {
				cleanup()
				return nil, fmt.Errorf("sync %s: %w", name, sErr)
			}
			sess.Syncs = append(sess.Syncs, h)
		default: // mount mode (or empty)
			if o.Mounter == nil {
				cleanup()
				return nil, fmt.Errorf("vol %s is mount-mode but DirectMountOptions.Mounter is nil", name)
			}
			h, mErr := o.Mounter.Mount(ctx, mount.Request{
				WorkspaceID:    w.Config.WorkspaceID,
				Compartment:    name,
				CompartmentKey: compKey,
				Cred:           s3Cred,
				Bucket:         w.Config.Bucket,
				MountPoint:     dst,
				Ephemeral:      o.Ephemeral,
				Mode:           "rw",
			})
			if mErr != nil {
				cleanup()
				return nil, fmt.Errorf("mount %s: %w", name, mErr)
			}
			sess.Mounts = append(sess.Mounts, h)
		}
	}

	return sess, nil
}
