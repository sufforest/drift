package workspace

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/mount"
	driftsync "github.com/sufforest/drift/internal/sync"
)

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
// the device's local parent cred. No bearer token is involved.
//
// This is the right entry point for any device that holds the parent
// S3 cred locally — the primary (always) and peer-paired secondaries
// (when LinkInit was run with PeerMode=true). For identity-only
// secondaries or third parties, use the token-based Redeem path.
//
// The master key is NOT required: MountDirect only needs the parent
// cred (to mint scoped bearer creds for rclone), the device's own
// X25519 priv (to unwrap CPRK from the manifest), and a sealed-for-us
// compartment key (which peer-paired devices receive via the link
// handoff's re-seal step).
func (w *Workspace) MountDirect(ctx context.Context, o DirectMountOptions) (*DirectMountSession, error) {
	if o.MountBase == "" {
		return nil, errors.New("MountDirect: MountBase required")
	}

	m, err := w.Manifest(ctx)
	if err != nil {
		return nil, err
	}
	parent, err := w.State.LoadParent()
	if err != nil {
		return nil, fmt.Errorf("MountDirect: no parent S3 credential on this device — only the primary or peer-paired devices can MountDirect (load: %w)", err)
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

	parentCred := domain.S3Credential{
		AccessKeyID:     parent.AccessKeyID,
		SecretAccessKey: parent.SecretAccessKey,
		// No SessionToken — parent cred is long-lived, not JWT-wrapped.
		Expires: time.Time{},
	}

	for _, name := range requested {
		comp, ok := m.Compartments[name]
		if !ok {
			cleanup()
			return nil, fmt.Errorf("no vol named %q in workspace", name)
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
				Cred:           parentCred,
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
				Cred:           parentCred,
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
