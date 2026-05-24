package workspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	gosync "sync"
	"time"

	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/manifest"
	"github.com/sufforest/drift/internal/mount"
	"github.com/sufforest/drift/internal/storage"
	driftsync "github.com/sufforest/drift/internal/sync"
	"github.com/sufforest/drift/internal/token"
)

// RedeemOptions wires the bearer flow. In production, Provider is an S3
// provider built using the token's ControlCred so it can only GET the three
// control-plane objects. In tests, Provider is a MemoryProvider that
// ignores authentication.
type RedeemOptions struct {
	Provider  storage.Provider
	Mounter   mount.Mounter
	Syncer    driftsync.Syncer // optional; if nil, sync-mode compartments fail at Redeem time
	MountBase string           // e.g. ~/workspace
	Ephemeral bool
	Now       func() time.Time

	// PollInterval defaults to 30s. Tests can shorten it.
	PollInterval time.Duration

	// SyncInterval is the bisync cadence for sync-mode vols. 0 = let the
	// Syncer pick its default (currently 60s). Floor is enforced by the
	// Syncer to prevent runaway S3 spend.
	SyncInterval time.Duration
}

// Session is a live `drift open`: a set of mounts plus a revocation poller.
// Close it from any goroutine to tear down the mounts and stop the poller.
type Session struct {
	TID         string
	WorkspaceID string
	Mounts      []mount.Handle
	Syncs       []driftsync.Handle

	options RedeemOptions
	result  *token.RedeemResult

	mu       gosync.Mutex
	closed   bool
	closeErr error
	cancel   context.CancelFunc
	done     chan struct{}

	// Revoked is closed by the poller when it observes the tid in
	// revocations.enc. Wait() returns the corresponding error.
	revoked   chan struct{}
	pollerErr chan error

	// minRevSeq is the highest Sequence the poller has observed in the
	// revocations file. Any subsequent fetch with a lower Sequence is
	// rejected as a rollback attempt.
	minRevSeq uint64

	// minManifestSeq is the same floor for poll-time manifest refetches.
	// Initialized from the redemption-time manifest.
	minManifestSeq uint64
}

// Redeem performs `drift open <encoded>`. It is independent of any local
// Workspace state — the bearer machine doesn't need to be enrolled.
//
// On success the returned Session is live: mounts are attached and a
// background poller is running. The caller must invoke Session.Close()
// when finished (e.g. on SIGINT or on Session.Wait() returning).
func Redeem(ctx context.Context, encoded string, o RedeemOptions) (*Session, error) {
	if o.Provider == nil {
		return nil, errors.New("workspace: RedeemOptions.Provider required")
	}
	if o.Mounter == nil {
		return nil, errors.New("workspace: RedeemOptions.Mounter required (use mount.NewNoopMounter for tests)")
	}
	if o.MountBase == "" {
		return nil, errors.New("workspace: RedeemOptions.MountBase required")
	}
	if o.PollInterval == 0 {
		o.PollInterval = 30 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}

	r := &token.Redeemer{Provider: o.Provider, Now: o.Now}
	result, err := r.Redeem(ctx, encoded)
	if err != nil {
		return nil, err
	}

	mounts := make([]mount.Handle, 0, len(result.Compartments))
	syncs := make([]driftsync.Handle, 0, len(result.Compartments))
	cleanup := func() {
		for _, h := range mounts {
			_ = o.Mounter.Unmount(ctx, h)
		}
		if o.Syncer != nil {
			for _, h := range syncs {
				_ = o.Syncer.Stop(ctx, h)
			}
		}
	}
	for name, grant := range result.Compartments {
		// The compartment's runtime mode is authoritative in the
		// manifest, not the per-grant value (which is RW/RO, not
		// mount/sync). Look it up.
		comp, ok := result.Manifest.Compartments[name]
		if !ok {
			cleanup()
			return nil, fmt.Errorf("manifest is missing compartment %s", name)
		}
		dst := filepath.Join(o.MountBase, name)
		switch comp.Mode {
		case domain.ModeSync:
			if o.Syncer == nil {
				cleanup()
				return nil, fmt.Errorf("compartment %s is sync-mode but RedeemOptions.Syncer is nil", name)
			}
			h, sErr := o.Syncer.Sync(ctx, driftsync.Request{
				WorkspaceID:    result.WorkspaceID,
				Compartment:    name,
				CompartmentKey: grant.Key,
				Cred:           result.DataCred,
				Bucket:         result.BucketInfo,
				LocalPath:      dst,
				Mode:           grant.Mode,
				Interval:       o.SyncInterval,
			})
			if sErr != nil {
				cleanup()
				return nil, fmt.Errorf("sync %s: %w", name, sErr)
			}
			syncs = append(syncs, h)
		default: // domain.ModeMount or empty
			h, mErr := o.Mounter.Mount(ctx, mount.Request{
				WorkspaceID:    result.WorkspaceID,
				Compartment:    name,
				CompartmentKey: grant.Key,
				Cred:           result.DataCred,
				Bucket:         result.BucketInfo,
				MountPoint:     dst,
				Ephemeral:      o.Ephemeral,
				Mode:           grant.Mode,
			})
			if mErr != nil {
				cleanup()
				return nil, fmt.Errorf("mount %s: %w", name, mErr)
			}
			mounts = append(mounts, h)
		}
	}

	pollerCtx, cancel := context.WithCancel(context.Background())
	sess := &Session{
		TID:            result.TID,
		WorkspaceID:    result.WorkspaceID,
		Mounts:         mounts,
		Syncs:          syncs,
		options:        o,
		result:         result,
		cancel:         cancel,
		done:           make(chan struct{}),
		revoked:        make(chan struct{}),
		pollerErr:      make(chan error, 1),
		minManifestSeq: result.Manifest.Sequence,
	}
	go sess.poll(pollerCtx)
	return sess, nil
}

// Result returns the verified token data the session was built from.
// Useful for callers that need DataCred / ControlCred / CPRK after
// redemption (e.g., to build their own bearer-authed S3 Provider).
func (s *Session) Result() *token.RedeemResult { return s.result }

// Wait blocks until the session is closed (manually) or revoked. Returns
// domain.ErrTokenRevoked if the poller observed a revocation. Equivalent
// to WaitContext(context.Background()) — provided for callers that don't
// have a context to thread.
func (s *Session) Wait() error {
	return s.WaitContext(context.Background())
}

// WaitContext blocks until ctx is done, the session is closed manually,
// or revocation is observed. On ctx cancellation it tears down mounts +
// syncers via Close() before returning ctx.Err(). This is the path the
// daemon takes when `drift close` sends SIGTERM — without it the daemon
// would hang until drift close's SIGKILL escalation 15s later.
func (s *Session) WaitContext(ctx context.Context) error {
	select {
	case <-ctx.Done():
		_ = s.Close()
		return ctx.Err()
	case <-s.revoked:
		_ = s.Close()
		return fmt.Errorf("%w: %s", domain.ErrTokenRevoked, s.TID)
	case <-s.done:
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.closeErr
	}
}

// Close stops the poller and unmounts everything. Idempotent.
func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return s.closeErr
	}
	s.closed = true
	s.mu.Unlock()

	s.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var firstErr error
	for _, h := range s.Mounts {
		if err := s.options.Mounter.Unmount(ctx, h); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.options.Syncer != nil {
		for _, h := range s.Syncs {
			if err := s.options.Syncer.Stop(ctx, h); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	s.mu.Lock()
	s.closeErr = firstErr
	close(s.done)
	s.mu.Unlock()
	return firstErr
}

// poll runs the revocation poller until ctx is canceled or a revocation is
// observed. Errors fetching the revocations file are logged via pollerErr
// but do NOT trigger Close — transient failures should not terminate the
// session.
func (s *Session) poll(ctx context.Context) {
	t := time.NewTicker(s.options.PollInterval)
	defer t.Stop()

	// Run one initial check so a token revoked between issue and open
	// is caught immediately.
	if s.checkRevoked(ctx) {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if s.checkRevoked(ctx) {
				return
			}
		}
	}
}

// checkRevoked returns true if the tid is now revoked, and closes s.revoked
// in that case so Wait can return. Also enforces the monotonic Sequence
// invariant — a fetched list with Sequence < the highest we've seen is
// treated as a bucket-side rollback attempt and logged via pollerErr (but
// we DON'T close the session: a rollback that *removes* a revocation is
// the attacker's goal, and ignoring it preserves the prior decision).
func (s *Session) checkRevoked(ctx context.Context) bool {
	body, err := s.options.Provider.Get(ctx, domain.RevocationsKey)
	if err != nil {
		select {
		case s.pollerErr <- err:
		default:
		}
		return false
	}
	if len(body) == 0 {
		return false
	}
	var list domain.RevocationList
	if err := json.Unmarshal(body, &list); err != nil {
		return false
	}
	s.mu.Lock()
	if list.Sequence < s.minRevSeq {
		s.mu.Unlock()
		select {
		case s.pollerErr <- fmt.Errorf("revocations rollback detected (seq %d < observed %d); ignoring", list.Sequence, s.minRevSeq):
		default:
		}
		return false
	}
	if list.Sequence > s.minRevSeq {
		s.minRevSeq = list.Sequence
	}
	s.mu.Unlock()
	// Refetch the manifest so revocations issued by devices enrolled AFTER
	// this session opened are recognized. Without this, a newly-paired
	// device cannot revoke a bearer for up to the session's full TTL.
	// Falls back to the redemption-time snapshot on transient fetch
	// failure so a network blip doesn't make us mistakenly honor a stale
	// signature lookup.
	devices := s.currentDevices(ctx)
	for _, entry := range list.Entries {
		if entry.TID != s.TID {
			continue
		}
		dev, ok := devices[entry.RevokedBy]
		if !ok {
			continue
		}
		if err := token.VerifyRevocationEntry(entry, dev.PublicKey); err != nil {
			continue
		}
		select {
		case <-s.revoked:
			// already closed
		default:
			close(s.revoked)
		}
		return true
	}
	return false
}

// currentDevices fetches the latest manifest using the bearer's ControlCred
// + CPRK and returns its Devices map. Falls back to the redemption-time
// snapshot on any failure — a transient network blip shouldn't make us
// forget who's allowed to revoke.
func (s *Session) currentDevices(ctx context.Context) map[string]domain.Device {
	body, err := s.options.Provider.Get(ctx, domain.ManifestKey)
	if err != nil {
		return s.result.Manifest.Devices
	}
	m, err := manifest.Decrypt(body, s.result.CPRK, s.result.WorkspaceID)
	if err != nil {
		return s.result.Manifest.Devices
	}
	if err := manifest.Verify(m); err != nil {
		return s.result.Manifest.Devices
	}
	// Enforce monotonic Sequence on poll-time manifest reads too.
	s.mu.Lock()
	if m.Sequence < s.minManifestSeq {
		s.mu.Unlock()
		select {
		case s.pollerErr <- fmt.Errorf("manifest rollback detected during poll (seq %d < observed %d); using snapshot", m.Sequence, s.minManifestSeq):
		default:
		}
		return s.result.Manifest.Devices
	}
	if m.Sequence > s.minManifestSeq {
		s.minManifestSeq = m.Sequence
	}
	s.mu.Unlock()
	return m.Devices
}

