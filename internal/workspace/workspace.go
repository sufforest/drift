package workspace

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	gosync "sync"
	"time"

	"github.com/sufforest/drift/internal/audit"
	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/credentials"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/manifest"
	"github.com/sufforest/drift/internal/mount"
	"github.com/sufforest/drift/internal/storage"
	"github.com/sufforest/drift/internal/token"

	"github.com/mr-tron/base58"
)

// Options carries the runtime dependencies for Init / Load. Production
// builds the Provider + Writer from the parent provider credential; tests
// inject the in-memory implementations directly.
type Options struct {
	State    *State
	Provider storage.Provider
	Writer   storage.ReadModifyWriter
	Mounter  mount.Mounter
	Now      func() time.Time
}

// Workspace is the primary/secondary-device view: it holds local keys and
// orchestrates control-plane operations (compartments, tokens, revocations).
//
// The bearer flow (`drift open <token>`) does NOT go through Workspace —
// see Redeem in this package.
//
// configMu guards mutations of Config.Min*Sequence and the SaveConfig
// call. Other readers (e.g. of Config.DeviceID, Config.WorkspaceID,
// Config.Bucket) are unsynchronized because those fields are immutable
// after Init / Load.
type Workspace struct {
	State    *State
	Provider storage.Provider
	Writer   storage.ReadModifyWriter
	Mounter  mount.Mounter

	Master *dcrypto.MasterKey // nil on secondary devices
	Device *dcrypto.DeviceKey
	Config *LocalConfig
	CPRK   []byte

	configMu gosync.Mutex
	now      func() time.Time
}

// InitParams describes the workspace to create.
type InitParams struct {
	Bucket     domain.BucketInfo
	Parent     *credentials.Parent
	DeviceName string // human label for the primary device
}

// Init creates a fresh workspace.
//
//  1. Generate master + device keys; save them to State.
//  2. Probe provider capabilities; pick a concurrency strategy.
//  3. Build the initial signed + encrypted manifest with this device enrolled.
//  4. Upload manifest + an empty revocations file.
//  5. Save local config + parent cred.
func Init(ctx context.Context, o Options, params InitParams) (*Workspace, error) {
	if err := requireOptions(o); err != nil {
		return nil, err
	}
	if params.Parent == nil {
		return nil, errors.New("workspace: parent credential required")
	}
	if params.Bucket.Name == "" {
		return nil, errors.New("workspace: bucket name required")
	}

	if o.State.HasMaster() {
		return nil, errors.New("workspace: this state dir already initialized; remove ~/.config/drift to reinit")
	}

	master, err := dcrypto.GenerateMasterKey()
	if err != nil {
		return nil, fmt.Errorf("generate master: %w", err)
	}
	device, err := dcrypto.GenerateDeviceKey()
	if err != nil {
		return nil, fmt.Errorf("generate device: %w", err)
	}
	wid, err := newWorkspaceID()
	if err != nil {
		return nil, err
	}
	did := "dev_" + shortID(8)
	deviceName := params.DeviceName
	if deviceName == "" {
		deviceName = did
	}

	caps, err := storage.ProbeCapabilities(ctx, o.Provider)
	if err != nil {
		return nil, fmt.Errorf("probe capabilities: %w", err)
	}

	cprk, err := dcrypto.DeriveCPRK(master.Root, wid, 0)
	if err != nil {
		return nil, err
	}

	now := optionsNow(o)
	masterPub, err := masterX25519Pub(master)
	if err != nil {
		return nil, err
	}
	devicePub, err := device.BoxPub()
	if err != nil {
		return nil, err
	}

	primaryEnrollment := manifest.SignEnrollment(
		did, now.UnixNano(),
		device.SignPub(), devicePub[:],
		master.SignPriv,
	)

	m := &domain.Manifest{
		Version:     1,
		WorkspaceID: wid,
		Sequence:    1, // manifests start at seq 1; every subsequent write increments
		Concurrency: caps.ConcurrencyLabel(),
		Devices: map[string]domain.Device{
			did: {
				ID:         did,
				Name:       deviceName,
				PublicKey:  device.SignPub(),
				EncryptKey: devicePub[:],
				EnrolledAt: now,
				LastSeen:   now,
			},
			// Master pseudo-device — pubkeys recorded so every reader
			// can verify the enrollment chain. Master itself does NOT
			// get an enrollment entry; it's the trust root.
			domain.MasterDeviceID: {
				ID:         domain.MasterDeviceID,
				Name:       "master",
				PublicKey:  master.SignPub(),
				EncryptKey: masterPub[:],
				EnrolledAt: now,
				LastSeen:   now,
			},
		},
		Compartments: map[string]domain.Compartment{},
		ActiveTokens: map[string]domain.TokenRecord{},
		Enrollments: map[string]domain.Enrollment{
			did: primaryEnrollment,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := manifest.Sign(m, did, device.SignPriv); err != nil {
		return nil, err
	}
	body, err := manifest.Encrypt(m, cprk)
	if err != nil {
		return nil, err
	}
	// PutIfNotExists protects against a re-init from a fresh
	// ~/.config/drift silently overwriting an existing workspace's
	// manifest (different wid, different CPRK — would lock every
	// outstanding token out of redemption).
	if _, err := o.Provider.PutIfNotExists(ctx, domain.ManifestKey, body); err != nil {
		if errors.Is(err, domain.ErrPreconditionFailed) {
			return nil, fmt.Errorf("bucket already has a workspace manifest; refusing to overwrite. Use `drift open <token>` to join, or pick a different bucket")
		}
		if errors.Is(err, domain.ErrConditionalUnsupported) {
			// B2 (no If-None-Match): fall back to a HEAD check. Race
			// window is narrow and the alternative is no protection at all.
			if exists, _ := o.Provider.Exists(ctx, domain.ManifestKey); exists {
				return nil, fmt.Errorf("bucket already has a workspace manifest; refusing to overwrite")
			}
			if pErr := o.Provider.Put(ctx, domain.ManifestKey, body); pErr != nil {
				return nil, fmt.Errorf("upload manifest: %w", pErr)
			}
		} else {
			return nil, fmt.Errorf("upload manifest: %w", err)
		}
	}
	// Empty revocations list — write so revocation polls don't 404 forever.
	if err := o.Provider.Put(ctx, domain.RevocationsKey, []byte(`{"version":1,"sequence":0,"entries":[]}`)); err != nil {
		return nil, fmt.Errorf("upload revocations: %w", err)
	}

	// Persist local state. Order: parent (least sensitive) → device →
	// master. If any of these fails AFTER the bucket already has our
	// manifest, this device is bricked — `drift open` from elsewhere
	// can't redeem (no token issued yet) and a re-init refuses because
	// of the PutIfNotExists guard. Roll back the bucket-side manifest
	// before returning so the user can retry cleanly.
	rollback := func(reason error) error {
		_ = o.Provider.Delete(ctx, domain.ManifestKey)
		_ = o.Provider.Delete(ctx, domain.RevocationsKey)
		return fmt.Errorf("init: rolled back bucket state because local save failed: %w", reason)
	}
	if err := o.State.SaveParent(params.Parent); err != nil {
		return nil, rollback(err)
	}
	if err := o.State.SaveDevice(device); err != nil {
		return nil, rollback(err)
	}
	if err := o.State.SaveMaster(master); err != nil {
		return nil, rollback(err)
	}
	masterFP := masterFingerprint(master.SignPub())
	cfg := LocalConfig{
		WorkspaceID:         wid,
		DeviceID:            did,
		Bucket:              params.Bucket,
		Concurrency:         caps.ConcurrencyLabel(),
		MinManifestSequence: m.Sequence,
		MasterFingerprint:   masterFP,
	}
	if err := o.State.SaveConfig(cfg); err != nil {
		return nil, rollback(err)
	}

	ws := &Workspace{
		State:    o.State,
		Provider: o.Provider,
		Writer:   o.Writer,
		Mounter:  o.Mounter,
		Master:   master,
		Device:   device,
		Config:   &cfg,
		CPRK:     cprk,
		now:      optionsNowFunc(o),
	}
	_ = ws.auditEmitter().Emit(ctx, domain.AuditKindWorkspaceInit, wid, map[string]any{
		"master_fingerprint": fmt.Sprintf("%x", masterFP),
		"device_id":          did,
	})
	return ws, nil
}

// Load opens an existing workspace from local state.
func Load(_ context.Context, o Options) (*Workspace, error) {
	if err := requireOptions(o); err != nil {
		return nil, err
	}
	cfg, err := o.State.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	device, err := o.State.LoadDevice()
	if err != nil {
		return nil, fmt.Errorf("load device key: %w", err)
	}
	var master *dcrypto.MasterKey
	var cprk []byte
	if o.State.HasMaster() {
		master, err = o.State.LoadMaster()
		if err != nil {
			return nil, fmt.Errorf("load master key: %w", err)
		}
		cprk, err = dcrypto.DeriveCPRK(master.Root, cfg.WorkspaceID, cfg.CPRKEpoch)
		if err != nil {
			return nil, err
		}
	} else {
		// Secondary device: CPRK was handed off at pairing time and
		// persisted in cprk.key. Without it, manifest reads will fail.
		cprk, err = o.State.LoadCPRK()
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("load cprk: %w", err)
		}
	}
	return &Workspace{
		State:    o.State,
		Provider: o.Provider,
		Writer:   o.Writer,
		Mounter:  o.Mounter,
		Master:   master,
		Device:   device,
		Config:   cfg,
		CPRK:     cprk,
		now:      optionsNowFunc(o),
	}, nil
}

// Manifest reads + decrypts + verifies the current manifest, and enforces
// the monotonic-sequence invariant.
//
// If the fetched manifest's Sequence is below w.Config.MinManifestSequence,
// returns ErrManifestConflict — a bucket-write attacker is trying to roll
// back. If above, the floor is bumped and persisted.
func (w *Workspace) Manifest(ctx context.Context) (*domain.Manifest, error) {
	if w.CPRK == nil {
		return nil, errors.New("workspace: this device has no master/CPRK; cannot decrypt manifest")
	}
	body, err := w.Provider.Get(ctx, domain.ManifestKey)
	if err != nil {
		return nil, err
	}
	m, err := manifest.Decrypt(body, w.CPRK, w.Config.WorkspaceID)
	if err != nil {
		// AEAD failure can mean (a) corruption, (b) the primary rotated
		// CPRK and our cached key is stale. Try a one-shot refresh; if
		// that also fails, surface the original error.
		if refreshed, refreshErr := w.refreshCPRK(ctx); refreshErr == nil {
			w.CPRK = refreshed
			m, err = manifest.Decrypt(body, refreshed, w.Config.WorkspaceID)
		}
		if err != nil {
			return nil, err
		}
	}
	// Walk the master-rotation chain BEFORE the structural verify: if a
	// rotation happened while we were offline, our pinned fingerprint
	// won't match the manifest's master pseudo-device, but the
	// announcement chain proves the new master is legitimate.
	if m.MasterRotationSequence > w.Config.LastObservedRotation {
		if err := w.walkRotationChain(ctx, m.MasterRotationSequence); err != nil {
			return nil, fmt.Errorf("walk master rotation chain: %w", err)
		}
	}
	if err := manifest.Verify(m); err != nil {
		return nil, err
	}
	if err := assertMasterFingerprint(m, w.Config.MasterFingerprint); err != nil {
		return nil, err
	}
	w.configMu.Lock()
	defer w.configMu.Unlock()
	if m.Sequence < w.Config.MinManifestSequence {
		return nil, fmt.Errorf("%w: fetched manifest sequence %d below floor %d (possible rollback)",
			domain.ErrManifestConflict, m.Sequence, w.Config.MinManifestSequence)
	}
	if m.Sequence > w.Config.MinManifestSequence {
		w.Config.MinManifestSequence = m.Sequence
		if err := w.State.SaveConfig(*w.Config); err != nil {
			// Surface, don't swallow: if we can't persist the floor, the
			// next process restart loses the rollback defense.
			return nil, fmt.Errorf("persist manifest sequence floor: %w", err)
		}
	}
	return m, nil
}

// CompartmentCreate adds a new compartment. The fresh compartment key is
// sealed to every currently-enrolled device's X25519 public key so each
// device can decrypt it independently.
func (w *Workspace) CompartmentCreate(ctx context.Context, name, mode string) error {
	if w.Master == nil {
		return errors.New("workspace: only the primary device can create compartments in v1")
	}
	if err := domain.ValidCompartmentName(name); err != nil {
		return err
	}
	if mode != domain.ModeMount && mode != domain.ModeSync {
		return fmt.Errorf("workspace: mode must be %q or %q (sync deferred to v1.1)", domain.ModeMount, domain.ModeSync)
	}
	now := w.now()
	key, err := dcrypto.GenerateCompartmentKey()
	if err != nil {
		return err
	}

	err = w.Writer.ReadModifyWrite(ctx, domain.ManifestKey, func(cur []byte) ([]byte, error) {
		m, err := manifest.Decrypt(cur, w.CPRK, w.Config.WorkspaceID)
		if err != nil {
			return nil, err
		}
		if _, exists := m.Compartments[name]; exists {
			return nil, fmt.Errorf("workspace: compartment %q already exists", name)
		}
		sealed := map[string][]byte{}
		for id, dev := range m.Devices {
			if len(dev.EncryptKey) != dcrypto.X25519KeySize {
				continue // skip devices missing an X25519 pubkey
			}
			// DD-8: skip devices whose CompartmentScope excludes the new
			// compartment. The master pseudo-device has no scope set, so
			// it always receives a sealed copy. Empty/nil scope on any
			// device == full access (pre-DD-8 default).
			if !dev.HasCompartmentAccess(name) {
				continue
			}
			var pub [dcrypto.X25519KeySize]byte
			copy(pub[:], dev.EncryptKey)
			ct, err := dcrypto.SealFor(pub, key)
			if err != nil {
				return nil, fmt.Errorf("seal compartment key for %s: %w", id, err)
			}
			sealed[id] = ct
		}
		m.Compartments[name] = domain.Compartment{
			Name:          name,
			Mode:          mode,
			KeyVersion:    1,
			EncryptedKeys: sealed,
			CreatedAt:     now,
		}
		m.UpdatedAt = now
		m.Sequence++
		if err := manifest.Sign(m, w.Config.DeviceID, w.Device.SignPriv); err != nil {
			return nil, err
		}
		return manifest.Encrypt(m, w.CPRK)
	})
	if err != nil {
		return err
	}
	// Best-effort audit emit. Logging failure does not roll the manifest
	// write back — the event happened; we just didn't record it.
	_ = w.auditEmitter().Emit(ctx, domain.AuditKindCompartmentCreate, name, map[string]any{"mode": mode})
	return nil
}

// GrantRequest describes a `drift grant`.
type GrantRequest struct {
	Scope []string
	Mode  string
	TTL   time.Duration
}

// Grant mints a token and registers it in the manifest. The minting
// device needs:
//
//   - A parent S3 credential (to sign the JWT for the bearer's scoped cred)
//   - A device signing key (to sign the token itself)
//   - Sealed compartment keys for the requested scope
//   - The master pubkey (for token verification by the bearer; pulled
//     from the manifest, doesn't require master priv)
//
// It does NOT need the master signing key. A peer-paired secondary
// device that received the parent cred via PairingHandoff can grant.
func (w *Workspace) Grant(ctx context.Context, req GrantRequest) (*token.IssueResult, error) {
	parent, err := w.State.LoadParent()
	if err != nil {
		return nil, fmt.Errorf("workspace: cannot mint tokens — no parent S3 credential on this device (load: %w)", err)
	}
	m, err := w.Manifest(ctx)
	if err != nil {
		return nil, err
	}
	// Pull the master pubkey from the manifest's master pseudo-device.
	// This is what gets embedded in the token; bearers verify against
	// the master fingerprint they pin at first contact. We don't need
	// the master signing PRIVATE key here.
	masterDev, ok := m.Devices[domain.MasterDeviceID]
	if !ok || len(masterDev.PublicKey) == 0 {
		return nil, errors.New("workspace: manifest is missing master pseudo-device entry; cannot mint")
	}
	masterPub := masterDev.PublicKey
	// DD-8: refuse to mint tokens whose scope exceeds this device's own
	// CompartmentScope. The "sealed key missing" check below also catches
	// it, but checking up front gives a clearer error before any partial
	// work happens.
	if me, ok := m.Devices[w.Config.DeviceID]; ok && len(me.CompartmentScope) > 0 {
		for _, want := range req.Scope {
			if !me.HasCompartmentAccess(want) {
				return nil, fmt.Errorf("workspace: device %s is not scoped for compartment %q (scope: %v)",
					w.Config.DeviceID, want, me.CompartmentScope)
			}
		}
	}
	comps := map[string][]byte{}
	for _, name := range req.Scope {
		c, ok := m.Compartments[name]
		if !ok {
			return nil, fmt.Errorf("%w: %s", domain.ErrCompartmentUnknown, name)
		}
		sealed, ok := c.EncryptedKeys[w.Config.DeviceID]
		if !ok {
			return nil, fmt.Errorf("workspace: device %s has no key for compartment %q", w.Config.DeviceID, name)
		}
		pub, err := w.Device.BoxPub()
		if err != nil {
			return nil, err
		}
		key, err := dcrypto.Open(pub, w.Device.BoxPriv, sealed)
		if err != nil {
			return nil, fmt.Errorf("decrypt compartment key %q: %w", name, err)
		}
		comps[name] = key
	}

	minter := w.buildMinter(parent)
	issuer := &token.Issuer{
		Provider:   w.Provider,
		Writer:     w.Writer,
		Minter:     minter,
		DeviceID:   w.Config.DeviceID,
		DeviceSign: w.Device.SignPriv,
		MasterPub:  masterPub,
		Now:        w.now,
	}
	res, err := issuer.Issue(ctx, token.IssueRequest{
		WorkspaceID:  w.Config.WorkspaceID,
		BucketInfo:   w.Config.Bucket,
		CPRK:         w.CPRK,
		Compartments: comps,
		Scope:        req.Scope,
		Mode:         req.Mode,
		TTL:          req.TTL,
	})
	if err != nil {
		return nil, err
	}
	_ = w.auditEmitter().Emit(ctx, domain.AuditKindTokenGrant, res.TID, map[string]any{
		"scope":      req.Scope,
		"mode":       req.Mode,
		"ttl_seconds": int64(req.TTL.Seconds()),
		"expires_at": res.ExpiresAt,
	})
	return res, nil
}

// Revoke adds tid to the revocation list. Enforces and updates the
// monotonic Sequence floor in LocalConfig so a bucket admin who rolls
// the list back is detected on the next write.
func (w *Workspace) Revoke(ctx context.Context, tid string) error {
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
	res, err := revoker.Revoke(ctx, tid)
	if err != nil {
		return err
	}
	w.configMu.Lock()
	defer w.configMu.Unlock()
	if res.NewSequence > w.Config.MinRevocationsSequence {
		w.Config.MinRevocationsSequence = res.NewSequence
		if err := w.State.SaveConfig(*w.Config); err != nil {
			return fmt.Errorf("persist revocations floor: %w", err)
		}
	}
	_ = w.auditEmitter().Emit(ctx, domain.AuditKindTokenRevoke, tid, map[string]any{
		"idempotent": res.Idempotent,
	})
	return nil
}

// TokenInfo summarizes one entry in m.ActiveTokens for `drift tokens`.
type TokenInfo struct {
	TID       string
	IssuedBy  string
	Scope     []string
	Mode      string
	ExpiresAt time.Time
	IssuedAt  time.Time
	Expired   bool
}

// Tokens lists every TokenRecord in the manifest, with an Expired flag for
// convenience. Revocation status is not joined here — callers can fetch
// revocations.enc separately if needed.
func (w *Workspace) Tokens(ctx context.Context) ([]TokenInfo, error) {
	m, err := w.Manifest(ctx)
	if err != nil {
		return nil, err
	}
	now := w.now()
	out := make([]TokenInfo, 0, len(m.ActiveTokens))
	for _, rec := range m.ActiveTokens {
		out = append(out, TokenInfo{
			TID:       rec.TID,
			IssuedBy:  rec.IssuedBy,
			Scope:     rec.Scope,
			Mode:      rec.Mode,
			ExpiresAt: rec.ExpiresAt,
			IssuedAt:  rec.IssuedAt,
			Expired:   now.After(rec.ExpiresAt),
		})
	}
	return out, nil
}

// Status summarizes workspace state for `drift status`.
type Status struct {
	WorkspaceID string
	DeviceID    string
	Bucket      domain.BucketInfo
	Concurrency string
	Compartments []CompartmentStatus
	Tokens       []TokenInfo
}

// CompartmentStatus is a manifest-derived view of one compartment.
type CompartmentStatus struct {
	Name       string
	Mode       string
	KeyVersion int
	CreatedAt  time.Time
}

// Status returns the user-facing snapshot for `drift status`.
func (w *Workspace) Status(ctx context.Context) (*Status, error) {
	m, err := w.Manifest(ctx)
	if err != nil {
		return nil, err
	}
	tokens, err := w.Tokens(ctx)
	if err != nil {
		return nil, err
	}
	comps := make([]CompartmentStatus, 0, len(m.Compartments))
	for _, c := range m.Compartments {
		comps = append(comps, CompartmentStatus{
			Name:       c.Name,
			Mode:       c.Mode,
			KeyVersion: c.KeyVersion,
			CreatedAt:  c.CreatedAt,
		})
	}
	return &Status{
		WorkspaceID:  w.Config.WorkspaceID,
		DeviceID:     w.Config.DeviceID,
		Bucket:       w.Config.Bucket,
		Concurrency:  w.Config.Concurrency,
		Compartments: comps,
		Tokens:       tokens,
	}, nil
}

// buildMinter picks a Minter based on the configured provider.
//
// R2 today returns R2LocalSignMinter. That mint path is currently
// broken against R2's API (returns InvalidArgument on
// X-Amz-Security-Token). Bearer flow on R2 will fail until
// R2APIMinter (calls /accounts/.../r2/temp-access-credentials) lands.
// We deliberately fail closed — drift does NOT silently embed the
// parent credential in bearer tokens. The primary device should use
// `drift mount` (direct local access) for its own vols instead of
// going through the bearer flow.
func (w *Workspace) buildMinter(parent *credentials.Parent) credentials.Minter {
	return &credentials.R2LocalSignMinter{
		AccessKeyID:     parent.AccessKeyID,
		SecretAccessKey: parent.SecretAccessKey,
		Endpoint:        w.Config.Bucket.Endpoint,
		Now:             w.now,
	}
}

// --- helpers ---

func requireOptions(o Options) error {
	if o.State == nil {
		return errors.New("workspace: Options.State required")
	}
	if o.Provider == nil {
		return errors.New("workspace: Options.Provider required")
	}
	if o.Writer == nil {
		return errors.New("workspace: Options.Writer required")
	}
	return nil
}

func optionsNow(o Options) time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func optionsNowFunc(o Options) func() time.Time {
	if o.Now != nil {
		return o.Now
	}
	return time.Now
}

func newWorkspaceID() (string, error) {
	b, err := dcrypto.GenerateRedemptionCode()
	if err != nil {
		return "", err
	}
	return "wks_" + base58.Encode(b[:12]), nil
}

func shortID(n int) string {
	b, _ := dcrypto.GenerateRedemptionCode()
	return base58.Encode(b[:n])
}

func masterX25519Pub(m *dcrypto.MasterKey) ([dcrypto.X25519KeySize]byte, error) {
	return m.BoxPub()
}

// masterFingerprint returns SHA-256 of the master Ed25519 public key. Used
// as the pinned trust root on every device and inside every token.
func masterFingerprint(pub ed25519.PublicKey) []byte {
	h := sha256.Sum256(pub)
	return h[:]
}

// auditEmitter constructs an audit emitter bound to this workspace +
// device. Returned for use by mutating methods that want to log an event.
// The CPRK is read at call time so a rotation-in-flight doesn't sign with
// a stale key.
//
// Load wraps the read in an OS-level flock so two concurrent `drift`
// invocations on the same state dir don't both compute the same Sequence
// number and corrupt each other's hash chain. The lock is held for the
// full Load → Save critical section by exposing release via the unlock
// callback the Emitter calls on Save.
func (w *Workspace) auditEmitter() *audit.Emitter {
	var (
		unlock     func()
		released   bool
		releaseOnce gosync.Mutex
	)
	doRelease := func() {
		releaseOnce.Lock()
		defer releaseOnce.Unlock()
		if released {
			return
		}
		released = true
		if unlock != nil {
			unlock()
		}
	}
	return &audit.Emitter{
		Provider:    w.Provider,
		WorkspaceID: w.Config.WorkspaceID,
		DeviceID:    w.Config.DeviceID,
		DeviceSign:  w.Device.SignPriv,
		CPRK:        w.CPRK,
		Now:         w.now,
		Load: func() (audit.State, error) {
			rel, err := w.State.AuditChainLock()
			if err != nil {
				return audit.State{}, err
			}
			unlock = rel
			seq, hash, err := w.State.LoadAuditState()
			if err != nil {
				return audit.State{}, err
			}
			return audit.State{LastSequence: seq, LastHash: hash}, nil
		},
		Save: func(s audit.State) error {
			return w.State.SaveAuditState(s.LastSequence, s.LastHash)
		},
		Release: doRelease,
	}
}

// walkRotationChain fetches every master-rotation announcement from
// LastObservedRotation+1 up to targetSeq, verifies each, and updates the
// pinned MasterFingerprint step by step. On any verify failure the chain
// stops and the original pin is preserved.
// maxRotationsPerWalk caps how many announcements walkRotationChain
// processes in a single call. A bucket admin who corrupts the manifest to
// claim MasterRotationSequence = 2^63 would otherwise cause unbounded
// sequential GETs; cap and surface as an error. Picked high enough that
// legitimate accumulated rotations never hit it.
const maxRotationsPerWalk = 256

func (w *Workspace) walkRotationChain(ctx context.Context, targetSeq uint64) error {
	w.configMu.Lock()
	startSeq := w.Config.LastObservedRotation + 1
	currentFP := append([]byte(nil), w.Config.MasterFingerprint...)
	w.configMu.Unlock()

	// Defensive: callers should never invoke us with targetSeq < startSeq
	// (the guard is at the call site), but the subtraction below would
	// underflow uint64 if they did. Cheap to check.
	if targetSeq < startSeq {
		return nil
	}
	if targetSeq-startSeq+1 > maxRotationsPerWalk {
		return fmt.Errorf("%w: manifest claims %d rotation announcements pending (cap %d) — possible forgery, refusing to walk",
			domain.ErrSignatureInvalid, targetSeq-startSeq+1, maxRotationsPerWalk)
	}

	for seq := startSeq; seq <= targetSeq; seq++ {
		body, err := w.Provider.Get(ctx, domain.MasterRotationKey(seq))
		if err != nil {
			return fmt.Errorf("fetch announcement %d: %w", seq, err)
		}
		var a domain.MasterRotationAnnouncement
		if err := json.Unmarshal(body, &a); err != nil {
			return fmt.Errorf("parse announcement %d: %w", seq, err)
		}
		if a.WorkspaceID != w.Config.WorkspaceID {
			return fmt.Errorf("%w: announcement %d wid %q != local %q",
				domain.ErrSignatureInvalid, seq, a.WorkspaceID, w.Config.WorkspaceID)
		}
		if a.Sequence != seq {
			return fmt.Errorf("%w: announcement %d body sequence %d", domain.ErrSignatureInvalid, seq, a.Sequence)
		}
		if err := VerifyMasterRotation(a, currentFP); err != nil {
			return err
		}
		newFP := sha256.Sum256(a.NewMasterPub)
		currentFP = newFP[:]
	}

	w.configMu.Lock()
	defer w.configMu.Unlock()
	w.Config.MasterFingerprint = currentFP
	w.Config.LastObservedRotation = targetSeq
	if err := w.State.SaveConfig(*w.Config); err != nil {
		return fmt.Errorf("persist rotated pin: %w", err)
	}
	return nil
}

// refreshCPRK reloads the CPRK after the cached one fails to decrypt the
// manifest (the usual cause is a primary-side `drift rotate cprk`).
//
// Primary device: re-derive from master.Root at the next epoch, walking
// forward up to a reasonable bound — handles "multiple rotations while
// this primary was offline" (unusual but supported).
//
// Secondary device: fetch .drift/cprk/<did>.enc, unseal with its X25519
// priv key, sanity-check the master pubkey, persist new key + epoch.
func (w *Workspace) refreshCPRK(ctx context.Context) ([]byte, error) {
	w.configMu.Lock()
	currentEpoch := w.Config.CPRKEpoch
	w.configMu.Unlock()

	if w.Master != nil {
		// Primary: try the next few epochs until decrypt succeeds. We
		// can't tell without trying which epoch the bucket is at.
		for offset := uint64(1); offset <= 8; offset++ {
			candidate, err := dcrypto.DeriveCPRK(w.Master.Root, w.Config.WorkspaceID, currentEpoch+offset)
			if err != nil {
				return nil, err
			}
			// Try decrypting the manifest under this candidate. If it
			// works, save + return.
			body, err := w.Provider.Get(ctx, domain.ManifestKey)
			if err != nil {
				return nil, err
			}
			if _, err := manifest.Decrypt(body, candidate, w.Config.WorkspaceID); err == nil {
				w.configMu.Lock()
				w.Config.CPRKEpoch = currentEpoch + offset
				_ = w.State.SaveConfig(*w.Config)
				w.configMu.Unlock()
				return candidate, nil
			}
		}
		return nil, errors.New("workspace: could not decrypt manifest with any CPRK epoch in the next 8 steps")
	}

	// Secondary: fetch the sealed handoff blob.
	sealed, err := w.Provider.Get(ctx, domain.CPRKKeyFor(w.Config.DeviceID))
	if err != nil {
		return nil, fmt.Errorf("fetch sealed cprk: %w", err)
	}
	devBox, err := w.Device.BoxPub()
	if err != nil {
		return nil, err
	}
	plain, err := dcrypto.Open(devBox, w.Device.BoxPriv, sealed)
	if err != nil {
		return nil, fmt.Errorf("unseal cprk: %w", err)
	}
	var ho domain.CPRKHandoff
	if err := json.Unmarshal(plain, &ho); err != nil {
		return nil, fmt.Errorf("parse cprk handoff: %w", err)
	}
	// Sanity check: master pubkey must match the locally pinned
	// fingerprint. A bucket-write attacker who substituted a forged
	// sealed blob (which they can't actually do without our box priv,
	// but defense in depth) would trip here.
	gotFP := sha256.Sum256(ho.MasterPub)
	if !bytes.Equal(gotFP[:], w.Config.MasterFingerprint) {
		return nil, fmt.Errorf("%w: sealed cprk handoff master pub mismatch", domain.ErrSignatureInvalid)
	}
	w.configMu.Lock()
	isNewer := ho.Epoch > w.Config.CPRKEpoch
	currentEpochSnapshot := w.Config.CPRKEpoch
	w.configMu.Unlock()
	if !isNewer {
		// A bucket-admin replay of an older sealed handoff would
		// otherwise overwrite the live cprk.key with a stale value and
		// trap the device in a refresh loop. Reject epoch downgrades.
		return nil, fmt.Errorf("%w: sealed handoff epoch %d not newer than local %d", domain.ErrManifestConflict, ho.Epoch, currentEpochSnapshot)
	}
	// Save the CPRK BEFORE the epoch counter. If SaveCPRK fails (disk
	// full, EPERM), we want the on-disk state to still match the cached
	// CPRK we have — bumping the epoch first would leave the device
	// pointing at an epoch with no readable key, and the downgrade
	// guard would prevent recovery via the same handoff.
	if err := w.State.SaveCPRK(ho.CPRK); err != nil {
		return nil, fmt.Errorf("persist cprk: %w", err)
	}
	w.configMu.Lock()
	w.Config.CPRKEpoch = ho.Epoch
	saveErr := w.State.SaveConfig(*w.Config)
	w.configMu.Unlock()
	if saveErr != nil {
		// CPRK is on disk but the epoch counter isn't; in-memory has
		// the right values. Caller can succeed using the returned key;
		// next startup will see the older epoch + new key. Surface the
		// error so operator notices.
		return ho.CPRK, fmt.Errorf("persist cprk epoch: %w", saveErr)
	}
	return ho.CPRK, nil
}

// assertMasterFingerprint checks that the manifest's master pseudo-device
// pubkey hashes to the expected fingerprint. If expected is empty, the
// check is skipped (e.g. on a fresh device before the pin is established).
func assertMasterFingerprint(m *domain.Manifest, expected []byte) error {
	if len(expected) == 0 {
		return nil
	}
	master, ok := m.Devices[domain.MasterDeviceID]
	if !ok {
		return fmt.Errorf("%w: manifest has no master pseudo-device", domain.ErrDeviceUnknown)
	}
	got := masterFingerprint(ed25519.PublicKey(master.PublicKey))
	if !bytes.Equal(got, expected) {
		return fmt.Errorf("%w: master fingerprint mismatch (possible workspace fork)", domain.ErrSignatureInvalid)
	}
	return nil
}
