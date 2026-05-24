package workspace

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/credentials"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/manifest"
)

// DefaultPairingTTL is the wall-clock window during which a pairing token
// is usable. Short by design — leaked pairing tokens become useless quickly.
const DefaultPairingTTL = 15 * time.Minute

// LinkInitResult is what the primary device returns from LinkInit. The
// pasteable Encoded string is what the user copies to the new device.
type LinkInitResult struct {
	Encoded   string
	PID       string
	ExpiresAt time.Time
}

// LinkInitOptions tunes the pairing initiation step.
type LinkInitOptions struct {
	// PeerMode toggles whether the eventual handoff includes the
	// parent S3 credential. true → the new device becomes a functional
	// peer (drift mount, drift grant). false → identity-only; the
	// new device acts as a bearer that needs `drift open <token>`.
	//
	// Choose true for solo dev with multiple personal machines.
	// Choose false for less-trusted devices (coworkers, contractors).
	PeerMode bool

	// CompartmentScope (DD-8), when non-empty, restricts the new device
	// to the listed compartments. The primary writes this onto the
	// PairingStub at init time; LinkConfirm reads it back and:
	//   1. Only seals the listed compartment keys for the new device
	//   2. Writes the scope onto the new device's Device entry, so
	//      newly-created compartments are also subject to the scope
	//      filter in CompartmentCreate.
	// nil/empty means "no restriction" — the new device gets every
	// compartment, matching the pre-DD-8 default.
	CompartmentScope []string
}

// LinkInit mints a master-signed pairing token, registers a stub in the
// manifest's Pairings map, and uploads an empty challenge marker so other
// enrolled devices know a handshake is in flight.
func (w *Workspace) LinkInit(ctx context.Context, ttl time.Duration, opts ...LinkInitOptions) (*LinkInitResult, error) {
	var opt LinkInitOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	if w.Master == nil {
		return nil, errors.New("workspace: only the primary device can initiate pairing in v1")
	}
	if ttl <= 0 {
		ttl = DefaultPairingTTL
	}
	// DD-8: reject malformed compartment names at the API boundary so a
	// typo like "main$" doesn't silently produce a peer scoped for a name
	// that can never match any real compartment.
	for _, name := range opt.CompartmentScope {
		if err := domain.ValidCompartmentName(name); err != nil {
			return nil, fmt.Errorf("workspace: invalid compartment in scope: %w", err)
		}
	}
	now := w.now()
	exp := now.Add(ttl)

	pid, err := newPairingID()
	if err != nil {
		return nil, err
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("pairing challenge: %w", err)
	}

	// Two narrowly-scoped credentials, disjoint actions, so a leaked
	// pairing token cannot write to any object except its own
	// response.json (and in particular cannot DoS the manifest).
	parent, err := w.State.LoadParent()
	if err != nil {
		return nil, fmt.Errorf("load parent cred: %w", err)
	}
	minter := w.buildMinter(parent)
	readCred, err := minter.Mint(ctx, credentials.MintRequest{
		Bucket: w.Config.Bucket.Name,
		Scope:  credentials.R2ScopeObjectReadOnly,
		ObjectPaths: []string{
			domain.ManifestKey,
			domain.PairingResponseKey(pid),
			domain.PairingHandoffKey(pid),
			domain.PairingAbortKey(pid),
		},
		Actions: credentials.ReadOnlyActions,
		TTL:     ttl,
	})
	if err != nil {
		return nil, fmt.Errorf("mint pairing read cred: %w", err)
	}
	writeCred, err := minter.Mint(ctx, credentials.MintRequest{
		Bucket: w.Config.Bucket.Name,
		Scope:  credentials.R2ScopeObjectReadWrite,
		ObjectPaths: []string{
			domain.PairingResponseKey(pid),
		},
		Actions: []string{"PutObject"},
		TTL:     ttl,
	})
	if err != nil {
		return nil, fmt.Errorf("mint pairing write cred: %w", err)
	}

	masterPub := w.Master.SignPub()
	masterFP := sha256.Sum256(masterPub)

	pt := &domain.PairingToken{
		Version:     domain.PairingVersion,
		PID:         pid,
		WorkspaceID: w.Config.WorkspaceID,
		Bucket:      w.Config.Bucket,
		ReadCred:    *readCred,
		WriteCred:   *writeCred,
		Challenge:   challenge,
		ExpiresAt:   exp,
		IssuerPub:   masterPub,
		MasterFP:    masterFP[:],
	}
	payload, err := json.Marshal(pt)
	if err != nil {
		return nil, fmt.Errorf("marshal pairing token: %w", err)
	}
	sig := dcrypto.Sign(w.Master.SignPriv, payload)
	encoded := dcrypto.EncodePairing(payload, sig)

	// Upload an empty challenge marker so a list-by-prefix on pairings
	// surfaces this PID, and so the new device's polling sees something
	// before its own response.json is uploaded.
	if err := w.Provider.Put(ctx, domain.PairingChallengeKey(pid), challenge); err != nil {
		return nil, fmt.Errorf("upload challenge marker: %w", err)
	}

	// Register the stub in the manifest under the manifest write lock.
	err = w.Writer.ReadModifyWrite(ctx, domain.ManifestKey, func(cur []byte) ([]byte, error) {
		m, err := manifest.Decrypt(cur, w.CPRK, w.Config.WorkspaceID)
		if err != nil {
			return nil, err
		}
		if m.Pairings == nil {
			m.Pairings = map[string]domain.PairingStub{}
		}
		m.Pairings[pid] = domain.PairingStub{
			PID:              pid,
			IssuedBy:         domain.MasterDeviceID,
			IssuedAt:         now,
			ExpiresAt:        exp,
			PeerMode:         opt.PeerMode,
			CompartmentScope: normalizeScope(opt.CompartmentScope),
		}
		m.UpdatedAt = now
		m.Sequence++
		if err := manifest.Sign(m, w.Config.DeviceID, w.Device.SignPriv); err != nil {
			return nil, err
		}
		return manifest.Encrypt(m, w.CPRK)
	})
	if err != nil {
		_ = w.Provider.Delete(ctx, domain.PairingChallengeKey(pid))
		return nil, fmt.Errorf("register pairing: %w", err)
	}

	return &LinkInitResult{
		Encoded:   encoded,
		PID:       pid,
		ExpiresAt: exp,
	}, nil
}

// LinkConfirmResult is what the primary device returns from LinkConfirm.
type LinkConfirmResult struct {
	DeviceID          string
	DeviceFingerprint string // hex of SHA-256(device sign pub), shown to user for visual verification
	SAS               string // Short Authentication String shown to user during the confirm prompt
	ResealedCount     int
	Sequence          uint64
}

// LinkConfirmOptions tunes the confirm step.
//
// ExpectFingerprint is a hex-encoded SHA-256 of the new device's Ed25519
// signing pubkey. The caller obtains this out-of-band from the new
// device's own `drift link` output and passes it here; mismatch aborts
// the enrollment before any bucket write. Empty string means "trust the
// response.json blindly" — kept for backward compat; new flows should
// prefer OnSAS / AcceptSAS.
//
// OnSAS, if non-nil, is invoked with the transcript-bound Short
// Authentication String the moment the primary has read + verified the
// response.json (after challenge-sig + fingerprint checks, before any
// manifest mutation). Returning a non-nil error aborts the enrollment,
// writes a small "aborted.flag" object to the bucket so the secondary
// fails fast instead of waiting for its full timeout, and leaves the
// manifest untouched.
//
// AcceptSAS, if non-empty, is compared against the computed SAS in
// case-insensitive form. Mismatch aborts the same way OnSAS does.
// Useful for scripted / non-interactive primary-side confirms.
type LinkConfirmOptions struct {
	ExpectFingerprint string
	OnSAS             func(sas string) error
	AcceptSAS         string
}

// LinkConfirm completes the pairing handshake from the primary device's
// side: read the new device's response, verify its challenge signature,
// build a master-signed enrollment cert, re-seal compartment keys for the
// new device, and merge into the manifest.
func (w *Workspace) LinkConfirm(ctx context.Context, pid string, opts LinkConfirmOptions) (*LinkConfirmResult, error) {
	if w.Master == nil {
		return nil, errors.New("workspace: only the primary device can confirm pairing")
	}
	now := w.now()

	body, err := w.Provider.Get(ctx, domain.PairingResponseKey(pid))
	if err != nil {
		if errors.Is(err, domain.ErrObjectNotFound) {
			return nil, fmt.Errorf("no response posted yet for %s — new device may not have run `drift link`", pid)
		}
		return nil, fmt.Errorf("fetch response: %w", err)
	}
	var resp domain.PairingResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	if resp.PID != pid {
		return nil, fmt.Errorf("response pid %q does not match expected %q", resp.PID, pid)
	}
	if err := domain.ValidCompartmentName(strings.TrimPrefix(resp.DeviceID, "dev_")); err != nil {
		// Reuse the compartment-name validator for device suffix shape;
		// the "dev_" prefix is fixed by the protocol.
		if !strings.HasPrefix(resp.DeviceID, "dev_") {
			return nil, fmt.Errorf("invalid device id %q (must start with dev_)", resp.DeviceID)
		}
		return nil, fmt.Errorf("invalid device id %q: %w", resp.DeviceID, err)
	}
	if len(resp.DeviceSignPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("response device_sign_pub size %d != %d", len(resp.DeviceSignPub), ed25519.PublicKeySize)
	}
	if len(resp.DeviceBoxPub) != dcrypto.X25519KeySize {
		return nil, fmt.Errorf("response device_box_pub size %d != %d", len(resp.DeviceBoxPub), dcrypto.X25519KeySize)
	}

	// The challenge originally sent must verify under the new device's
	// claimed signing key. Without this, anyone could write any
	// response.json and claim any keypair.
	challenge, err := w.Provider.Get(ctx, domain.PairingChallengeKey(pid))
	if err != nil {
		return nil, fmt.Errorf("fetch challenge: %w", err)
	}
	if err := dcrypto.Verify(ed25519.PublicKey(resp.DeviceSignPub), challenge, resp.ChallengeSig); err != nil {
		return nil, fmt.Errorf("challenge signature: %w", err)
	}

	fpRaw := sha256.Sum256(resp.DeviceSignPub)
	deviceFp := hex.EncodeToString(fpRaw[:])
	if opts.ExpectFingerprint != "" && !strings.EqualFold(opts.ExpectFingerprint, deviceFp) {
		return nil, fmt.Errorf("device fingerprint mismatch: expected %s, got %s — abort", opts.ExpectFingerprint, deviceFp)
	}

	// SAS gate: derive the transcript-bound Short Authentication String
	// from the same inputs the secondary used (master pubkey + pid +
	// device sign/box pubkeys + challenge). On mismatch — whether
	// declared by the user via OnSAS or pre-supplied via AcceptSAS —
	// we drop an abort marker so the secondary stops polling, delete
	// the response.json, and bail before any manifest mutation.
	sas := ComputeSAS(w.Master.SignPub(), pid, resp.DeviceSignPub, resp.DeviceBoxPub, challenge)
	abortPairing := func(reason error) error {
		_ = w.Provider.Put(ctx, domain.PairingAbortKey(pid), []byte("aborted"))
		_ = w.Provider.Delete(ctx, domain.PairingResponseKey(pid))
		return reason
	}
	if opts.AcceptSAS != "" && !strings.EqualFold(opts.AcceptSAS, sas) {
		return nil, abortPairing(fmt.Errorf("sas mismatch: expected %s, computed %s — abort", opts.AcceptSAS, sas))
	}
	if opts.OnSAS != nil {
		if err := opts.OnSAS(sas); err != nil {
			return nil, abortPairing(fmt.Errorf("sas verification declined: %w", err))
		}
	}

	result := &LinkConfirmResult{
		DeviceID:          resp.DeviceID,
		DeviceFingerprint: deviceFp,
		SAS:               sas,
	}

	enrollment := manifest.SignEnrollment(
		resp.DeviceID, now.UnixNano(),
		resp.DeviceSignPub, resp.DeviceBoxPub,
		w.Master.SignPriv,
	)

	var newBoxPub [dcrypto.X25519KeySize]byte
	copy(newBoxPub[:], resp.DeviceBoxPub)

	var peerMode bool
	var scope []string
	err = w.Writer.ReadModifyWrite(ctx, domain.ManifestKey, func(cur []byte) ([]byte, error) {
		m, err := manifest.Decrypt(cur, w.CPRK, w.Config.WorkspaceID)
		if err != nil {
			return nil, err
		}
		if _, ok := m.Pairings[pid]; !ok {
			return nil, fmt.Errorf("pairing %s not in manifest (already confirmed or expired)", pid)
		}
		stub := m.Pairings[pid]
		if now.After(stub.ExpiresAt) {
			return nil, fmt.Errorf("pairing %s expired at %s", pid, stub.ExpiresAt.UTC().Format(time.RFC3339))
		}
		// Capture the peer-mode flag + DD-8 compartment scope from the stub
		// so we know whether to include the parent cred in the post-RMW
		// handoff blob, and which compartments to seal for the new device.
		peerMode = stub.PeerMode
		scope = append(scope[:0], stub.CompartmentScope...)
		if _, dup := m.Devices[resp.DeviceID]; dup {
			return nil, fmt.Errorf("device id %s already enrolled", resp.DeviceID)
		}

		// Re-seal every existing compartment for the new device, subject
		// to the device's CompartmentScope (DD-8). nil/empty scope means
		// "no restriction" → seal everything.
		resealed := 0
		for name, c := range m.Compartments {
			if len(scope) > 0 && !scopeContains(scope, name) {
				continue
			}
			// Decrypt the current sealed key using primary's box priv.
			myBoxPub, err := w.Device.BoxPub()
			if err != nil {
				return nil, err
			}
			sealedForUs, ok := c.EncryptedKeys[w.Config.DeviceID]
			if !ok {
				return nil, fmt.Errorf("this device has no sealed key for %s — cannot re-seal", name)
			}
			plainKey, err := dcrypto.Open(myBoxPub, w.Device.BoxPriv, sealedForUs)
			if err != nil {
				return nil, fmt.Errorf("open compartment key %s: %w", name, err)
			}
			sealedForNew, err := dcrypto.SealFor(newBoxPub, plainKey)
			if err != nil {
				return nil, fmt.Errorf("seal compartment key %s for new device: %w", name, err)
			}
			if c.EncryptedKeys == nil {
				c.EncryptedKeys = map[string][]byte{}
			}
			c.EncryptedKeys[resp.DeviceID] = sealedForNew
			m.Compartments[name] = c
			resealed++
		}

		m.Devices[resp.DeviceID] = domain.Device{
			ID:               resp.DeviceID,
			Name:             resp.Name,
			PublicKey:        resp.DeviceSignPub,
			EncryptKey:       resp.DeviceBoxPub,
			EnrolledAt:       now,
			LastSeen:         now,
			CompartmentScope: scope,
		}
		if m.Enrollments == nil {
			m.Enrollments = map[string]domain.Enrollment{}
		}
		m.Enrollments[resp.DeviceID] = enrollment
		delete(m.Pairings, pid)
		m.UpdatedAt = now
		m.Sequence++
		result.ResealedCount = resealed
		result.Sequence = m.Sequence

		if err := manifest.Sign(m, w.Config.DeviceID, w.Device.SignPriv); err != nil {
			return nil, err
		}
		return manifest.Encrypt(m, w.CPRK)
	})
	if err != nil {
		return nil, err
	}

	_ = w.auditEmitter().Emit(ctx, domain.AuditKindDeviceLink, resp.DeviceID, map[string]any{
		"name":                resp.Name,
		"device_fingerprint":  result.DeviceFingerprint,
		"resealed_compartments": result.ResealedCount,
	})

	// Seal CPRK + master pubkey for the new device and write the handoff
	// blob. The new device polls this and unwraps with its own box key.
	//
	// In peer mode, ALSO include the parent S3 credential. The sealed
	// channel is already E2E encrypted to the new device's pubkey, so
	// transmitting the parent cred this way doesn't widen exposure
	// beyond "the new device's keychain now holds it too."
	ho := domain.PairingHandoff{
		CPRK:      w.CPRK,
		MasterPub: w.Master.SignPub(),
	}
	if peerMode {
		parent, err := w.State.LoadParent()
		if err != nil {
			return nil, fmt.Errorf("load parent cred for peer handoff: %w", err)
		}
		ho.Parent = &domain.PairingHandoffParent{
			Provider:        parent.Provider,
			AccessKeyID:     parent.AccessKeyID,
			SecretAccessKey: parent.SecretAccessKey,
		}
	}
	handoffBody, err := json.Marshal(ho)
	if err != nil {
		return nil, fmt.Errorf("marshal handoff: %w", err)
	}
	sealed, err := dcrypto.SealFor(newBoxPub, handoffBody)
	if err != nil {
		return nil, fmt.Errorf("seal handoff: %w", err)
	}
	if err := w.Provider.Put(ctx, domain.PairingHandoffKey(pid), sealed); err != nil {
		return nil, fmt.Errorf("upload handoff: %w", err)
	}

	// Best-effort cleanup of bucket-side handshake artifacts. The handoff
	// itself remains until the new device fetches it; we leave that for
	// `drift gc` to sweep based on TTL.
	_ = w.Provider.Delete(ctx, domain.PairingResponseKey(pid))

	return result, nil
}

// LinkAbort cancels an in-flight pairing: removes its stub from the
// manifest, deletes the bucket-side challenge + response + handoff
// objects. Safe to call on an unknown pid; returns nil with no
// mutations.
func (w *Workspace) LinkAbort(ctx context.Context, pid string) error {
	if w.Master == nil {
		return errors.New("workspace: only the primary device can abort pairings in v1")
	}
	if pid == "" {
		return errors.New("workspace: pid required")
	}
	err := w.Writer.ReadModifyWrite(ctx, domain.ManifestKey, func(cur []byte) ([]byte, error) {
		m, err := manifest.Decrypt(cur, w.CPRK, w.Config.WorkspaceID)
		if err != nil {
			return nil, err
		}
		if _, ok := m.Pairings[pid]; !ok {
			// Unknown pid — leave the manifest alone but still
			// sweep bucket artifacts in case they're stranded.
			return cur, nil
		}
		delete(m.Pairings, pid)
		m.UpdatedAt = w.now()
		m.Sequence++
		if err := manifest.Sign(m, w.Config.DeviceID, w.Device.SignPriv); err != nil {
			return nil, err
		}
		return manifest.Encrypt(m, w.CPRK)
	})
	if err != nil {
		return err
	}
	_ = w.Provider.Delete(ctx, domain.PairingResponseKey(pid))
	_ = w.Provider.Delete(ctx, domain.PairingChallengeKey(pid))
	_ = w.Provider.Delete(ctx, domain.PairingHandoffKey(pid))
	_ = w.Provider.Delete(ctx, domain.PairingAbortKey(pid))
	return nil
}

// PairingStubInfo is the lightweight view returned by Pairings(). The
// underlying domain.PairingStub is also exposed; this struct just adds
// a derived "expired" boolean for the CLI.
type PairingStubInfo struct {
	domain.PairingStub
	Expired bool
}

// Pairings returns every in-flight pairing recorded in the manifest.
// Useful for `drift link --list`.
func (w *Workspace) Pairings(ctx context.Context) ([]PairingStubInfo, error) {
	m, err := w.Manifest(ctx)
	if err != nil {
		return nil, err
	}
	now := w.now()
	out := make([]PairingStubInfo, 0, len(m.Pairings))
	for _, p := range m.Pairings {
		out = append(out, PairingStubInfo{PairingStub: p, Expired: now.After(p.ExpiresAt)})
	}
	return out, nil
}

// newPairingID returns a fresh "pair_<12 hex>" identifier.
func newPairingID() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "pair_" + hex.EncodeToString(b), nil
}

// scopeContains reports whether the string slice already holds s. Used
// for small (~tens of entries at most) scope checks where map overhead
// isn't justified.
func scopeContains(haystack []string, s string) bool {
	for _, x := range haystack {
		if x == s {
			return true
		}
	}
	return false
}

// normalizeScope returns a sorted, de-duplicated copy of in. Empty/nil
// input returns nil so the omitempty tag drops the field from JSON.
// Sorting yields canonical serialization for manifest signing — two
// LinkInit calls with the same conceptual scope must produce the same
// bytes regardless of input order.
func normalizeScope(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}
