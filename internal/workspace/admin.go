package workspace

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/manifest"
	"github.com/sufforest/drift/internal/storage"
	"github.com/sufforest/drift/internal/token"
)

// DeviceInfo is the per-device view returned by Devices().
type DeviceInfo struct {
	ID         string
	Name       string
	EnrolledAt time.Time
	LastSeen   time.Time

	// IsThis is true if this entry matches the running device.
	IsThis bool
}

// Devices lists every enrolled device in the manifest.
func (w *Workspace) Devices(ctx context.Context) ([]DeviceInfo, error) {
	m, err := w.Manifest(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]DeviceInfo, 0, len(m.Devices))
	for _, d := range m.Devices {
		out = append(out, DeviceInfo{
			ID:         d.ID,
			Name:       d.Name,
			EnrolledAt: d.EnrolledAt,
			LastSeen:   d.LastSeen,
			IsThis:     d.ID == w.Config.DeviceID,
		})
	}
	return out, nil
}

// VerifyReport summarizes what `drift verify` checked.
type VerifyReport struct {
	ManifestSignature bool
	ConditionalPut    bool
	ProviderReachable bool
	NumDevices        int
	NumCompartments   int
	NumActiveTokens   int
	Notes             []string
}

// Verify runs a non-destructive integrity check:
//   - decrypts + verifies the manifest signature
//   - re-probes provider capabilities (compared against the recorded value)
//   - counts devices / compartments / tokens
//
// Does not touch data-plane chunks; that belongs to a future `drift fsck`.
func (w *Workspace) Verify(ctx context.Context) (*VerifyReport, error) {
	report := &VerifyReport{}
	m, err := w.Manifest(ctx)
	if err != nil {
		// Manifest() runs Verify internally; surface that distinction.
		if errors.Is(err, domain.ErrSignatureInvalid) || errors.Is(err, domain.ErrDeviceUnknown) {
			report.ManifestSignature = false
			report.Notes = append(report.Notes, fmt.Sprintf("manifest signature: %v", err))
			return report, err
		}
		return nil, err
	}
	report.ManifestSignature = true
	// Re-run an explicit Verify on the decrypted manifest so the test
	// path doesn't depend on Manifest() doing it implicitly.
	if err := manifest.Verify(m); err != nil {
		report.ManifestSignature = false
		report.Notes = append(report.Notes, fmt.Sprintf("manifest re-verify: %v", err))
	}

	report.NumDevices = len(m.Devices)
	report.NumCompartments = len(m.Compartments)
	report.NumActiveTokens = len(m.ActiveTokens)

	caps, err := storage.ProbeCapabilities(ctx, w.Provider)
	if err != nil {
		report.ProviderReachable = false
		report.Notes = append(report.Notes, fmt.Sprintf("provider probe: %v", err))
		return report, nil
	}
	report.ProviderReachable = true
	report.ConditionalPut = caps.ConditionalPut

	// Drift compares recorded vs probed concurrency so a downgrade is
	// surfaced (B2 used to support it, now doesn't — would be weird, but
	// the check is cheap).
	if caps.ConcurrencyLabel() != w.Config.Concurrency {
		report.Notes = append(report.Notes,
			fmt.Sprintf("concurrency drift: recorded=%s probed=%s — manifest will be updated on next write",
				w.Config.Concurrency, caps.ConcurrencyLabel()))
	}
	return report, nil
}

// DeviceRename updates the human-readable label on an enrolled device.
// The Name field is purely informational — it's never used in
// cryptographic operations — so changing it doesn't require re-issuing
// an enrollment cert.
func (w *Workspace) DeviceRename(ctx context.Context, deviceID, newName string) error {
	if w.Master == nil {
		return errors.New("workspace: only the primary device can rename devices in v1")
	}
	if deviceID == "" {
		return errors.New("workspace: device id required")
	}
	if newName == "" {
		return errors.New("workspace: new name required")
	}
	err := w.Writer.ReadModifyWrite(ctx, domain.ManifestKey, func(cur []byte) ([]byte, error) {
		m, err := manifest.Decrypt(cur, w.CPRK, w.Config.WorkspaceID)
		if err != nil {
			return nil, err
		}
		dev, ok := m.Devices[deviceID]
		if !ok {
			return nil, fmt.Errorf("%w: %s", domain.ErrDeviceUnknown, deviceID)
		}
		dev.Name = newName
		m.Devices[deviceID] = dev
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
	_ = w.auditEmitter().Emit(ctx, "device.rename", deviceID, map[string]any{
		"new_name": newName,
	})
	return nil
}

// DeviceRevokeResult summarizes what `drift device revoke` did. Useful for
// the CLI to show a precise post-action report.
type DeviceRevokeResult struct {
	DeviceID           string
	RemovedFromDevices bool
	RotatedCompartments []string // compartments whose keys were rotated
}

// DeviceRevoke removes a device from the manifest.
//
// If rotate is true (the default for the CLI), every compartment the device
// had a sealed key for gets a fresh symmetric key, re-sealed for the
// remaining devices, with KeyVersion incremented. This bounds the blast
// radius if the revoked device's local key material leaked: future writes
// to that compartment are unreadable to anyone holding the old key.
//
// Honest caveat: existing chunks already encrypted with the OLD key remain
// decryptable by anyone who still has that key, including the revoked
// device. v1 does not re-encrypt existing data.
func (w *Workspace) DeviceRevoke(ctx context.Context, deviceID string, rotate bool) (*DeviceRevokeResult, error) {
	if w.Master == nil {
		return nil, errors.New("workspace: only the primary device can revoke devices in v1")
	}
	if deviceID == "" {
		return nil, errors.New("workspace: device id required")
	}
	if deviceID == w.Config.DeviceID {
		return nil, errors.New("workspace: refusing to revoke the running device (would lock you out)")
	}

	result := &DeviceRevokeResult{DeviceID: deviceID}

	err := w.Writer.ReadModifyWrite(ctx, domain.ManifestKey, func(cur []byte) ([]byte, error) {
		m, err := manifest.Decrypt(cur, w.CPRK, w.Config.WorkspaceID)
		if err != nil {
			return nil, err
		}
		if _, ok := m.Devices[deviceID]; !ok {
			return nil, fmt.Errorf("%w: %s", domain.ErrDeviceUnknown, deviceID)
		}
		delete(m.Devices, deviceID)
		delete(m.Enrollments, deviceID)
		result.RemovedFromDevices = true

		if rotate {
			rotated, err := rotateAffectedCompartments(m, deviceID)
			if err != nil {
				return nil, err
			}
			result.RotatedCompartments = rotated
		}
		m.UpdatedAt = w.now()
		m.Sequence++
		if err := manifest.Sign(m, w.Config.DeviceID, w.Device.SignPriv); err != nil {
			return nil, err
		}
		return manifest.Encrypt(m, w.CPRK)
	})
	if err != nil {
		return nil, err
	}
	_ = w.auditEmitter().Emit(ctx, domain.AuditKindDeviceRevoke, deviceID, map[string]any{
		"rotated_compartments": result.RotatedCompartments,
	})
	return result, nil
}

// rotateAffectedCompartments mutates m: for every compartment with a sealed
// key entry for revokedID, generate a fresh symmetric key, re-seal it for
// every remaining device, and bump KeyVersion. Returns the list of
// compartments rotated.
func rotateAffectedCompartments(m *domain.Manifest, revokedID string) ([]string, error) {
	var rotated []string
	for name, c := range m.Compartments {
		if _, hadKey := c.EncryptedKeys[revokedID]; !hadKey {
			continue
		}
		newKey, err := dcrypto.GenerateCompartmentKey()
		if err != nil {
			return nil, fmt.Errorf("rotate %s: %w", name, err)
		}
		sealed := map[string][]byte{}
		for id, dev := range m.Devices {
			if len(dev.EncryptKey) != dcrypto.X25519KeySize {
				continue
			}
			var pub [dcrypto.X25519KeySize]byte
			copy(pub[:], dev.EncryptKey)
			ct, err := dcrypto.SealFor(pub, newKey)
			if err != nil {
				return nil, fmt.Errorf("rotate %s seal for %s: %w", name, id, err)
			}
			sealed[id] = ct
		}
		c.EncryptedKeys = sealed
		c.KeyVersion++
		m.Compartments[name] = c
		rotated = append(rotated, name)
	}
	return rotated, nil
}

// GCOptions tunes `drift gc`. CredentialsGracePeriod prevents racing a
// just-revoked tid against bearers who haven't polled yet (default 7 days).
type GCOptions struct {
	CredentialsGracePeriod time.Duration
	DryRun                 bool
}

// GCReport summarizes what `drift gc` would do (DryRun) or did.
type GCReport struct {
	OrphanedCompartmentChunks []string // keys to be deleted under compartments/<name>/
	OrphanedCredentialBlobs   []string // .drift/credentials/<tid>.enc that can be reaped
	Deleted                   int
}

// AuditGCResult summarizes a `drift gc --audit-older-than` sweep.
type AuditGCResult struct {
	Scanned int
	Deleted []string
}

// AuditGC deletes audit entries older than threshold. Hard cut — the
// per-device hash chain is broken at the cut point; VerifyChain will
// report a chain-restart on the oldest surviving entry. For users who
// want signed-history retention, the right answer is to NOT run this.
//
// The threshold is compared against each entry's encrypted timestamp
// prefix in EntryID, so we don't need to decrypt every entry just to
// learn its age — list-by-prefix returns names in temporal order.
func (w *Workspace) AuditGC(ctx context.Context, threshold time.Duration) (*AuditGCResult, error) {
	if w.Master == nil {
		return nil, errors.New("workspace: only the primary device can gc audit entries in v1")
	}
	if threshold <= 0 {
		return nil, errors.New("workspace: threshold must be > 0")
	}
	now := w.now()
	cutoff := now.Add(-threshold).UnixNano()
	if cutoff < 0 {
		// Defensive: caller asked for a threshold longer than the
		// epoch. Don't reap anything.
		return &AuditGCResult{}, nil
	}

	keys, err := w.Provider.List(ctx, domain.AuditDir)
	if err != nil {
		return nil, fmt.Errorf("list audit dir: %w", err)
	}
	result := &AuditGCResult{Scanned: len(keys)}
	for _, key := range keys {
		// EntryID prefix is "<unix_nano (18 digits zero-padded)>-..."
		// — extract and compare numerically. The prefix is plaintext
		// (filename), so we don't decrypt anything just to learn age.
		ts, ok := parseEntryTimestamp(key)
		if !ok {
			continue
		}
		if ts >= cutoff {
			continue
		}
		if err := w.Provider.Delete(ctx, key); err != nil {
			if errors.Is(err, domain.ErrObjectNotFound) {
				continue
			}
			return result, fmt.Errorf("delete %s: %w", key, err)
		}
		result.Deleted = append(result.Deleted, key)
	}
	return result, nil
}

// parseEntryTimestamp pulls the leading unix_nano from an audit object
// key. EntryID format is "<unix_nano>-<device_id>-<nonce_hex>"; the
// timestamp is variable-width (the %018d format-string pads to 18 but
// does not truncate a 19-digit value). Reads digits up to the first '-'.
func parseEntryTimestamp(key string) (int64, bool) {
	const prefix = domain.AuditDir
	if !strings.HasPrefix(key, prefix) {
		return 0, false
	}
	rest := key[len(prefix):]
	var ts int64
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if c == '-' {
			if i == 0 {
				return 0, false
			}
			return ts, true
		}
		if c < '0' || c > '9' {
			return 0, false
		}
		ts = ts*10 + int64(c-'0')
	}
	return 0, false
}

// GC sweeps storage of objects no longer referenced by the manifest:
//
//   - Compartment chunks under `compartments/<name>/` where <name> is no
//     longer in `manifest.Compartments`. Happens after `drift compartment
//     delete` (which v1 leaves chunks behind for `drift gc`).
//
//   - Credential blobs at `.drift/credentials/<tid>.enc` for tids that
//     either appear in revocations or whose ExpiresAt was more than
//     CredentialsGracePeriod ago.
//
// The grace period exists because honest clients are still allowed to
// redeem at any point until their cred TTL expires; deleting the blob
// out from under them gives a confusing error. 7 days past expiry is more
// than enough to be sure no honest client cares.
//
// GC is safe to interrupt: each Delete is independent. Re-running picks
// up wherever it left off.
func (w *Workspace) GC(ctx context.Context, opts GCOptions) (*GCReport, error) {
	if w.Master == nil {
		return nil, errors.New("workspace: only the primary device can run gc in v1")
	}
	if opts.CredentialsGracePeriod == 0 {
		opts.CredentialsGracePeriod = 7 * 24 * time.Hour
	}
	report := &GCReport{}
	m, err := w.Manifest(ctx)
	if err != nil {
		return nil, err
	}

	// 1. Compartment chunks.
	chunks, err := w.Provider.List(ctx, domain.CompartmentsRoot)
	if err != nil {
		return nil, fmt.Errorf("list compartments: %w", err)
	}
	for _, key := range chunks {
		name := compartmentNameFromKey(key)
		if name == "" {
			continue
		}
		if _, kept := m.Compartments[name]; !kept {
			report.OrphanedCompartmentChunks = append(report.OrphanedCompartmentChunks, key)
		}
	}

	// 2. Credential blobs. Read revocations once so we can flag tids that
	//    are revoked OR past grace.
	revoked, err := w.readRevocationSet(ctx)
	if err != nil {
		return nil, err
	}
	credKeys, err := w.Provider.List(ctx, domain.CredentialsDir)
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	now := w.now()
	for _, key := range credKeys {
		tid := tidFromCredentialsKey(key)
		if tid == "" {
			continue
		}
		rec, hasRecord := m.ActiveTokens[tid]
		// Reap only when we're confident no honest bearer is still
		// holding the token: either it's expired past grace (the RFC's
		// expected lifecycle), or it's revoked AND expired past grace
		// (covers cases where revocation happened well before TTL).
		switch {
		case hasRecord && now.Sub(rec.ExpiresAt) > opts.CredentialsGracePeriod:
			report.OrphanedCredentialBlobs = append(report.OrphanedCredentialBlobs, key)
		case !hasRecord && revoked[tid]:
			// No manifest record, but revocations remembers it — half-
			// issued (Issue failed before the manifest RMW step) and then
			// explicitly revoked. Safe to reap.
			report.OrphanedCredentialBlobs = append(report.OrphanedCredentialBlobs, key)
		}
	}

	if opts.DryRun {
		return report, nil
	}
	for _, key := range report.OrphanedCompartmentChunks {
		if err := w.Provider.Delete(ctx, key); err != nil && !errors.Is(err, domain.ErrObjectNotFound) {
			return report, fmt.Errorf("delete %s: %w", key, err)
		}
		report.Deleted++
	}
	for _, key := range report.OrphanedCredentialBlobs {
		if err := w.Provider.Delete(ctx, key); err != nil && !errors.Is(err, domain.ErrObjectNotFound) {
			return report, fmt.Errorf("delete %s: %w", key, err)
		}
		report.Deleted++
	}
	return report, nil
}

// RevokedTokens returns the set of revoked tids. Exported wrapper around
// readRevocationSet for CLI consumers (e.g. `drift tokens` cross-checking).
func (w *Workspace) RevokedTokens(ctx context.Context) (map[string]bool, error) {
	return w.readRevocationSet(ctx)
}

// readRevocationSet returns the set of revoked tids by reading
// .drift/revocations.enc. Empty if the file does not exist.
func (w *Workspace) readRevocationSet(ctx context.Context) (map[string]bool, error) {
	body, err := w.Provider.Get(ctx, domain.RevocationsKey)
	if errors.Is(err, domain.ErrObjectNotFound) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return map[string]bool{}, nil
	}
	list, err := token.DecodeRevocations(body)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(list.Entries))
	for _, e := range list.Entries {
		set[e.TID] = true
	}
	return set, nil
}

// compartmentNameFromKey extracts <name> from "compartments/<name>/...".
// Returns "" if the key is malformed.
func compartmentNameFromKey(key string) string {
	const prefix = domain.CompartmentsRoot
	if len(key) <= len(prefix) || key[:len(prefix)] != prefix {
		return ""
	}
	rest := key[len(prefix):]
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' {
			return rest[:i]
		}
	}
	return rest
}

// tidFromCredentialsKey extracts <tid> from ".drift/credentials/<tid>.enc".
func tidFromCredentialsKey(key string) string {
	const prefix = domain.CredentialsDir
	const suffix = ".enc"
	if len(key) <= len(prefix)+len(suffix) {
		return ""
	}
	if key[:len(prefix)] != prefix || key[len(key)-len(suffix):] != suffix {
		return ""
	}
	return key[len(prefix) : len(key)-len(suffix)]
}

// CompartmentDelete removes a compartment from the manifest.
//
// **v1 only deletes the manifest entry.** The encrypted chunks under
// compartments/<name>/ are NOT removed — they remain in the bucket as
// orphans. A future `drift gc` will sweep these. Rationale: deletion is
// rare; chunk removal requires LIST + many DELETE calls and is best done
// behind a dedicated command the user invokes intentionally.
func (w *Workspace) CompartmentDelete(ctx context.Context, name string) error {
	if w.Master == nil {
		return errors.New("workspace: only the primary device can delete compartments in v1")
	}
	if name == "" {
		return errors.New("workspace: compartment name required")
	}
	err := w.Writer.ReadModifyWrite(ctx, domain.ManifestKey, func(cur []byte) ([]byte, error) {
		m, err := manifest.Decrypt(cur, w.CPRK, w.Config.WorkspaceID)
		if err != nil {
			return nil, err
		}
		if _, ok := m.Compartments[name]; !ok {
			return nil, fmt.Errorf("%w: %s", domain.ErrCompartmentUnknown, name)
		}
		delete(m.Compartments, name)
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
	_ = w.auditEmitter().Emit(ctx, domain.AuditKindCompartmentDelete, name, nil)
	return nil
}
