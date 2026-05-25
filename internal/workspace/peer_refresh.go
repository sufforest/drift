package workspace

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sufforest/drift/internal/credentials"
	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/domain"
)

// PeerRefreshMintResult summarizes a primary-side refresh.
type PeerRefreshMintResult struct {
	DeviceID  string
	OldJTI    string
	NewJTI    string
	ExpiresAt string // RFC3339 for the CLI report
}

// PeerRefreshMint (primary side) issues a fresh PeerCred for the named
// bearer peer, seals it for that peer's X25519 pubkey, and uploads to
// the bucket at peers/<id>/refresh.enc. The peer's next
// PeerRefreshFetch (or scripted `drift peer refresh`) reads, unseals,
// verifies, and replaces its local peercred.json.
//
// Master-only. Refuses if the peer is currently marked Revoked in the
// manifest — refresh is for active peers, not zombies. Operators
// rehabilitating a revoked peer should call IssuePeerCred directly,
// which clears the flag, then call this to deliver the new cred.
//
// Idempotent semantics: each call mints a fresh JTI and overwrites
// the bucket object. Old refresh blobs that the peer never picked up
// are clobbered — that's fine, the peer only needs the latest.
func (w *Workspace) PeerRefreshMint(ctx context.Context, deviceID string) (*PeerRefreshMintResult, error) {
	if w.Master == nil {
		return nil, errors.New("workspace: only the primary device can refresh bearer-mode peers")
	}
	if deviceID == "" {
		return nil, errors.New("workspace: device id required")
	}

	m, err := w.Manifest(ctx)
	if err != nil {
		return nil, err
	}
	rec, ok := m.PeerCreds[deviceID]
	if !ok {
		return nil, fmt.Errorf("workspace: device %s has no bearer PeerCred record — pair them with `drift link --new-device --peer-bearer` first", deviceID)
	}
	if rec.Revoked {
		return nil, fmt.Errorf("workspace: device %s is currently revoked; refusing to refresh. If you want to reinstate them, use `drift link --new-device --peer-bearer` to re-pair (issues a fresh cred + clears the revoke flag)", deviceID)
	}
	dev, ok := m.Devices[deviceID]
	if !ok {
		return nil, fmt.Errorf("workspace: device %s not in Devices map — refusing to refresh", deviceID)
	}
	if len(dev.EncryptKey) != dcrypto.X25519KeySize {
		return nil, fmt.Errorf("workspace: device %s has no valid X25519 pubkey — cannot seal refresh blob", deviceID)
	}

	result := &PeerRefreshMintResult{
		DeviceID: deviceID,
		OldJTI:   rec.JTI,
	}

	// Re-issue the PeerCred. IssuePeerCred takes scope explicitly; we
	// reuse the device's current Manifest.PeerCreds[did].Scope so the
	// refresh preserves whatever scope the operator most recently set
	// (via initial pairing or vol grant).
	newCred, err := w.IssuePeerCred(ctx, deviceID, rec.Scope, 0)
	if err != nil {
		return nil, fmt.Errorf("re-issue PeerCred: %w", err)
	}
	result.NewJTI = newCred.JTI
	result.ExpiresAt = newCred.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")

	// Seal the cred for the peer's X25519 pubkey and upload.
	credBytes, err := json.Marshal(newCred)
	if err != nil {
		return nil, fmt.Errorf("marshal new cred: %w", err)
	}
	var peerBoxPub [dcrypto.X25519KeySize]byte
	copy(peerBoxPub[:], dev.EncryptKey)
	sealed, err := dcrypto.SealFor(peerBoxPub, credBytes)
	if err != nil {
		return nil, fmt.Errorf("seal cred for peer: %w", err)
	}
	if err := w.Provider.Put(ctx, domain.PeerCredRefreshKey(deviceID), sealed); err != nil {
		return nil, fmt.Errorf("upload sealed refresh blob: %w", err)
	}

	_ = w.auditEmitter().Emit(ctx, domain.AuditKindPeerCredRefreshed, deviceID, map[string]any{
		"old_jti": result.OldJTI,
		"new_jti": result.NewJTI,
	})
	return result, nil
}

// PeerRefreshFetchResult summarizes a peer-side fetch.
type PeerRefreshFetchResult struct {
	OldJTI string
	NewJTI string
}

// PeerRefreshFetch (peer side) fetches the sealed refresh blob from
// the bucket, verifies it, and replaces the locally-stored PeerCred.
// Safe to call on any device:
//   - non-bearer device → error (nothing to refresh)
//   - bearer device with no refresh blob in bucket → error (primary
//     hasn't run PeerRefreshMint yet, OR the peer already fetched and
//     the blob was cleaned up)
//
// Verification gates BEFORE replacing local state:
//   1. Sealed-box opens with peer's box priv (proves the blob was
//      sealed for THIS device by someone who knew our X25519 pub)
//   2. PeerCred signature verifies under the workspace's master pub
//      (proves the cred was minted by the trust root)
//   3. PeerCred.DeviceID matches this device (catches misroutes)
//   4. Manifest.PeerCreds[me].JTI matches the new JTI (catches stale
//      blobs — primary may have already re-issued past this one)
//
// On success, the local peercred.json is replaced. The OLD cred is
// gone; if a race occurred and the OLD cred is still in use by some
// process, it'll fail at next sign verification anyway.
func (w *Workspace) PeerRefreshFetch(ctx context.Context) (*PeerRefreshFetchResult, error) {
	if !w.State.HasPeerCred() {
		return nil, errors.New("workspace: this device is not bearer-mode — nothing to refresh")
	}
	oldCred, err := w.State.LoadPeerCred()
	if err != nil {
		return nil, err
	}
	result := &PeerRefreshFetchResult{OldJTI: oldCred.JTI}

	body, err := w.Provider.Get(ctx, domain.PeerCredRefreshKey(w.Config.DeviceID))
	if err != nil {
		if errors.Is(err, domain.ErrObjectNotFound) {
			return nil, fmt.Errorf("workspace: no refresh blob from primary yet for this device — ask the primary to run `drift peer refresh %s`", w.Config.DeviceID)
		}
		return nil, fmt.Errorf("fetch refresh blob: %w", err)
	}

	// Open the sealed-box envelope. SealFor / Open use ephemeral
	// X25519 + ChaCha20-Poly1305; the recipient's box priv is the
	// only key that decrypts.
	myBoxPub, err := w.Device.BoxPub()
	if err != nil {
		return nil, err
	}
	plain, err := dcrypto.Open(myBoxPub, w.Device.BoxPriv, body)
	if err != nil {
		return nil, fmt.Errorf("open refresh blob (corrupted or sealed for a different device?): %w", err)
	}

	var newCred credentials.PeerCred
	if err := json.Unmarshal(plain, &newCred); err != nil {
		return nil, fmt.Errorf("parse refreshed PeerCred: %w", err)
	}

	// Verify under master pubkey from the manifest.
	m, err := w.Manifest(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest to verify refresh: %w", err)
	}
	masterDev, ok := m.Devices[domain.MasterDeviceID]
	if !ok {
		return nil, errors.New("workspace: manifest missing master pseudo-device — cannot verify refresh")
	}
	if err := credentials.VerifyPeerCred(newCred, ed25519.PublicKey(masterDev.PublicKey)); err != nil {
		return nil, fmt.Errorf("refresh blob signature failed: %w", err)
	}
	if newCred.DeviceID != w.Config.DeviceID {
		return nil, fmt.Errorf("refresh blob's DeviceID %s does not match this device %s — refusing to save", newCred.DeviceID, w.Config.DeviceID)
	}
	// Cross-check JTI matches what the manifest now expects. Catches
	// stale blobs.
	rec, ok := m.PeerCreds[w.Config.DeviceID]
	if !ok {
		return nil, errors.New("workspace: manifest no longer has a PeerCreds record for this device — primary may have revoked us")
	}
	if rec.Revoked {
		return nil, errors.New("workspace: this device is marked revoked in the manifest — refusing to apply refresh")
	}
	if rec.JTI != newCred.JTI {
		return nil, fmt.Errorf("workspace: refresh blob's JTI %s does not match manifest record %s (stale blob; ask primary to re-mint)", newCred.JTI, rec.JTI)
	}

	if err := w.State.SavePeerCred(&newCred); err != nil {
		return nil, fmt.Errorf("save refreshed PeerCred: %w", err)
	}
	result.NewJTI = newCred.JTI
	return result, nil
}
