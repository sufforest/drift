package workspace

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/sufforest/drift/internal/credentials"
	"github.com/sufforest/drift/internal/domain"
)

// PeerInfo is the CLI-facing summary of a bearer-mode peer.
type PeerInfo struct {
	DeviceID  string
	Name      string
	Scope     []string
	JTI       string
	IssuedAt  time.Time
	ExpiresAt time.Time
	Revoked   bool
	// Expired is derived against the workspace's now() at call time —
	// peer is past ExpiresAt and would be refused at mount.
	Expired bool
	// NeedsRefresh is true once the cred has crossed its half-life
	// (manifest doesn't record RefreshAt, so the CLI computes it as
	// IssuedAt + (ExpiresAt-IssuedAt)/2 — same formula as issuance).
	NeedsRefresh bool
}

// PeerList returns every bearer-mode peer recorded in
// Manifest.PeerCreds, sorted by DeviceID for stable CLI output.
// Master-only by convention (the manifest is workspace-wide so any
// reader could call it, but listing bearer peers is an admin
// operation; we gate to match the rest of the peer.* surface).
func (w *Workspace) PeerList(ctx context.Context) ([]PeerInfo, error) {
	if w.Master == nil {
		return nil, errors.New("workspace: only the primary device can list bearer-mode peers")
	}
	m, err := w.Manifest(ctx)
	if err != nil {
		return nil, err
	}
	now := w.now()
	out := make([]PeerInfo, 0, len(m.PeerCreds))
	for did, rec := range m.PeerCreds {
		dev := m.Devices[did]
		refreshAt := rec.IssuedAt.Add(rec.ExpiresAt.Sub(rec.IssuedAt) / 2)
		out = append(out, PeerInfo{
			DeviceID:     did,
			Name:         dev.Name,
			Scope:        append([]string(nil), rec.Scope...),
			JTI:          rec.JTI,
			IssuedAt:     rec.IssuedAt,
			ExpiresAt:    rec.ExpiresAt,
			Revoked:      rec.Revoked,
			Expired:      !now.Before(rec.ExpiresAt),
			NeedsRefresh: !now.Before(refreshAt),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out, nil
}

// PeerLocalStatus is the CLI-facing summary of THIS device's own
// bearer-mode PeerCred (if any). Useful for `drift peer status` on
// a paired peer to confirm its scope, expiry, and revocation status
// without poking the bucket.
type PeerLocalStatus struct {
	HasPeerCred         bool
	DeviceID            string
	Scope               []string
	JTI                 string
	IssuedAt            time.Time
	ExpiresAt           time.Time
	RefreshAt           time.Time
	Expired             bool
	NeedsRefresh        bool
	// SignatureValid reports whether the locally-stored PeerCred
	// signature verifies under the workspace's master pubkey. Should
	// always be true; false indicates either a wrong-workspace cred
	// got saved or local tampering. UNDEFINED when SignatureChecked
	// is false — that case typically means we couldn't fetch the
	// manifest to get the master pubkey (offline, network issue, or
	// the cred itself can't reach R2).
	SignatureValid bool
	// SignatureChecked is true iff we successfully attempted the
	// signature verification (i.e., we fetched the manifest and got
	// the master pubkey). If false, SignatureValid is meaningless;
	// the CLI should report "unknown" rather than "invalid".
	SignatureChecked bool
	// ManifestSyncErr, if non-nil, is the error from trying to fetch
	// the manifest to check the workspace-side Revoked flag. A
	// network-offline peer still gets a meaningful status report
	// (everything except Revoked) with this field set.
	ManifestSyncErr error
	// ManifestRevoked indicates Manifest.PeerCreds[me].Revoked. Only
	// trustworthy when ManifestSyncErr is nil.
	ManifestRevoked bool
	// ManifestJTI is the manifest's recorded JTI; mismatch with the
	// local PeerCred's JTI means primary issued a newer cred.
	ManifestJTI string
}

// PeerStatus returns the local PeerCred summary. Safe on any device:
//   - on a non-bearer device, HasPeerCred=false and the rest is zero
//   - on a bearer device, all fields populated; ManifestSyncErr may be
//     set if we can't reach the bucket
func (w *Workspace) PeerStatus(ctx context.Context) (*PeerLocalStatus, error) {
	out := &PeerLocalStatus{}
	if !w.State.HasPeerCred() {
		return out, nil
	}
	pc, err := w.State.LoadPeerCred()
	if err != nil {
		return nil, err
	}
	out.HasPeerCred = true
	out.DeviceID = pc.DeviceID
	out.Scope = append([]string(nil), pc.Scope...)
	out.JTI = pc.JTI
	out.IssuedAt = pc.IssuedAt
	out.ExpiresAt = pc.ExpiresAt
	out.RefreshAt = pc.RefreshAt
	now := w.now()
	out.Expired = pc.IsExpired(now)
	out.NeedsRefresh = pc.NeedsRefresh(now)
	// Signature check needs the master pubkey, which lives in the
	// manifest. Fetch best-effort.
	m, mErr := w.Manifest(ctx)
	if mErr != nil {
		out.ManifestSyncErr = mErr
		return out, nil
	}
	if masterDev, ok := m.Devices[domain.MasterDeviceID]; ok {
		out.SignatureChecked = true
		out.SignatureValid = credentials.VerifyPeerCred(*pc, masterDev.PublicKey) == nil
	}
	if rec, ok := m.PeerCreds[w.Config.DeviceID]; ok {
		out.ManifestRevoked = rec.Revoked
		out.ManifestJTI = rec.JTI
	}
	return out, nil
}
