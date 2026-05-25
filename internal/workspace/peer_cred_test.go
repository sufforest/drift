package workspace

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/sufforest/drift/internal/credentials"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/manifest"
)

// pairedPeer pairs a peer device into the workspace with the requested
// scope (nil = full) and returns the deviceID + primary. Used as the
// fixture for IssuePeerCred tests — we need a real enrolled device id,
// and the existing scoped-handshake helper provides one with the right
// shape.
func pairedPeer(t *testing.T, scope []string) (*Workspace, string) {
	t.Helper()
	primary, _, claim, _, _ := driveScopedHandshake(t, scope)
	return primary, claim.DeviceID
}

// TestIssuePeerCred_happyPath: issue produces a signed PeerCred that
// verifies under the workspace master pubkey. The manifest's
// PeerCreds[deviceID] record matches the issued cred's metadata.
func TestIssuePeerCred_happyPath(t *testing.T) {
	ctx := context.Background()
	primary, peerID := pairedPeer(t, []string{"allowed"})

	pc, err := primary.IssuePeerCred(ctx, peerID, []string{"allowed"}, 0)
	if err != nil {
		t.Fatalf("IssuePeerCred: %v", err)
	}

	// PeerCred must be signed by master.
	masterPub := ed25519.PublicKey(primary.Master.SignPub())
	if err := credentials.VerifyPeerCred(*pc, masterPub); err != nil {
		t.Fatalf("returned PeerCred must verify under primary's master pubkey: %v", err)
	}

	// Metadata sanity.
	if pc.DeviceID != peerID {
		t.Errorf("DeviceID = %q, want %q", pc.DeviceID, peerID)
	}
	if pc.Mode != "rw" {
		t.Errorf("Mode = %q, want rw", pc.Mode)
	}
	if len(pc.Scope) != 1 || pc.Scope[0] != "allowed" {
		t.Errorf("Scope = %v, want [allowed]", pc.Scope)
	}
	if pc.ExpiresAt.Sub(pc.IssuedAt) != PeerCredDefaultTTL {
		t.Errorf("default TTL: ExpiresAt - IssuedAt = %v, want %v", pc.ExpiresAt.Sub(pc.IssuedAt), PeerCredDefaultTTL)
	}
	// RefreshAt = IssuedAt + TTL/2 (half-life).
	wantRefresh := pc.IssuedAt.Add(PeerCredDefaultTTL / 2)
	if !pc.RefreshAt.Equal(wantRefresh) {
		t.Errorf("RefreshAt = %v, want %v (IssuedAt + half-TTL)", pc.RefreshAt, wantRefresh)
	}
	if pc.JTI == "" || !strings.HasPrefix(pc.JTI, "pc_") {
		t.Errorf("JTI = %q, want non-empty pc_ prefix", pc.JTI)
	}
	if pc.Data.Bucket != primary.Config.Bucket.Name {
		t.Errorf("Data.Bucket = %q, want %q", pc.Data.Bucket, primary.Config.Bucket.Name)
	}
	if pc.Data.SessionToken == "" || pc.Data.SecretAccessKey == "" {
		t.Error("PeerCred Data missing R2-protocol fields after issuance")
	}

	// Manifest record present + matches.
	m, _ := primary.Manifest(ctx)
	rec, ok := m.PeerCreds[peerID]
	if !ok {
		t.Fatalf("manifest must record PeerCreds[%s] after issuance", peerID)
	}
	if rec.JTI != pc.JTI {
		t.Errorf("manifest record JTI = %q, want %q", rec.JTI, pc.JTI)
	}
	if rec.Revoked {
		t.Error("freshly-issued cred must not be marked revoked")
	}
	if !rec.IssuedAt.Equal(pc.IssuedAt) || !rec.ExpiresAt.Equal(pc.ExpiresAt) {
		t.Error("manifest record timestamps must match the issued PeerCred")
	}
}

// TestIssuePeerCred_customTTL: explicit TTL is honored; RefreshAt is
// half of it.
func TestIssuePeerCred_customTTL(t *testing.T) {
	ctx := context.Background()
	primary, peerID := pairedPeer(t, []string{"allowed"})

	pc, err := primary.IssuePeerCred(ctx, peerID, []string{"allowed"}, 48*time.Hour)
	if err != nil {
		t.Fatalf("IssuePeerCred: %v", err)
	}
	if pc.ExpiresAt.Sub(pc.IssuedAt) != 48*time.Hour {
		t.Errorf("custom TTL: ExpiresAt - IssuedAt = %v, want 48h", pc.ExpiresAt.Sub(pc.IssuedAt))
	}
	if !pc.RefreshAt.Equal(pc.IssuedAt.Add(24 * time.Hour)) {
		t.Errorf("RefreshAt = %v, want IssuedAt+24h (half of 48h)", pc.RefreshAt)
	}
}

// TestIssuePeerCred_ttlCapEnforced: TTL > PeerCredMaxTTL must error.
// This is the security boundary that limits leaked-cred exposure.
func TestIssuePeerCred_ttlCapEnforced(t *testing.T) {
	ctx := context.Background()
	primary, peerID := pairedPeer(t, []string{"allowed"})

	_, err := primary.IssuePeerCred(ctx, peerID, []string{"allowed"}, PeerCredMaxTTL+time.Hour)
	if err == nil {
		t.Fatal("TTL exceeding cap must error")
	}
	if !strings.Contains(err.Error(), "exceeds max") {
		t.Errorf("error must mention cap: %v", err)
	}
}

// TestIssuePeerCred_refusesWithoutMaster: peers can't mint bearer creds
// for other devices.
func TestIssuePeerCred_refusesWithoutMaster(t *testing.T) {
	ctx := context.Background()
	primary, peerID := pairedPeer(t, []string{"allowed"})
	primary.Master = nil

	_, err := primary.IssuePeerCred(ctx, peerID, []string{"allowed"}, 0)
	if err == nil {
		t.Fatal("expected refusal without master")
	}
	if !strings.Contains(err.Error(), "primary") {
		t.Errorf("error must mention primary: %v", err)
	}
}

// TestIssuePeerCred_rejectsEmptyScope: bearer-mode peers MUST have a
// declared scope. Issuing with no scope would silently produce a
// full-bucket bearer cred whose blast radius defeats the whole
// bearer-mode design.
func TestIssuePeerCred_rejectsEmptyScope(t *testing.T) {
	ctx := context.Background()
	primary, peerID := pairedPeer(t, []string{"allowed"})

	for _, scope := range [][]string{nil, {}} {
		_, err := primary.IssuePeerCred(ctx, peerID, scope, 0)
		if err == nil {
			t.Errorf("empty scope %v must error", scope)
		}
	}
}

// TestIssuePeerCred_rejectsUnknownCompartment
func TestIssuePeerCred_rejectsUnknownCompartment(t *testing.T) {
	ctx := context.Background()
	primary, peerID := pairedPeer(t, []string{"allowed"})

	_, err := primary.IssuePeerCred(ctx, peerID, []string{"never-existed"}, 0)
	if err == nil {
		t.Fatal("scope with unknown compartment must error")
	}
	if !strings.Contains(err.Error(), "non-existent") {
		t.Errorf("error must mention non-existent: %v", err)
	}
}

// TestIssuePeerCred_refusesUnknownDevice
func TestIssuePeerCred_refusesUnknownDevice(t *testing.T) {
	ctx := context.Background()
	primary, _ := newPrimary(t)
	if err := primary.CompartmentCreate(ctx, "x", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	_, err := primary.IssuePeerCred(ctx, "dev_nonexistent", []string{"x"}, 0)
	if err == nil {
		t.Fatal("expected unknown-device error")
	}
}

// TestIssuePeerCred_refusesMasterPseudoDevice
func TestIssuePeerCred_refusesMasterPseudoDevice(t *testing.T) {
	ctx := context.Background()
	primary, _ := newPrimary(t)
	if err := primary.CompartmentCreate(ctx, "x", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	_, err := primary.IssuePeerCred(ctx, domain.MasterDeviceID, []string{"x"}, 0)
	if err == nil {
		t.Fatal("expected refusal for master pseudo-device")
	}
}

// TestIssuePeerCred_refusesOutOfDeviceScope: if the target device has
// CompartmentScope=[X] in its manifest entry, issuing a PeerCred with
// scope=[Y] must be refused — IssuePeerCred can't elevate beyond the
// device's own bounds.
func TestIssuePeerCred_refusesOutOfDeviceScope(t *testing.T) {
	ctx := context.Background()
	// Pair the peer scoped for "allowed" only (driveScopedHandshake
	// creates "allowed" + "blocked" but only scopes peer for "allowed").
	primary, peerID := pairedPeer(t, []string{"allowed"})
	_, err := primary.IssuePeerCred(ctx, peerID, []string{"blocked"}, 0)
	if err == nil {
		t.Fatal("issuing for out-of-device-scope compartment must error")
	}
	if !strings.Contains(err.Error(), "not scoped for") {
		t.Errorf("error must explain scope mismatch: %v", err)
	}
}

// TestIssuePeerCred_reissuanceOverwritesRecord: issuing twice for the
// same device replaces the manifest record with the new JTI. Manifest
// sequence advances each time.
func TestIssuePeerCred_reissuanceOverwritesRecord(t *testing.T) {
	ctx := context.Background()
	primary, peerID := pairedPeer(t, []string{"allowed"})

	first, err := primary.IssuePeerCred(ctx, peerID, []string{"allowed"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	m1, _ := primary.Manifest(ctx)
	seq1 := m1.Sequence

	second, err := primary.IssuePeerCred(ctx, peerID, []string{"allowed"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if first.JTI == second.JTI {
		t.Error("re-issuance must produce a fresh JTI")
	}

	m2, _ := primary.Manifest(ctx)
	if m2.Sequence <= seq1 {
		t.Errorf("re-issuance must advance sequence: %d -> %d", seq1, m2.Sequence)
	}
	if m2.PeerCreds[peerID].JTI != second.JTI {
		t.Errorf("manifest record must track LATEST JTI: %q vs %q", m2.PeerCreds[peerID].JTI, second.JTI)
	}
	if m2.PeerCreds[peerID].Revoked {
		t.Error("re-issuance must reset Revoked to false")
	}
}

// TestIssuePeerCred_jwtSplit_dataCredScope: under DD-10, the Data
// JWT must grant RW on compartment paths and MUST NOT include any
// control-plane path. The data plane is data-only.
func TestIssuePeerCred_jwtSplit_dataCredScope(t *testing.T) {
	ctx := context.Background()
	primary, peerID := pairedPeer(t, []string{"allowed"})

	pc, err := primary.IssuePeerCred(ctx, peerID, []string{"allowed"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	dataJWT, _ := credentials.DecodeR2SessionToken(pc.Data.SessionToken)
	dataClaims, _, _, err := credentials.DecodeR2JWT(dataJWT)
	if err != nil {
		t.Fatalf("decode Data JWT: %v", err)
	}
	if dataClaims.Scope != credentials.R2ScopeObjectReadWrite {
		t.Errorf("Data JWT scope = %q, want object-read-write", dataClaims.Scope)
	}
	if !scopeContains(dataClaims.Paths.PrefixPaths, "compartments/allowed/") {
		t.Errorf("Data JWT missing compartments/allowed/ prefix; got: %v", dataClaims.Paths.PrefixPaths)
	}
	if !scopeContains(dataClaims.Paths.ObjectPaths, "compartments/allowed") {
		t.Errorf("Data JWT missing compartments/allowed object (rclone HEAD probe); got: %v", dataClaims.Paths.ObjectPaths)
	}
	// Data must NOT carry control paths — that's the whole point.
	for _, ctrl := range []string{domain.ManifestKey, domain.RevocationsKey, domain.PeerCredRefreshKey(peerID)} {
		if scopeContains(dataClaims.Paths.ObjectPaths, ctrl) {
			t.Errorf("Data JWT must NOT include control-plane path %q (DD-10: that's Control's job)", ctrl)
		}
	}
}

// TestIssuePeerCred_jwtSplit_controlCredScope: under DD-10, the
// Control JWT must be RO and cover exactly the three control-plane
// paths (manifest, revocations, this peer's refresh blob).
func TestIssuePeerCred_jwtSplit_controlCredScope(t *testing.T) {
	ctx := context.Background()
	primary, peerID := pairedPeer(t, []string{"allowed"})

	pc, err := primary.IssuePeerCred(ctx, peerID, []string{"allowed"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if pc.Control == nil {
		t.Fatal("DD-10: Control cred must be present on R2 local-sign")
	}
	ctrlJWT, _ := credentials.DecodeR2SessionToken(pc.Control.SessionToken)
	ctrlClaims, _, _, err := credentials.DecodeR2JWT(ctrlJWT)
	if err != nil {
		t.Fatalf("decode Control JWT: %v", err)
	}
	if ctrlClaims.Scope != credentials.R2ScopeObjectReadOnly {
		t.Errorf("Control JWT scope = %q, want object-read-only (this is the entire DD-10 point)", ctrlClaims.Scope)
	}
	for _, p := range []string{domain.ManifestKey, domain.RevocationsKey, domain.PeerCredRefreshKey(peerID)} {
		if !scopeContains(ctrlClaims.Paths.ObjectPaths, p) {
			t.Errorf("Control JWT missing control-plane path %q; got: %v", p, ctrlClaims.Paths.ObjectPaths)
		}
	}
	// Control must NOT grant access to compartment data.
	if scopeContains(ctrlClaims.Paths.ObjectPaths, "compartments/allowed") ||
		scopeContains(ctrlClaims.Paths.PrefixPaths, "compartments/allowed/") {
		t.Errorf("Control JWT must NOT include compartment paths (defense in depth); got: %+v", ctrlClaims.Paths)
	}
}

// TestIssuePeerCred_jwtsShareTTL: Data and Control JWTs must expire
// together. Otherwise we'd get half-broken states where the peer can
// still read data but can't fetch manifest (or vice versa).
func TestIssuePeerCred_jwtsShareTTL(t *testing.T) {
	ctx := context.Background()
	primary, peerID := pairedPeer(t, []string{"allowed"})

	pc, err := primary.IssuePeerCred(ctx, peerID, []string{"allowed"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	dataJWT, _ := credentials.DecodeR2SessionToken(pc.Data.SessionToken)
	dataClaims, _, _, _ := credentials.DecodeR2JWT(dataJWT)
	ctrlJWT, _ := credentials.DecodeR2SessionToken(pc.Control.SessionToken)
	ctrlClaims, _, _, _ := credentials.DecodeR2JWT(ctrlJWT)

	if dataClaims.IssuedAt != ctrlClaims.IssuedAt {
		t.Errorf("Data + Control JWTs must share IssuedAt: data=%d ctrl=%d",
			dataClaims.IssuedAt, ctrlClaims.IssuedAt)
	}
	if dataClaims.ExpiresAt != ctrlClaims.ExpiresAt {
		t.Errorf("Data + Control JWTs must share ExpiresAt: data=%d ctrl=%d",
			dataClaims.ExpiresAt, ctrlClaims.ExpiresAt)
	}
}

// TestIssuePeerCred_deviceRevokeRemovesPeerCredRecord: when a peer is
// revoked via `drift device revoke`, the PeerCreds entry must be
// cleaned up too. Without this, the manifest would carry a stale
// record pointing at a device that's no longer in Devices — a real
// inconsistency that confuses any code iterating PeerCreds.
func TestIssuePeerCred_deviceRevokeRemovesPeerCredRecord(t *testing.T) {
	ctx := context.Background()
	primary, peerID := pairedPeer(t, []string{"allowed"})

	if _, err := primary.IssuePeerCred(ctx, peerID, []string{"allowed"}, 0); err != nil {
		t.Fatal(err)
	}
	m, _ := primary.Manifest(ctx)
	if _, ok := m.PeerCreds[peerID]; !ok {
		t.Fatal("precondition: PeerCreds entry must exist before revoke")
	}

	if _, err := primary.DeviceRevoke(ctx, peerID, false); err != nil {
		t.Fatalf("DeviceRevoke: %v", err)
	}
	m, _ = primary.Manifest(ctx)
	if _, ok := m.PeerCreds[peerID]; ok {
		t.Error("DeviceRevoke must clean up PeerCreds entry")
	}
	if _, ok := m.Devices[peerID]; ok {
		t.Error("device entry must also be gone")
	}
}

// TestIssuePeerCred_reissuanceClearsRevoked: if the previous record
// was Revoked=true, re-issuing for the same device should reset to
// not-revoked. (Operator-controlled "rehabilitate" path.)
func TestIssuePeerCred_reissuanceClearsRevoked(t *testing.T) {
	ctx := context.Background()
	primary, peerID := pairedPeer(t, []string{"allowed"})

	// Issue first.
	if _, err := primary.IssuePeerCred(ctx, peerID, []string{"allowed"}, 0); err != nil {
		t.Fatal(err)
	}
	// Manually flip Revoked to simulate a prior revocation.
	if err := primary.Writer.ReadModifyWrite(ctx, domain.ManifestKey, func(cur []byte) ([]byte, error) {
		mm, err := manifest.Decrypt(cur, primary.CPRK, primary.Config.WorkspaceID)
		if err != nil {
			return nil, err
		}
		rec := mm.PeerCreds[peerID]
		rec.Revoked = true
		mm.PeerCreds[peerID] = rec
		mm.Sequence++
		if err := manifest.Sign(mm, primary.Config.DeviceID, primary.Device.SignPriv); err != nil {
			return nil, err
		}
		return manifest.Encrypt(mm, primary.CPRK)
	}); err != nil {
		t.Fatalf("flip Revoked: %v", err)
	}
	// Re-issue.
	if _, err := primary.IssuePeerCred(ctx, peerID, []string{"allowed"}, 0); err != nil {
		t.Fatal(err)
	}
	m, _ := primary.Manifest(ctx)
	if m.PeerCreds[peerID].Revoked {
		t.Error("re-issuance must clear the Revoked flag")
	}
}
