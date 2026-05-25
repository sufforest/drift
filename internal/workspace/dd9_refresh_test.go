package workspace

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sufforest/drift/internal/credentials"
	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/mount"
	driftsync "github.com/sufforest/drift/internal/sync"
)

// TestDD9Refresh_endToEnd: primary mints a refresh + uploads;
// secondary pulls + saves; secondary's MountDirect works again.
func TestDD9Refresh_endToEnd(t *testing.T) {
	ctx := context.Background()
	primary, secondaryState, claim, prov := driveBearerHandshake(t, []string{"allowed"})

	// Capture the initial local JTI on the peer.
	oldCred, _ := secondaryState.LoadPeerCred()
	oldJTI := oldCred.JTI

	// Primary side: mint refresh.
	mintRes, err := primary.PeerRefreshMint(ctx, claim.DeviceID)
	if err != nil {
		t.Fatalf("PeerRefreshMint: %v", err)
	}
	if mintRes.OldJTI != oldJTI {
		t.Errorf("mint OldJTI = %q, want %q", mintRes.OldJTI, oldJTI)
	}
	if mintRes.NewJTI == oldJTI {
		t.Error("refresh must produce a NEW JTI")
	}
	// Bucket key exists.
	if ok, _ := prov.Exists(ctx, domain.PeerCredRefreshKey(claim.DeviceID)); !ok {
		t.Error("refresh blob must be present in bucket after PeerRefreshMint")
	}

	// At this moment the peer's local cred is stale (manifest's JTI is
	// new, local is old). Mount should be refused until peer fetches.
	staleSecondary := loadBearerSecondary(t, primary, secondaryState, prov)
	_, mountErr := staleSecondary.MountDirect(ctx, DirectMountOptions{
		Mounter:   mount.NewNoopMounter(),
		Syncer:    driftsync.NewNoopSyncer(),
		MountBase: t.TempDir(),
		Vols:      []string{"allowed"},
	})
	if mountErr == nil || !strings.Contains(mountErr.Error(), "JTI") {
		t.Errorf("stale-cred mount should fail with JTI mismatch, got: %v", mountErr)
	}

	// Peer side: fetch refresh.
	fetchRes, err := staleSecondary.PeerRefreshFetch(ctx)
	if err != nil {
		t.Fatalf("PeerRefreshFetch: %v", err)
	}
	if fetchRes.OldJTI != oldJTI {
		t.Errorf("fetch OldJTI = %q, want %q", fetchRes.OldJTI, oldJTI)
	}
	if fetchRes.NewJTI != mintRes.NewJTI {
		t.Errorf("fetch NewJTI = %q, want %q", fetchRes.NewJTI, mintRes.NewJTI)
	}

	// Now the peer's local PeerCred has the new JTI; mount should
	// succeed.
	freshSecondary := loadBearerSecondary(t, primary, secondaryState, prov)
	sess, err := freshSecondary.MountDirect(ctx, DirectMountOptions{
		Mounter:   mount.NewNoopMounter(),
		Syncer:    driftsync.NewNoopSyncer(),
		MountBase: t.TempDir(),
		Vols:      []string{"allowed"},
	})
	if err != nil {
		t.Fatalf("post-refresh mount must succeed, got: %v", err)
	}
	_ = sess.Close()
}

// TestDD9Refresh_mintRefusesRevokedPeer: primary won't mint a refresh
// for a revoked peer — refresh is for active peers only. Operator
// must explicitly re-pair to rehabilitate.
func TestDD9Refresh_mintRefusesRevokedPeer(t *testing.T) {
	ctx := context.Background()
	primary, _, claim, _ := driveBearerHandshake(t, []string{"allowed"})
	if _, err := primary.PeerRevoke(ctx, claim.DeviceID); err != nil {
		t.Fatal(err)
	}
	_, err := primary.PeerRefreshMint(ctx, claim.DeviceID)
	if err == nil {
		t.Fatal("refresh of a revoked peer must error")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Errorf("error must explain why: %v", err)
	}
}

// TestDD9Refresh_mintRefusesWithoutMaster
func TestDD9Refresh_mintRefusesWithoutMaster(t *testing.T) {
	ctx := context.Background()
	primary, _, claim, _ := driveBearerHandshake(t, []string{"allowed"})
	primary.Master = nil
	_, err := primary.PeerRefreshMint(ctx, claim.DeviceID)
	if err == nil {
		t.Fatal("expected refusal without master")
	}
}

// TestDD9Refresh_mintRefusesUnknownPeer
func TestDD9Refresh_mintRefusesUnknownPeer(t *testing.T) {
	ctx := context.Background()
	primary, _ := newPrimary(t)
	_, err := primary.PeerRefreshMint(ctx, "dev_nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown peer")
	}
	if !strings.Contains(err.Error(), "no bearer PeerCred record") {
		t.Errorf("error must explain why: %v", err)
	}
}

// TestDD9Refresh_fetchRefusesOnNonBearerDevice
func TestDD9Refresh_fetchRefusesOnNonBearerDevice(t *testing.T) {
	ctx := context.Background()
	primary, _ := newPrimary(t)
	_, err := primary.PeerRefreshFetch(ctx)
	if err == nil {
		t.Fatal("fetch on non-bearer device must error")
	}
	if !strings.Contains(err.Error(), "not bearer-mode") {
		t.Errorf("error must mention bearer-mode: %v", err)
	}
}

// TestDD9Refresh_fetchRefusesWhenNoBlobInBucket: secondary tries to
// pull when primary hasn't minted yet.
func TestDD9Refresh_fetchRefusesWhenNoBlobInBucket(t *testing.T) {
	ctx := context.Background()
	primary, secondaryState, _, prov := driveBearerHandshake(t, []string{"allowed"})
	secondary := loadBearerSecondary(t, primary, secondaryState, prov)

	_, err := secondary.PeerRefreshFetch(ctx)
	if err == nil {
		t.Fatal("fetch with no blob in bucket must error")
	}
	if !strings.Contains(err.Error(), "no refresh blob") {
		t.Errorf("error must mention missing blob: %v", err)
	}
}

// TestDD9Refresh_fetchRefusesTamperedBlob: an attacker who can write
// to the bucket cannot substitute a forged PeerCred — the seal +
// signature verifies on the peer side.
func TestDD9Refresh_fetchRefusesTamperedBlob(t *testing.T) {
	ctx := context.Background()
	primary, secondaryState, claim, prov := driveBearerHandshake(t, []string{"allowed"})

	// Primary legitimately mints a refresh.
	if _, err := primary.PeerRefreshMint(ctx, claim.DeviceID); err != nil {
		t.Fatal(err)
	}

	// "Attacker" overwrites the sealed blob with random garbage. The
	// peer's open should fail.
	if err := prov.Put(ctx, domain.PeerCredRefreshKey(claim.DeviceID), []byte("garbage-not-a-sealed-box")); err != nil {
		t.Fatal(err)
	}

	secondary := loadBearerSecondary(t, primary, secondaryState, prov)
	_, err := secondary.PeerRefreshFetch(ctx)
	if err == nil {
		t.Fatal("tampered refresh blob must be refused")
	}
}

// TestDD9Refresh_fetchRefusesForgedSignature: even if the sealed-box
// envelope opens (because attacker sealed it for the peer's pubkey),
// the inner PeerCred's signature must verify under the workspace
// master — a forged sig fails.
func TestDD9Refresh_fetchRefusesForgedSignature(t *testing.T) {
	ctx := context.Background()
	primary, secondaryState, claim, prov := driveBearerHandshake(t, []string{"allowed"})

	// Build a forged PeerCred signed by an attacker keypair. Pulled
	// from the existing cred to inherit DeviceID + scope (so the
	// non-sig checks pass).
	good, _ := secondaryState.LoadPeerCred()
	_, attackerPriv, _ := ed25519.GenerateKey(nil)
	forged := credentials.SignPeerCred(*good, attackerPriv)
	credBytes, _ := json.Marshal(forged)

	// Seal for the real peer (we know their X25519 pub from the
	// manifest). Attacker doesn't need to know the master priv; they
	// just need bucket-write to drop the seal there.
	m, _ := primary.Manifest(ctx)
	dev := m.Devices[claim.DeviceID]
	var peerPub [dcrypto.X25519KeySize]byte
	copy(peerPub[:], dev.EncryptKey)
	sealed, err := dcrypto.SealFor(peerPub, credBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := prov.Put(ctx, domain.PeerCredRefreshKey(claim.DeviceID), sealed); err != nil {
		t.Fatal(err)
	}

	secondary := loadBearerSecondary(t, primary, secondaryState, prov)
	_, fetchErr := secondary.PeerRefreshFetch(ctx)
	if fetchErr == nil {
		t.Fatal("forged-signature refresh blob must be refused")
	}
	if !strings.Contains(fetchErr.Error(), "signature") {
		t.Errorf("error must mention signature: %v", fetchErr)
	}
}
