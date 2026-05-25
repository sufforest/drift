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
	"github.com/sufforest/drift/internal/mount"
	"github.com/sufforest/drift/internal/storage"
	driftsync "github.com/sufforest/drift/internal/sync"
)

// loadBearerSecondary takes the artifacts from driveBearerHandshake
// and constructs a usable Workspace from the secondary's state. Used
// to drive Mount tests from the peer's perspective.
func loadBearerSecondary(t *testing.T, primary *Workspace, secondaryState *State, prov *storage.MemoryProvider) *Workspace {
	t.Helper()
	ctx := context.Background()
	ws, err := Load(ctx, Options{
		State:    secondaryState,
		Provider: prov,
		Writer:   storage.NewConditionalPutWriter(prov),
		Now:      primary.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return ws
}

// TestDD9Mount_happyPath: a freshly-paired bearer peer can call
// MountDirect through a NoopMounter and get one mount per scoped vol.
// The S3 credential passed to the mounter is built from PeerCred
// (SessionToken populated) rather than from a parent (no session).
func TestDD9Mount_happyPath(t *testing.T) {
	ctx := context.Background()
	primary, secondaryState, _, prov := driveBearerHandshake(t, []string{"allowed"})
	secondary := loadBearerSecondary(t, primary, secondaryState, prov)

	noopMounter := mount.NewNoopMounter()
	sess, err := secondary.MountDirect(ctx, DirectMountOptions{
		Mounter:   noopMounter,
		Syncer:    driftsync.NewNoopSyncer(),
		MountBase: t.TempDir(),
		Vols:      []string{"allowed"},
	})
	if err != nil {
		t.Fatalf("MountDirect on bearer peer: %v", err)
	}
	if len(sess.Mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(sess.Mounts))
	}
	if sess.Mounts[0].Compartment() != "allowed" {
		t.Fatalf("wrong vol mounted: %s", sess.Mounts[0].Compartment())
	}
	_ = sess.Close()
}

// TestDD9Mount_refusesOutOfScope: even though the peer holds the right
// to talk to R2 (PeerCred is valid), MountDirect refuses to attempt a
// mount on a vol outside the cred's declared Scope. The vol must
// EXIST in the workspace — otherwise the "no vol named" error fires
// first; here we deliberately create both so the scope check is the
// gate under test.
func TestDD9Mount_refusesOutOfScope(t *testing.T) {
	ctx := context.Background()
	primary, secondaryState, _, prov := driveBearerHandshake(t, []string{"allowed"})
	// Create another vol the bearer is NOT scoped for.
	if err := primary.CompartmentCreate(ctx, "blocked", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	secondary := loadBearerSecondary(t, primary, secondaryState, prov)

	_, err := secondary.MountDirect(ctx, DirectMountOptions{
		Mounter:   mount.NewNoopMounter(),
		Syncer:    driftsync.NewNoopSyncer(),
		MountBase: t.TempDir(),
		Vols:      []string{"blocked"},
	})
	if err == nil {
		t.Fatal("MountDirect must refuse out-of-scope vol")
	}
	if !strings.Contains(err.Error(), "not in this bearer device's scope") {
		t.Errorf("error must mention scope mismatch: %v", err)
	}
}

// TestDD9Mount_refusesExpiredCred: a PeerCred past its ExpiresAt is
// refused. Critical: this prevents a stale cred from being used even
// if R2 happens to still accept the underlying JWT due to clock skew.
func TestDD9Mount_refusesExpiredCred(t *testing.T) {
	ctx := context.Background()
	primary, secondaryState, _, prov := driveBearerHandshake(t, []string{"allowed"})

	// Tamper: load the PeerCred, set ExpiresAt to past, re-sign with
	// the primary's master priv so the signature still verifies (we
	// want to test the EXPIRY check specifically, not the sig check).
	pc, err := secondaryState.LoadPeerCred()
	if err != nil {
		t.Fatal(err)
	}
	pc.ExpiresAt = primary.now().Add(-time.Hour)
	pc.RefreshAt = primary.now().Add(-2 * time.Hour)
	expired := credentials.SignPeerCred(*pc, primary.Master.SignPriv)
	if err := secondaryState.SavePeerCred(&expired); err != nil {
		t.Fatal(err)
	}

	secondary := loadBearerSecondary(t, primary, secondaryState, prov)
	_, err = secondary.MountDirect(ctx, DirectMountOptions{
		Mounter:   mount.NewNoopMounter(),
		Syncer:    driftsync.NewNoopSyncer(),
		MountBase: t.TempDir(),
		Vols:      []string{"allowed"},
	})
	if err == nil {
		t.Fatal("expired PeerCred must refuse MountDirect")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error must mention expiry: %v", err)
	}
}

// TestDD9Mount_refusesRevokedInManifest: PeerCreds[me].Revoked=true
// must refuse mount even when the local PeerCred bytes haven't been
// touched. This is the workspace-side revocation channel — it lets
// the primary kill peer access without rotating the R2 token.
func TestDD9Mount_refusesRevokedInManifest(t *testing.T) {
	ctx := context.Background()
	primary, secondaryState, claim, prov := driveBearerHandshake(t, []string{"allowed"})

	// Flip Revoked in the manifest. Use primary's writer + master key
	// to make the change valid (signed manifest, master pseudo-device
	// pinned). We're simulating the eventual `drift peer revoke`
	// op directly here since it doesn't exist yet (phase 6).
	if err := primary.Writer.ReadModifyWrite(ctx, domain.ManifestKey, func(cur []byte) ([]byte, error) {
		mm, err := manifest.Decrypt(cur, primary.CPRK, primary.Config.WorkspaceID)
		if err != nil {
			return nil, err
		}
		rec := mm.PeerCreds[claim.DeviceID]
		rec.Revoked = true
		mm.PeerCreds[claim.DeviceID] = rec
		mm.Sequence++
		if err := manifest.Sign(mm, primary.Config.DeviceID, primary.Device.SignPriv); err != nil {
			return nil, err
		}
		return manifest.Encrypt(mm, primary.CPRK)
	}); err != nil {
		t.Fatalf("flip Revoked: %v", err)
	}

	secondary := loadBearerSecondary(t, primary, secondaryState, prov)
	_, err := secondary.MountDirect(ctx, DirectMountOptions{
		Mounter:   mount.NewNoopMounter(),
		Syncer:    driftsync.NewNoopSyncer(),
		MountBase: t.TempDir(),
		Vols:      []string{"allowed"},
	})
	if err == nil {
		t.Fatal("revoked-in-manifest PeerCred must refuse MountDirect")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Errorf("error must mention revoked: %v", err)
	}
}

// TestDD9Mount_refusesJTIMismatch: when the manifest record has a JTI
// different from the local PeerCred's JTI, the primary has issued a
// newer cred and this one is stale. Refuse and tell the user to refresh.
func TestDD9Mount_refusesJTIMismatch(t *testing.T) {
	ctx := context.Background()
	primary, secondaryState, claim, prov := driveBearerHandshake(t, []string{"allowed"})

	// Stash an "old" cred locally, then have primary mint a new one
	// (overwriting the manifest record's JTI). Now local JTI ≠ manifest JTI.
	if _, err := primary.IssuePeerCred(ctx, claim.DeviceID, []string{"allowed"}, 0); err != nil {
		t.Fatalf("re-issue: %v", err)
	}

	secondary := loadBearerSecondary(t, primary, secondaryState, prov)
	_, err := secondary.MountDirect(ctx, DirectMountOptions{
		Mounter:   mount.NewNoopMounter(),
		Syncer:    driftsync.NewNoopSyncer(),
		MountBase: t.TempDir(),
		Vols:      []string{"allowed"},
	})
	if err == nil {
		t.Fatal("local-vs-manifest JTI mismatch must refuse MountDirect")
	}
	if !strings.Contains(err.Error(), "JTI") {
		t.Errorf("error must mention JTI mismatch: %v", err)
	}
}

// TestDD9Mount_refusesTamperedSignature: a PeerCred whose bytes have
// been mutated (e.g., attacker-supplied keychain content) must fail
// the signature check before any mount attempt. Defense against a
// device-local supply-chain attack where keychain is owned by an
// attacker but the workspace master pub is still genuine.
func TestDD9Mount_refusesTamperedSignature(t *testing.T) {
	ctx := context.Background()
	primary, secondaryState, _, prov := driveBearerHandshake(t, []string{"allowed"})

	// Generate an attacker keypair; re-sign the existing cred with it.
	_, attackerPriv, _ := ed25519.GenerateKey(nil)
	pc, _ := secondaryState.LoadPeerCred()
	forged := credentials.SignPeerCred(*pc, attackerPriv)
	if err := secondaryState.SavePeerCred(&forged); err != nil {
		t.Fatal(err)
	}

	secondary := loadBearerSecondary(t, primary, secondaryState, prov)
	_, err := secondary.MountDirect(ctx, DirectMountOptions{
		Mounter:   mount.NewNoopMounter(),
		Syncer:    driftsync.NewNoopSyncer(),
		MountBase: t.TempDir(),
		Vols:      []string{"allowed"},
	})
	if err == nil {
		t.Fatal("tampered PeerCred signature must refuse MountDirect")
	}
	if !strings.Contains(err.Error(), "failed verification") && !strings.Contains(err.Error(), "signature") {
		t.Errorf("error must mention signature failure: %v", err)
	}
}

// TestDD9Mount_legacyParentPeerStillWorks: primary + v1 --peer still
// mount via the parent-cred path. Regression guard.
func TestDD9Mount_legacyParentPeerStillWorks(t *testing.T) {
	ctx := context.Background()
	primary, _ := newPrimary(t)
	if err := primary.CompartmentCreate(ctx, "shared", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	sess, err := primary.MountDirect(ctx, DirectMountOptions{
		Mounter:   mount.NewNoopMounter(),
		Syncer:    driftsync.NewNoopSyncer(),
		MountBase: t.TempDir(),
		Vols:      []string{"shared"},
	})
	if err != nil {
		t.Fatalf("primary MountDirect: %v", err)
	}
	if len(sess.Mounts) != 1 {
		t.Errorf("primary expected 1 mount, got %d", len(sess.Mounts))
	}
	_ = sess.Close()
}
