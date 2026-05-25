package workspace

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/mount"
	driftsync "github.com/sufforest/drift/internal/sync"
)

// TestDD9Revoke_happyPath: revoke a bearer peer. Manifest record
// flipped, JTI appended to revocations.enc, audit emitted, sequence
// advanced.
func TestDD9Revoke_happyPath(t *testing.T) {
	ctx := context.Background()
	primary, _, claim, prov := driveBearerHandshake(t, []string{"allowed"})

	m, _ := primary.Manifest(ctx)
	beforeSeq := m.Sequence
	jtiBefore := m.PeerCreds[claim.DeviceID].JTI

	res, err := primary.PeerRevoke(ctx, claim.DeviceID)
	if err != nil {
		t.Fatalf("PeerRevoke: %v", err)
	}
	if res.AlreadyRevoked {
		t.Fatal("first revoke must not be already-revoked")
	}
	if res.JTI != jtiBefore {
		t.Errorf("result JTI = %q, want %q (manifest's)", res.JTI, jtiBefore)
	}
	if res.Sequence <= beforeSeq {
		t.Errorf("sequence must advance: %d -> %d", beforeSeq, res.Sequence)
	}

	// Manifest reflects the revocation.
	m, _ = primary.Manifest(ctx)
	if !m.PeerCreds[claim.DeviceID].Revoked {
		t.Error("manifest must reflect Revoked=true after PeerRevoke")
	}

	// revocations.enc contains the JTI as a revoked entry.
	revBody, err := prov.Get(ctx, domain.RevocationsKey)
	if err != nil {
		t.Fatalf("fetch revocations.enc: %v", err)
	}
	if !revocationsContainTID(t, primary, revBody, res.JTI) {
		t.Errorf("revocations.enc must contain JTI %s after PeerRevoke", res.JTI)
	}
}

// TestDD9Revoke_revokedPeerCannotMount: after revoke, the secondary's
// MountDirect attempts are refused with the revoked error from phase 4.
// End-to-end check of the revocation channel.
func TestDD9Revoke_revokedPeerCannotMount(t *testing.T) {
	ctx := context.Background()
	primary, secondaryState, claim, prov := driveBearerHandshake(t, []string{"allowed"})

	if _, err := primary.PeerRevoke(ctx, claim.DeviceID); err != nil {
		t.Fatalf("PeerRevoke: %v", err)
	}

	secondary := loadBearerSecondary(t, primary, secondaryState, prov)
	_, err := secondary.MountDirect(ctx, DirectMountOptions{
		Mounter:   mount.NewNoopMounter(),
		Syncer:    driftsync.NewNoopSyncer(),
		MountBase: t.TempDir(),
		Vols:      []string{"allowed"},
	})
	if err == nil {
		t.Fatal("revoked peer must NOT be able to MountDirect")
	}
	if !strings.Contains(err.Error(), "revoked") {
		t.Errorf("error must mention revocation: %v", err)
	}
}

// TestDD9Revoke_idempotent: revoking twice returns AlreadyRevoked
// and does not advance the manifest sequence.
func TestDD9Revoke_idempotent(t *testing.T) {
	ctx := context.Background()
	primary, _, claim, _ := driveBearerHandshake(t, []string{"allowed"})

	if _, err := primary.PeerRevoke(ctx, claim.DeviceID); err != nil {
		t.Fatal(err)
	}
	m, _ := primary.Manifest(ctx)
	seqAfterFirst := m.Sequence

	res, err := primary.PeerRevoke(ctx, claim.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if !res.AlreadyRevoked {
		t.Error("second revoke must be AlreadyRevoked")
	}
	m, _ = primary.Manifest(ctx)
	if m.Sequence != seqAfterFirst {
		t.Errorf("idempotent revoke must not advance sequence: %d -> %d", seqAfterFirst, m.Sequence)
	}
}

// TestDD9Revoke_refusesUnknownPeer: revoking a device that has no
// PeerCred record errors clearly. Catches typos / wrong-id.
func TestDD9Revoke_refusesUnknownPeer(t *testing.T) {
	ctx := context.Background()
	primary, _, _, _ := driveBearerHandshake(t, []string{"allowed"})

	_, err := primary.PeerRevoke(ctx, "dev_nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown peer")
	}
	if !strings.Contains(err.Error(), "no bearer PeerCred record") {
		t.Errorf("error must explain why: %v", err)
	}
}

// TestDD9Revoke_refusesWithoutMaster
func TestDD9Revoke_refusesWithoutMaster(t *testing.T) {
	ctx := context.Background()
	primary, _, claim, _ := driveBearerHandshake(t, []string{"allowed"})
	primary.Master = nil

	_, err := primary.PeerRevoke(ctx, claim.DeviceID)
	if err == nil {
		t.Fatal("expected refusal without master")
	}
	if !strings.Contains(err.Error(), "primary") {
		t.Errorf("error must mention primary: %v", err)
	}
}

// TestDD9Revoke_thenReissueClearsFlag: after revoke, primary can
// re-issue a fresh PeerCred for the same device — the new issuance
// clears the Revoked flag (rehabilitation path, already tested in
// phase 2 but verified again end-to-end here).
func TestDD9Revoke_thenReissueClearsFlag(t *testing.T) {
	ctx := context.Background()
	primary, _, claim, _ := driveBearerHandshake(t, []string{"allowed"})

	if _, err := primary.PeerRevoke(ctx, claim.DeviceID); err != nil {
		t.Fatal(err)
	}
	m, _ := primary.Manifest(ctx)
	if !m.PeerCreds[claim.DeviceID].Revoked {
		t.Fatal("precondition: should be revoked")
	}

	if _, err := primary.IssuePeerCred(ctx, claim.DeviceID, []string{"allowed"}, 0); err != nil {
		t.Fatalf("re-issue: %v", err)
	}
	m, _ = primary.Manifest(ctx)
	if m.PeerCreds[claim.DeviceID].Revoked {
		t.Error("re-issuance must clear Revoked flag")
	}
}

// revocationsContainTID checks whether revocations.enc carries the
// named TID/JTI. revocations.enc is signed-but-not-encrypted (see
// internal/token/revoke.go) so a plain JSON parse works.
func revocationsContainTID(t *testing.T, _ *Workspace, body []byte, target string) bool {
	t.Helper()
	var doc struct {
		Entries []struct {
			TID string `json:"tid"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Logf("parse revocations.enc: %v", err)
		return false
	}
	for _, e := range doc.Entries {
		if e.TID == target {
			return true
		}
	}
	return false
}
