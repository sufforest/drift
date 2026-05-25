package workspace

import (
	"context"
	"testing"
)

// TestDD9List_emptyWorkspace: no bearer peers → empty slice, no error.
func TestDD9List_emptyWorkspace(t *testing.T) {
	primary, _ := newPrimary(t)
	peers, err := primary.PeerList(context.Background())
	if err != nil {
		t.Fatalf("PeerList: %v", err)
	}
	if len(peers) != 0 {
		t.Errorf("expected 0 bearer peers, got %d", len(peers))
	}
}

// TestDD9List_freshlyPaired: a freshly-paired bearer peer shows up
// with active state, the right scope, and a JTI matching the manifest
// record.
func TestDD9List_freshlyPaired(t *testing.T) {
	primary, _, claim, _ := driveBearerHandshake(t, []string{"allowed"})
	peers, err := primary.PeerList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 bearer peer, got %d", len(peers))
	}
	p := peers[0]
	if p.DeviceID != claim.DeviceID {
		t.Errorf("DeviceID = %q, want %q", p.DeviceID, claim.DeviceID)
	}
	if p.Revoked || p.Expired || p.NeedsRefresh {
		t.Errorf("fresh peer should be in active state: revoked=%v expired=%v needs=%v",
			p.Revoked, p.Expired, p.NeedsRefresh)
	}
	if len(p.Scope) != 1 || p.Scope[0] != "allowed" {
		t.Errorf("Scope = %v, want [allowed]", p.Scope)
	}
}

// TestDD9List_revokedShowsAsRevoked
func TestDD9List_revokedShowsAsRevoked(t *testing.T) {
	ctx := context.Background()
	primary, _, claim, _ := driveBearerHandshake(t, []string{"allowed"})
	if _, err := primary.PeerRevoke(ctx, claim.DeviceID); err != nil {
		t.Fatal(err)
	}
	peers, _ := primary.PeerList(ctx)
	if len(peers) != 1 || !peers[0].Revoked {
		t.Errorf("revoked peer should show Revoked=true, got %+v", peers)
	}
}

// TestDD9List_refusesWithoutMaster: peers cannot list bearer-mode
// peers (admin operation, matches the rest of peer.* surface).
func TestDD9List_refusesWithoutMaster(t *testing.T) {
	primary, _ := newPrimary(t)
	primary.Master = nil
	_, err := primary.PeerList(context.Background())
	if err == nil {
		t.Fatal("expected refusal without master")
	}
}

// TestDD9Status_onPrimary: HasPeerCred=false on the primary (no
// peercred.json there).
func TestDD9Status_onPrimary(t *testing.T) {
	primary, _ := newPrimary(t)
	s, err := primary.PeerStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.HasPeerCred {
		t.Error("primary should have HasPeerCred=false")
	}
}

// TestDD9Status_onBearerPeer: HasPeerCred=true, SignatureValid=true,
// fields populated.
func TestDD9Status_onBearerPeer(t *testing.T) {
	ctx := context.Background()
	primary, secondaryState, claim, prov := driveBearerHandshake(t, []string{"allowed"})
	secondary := loadBearerSecondary(t, primary, secondaryState, prov)

	s, err := secondary.PeerStatus(ctx)
	if err != nil {
		t.Fatalf("PeerStatus: %v", err)
	}
	if !s.HasPeerCred {
		t.Fatal("secondary should have HasPeerCred=true")
	}
	if !s.SignatureValid {
		t.Error("freshly-issued cred should have SignatureValid=true")
	}
	if s.DeviceID != claim.DeviceID {
		t.Errorf("DeviceID = %q, want %q", s.DeviceID, claim.DeviceID)
	}
	if s.Expired || s.NeedsRefresh {
		t.Errorf("fresh cred should not be expired or need refresh: expired=%v needs=%v",
			s.Expired, s.NeedsRefresh)
	}
	if s.ManifestRevoked {
		t.Error("fresh cred should not be ManifestRevoked")
	}
	if s.ManifestJTI != s.JTI {
		t.Errorf("local JTI %q must match manifest JTI %q", s.JTI, s.ManifestJTI)
	}
}

// TestDD9Status_detectsManifestRevocation: after primary revokes the
// peer, the peer's PeerStatus shows ManifestRevoked=true even though
// the local PeerCred bytes are unchanged.
func TestDD9Status_detectsManifestRevocation(t *testing.T) {
	ctx := context.Background()
	primary, secondaryState, claim, prov := driveBearerHandshake(t, []string{"allowed"})
	if _, err := primary.PeerRevoke(ctx, claim.DeviceID); err != nil {
		t.Fatal(err)
	}
	secondary := loadBearerSecondary(t, primary, secondaryState, prov)
	s, _ := secondary.PeerStatus(ctx)
	if !s.ManifestRevoked {
		t.Error("ManifestRevoked must be true after primary's PeerRevoke")
	}
}
