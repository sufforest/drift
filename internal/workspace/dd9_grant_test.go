package workspace

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sufforest/drift/internal/domain"
)

// TestDD9Grant_bearerPeerRefused: a DD-9 bearer peer cannot run
// drift grant. The error is explicit (mentions bearer-mode, points
// the user to the primary) so the operator immediately knows what to
// do — not a generic "no parent" message.
func TestDD9Grant_bearerPeerRefused(t *testing.T) {
	ctx := context.Background()
	primary, secondaryState, _, prov := driveBearerHandshake(t, []string{"allowed"})
	secondary := loadBearerSecondary(t, primary, secondaryState, prov)

	_, err := secondary.Grant(ctx, GrantRequest{
		Scope: []string{"allowed"},
		Mode:  domain.TokenModeRW,
		TTL:   time.Hour,
	})
	if err == nil {
		t.Fatal("bearer peer must refuse Grant")
	}
	if !strings.Contains(err.Error(), "bearer-mode") {
		t.Errorf("error must explicitly mention bearer-mode: %v", err)
	}
	if !strings.Contains(err.Error(), "primary") {
		t.Errorf("error must point user at the primary device: %v", err)
	}
}

// TestDD9Grant_primaryAndV1PeerStillMint: regression — Grant continues
// to work on devices that hold a parent.json (primary or DD-4 v1 peer
// from `drift link --peer`). The bearer-mode check is gated on
// HasPeerCred specifically, so devices with parent but no PeerCred
// are unaffected.
func TestDD9Grant_primaryStillMints(t *testing.T) {
	ctx := context.Background()
	primary, _ := newPrimary(t)
	if err := primary.CompartmentCreate(ctx, "x", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	res, err := primary.Grant(ctx, GrantRequest{
		Scope: []string{"x"},
		Mode:  domain.TokenModeRW,
		TTL:   time.Hour,
	})
	if err != nil {
		t.Fatalf("primary Grant: %v", err)
	}
	if res == nil || res.Encoded == "" {
		t.Fatal("primary Grant returned empty result")
	}
}
