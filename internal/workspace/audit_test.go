package workspace

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/sufforest/drift/internal/audit"
	"github.com/sufforest/drift/internal/domain"
)

func TestAudit_emittedOnMutationsAndChainVerifies(t *testing.T) {
	ctx := context.Background()
	ws, prov := newPrimary(t)

	if err := ws.CompartmentCreate(ctx, "log-target", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	issued, err := ws.Grant(ctx, GrantRequest{
		Scope: []string{"log-target"},
		Mode:  domain.TokenModeRW,
		TTL:   time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ws.Revoke(ctx, issued.TID); err != nil {
		t.Fatal(err)
	}

	m, _ := ws.Manifest(ctx)
	resolve := func(did string) ed25519.PublicKey {
		if d, ok := m.Devices[did]; ok {
			return ed25519.PublicKey(d.PublicKey)
		}
		return nil
	}

	entries, _, err := audit.List(ctx, prov, ws.Config.WorkspaceID, ws.CPRK, resolve)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 4 {
		t.Fatalf("expected at least 4 audit entries (init + create + grant + revoke); got %d", len(entries))
	}
	kinds := map[string]bool{}
	for _, e := range entries {
		if e.VerifyErr != nil {
			t.Fatalf("audit entry %s failed verify: %v", e.Entry.EntryID, e.VerifyErr)
		}
		kinds[e.Entry.Kind] = true
	}
	for _, want := range []string{
		domain.AuditKindCompartmentCreate,
		domain.AuditKindTokenGrant,
		domain.AuditKindTokenRevoke,
	} {
		if !kinds[want] {
			t.Errorf("missing audit kind %q (saw %v)", want, kinds)
		}
	}

	// Sorted by EntryID, chain should verify.
	if err := audit.VerifyChain(entries); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

func TestAuditGC_dropsOldEntries(t *testing.T) {
	ctx := context.Background()
	ws, prov := newPrimary(t)
	// Create a couple of entries so audit/ has content.
	if err := ws.CompartmentCreate(ctx, "gc-target-1", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	if err := ws.CompartmentCreate(ctx, "gc-target-2", domain.ModeMount); err != nil {
		t.Fatal(err)
	}

	keysBefore, _ := prov.List(ctx, domain.AuditDir)
	if len(keysBefore) < 2 {
		t.Fatalf("expected at least 2 audit entries before GC, got %d", len(keysBefore))
	}

	// Advance the workspace clock so audit entries are "in the past".
	ws.now = func() time.Time {
		return time.Now().Add(48 * time.Hour) // emitted-at + 48h
	}

	res, err := ws.AuditGC(ctx, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Deleted) == 0 {
		t.Fatalf("expected deletions, got 0 (scanned=%d)", res.Scanned)
	}
	keysAfter, _ := prov.List(ctx, domain.AuditDir)
	if len(keysAfter) >= len(keysBefore) {
		t.Fatalf("audit entries didn't shrink: before=%d after=%d", len(keysBefore), len(keysAfter))
	}
}

func TestAuditGC_keepsRecent(t *testing.T) {
	ctx := context.Background()
	ws, prov := newPrimary(t)
	if err := ws.CompartmentCreate(ctx, "recent", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	keysBefore, _ := prov.List(ctx, domain.AuditDir)
	res, err := ws.AuditGC(ctx, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Deleted) != 0 {
		t.Fatalf("expected no deletions for recent entries, got %d", len(res.Deleted))
	}
	keysAfter, _ := prov.List(ctx, domain.AuditDir)
	if len(keysAfter) != len(keysBefore) {
		t.Fatalf("audit entries changed: before=%d after=%d", len(keysBefore), len(keysAfter))
	}
}
