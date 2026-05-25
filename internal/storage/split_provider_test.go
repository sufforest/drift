package storage

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sufforest/drift/internal/domain"
)

// labeledProvider wraps a MemoryProvider with a label so tests can
// assert WHICH backing provider an operation routed to (by inspecting
// the data we put there, or by checking explicit error sentinels).
type labeledProvider struct {
	Label string
	*MemoryProvider
}

func newLabeled(label string) *labeledProvider {
	return &labeledProvider{Label: label, MemoryProvider: NewMemoryProvider()}
}

// TestSplitProvider_routingByKey: each Provider method must route
// based on the key. Read-then-verify-which-backing-provider-stored-it
// is the most direct way to check.
func TestSplitProvider_routingByKey(t *testing.T) {
	ctx := context.Background()
	data := newLabeled("DATA")
	control := newLabeled("CTRL")
	sp := NewSplitProvider(data, control)

	cases := []struct {
		key      string
		wantBack *labeledProvider
		why      string
	}{
		{domain.ManifestKey, control, "manifest.enc → Control"},
		{domain.RevocationsKey, control, "revocations.enc → Control"},
		{domain.PeersDir + "dev_x/refresh.enc", control, "peers/ → Control"},
		{domain.PeersDir + "dev_y/anything", control, "any peers/ subkey → Control"},
		{"compartments/main/blob", data, "compartments → Data"},
		{"compartments/main", data, "compartments without slash → Data"},
		{"random/other/path", data, "default → Data"},
	}
	for _, c := range cases {
		t.Run(c.why, func(t *testing.T) {
			body := []byte("hello-" + c.key)
			if err := sp.Put(ctx, c.key, body); err != nil {
				t.Fatalf("Put: %v", err)
			}
			// Verify the bytes landed in the EXPECTED backing provider
			// only, not the other one.
			got, err := c.wantBack.Get(ctx, c.key)
			if err != nil {
				t.Fatalf("backing %s should have the key, got: %v", c.wantBack.Label, err)
			}
			if string(got) != string(body) {
				t.Errorf("backing %s body mismatch", c.wantBack.Label)
			}
			// The other backing provider must NOT have the key.
			other := data
			if c.wantBack == data {
				other = control
			}
			if _, err := other.Get(ctx, c.key); !errors.Is(err, domain.ErrObjectNotFound) {
				t.Errorf("backing %s should NOT have the key (got err: %v) — routing failure", other.Label, err)
			}
		})
	}
}

// TestSplitProvider_nilControl_routesEverythingToData: when Control
// is nil (the AWS-STS / R2-server-mint future shape), every operation
// must go to Data. SplitProvider is essentially a passthrough in that
// configuration.
func TestSplitProvider_nilControl_routesEverythingToData(t *testing.T) {
	ctx := context.Background()
	data := newLabeled("DATA")
	sp := NewSplitProvider(data, nil)

	for _, key := range []string{
		domain.ManifestKey,
		domain.RevocationsKey,
		domain.PeersDir + "dev_x/refresh.enc",
		"compartments/main/x",
	} {
		if err := sp.Put(ctx, key, []byte("v")); err != nil {
			t.Fatalf("Put %s: %v", key, err)
		}
		if _, err := data.Get(ctx, key); err != nil {
			t.Errorf("nil-Control: %q should have landed in Data, got err: %v", key, err)
		}
	}
}

// TestSplitProvider_isControlKey: direct unit on the routing predicate.
// Bare assertion that catches future refactors that accidentally
// re-route the wrong keys.
func TestSplitProvider_isControlKey(t *testing.T) {
	sp := NewSplitProvider(newLabeled("D"), newLabeled("C"))
	cases := map[string]bool{
		domain.ManifestKey:                       true,
		domain.RevocationsKey:                    true,
		domain.PeersDir + "anything":             true,
		domain.PeersDir + "deep/nested/path.enc": true,
		"compartments/main/data":                 false,
		"compartments/main":                      false,
		"":                                       false,
		"random":                                 false,
	}
	for key, want := range cases {
		if got := sp.isControlKey(key); got != want {
			t.Errorf("isControlKey(%q) = %v, want %v", key, got, want)
		}
	}
}

// TestSplitProvider_isControlKey_nilControlAlwaysFalse: with Control
// nil, isControlKey returns false for everything (nothing routes to
// Control because there is no Control).
func TestSplitProvider_isControlKey_nilControlAlwaysFalse(t *testing.T) {
	sp := NewSplitProvider(newLabeled("D"), nil)
	for _, key := range []string{
		domain.ManifestKey,
		domain.RevocationsKey,
		domain.PeersDir + "anything",
	} {
		if sp.isControlKey(key) {
			t.Errorf("isControlKey(%q) with nil Control should be false", key)
		}
	}
}

// TestSplitProvider_writeOnControlPath_routesToControl: this is the
// security property in test form. A Put on a control-plane key must
// hit the Control provider — in production, Control is RO and R2
// returns 403; in test we just verify the routing landed there so
// the R2-side enforcement would fire.
func TestSplitProvider_writeOnControlPath_routesToControl(t *testing.T) {
	ctx := context.Background()
	data := newLabeled("DATA")
	control := newLabeled("CTRL")
	sp := NewSplitProvider(data, control)

	if err := sp.Put(ctx, domain.ManifestKey, []byte("attempt-to-mutate")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := control.Get(ctx, domain.ManifestKey); err != nil {
		t.Errorf("write on manifest must route to Control (would be RO in production); got: %v", err)
	}
	if _, err := data.Get(ctx, domain.ManifestKey); !errors.Is(err, domain.ErrObjectNotFound) {
		t.Errorf("manifest write must NOT also land in Data; got: %v", err)
	}
}

// TestSplitProvider_listRoutesByPrefix: List should route by prefix the
// same way key-based operations route by key.
func TestSplitProvider_listRoutesByPrefix(t *testing.T) {
	ctx := context.Background()
	data := newLabeled("DATA")
	control := newLabeled("CTRL")
	sp := NewSplitProvider(data, control)

	_ = data.Put(ctx, "compartments/main/a", []byte("a"))
	_ = control.Put(ctx, domain.PeersDir+"dev1/refresh.enc", []byte("r"))

	got, err := sp.List(ctx, "compartments/")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "compartments/main/a" {
		t.Errorf("List(compartments/) should route to Data, got: %v", got)
	}

	got, err = sp.List(ctx, domain.PeersDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != domain.PeersDir+"dev1/refresh.enc" {
		t.Errorf("List(%q) should route to Control, got: %v", domain.PeersDir, got)
	}
}

// TestSplitProvider_conditionalWritesRoute: PutIfNotExists and
// PutConditional are the writer's RMW primitives; they MUST route
// the same as Put.
func TestSplitProvider_conditionalWritesRoute(t *testing.T) {
	ctx := context.Background()
	data := newLabeled("DATA")
	control := newLabeled("CTRL")
	sp := NewSplitProvider(data, control)

	// PutIfNotExists on manifest → control.
	if _, err := sp.PutIfNotExists(ctx, domain.ManifestKey, []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if exists, _ := control.Exists(ctx, domain.ManifestKey); !exists {
		t.Error("PutIfNotExists on manifest must land in Control")
	}

	// PutConditional on a compartment key → data.
	if _, err := sp.PutIfNotExists(ctx, "compartments/x/v", []byte("blob")); err != nil {
		t.Fatal(err)
	}
	if exists, _ := data.Exists(ctx, "compartments/x/v"); !exists {
		t.Error("PutIfNotExists on compartment must land in Data")
	}

	// Now read the etag from data and use PutConditional.
	_, etag, err := sp.GetWithETag(ctx, "compartments/x/v")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sp.PutConditional(ctx, "compartments/x/v", []byte("blob2"), etag); err != nil {
		t.Errorf("PutConditional on compartment must succeed via Data: %v", err)
	}
}

// Compile-time interface satisfaction check — SplitProvider must
// implement Provider in full.
var _ Provider = (*SplitProvider)(nil)

// Quiet the "unused import" linter on strings since we don't currently
// use it directly in test bodies (the import is in split_provider.go).
var _ = strings.HasPrefix
