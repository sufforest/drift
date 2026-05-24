package domain

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDevice_HasCompartmentAccess_emptyMeansAll(t *testing.T) {
	d := Device{ID: "dev_a"}
	for _, name := range []string{"main", "docs", "anything", ""} {
		if !d.HasCompartmentAccess(name) {
			t.Errorf("empty CompartmentScope must grant access to %q", name)
		}
	}
}

func TestDevice_HasCompartmentAccess_scoped(t *testing.T) {
	d := Device{ID: "dev_a", CompartmentScope: []string{"main", "docs"}}
	if !d.HasCompartmentAccess("main") {
		t.Error("scoped device must have access to main")
	}
	if !d.HasCompartmentAccess("docs") {
		t.Error("scoped device must have access to docs")
	}
	if d.HasCompartmentAccess("payroll") {
		t.Error("scoped device must NOT have access to payroll")
	}
}

// Backward compat: a manifest written without compartment_scope must
// deserialize into Device{CompartmentScope: nil} and behave as full
// access. omitempty must keep the field absent in JSON for legacy bytes.
func TestDevice_dd8BackwardCompat_emptyScopeOmittedInJSON(t *testing.T) {
	d := Device{ID: "dev_a", Name: "primary"}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "compartment_scope") {
		t.Errorf("omitempty failed — empty scope must not appear in JSON: %s", b)
	}
}

func TestDevice_dd8RoundtripWithScope(t *testing.T) {
	orig := Device{
		ID:               "dev_a",
		Name:             "alt",
		CompartmentScope: []string{"main", "docs"},
		EnrolledAt:       time.Unix(1, 0).UTC(),
		LastSeen:         time.Unix(2, 0).UTC(),
	}
	b, _ := json.Marshal(orig)
	var got Device
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.CompartmentScope) != 2 || got.CompartmentScope[0] != "main" || got.CompartmentScope[1] != "docs" {
		t.Errorf("CompartmentScope round-trip mismatch: %v", got.CompartmentScope)
	}
}

// PairingStub.CompartmentScope must round-trip with omitempty.
func TestPairingStub_compartmentScopeOmitemptyAndRoundtrip(t *testing.T) {
	bare := PairingStub{PID: "p", IssuedBy: "master", IssuedAt: time.Unix(0, 0).UTC(), ExpiresAt: time.Unix(60, 0).UTC()}
	b, _ := json.Marshal(bare)
	if strings.Contains(string(b), "compartment_scope") {
		t.Errorf("bare stub should not include compartment_scope: %s", b)
	}
	scoped := bare
	scoped.CompartmentScope = []string{"main"}
	b, _ = json.Marshal(scoped)
	var got PairingStub
	_ = json.Unmarshal(b, &got)
	if len(got.CompartmentScope) != 1 || got.CompartmentScope[0] != "main" {
		t.Errorf("stub scope round-trip: %v", got.CompartmentScope)
	}
}

// Legacy manifest payload (pre-DD-8) must deserialize cleanly into the
// new Device struct, with CompartmentScope == nil → full access.
func TestDevice_dd8DecodesLegacyJSON(t *testing.T) {
	legacy := `{"id":"dev_old","name":"legacy","public_key":"AA==","encrypt_key":"AA==","enrolled_at":"2026-01-01T00:00:00Z","last_seen":"2026-01-01T00:00:00Z"}`
	var d Device
	if err := json.Unmarshal([]byte(legacy), &d); err != nil {
		t.Fatal(err)
	}
	if d.CompartmentScope != nil {
		t.Errorf("legacy decode should leave CompartmentScope nil, got %v", d.CompartmentScope)
	}
	if !d.HasCompartmentAccess("anything") {
		t.Error("legacy device must have full access")
	}
}
