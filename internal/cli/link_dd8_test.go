package cli

import (
	"strings"
	"testing"
)

// TestCLI_linkNewDevice_peerCompartmentsFlagParses asserts the
// --peer-compartments flag is wired on the link command and parses
// a comma-separated list correctly. We don't drive a real workspace
// here — just confirm flag wiring.
func TestCLI_linkNewDevice_peerCompartmentsFlagParses(t *testing.T) {
	cmd := linkCmd()
	flag := cmd.Flag("peer-compartments")
	if flag == nil {
		t.Fatal("--peer-compartments flag missing from link command")
	}
	if !strings.Contains(flag.Usage, "DD-8") {
		t.Errorf("--peer-compartments help should reference DD-8 for traceability, got: %q", flag.Usage)
	}

	// Parse a comma-separated value.
	if err := cmd.ParseFlags([]string{"--new-device", "alt", "--peer", "--peer-compartments", "code,artifacts"}); err != nil {
		t.Fatalf("flag parse: %v", err)
	}
	got, err := cmd.Flags().GetStringSlice("peer-compartments")
	if err != nil {
		t.Fatalf("GetStringSlice: %v", err)
	}
	if len(got) != 2 || got[0] != "code" || got[1] != "artifacts" {
		t.Errorf("--peer-compartments parsed wrong: %v", got)
	}
}

// TestCLI_volGrant_isRegistered asserts `drift vol grant` exists with
// the right argument signature. Smoke test only.
func TestCLI_volGrant_isRegistered(t *testing.T) {
	cmd := volCmd()
	var found bool
	for _, sub := range cmd.Commands() {
		if sub.Name() == "grant" {
			found = true
			if !strings.Contains(sub.Long, "DD-8") {
				t.Errorf("vol grant Long help should reference DD-8: %q", sub.Long)
			}
			break
		}
	}
	if !found {
		t.Fatal("`drift vol grant` subcommand missing")
	}
}

// TestCLI_compartmentGrant_aliasRegistered: the deprecated
// `drift compartment grant` alias still works for back-compat scripts.
func TestCLI_compartmentGrant_aliasRegistered(t *testing.T) {
	cmd := compartmentCmd()
	for _, sub := range cmd.Commands() {
		if sub.Name() == "grant" {
			return
		}
	}
	t.Fatal("`drift compartment grant` alias subcommand missing")
}
