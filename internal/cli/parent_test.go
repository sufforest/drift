package cli

import (
	"strings"
	"testing"
)

// TestCLI_parent_isRegistered: `drift parent` exists and has set + show.
func TestCLI_parent_isRegistered(t *testing.T) {
	cmd := parentCmd()
	if cmd.Name() != "parent" {
		t.Fatalf("parentCmd().Name() = %q, want parent", cmd.Name())
	}
	wants := map[string]bool{"set": false, "show": false}
	for _, sub := range cmd.Commands() {
		if _, ok := wants[sub.Name()]; ok {
			wants[sub.Name()] = true
		}
	}
	for name, found := range wants {
		if !found {
			t.Errorf("`drift parent %s` subcommand missing", name)
		}
	}
}

// TestCLI_parentSet_flagsWired: --access-key, --secret-key, --provider,
// --skip-verify all parse cleanly.
func TestCLI_parentSet_flagsWired(t *testing.T) {
	cmd := parentSetCmd()
	for _, name := range []string{"access-key", "secret-key", "provider", "skip-verify"} {
		if cmd.Flag(name) == nil {
			t.Errorf("--%s flag missing on `drift parent set`", name)
		}
	}
	if err := cmd.ParseFlags([]string{"--access-key", "K", "--provider", "r2", "--skip-verify"}); err != nil {
		t.Fatalf("flag parse: %v", err)
	}
}

// TestCLI_configSetParent_hiddenButAlive: the deprecated alias is
// hidden from help but still callable.
func TestCLI_configSetParent_hiddenButAlive(t *testing.T) {
	cfg := configCmd()
	var setParent *struct{ found, hidden bool }
	for _, sub := range cfg.Commands() {
		if sub.Name() == "set-parent" {
			setParent = &struct{ found, hidden bool }{true, sub.Hidden}
			if !strings.Contains(sub.Long, "Deprecated") {
				t.Error("config set-parent Long should mark it deprecated")
			}
			break
		}
	}
	if setParent == nil || !setParent.found {
		t.Fatal("config set-parent must still exist as a hidden alias")
	}
	if !setParent.hidden {
		t.Error("config set-parent must be hidden from help to nudge users to `drift parent set`")
	}
}
