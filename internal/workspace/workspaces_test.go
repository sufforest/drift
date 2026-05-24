package workspace

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWorkspaceStateDir_validates(t *testing.T) {
	if _, err := WorkspaceStateDir("/tmp/root", ""); err == nil {
		t.Error("empty name should fail")
	}
	if _, err := WorkspaceStateDir("/tmp/root", "../escape"); err == nil {
		t.Error("path-traversal name should fail")
	}
	if _, err := WorkspaceStateDir("/tmp/root", "WORK"); err == nil {
		t.Error("uppercase should fail")
	}
	dir, err := WorkspaceStateDir("/tmp/root", "personal")
	if err != nil {
		t.Fatalf("valid name: %v", err)
	}
	if dir != "/tmp/root/workspaces/personal" {
		t.Errorf("dir = %q", dir)
	}
}

func TestCurrentWorkspace_pointer(t *testing.T) {
	root := t.TempDir()
	// No pointer, no workspace → not-found.
	if _, ok := CurrentWorkspace(root); ok {
		t.Fatal("expected no current workspace on empty root")
	}
	// Fake a workspace by writing local-config.json.
	dir, _ := WorkspaceStateDir(root, "work")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "local-config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SetCurrentWorkspace(root, "work"); err != nil {
		t.Fatalf("SetCurrent: %v", err)
	}
	name, ok := CurrentWorkspace(root)
	if !ok || name != "work" {
		t.Fatalf("CurrentWorkspace = (%q, %v), want (work, true)", name, ok)
	}
	// Unset.
	if err := UnsetCurrentWorkspace(root); err != nil {
		t.Fatalf("Unset: %v", err)
	}
	if _, ok := CurrentWorkspace(root); ok {
		t.Fatal("expected no current workspace after unset")
	}
}

func TestSetCurrentWorkspace_refusesMissingDir(t *testing.T) {
	root := t.TempDir()
	if err := SetCurrentWorkspace(root, "ghost"); err == nil {
		t.Fatal("expected SetCurrent to refuse a workspace without local-config.json")
	}
}

func TestListWorkspaces_legacy_and_named(t *testing.T) {
	root := t.TempDir()

	// Legacy slot: write local-config at top level.
	if err := os.WriteFile(filepath.Join(root, "local-config.json"), []byte(`{"workspace_id":"wid_legacy"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// Named workspaces.
	for _, name := range []string{"alpha", "beta"} {
		dir, _ := WorkspaceStateDir(root, name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		body := []byte(`{"workspace_id":"wid_` + name + `"}`)
		if err := os.WriteFile(filepath.Join(dir, "local-config.json"), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := ListWorkspaces(root)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}

	// Pin one and re-list — that one should be IsCurrent, legacy is not.
	if err := SetCurrentWorkspace(root, "alpha"); err != nil {
		t.Fatalf("SetCurrent: %v", err)
	}
	entries, _ = ListWorkspaces(root)
	for _, e := range entries {
		switch e.Name {
		case "alpha":
			if !e.IsCurrent {
				t.Errorf("alpha should be current")
			}
		default:
			if e.IsCurrent {
				t.Errorf("%q should not be current", e.Name)
			}
		}
	}
}

func TestRemoveWorkspaceState(t *testing.T) {
	root := t.TempDir()
	dir, _ := WorkspaceStateDir(root, "scratch")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "local-config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SetCurrentWorkspace(root, "scratch"); err != nil {
		t.Fatal(err)
	}

	if err := RemoveWorkspaceState(root, "scratch"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("dir should be gone")
	}
	// Pointer should be cleared too.
	if name, ok := CurrentWorkspace(root); ok {
		t.Errorf("expected current cleared, got %q", name)
	}
}
