package workspace

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// WorkspacesSubdir is the relative path under the root state dir that
// holds named multi-workspace state. Each named workspace lives at
// <root>/workspaces/<name>/, with the same layout (master.json,
// device.json, local-config.json, etc.) as the legacy single-workspace
// root layout.
const WorkspacesSubdir = "workspaces"

// CurrentPointerFile is a one-line text file under the root state dir
// that names the active workspace. If absent, the legacy top-level
// layout (root state dir itself) is used.
const CurrentPointerFile = "current"

// WorkspaceStateDir returns the state directory for a named workspace
// under the given root. Validates name to a tight subset that can be
// used as a single path segment.
func WorkspaceStateDir(root, name string) (string, error) {
	if err := validateWorkspaceName(name); err != nil {
		return "", err
	}
	return filepath.Join(root, WorkspacesSubdir, name), nil
}

func validateWorkspaceName(name string) error {
	if name == "" {
		return fmt.Errorf("workspace name required")
	}
	if len(name) > 64 {
		return fmt.Errorf("workspace name too long (%d chars, max 64)", len(name))
	}
	for i, r := range name {
		valid := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if i > 0 {
			valid = valid || r == '-' || r == '_'
		}
		if !valid {
			return fmt.Errorf("workspace name %q: invalid char at position %d (allow [a-z0-9] then [a-z0-9_-])", name, i)
		}
	}
	return nil
}

// CurrentWorkspace reads the current-pointer file. Returns (name, true)
// if the pointer exists and names a valid workspace; (empty, false)
// otherwise.
func CurrentWorkspace(root string) (string, bool) {
	body, err := os.ReadFile(filepath.Join(root, CurrentPointerFile))
	if err != nil {
		return "", false
	}
	name := strings.TrimSpace(string(body))
	if err := validateWorkspaceName(name); err != nil {
		return "", false
	}
	// Confirm the pointed-to workspace actually exists on disk.
	dir, _ := WorkspaceStateDir(root, name)
	if _, err := os.Stat(filepath.Join(dir, "local-config.json")); err != nil {
		return "", false
	}
	return name, true
}

// SetCurrentWorkspace writes the current-pointer file. Refuses to point
// at a workspace that does not yet have a local-config.json — preventing
// a typo from making every command target a nonexistent directory.
func SetCurrentWorkspace(root, name string) error {
	if err := validateWorkspaceName(name); err != nil {
		return err
	}
	dir, _ := WorkspaceStateDir(root, name)
	if _, err := os.Stat(filepath.Join(dir, "local-config.json")); err != nil {
		return fmt.Errorf("workspace %q does not exist at %s", name, dir)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(root, CurrentPointerFile+".tmp")
	if err := os.WriteFile(tmp, []byte(name+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(root, CurrentPointerFile))
}

// UnsetCurrentWorkspace removes the pointer file (commands fall back to
// the legacy top-level layout). Idempotent.
func UnsetCurrentWorkspace(root string) error {
	err := os.Remove(filepath.Join(root, CurrentPointerFile))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// WorkspaceEntry describes one workspace discovered by ListWorkspaces.
type WorkspaceEntry struct {
	Name        string // "" for the legacy top-level workspace
	StateDir    string
	WorkspaceID string // populated if local-config.json is readable
	IsCurrent   bool
}

// ListWorkspaces enumerates every workspace under root: both the legacy
// top-level slot (if a local-config.json sits at root) and every named
// subdir under workspaces/. Reads each workspace's local-config.json
// to populate WorkspaceID; errors on individual entries are silently
// skipped (the entry still appears with WorkspaceID empty).
func ListWorkspaces(root string) ([]WorkspaceEntry, error) {
	current, _ := CurrentWorkspace(root)
	var entries []WorkspaceEntry

	// Legacy slot.
	if _, err := os.Stat(filepath.Join(root, "local-config.json")); err == nil {
		entries = append(entries, WorkspaceEntry{
			Name:        "",
			StateDir:    root,
			WorkspaceID: readWorkspaceID(root),
			IsCurrent:   current == "",
		})
	}

	wsRoot := filepath.Join(root, WorkspacesSubdir)
	dents, err := os.ReadDir(wsRoot)
	if err != nil && !os.IsNotExist(err) {
		return entries, err
	}
	for _, d := range dents {
		if !d.IsDir() {
			continue
		}
		name := d.Name()
		if err := validateWorkspaceName(name); err != nil {
			continue
		}
		dir := filepath.Join(wsRoot, name)
		if _, err := os.Stat(filepath.Join(dir, "local-config.json")); err != nil {
			continue
		}
		entries = append(entries, WorkspaceEntry{
			Name:        name,
			StateDir:    dir,
			WorkspaceID: readWorkspaceID(dir),
			IsCurrent:   current == name,
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

func readWorkspaceID(dir string) string {
	state, err := NewState(dir)
	if err != nil {
		return ""
	}
	cfg, err := state.LoadConfig()
	if err != nil {
		return ""
	}
	return cfg.WorkspaceID
}

// RemoveWorkspaceState deletes a named workspace's local state directory.
// Refuses to remove the legacy top-level slot. Does NOT touch the bucket
// — that's an explicit choice; users may want to keep the data and
// re-link from another device.
func RemoveWorkspaceState(root, name string) error {
	if name == "" {
		return fmt.Errorf("remove: empty workspace name (use `drift workspace remove <name>`)")
	}
	dir, err := WorkspaceStateDir(root, name)
	if err != nil {
		return err
	}
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("workspace %q: %w", name, err)
	}
	// Clear the current pointer if it pointed here.
	if cur, _ := CurrentWorkspace(root); cur == name {
		_ = UnsetCurrentWorkspace(root)
	}
	return os.RemoveAll(dir)
}
