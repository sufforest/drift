package cli

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufforest/drift/internal/workspace"
)

func restoreMasterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "restore-master [backup-path]",
		Short: "Restore a rotated-out master.json backup (last-resort recovery)",
		Long: `Re-installs a previously-rotated master.json from its timestamped local
backup. If you don't pass an explicit path, lists the available backups
in the state dir.

Restoring undoes a rotation FROM THIS DEVICE'S PERSPECTIVE. The
bucket-side master rotation announcement is untouched — other enrolled
devices will keep walking forward to the post-rotation master and your
restored device will be out of sync with them. Useful for "I rotated and
now nothing works, let me unbreak this device first."`,
		Args: cobra.MaximumNArgs(1),
		RunE: runRestoreMaster,
	}
	cmd.Flags().Bool("force", false, "Overwrite an existing master.json (default: refuse)")
	return cmd
}

func runRestoreMaster(cmd *cobra.Command, args []string) error {
	dir, err := stateDir(cmd)
	if err != nil {
		return err
	}
	state, err := workspace.NewState(dir)
	if err != nil {
		return err
	}

	// No path → list backups and exit.
	if len(args) == 0 {
		backups, err := listMasterBackups(dir)
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		if len(backups) == 0 {
			fmt.Fprintln(out, "no master.json backups found in", dir)
			fmt.Fprintln(out, "(backups are created automatically by `drift rotate master`)")
			return nil
		}
		fmt.Fprintln(out, "Available master.json backups:")
		for _, b := range backups {
			fmt.Fprintf(out, "  %s\n", b)
		}
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Restore with: drift restore-master <path>")
		return nil
	}

	force, _ := cmd.Flags().GetBool("force")
	master, err := state.RestoreMaster(args[0], force)
	if err != nil {
		return err
	}

	// Re-pin the master fingerprint in LocalConfig so the workspace
	// loads cleanly next time. Otherwise Manifest()'s pin check would
	// fail comparing the OLD-master manifest entry against the NEW-pin
	// recorded mid-rotation.
	cfg, err := state.LoadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	fp := sha256.Sum256(master.SignPub())
	cfg.MasterFingerprint = fp[:]
	if err := state.SaveConfig(*cfg); err != nil {
		return fmt.Errorf("update config: %w", err)
	}

	fmt.Fprintf(cmd.OutOrStdout(),
		"✓ Restored master.json from %s\n"+
			"  New (restored) fingerprint: %x\n\n"+
			"This device is now pinned to the OLD master. Other devices in this\n"+
			"workspace will continue walking the bucket-side rotation chain forward —\n"+
			"they may refuse to load a manifest signed by this restored key.\n",
		args[0], fp)
	return nil
}

// listMasterBackups returns the timestamped backup filenames in dir.
func listMasterBackups(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), "master.json.rotated-") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out, nil
}
