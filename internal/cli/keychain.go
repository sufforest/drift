package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sufforest/drift/internal/keychain"
)

func keychainCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keychain",
		Short: "Show whether OS keychain integration is available + enabled",
		Long: `Probes the OS-level secret store (macOS Keychain, GNOME Keyring on
Linux, Windows Credential Manager). Reports whether it's reachable and
whether DRIFT_KEYCHAIN=1 is currently in effect.

Set DRIFT_KEYCHAIN=1 before running drift init / drift link to store
master + device + parent keys in the OS keychain instead of on-disk
JSON. Existing on-disk state is NOT migrated automatically in v1 —
re-initialize the workspace under the env var, or wait for v1.2's
drift keychain migrate command.`,
		RunE: runKeychain,
	}
}

func runKeychain(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()
	if v := os.Getenv("DRIFT_KEYCHAIN"); v != "" {
		fmt.Fprintf(out, "DRIFT_KEYCHAIN=%q (enabled)\n", v)
	} else {
		fmt.Fprintln(out, "DRIFT_KEYCHAIN not set (file-backed storage)")
	}
	if keychain.Available() {
		fmt.Fprintln(out, "OS keychain: reachable ✓")
	} else {
		fmt.Fprintln(out, "OS keychain: not reachable (likely a headless system or missing dbus session)")
	}
	return nil
}
