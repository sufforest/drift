// Package cli wires the Drift CLI commands.
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is overridden at build time via -ldflags.
var Version = "0.0.0-dev"

// Root builds the cobra command tree and returns the root *cobra.Command.
func Root() *cobra.Command {
	root := &cobra.Command{
		Use:           "drift",
		Short:         "Drift — portable, encrypted workspaces over object storage",
		Long:          `Drift maintains an end-to-end encrypted workspace on your own S3-compatible bucket and lets you bring it up on any Linux host using a short-lived capability token.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       Version,
	}

	root.PersistentFlags().String("config", "", "Path to config file (default: ~/.config/drift/config.yaml)")
	root.PersistentFlags().String("workspace", "", "Workspace name (overrides default_workspace from config)")
	root.PersistentFlags().BoolP("verbose", "v", false, "Verbose output")

	root.AddCommand(
		initCmd(),
		openCmd(),
		mountCmd(),
		closeCmd(),
		grantCmd(),
		revokeCmd(),
		statusCmd(),
		volCmd(),
		compartmentCmd(),
		deviceCmd(),
		tokensCmd(),
		verifyCmd(),
		gcCmd(),
		linkCmd(),
		rotateCmd(),
		auditCmd(),
		inspectCmd(),
		restoreMasterCmd(),
		keychainCmd(),
		doctorCmd(),
		recoverCmd(),
		recoveryCmd(),
		autostartCmd(),
		workspaceCmd(),
		configCmd(),
		completionCmd(),
	)

	return root
}

// notImplemented is a RunE helper for stubs. It prints a clear "not yet
// implemented" message rather than silently no-op'ing.
func notImplemented(label string) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, _ []string) error {
		return fmt.Errorf("%s: not yet implemented (%s)", cmd.CommandPath(), label)
	}
}
