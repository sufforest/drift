package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufforest/drift/internal/domain"
)

// volCmd is the canonical, user-facing noun. Internally the cryptographic
// term remains "compartment" (it's what the domain types are called) but
// users see "vol" everywhere in help text and output.
func volCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vol",
		Short: "Manage vols (named, independently-keyed sub-spaces of the workspace)",
		Long: `A vol is a folder-shaped slice of the workspace with its own encryption
key. Tokens scope to one or more vols; rotating a vol's key only re-encrypts
that vol; a bearer with access to vol A cannot read vol B.`,
	}
	cmd.AddCommand(
		volCreateCmd(),
		volListCmd(),
		volDeleteCmd(),
		volGrantCmd(),
	)
	return cmd
}

// compartmentCmd is the deprecated alias surface. Hidden from the top-
// level help so new users don't reach for it, but every subcommand still
// works for back-compat with scripts.
func compartmentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "compartment",
		Aliases: []string{"comp"},
		Short:   "Alias for `drift vol` (deprecated; use vol)",
		Hidden:  true,
	}
	cmd.AddCommand(
		volCreateCmd(),
		volListCmd(),
		volDeleteCmd(),
		volGrantCmd(),
	)
	return cmd
}

func volCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new vol",
		Args:  cobra.ExactArgs(1),
		RunE:  runVolCreate,
	}
	cmd.Flags().String("mode", domain.ModeMount, "Access mode: mount or sync")
	return cmd
}

func runVolCreate(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	mode, _ := cmd.Flags().GetString("mode")
	if err := ws.CompartmentCreate(ctx, args[0], mode); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ Created vol %s (mode=%s)\n", args[0], mode)
	return nil
}

func volListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List vols in the workspace",
		RunE:  runVolList,
	}
}

func runVolList(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	s, err := ws.Status(ctx)
	if err != nil {
		return err
	}
	if len(s.Compartments) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "no vols (create one with `drift vol create <name>`)")
		return nil
	}
	for _, c := range s.Compartments {
		fmt.Fprintf(cmd.OutOrStdout(), "%-20s mode=%s key_version=%d\n", c.Name, c.Mode, c.KeyVersion)
	}
	return nil
}

func volDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Remove a vol from the manifest (data chunks left for `drift gc`)",
		Args:  cobra.ExactArgs(1),
		RunE:  runVolDelete,
	}
	cmd.Flags().Bool("force", false, "Skip confirmation")
	return cmd
}

func runVolDelete(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	if force, _ := cmd.Flags().GetBool("force"); !force {
		fmt.Fprintf(cmd.OutOrStdout(),
			"This removes vol %q from the manifest.\n"+
				"Encrypted chunks under compartments/%s/ are left in the bucket (use `drift gc` to sweep).\n"+
				"Re-run with --force to confirm.\n", args[0], args[0])
		return nil
	}
	if err := ws.CompartmentDelete(ctx, args[0]); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ Removed vol %s from manifest\n", args[0])
	return nil
}

// volGrantCmd implements DD-8 retroactive scope grant.
func volGrantCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "grant <device-id> <vol>",
		Short: "Grant a paired device access to a vol (DD-8 scope grant)",
		Long: `Add a vol to a peer device's compartment scope, sealing the vol's
encryption key for that device. Implements DD-8 (per-device compartment scope).

Use this when:
  - You paired a peer with --peer-compartments restricting scope, and now
    want to extend its access to one more vol.
  - You created a new vol after pairing a scoped peer (new vols aren't
    auto-sealed for scoped peers).

Idempotent: granting the same (device, vol) twice is a no-op.

Note: this CANNOT revoke access. To remove a peer's access to a vol,
rotate that vol's key with ` + "`drift vol rotate`" + ` (planned) — that
re-seals only for currently-scoped devices.`,
		Args: cobra.ExactArgs(2),
		RunE: runVolGrant,
	}
}

func runVolGrant(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	deviceID := args[0]
	compartment := args[1]
	res, err := ws.CompartmentGrant(ctx, deviceID, compartment)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if res.AlreadyGranted {
		fmt.Fprintf(out, "✓ Device %s already has access to vol %s (no-op)\n", deviceID, compartment)
		return nil
	}
	fmt.Fprintf(out,
		"✓ Granted vol %s to device %s\n"+
			"  Manifest sequence: %d\n",
		compartment, deviceID, res.Sequence)
	return nil
}
