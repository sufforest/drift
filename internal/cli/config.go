package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sufforest/drift/internal/credentials"
	"github.com/sufforest/drift/internal/workspace"
)

func configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage local workspace configuration (parent credentials, etc.)",
	}
	cmd.AddCommand(configSetParentCmd())
	return cmd
}

func configSetParentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "set-parent",
		Short:  "Deprecated alias for `drift parent set` (kept for script compatibility)",
		Hidden: true,
		Long: `Deprecated: prefer 'drift parent set'. This command remains for
scripts that pre-date the 'drift parent' namespace but does NOT run the
live HEAD verification step. New code should call 'drift parent set'.`,
		RunE: runConfigSetParent,
	}
	cmd.Flags().String("access-key", "", "New access key ID (defaults to $DRIFT_ACCESS_KEY_ID)")
	cmd.Flags().String("secret-key", "", "New secret access key (defaults to $DRIFT_SECRET_ACCESS_KEY)")
	return cmd
}

func runConfigSetParent(cmd *cobra.Command, _ []string) error {
	dir, err := stateDir(cmd)
	if err != nil {
		return err
	}
	state, err := workspace.NewState(dir)
	if err != nil {
		return err
	}
	existing, err := state.LoadParent()
	if err != nil {
		return fmt.Errorf("load existing parent cred: %w", err)
	}

	ak, _ := cmd.Flags().GetString("access-key")
	if ak == "" {
		ak = os.Getenv("DRIFT_ACCESS_KEY_ID")
	}
	sk, _ := cmd.Flags().GetString("secret-key")
	if sk == "" {
		sk = os.Getenv("DRIFT_SECRET_ACCESS_KEY")
	}
	if ak == "" || sk == "" {
		return errors.New("set-parent: missing access-key or secret-key (pass flags or export DRIFT_ACCESS_KEY_ID + DRIFT_SECRET_ACCESS_KEY)")
	}

	updated := &credentials.Parent{
		Provider:        existing.Provider,
		AccessKeyID:     ak,
		SecretAccessKey: sk,
	}
	if err := state.SaveParent(updated); err != nil {
		return fmt.Errorf("save parent: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(),
		"✓ Parent credential updated.\n"+
			"  Provider: %s (unchanged)\n"+
			"  Access key: %s…\n",
		updated.Provider, abbrev(ak, 6))
	return nil
}
