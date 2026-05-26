package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

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
scripts that pre-date the 'drift parent' namespace and now reuses the
same verified credential-replacement flow as 'drift parent set'.`,
		RunE: runConfigSetParent,
	}
	cmd.Flags().String("access-key", "", "New access key ID (defaults to $DRIFT_ACCESS_KEY_ID)")
	return cmd
}

func runConfigSetParent(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}

	ak, _ := cmd.Flags().GetString("access-key")
	if ak == "" {
		ak = os.Getenv("DRIFT_ACCESS_KEY_ID")
	}
	sk := os.Getenv("DRIFT_SECRET_ACCESS_KEY")
	if sk == "" {
		prompted, perr := promptPassphrase("New secret access key (input hidden): ")
		if perr != nil {
			return perr
		}
		sk = prompted
	}
	res, err := ws.ParentSet(ctx, workspace.ParentSetOptions{
		AccessKeyID:     ak,
		SecretAccessKey: sk,
		SkipVerify:      false,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(),
		"✓ Parent credential updated.\n"+
			"  Provider: %s\n"+
			"  Access key: %s…\n",
		res.Provider, abbrev(ak, 6))
	return nil
}
