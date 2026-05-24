package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

func revokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <tid>",
		Short: "Revoke an outstanding token by its tid",
		Long: `Adds the token id to .drift/revocations.enc.

Honest clients unmount within the poll interval (default 30s). A hostile
bearer who already extracted the S3 credential keeps access until the
credential's own TTL expires. To kill all derived credentials immediately,
revoke the parent provider token at the dashboard and re-init.`,
		Args: cobra.ExactArgs(1),
		RunE: runRevoke,
	}
}

func runRevoke(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	tid := args[0]
	if err := ws.Revoke(ctx, tid); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(),
		"✓ Token %s revoked.\n\n"+
			"  Honest clients will unmount within ~30s.\n"+
			"  An extracted S3 credential remains valid until its own TTL expires.\n",
		tid)
	return nil
}
