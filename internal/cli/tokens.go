package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

func tokensCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tokens",
		Short: "List currently active tokens",
		Long: `Default: shows only tokens that are currently usable by a bearer
(in the manifest, not in revocations, not yet expired).

Flags:
  --all       Show all manifest entries including revoked and expired
  --revoked   Show only revoked tokens
  --expired   Show only expired-but-not-revoked tokens

A revoked token's manifest entry sticks around as issuance history; honest
bearers respect the revocations file regardless. For a chronological view
of grant/revoke events, use ` + "`drift audit`" + `.`,
		RunE: runTokens,
	}
	cmd.Flags().Bool("all", false, "Include revoked and expired tokens")
	cmd.Flags().Bool("revoked", false, "Show only revoked tokens")
	cmd.Flags().Bool("expired", false, "Show only expired-but-not-revoked tokens")
	return cmd
}

func runTokens(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	tokens, err := ws.Tokens(ctx)
	if err != nil {
		return err
	}
	revoked, err := ws.RevokedTokens(ctx)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not read revocations.enc (%v); listing may show revoked tokens as active\n", err)
		revoked = map[string]bool{}
	}

	all, _ := cmd.Flags().GetBool("all")
	wantRevoked, _ := cmd.Flags().GetBool("revoked")
	wantExpired, _ := cmd.Flags().GetBool("expired")

	out := cmd.OutOrStdout()
	hidden := 0
	shown := 0
	for _, t := range tokens {
		state := "active"
		switch {
		case revoked[t.TID]:
			state = "revoked"
		case t.Expired:
			state = "expired"
		}
		keep := false
		switch {
		case wantRevoked:
			keep = state == "revoked"
		case wantExpired:
			keep = state == "expired"
		case all:
			keep = true
		default:
			keep = state == "active"
		}
		if !keep {
			hidden++
			continue
		}
		shown++
		fmt.Fprintf(out, "%s  by=%s  mode=%s  scope=%v  expires=%s  %s\n",
			t.TID, t.IssuedBy, t.Mode, t.Scope,
			t.ExpiresAt.UTC().Format(time.RFC3339), state)
	}

	if shown == 0 {
		switch {
		case wantRevoked:
			fmt.Fprintln(out, "no revoked tokens")
		case wantExpired:
			fmt.Fprintln(out, "no expired tokens")
		case all:
			fmt.Fprintln(out, "no tokens in manifest")
		default:
			if hidden > 0 {
				fmt.Fprintf(out, "no active tokens (%d revoked/expired; use --all to see)\n", hidden)
			} else {
				fmt.Fprintln(out, "no tokens in manifest")
			}
		}
	} else if !all && hidden > 0 {
		fmt.Fprintf(out, "\n(%d revoked/expired tokens hidden; use --all to see)\n", hidden)
	}
	return nil
}
