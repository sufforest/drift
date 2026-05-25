package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sufforest/drift/internal/workspace"
)

// parentCmd is the discoverable top-level surface for managing the
// device's stored parent S3 credential. The older `drift config
// set-parent` command is still supported (hidden) for back-compat.
func parentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "parent",
		Short: "Manage the parent S3 credential stored on this device",
		Long: `The parent credential is the long-lived AK/SK pair this device uses to
talk to the object-storage bucket directly (R2 / S3 / B2 / MinIO).

Use these commands when you rotate the credential at the cloud provider
(e.g. after a suspected compromise of a peer device, or as part of
routine credential hygiene).`,
	}
	cmd.AddCommand(parentSetCmd(), parentShowCmd())
	return cmd
}

func parentSetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Replace the parent S3 credential with a new AK/SK pair",
		Long: `Reads the new AK/SK from --access-key + $DRIFT_SECRET_ACCESS_KEY (or
--secret-key, though passing secrets as CLI flags is visible in process
listings — env var is recommended) and overwrites the locally-stored
parent credential.

By default, the new credential is verified by issuing a HEAD against
this workspace's manifest object. If the HEAD fails (bad cred, wrong
permissions, network), the old credential is preserved and an error is
returned. Pass --skip-verify to bypass the live probe.

Master-only: the parent credential is the most powerful credential
drift holds. Peer devices that need their parent rotated should be
re-paired from the primary via 'drift link --new-device' rather than
running set themselves.`,
		RunE: runParentSet,
	}
	cmd.Flags().String("access-key", "", "New access key ID (or $DRIFT_ACCESS_KEY_ID)")
	cmd.Flags().String("secret-key", "", "New secret access key (PREFER $DRIFT_SECRET_ACCESS_KEY to keep secrets out of argv)")
	cmd.Flags().String("provider", "", "Override the provider id (default: keep existing — typically 'r2')")
	cmd.Flags().Bool("skip-verify", false, "Skip the live HEAD probe (dangerous: a wrong secret will silently brick this device's R2 access)")
	return cmd
}

func runParentSet(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
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
		return errors.New("drift parent set: missing access-key or secret-key (pass flags or export DRIFT_ACCESS_KEY_ID + DRIFT_SECRET_ACCESS_KEY)")
	}
	provider, _ := cmd.Flags().GetString("provider")
	skipVerify, _ := cmd.Flags().GetBool("skip-verify")

	res, err := ws.ParentSet(ctx, workspace.ParentSetOptions{
		Provider:        provider,
		AccessKeyID:     ak,
		SecretAccessKey: sk,
		SkipVerify:      skipVerify,
	})
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out,
		"✓ Parent credential replaced.\n"+
			"  Provider:           %s\n"+
			"  Old access key:     %s…\n"+
			"  New access key:     %s…\n"+
			"  Verified live:      %v\n",
		res.Provider,
		abbrev(res.OldAccessKeyID, 6),
		abbrev(res.NewAccessKeyID, 6),
		res.Verified)
	if !res.Verified {
		fmt.Fprintln(out, "  Note: skipped live verification — confirm the cred works before relying on it.")
	}
	return nil
}

func parentShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print the stored parent credential (access key abbreviated; secret never printed)",
		RunE:  runParentShow,
	}
}

func runParentShow(cmd *cobra.Command, _ []string) error {
	dir, err := stateDir(cmd)
	if err != nil {
		return err
	}
	state, err := workspace.NewState(dir)
	if err != nil {
		return err
	}
	parent, err := state.LoadParent()
	if err != nil {
		return fmt.Errorf("load parent: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(),
		"Parent credential\n"+
			"  Provider:           %s\n"+
			"  Access key:         %s…  (last 4: …%s)\n"+
			"  Secret:             <hidden>\n",
		parent.Provider,
		abbrev(parent.AccessKeyID, 6),
		suffix(parent.AccessKeyID, 4))
	return nil
}

// suffix returns the last n runes of s.
func suffix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
