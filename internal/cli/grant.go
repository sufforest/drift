package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufforest/drift/internal/token"
	"github.com/sufforest/drift/internal/workspace"
)

func grantCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "grant",
		Short: "Issue a scoped, time-bounded capability token",
		Long: `Mints a master-signed bearer token authorizing access to the listed
vols at the given mode + TTL. Output paths:

  • default              human-readable summary + the encoded token on stdout
  • --token-only         emits only the token on stdout (status on stderr)
  • --out FILE           writes the token to a chmod-0600 file
  • --ssh user@host      delivers the token over SSH and runs drift open
                         --stdin --background on the remote; the token never
                         touches your clipboard, shell history, or argv

The --ssh flow needs drift + rclone installed on the remote and a working
ssh config (no flags are forwarded — use ~/.ssh/config for identity/port).`,
		RunE: runGrant,
	}
	cmd.Flags().StringSlice("scope", nil, "Vols to grant (comma-separated)")
	cmd.Flags().String("mode", "rw", "Access mode: rw or ro")
	cmd.Flags().Duration("expires", 24*time.Hour, "Token TTL (max 24h)")
	cmd.Flags().Bool("token-only", false, "Print ONLY the token on stdout (status to stderr)")
	cmd.Flags().String("out", "", "Write token to this file at chmod 0600 instead of stdout")
	cmd.Flags().String("ssh", "", "Deliver via SSH: runs `drift open --stdin --background` on user@host")
	cmd.Flags().Bool("no-mount", false, "When using --ssh, ask the remote to redeem with --no-mount (control plane only)")
	_ = cmd.MarkFlagRequired("scope")
	return cmd
}

func runGrant(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	scope, _ := cmd.Flags().GetStringSlice("scope")
	mode, _ := cmd.Flags().GetString("mode")
	ttl, _ := cmd.Flags().GetDuration("expires")
	tokenOnly, _ := cmd.Flags().GetBool("token-only")
	outFile, _ := cmd.Flags().GetString("out")
	sshTarget, _ := cmd.Flags().GetString("ssh")
	noMount, _ := cmd.Flags().GetBool("no-mount")

	if countNonEmpty(tokenOnly, outFile != "", sshTarget != "") > 1 {
		return errors.New("--token-only, --out, and --ssh are mutually exclusive")
	}

	res, err := ws.Grant(ctx, workspace.GrantRequest{
		Scope: scope,
		Mode:  mode,
		TTL:   ttl,
	})
	if err != nil {
		return err
	}

	stdout := cmd.OutOrStdout()
	stderr := cmd.ErrOrStderr()

	switch {
	case sshTarget != "":
		return deliverViaSSH(stdout, stderr, sshTarget, res, noMount)
	case outFile != "":
		if err := os.WriteFile(outFile, []byte(res.Encoded+"\n"), 0o600); err != nil {
			return fmt.Errorf("write --out: %w", err)
		}
		fmt.Fprintf(stdout,
			"✓ Token %s issued (scope=%v mode=%s expires=%s)\n"+
				"  Written to %s (chmod 0600). Revoke: drift revoke %s\n",
			res.TID, scope, mode, res.ExpiresAt.UTC().Format(time.RFC3339), outFile, res.TID)
		return nil
	case tokenOnly:
		fmt.Fprintf(stderr,
			"✓ Token %s issued (scope=%v mode=%s expires=%s). Revoke: drift revoke %s\n",
			res.TID, scope, mode, res.ExpiresAt.UTC().Format(time.RFC3339), res.TID)
		fmt.Fprintln(stdout, res.Encoded)
		return nil
	default:
		fmt.Fprintf(stdout,
			"✓ Token %s issued (scope=%v mode=%s expires=%s)\n\n%s\n\n"+
				"⚠  Treat this string as a bearer credential. Paste only over secure channels.\n",
			res.TID, scope, mode, res.ExpiresAt.UTC().Format(time.RFC3339), res.Encoded,
		)
		return nil
	}
}

// deliverViaSSH ships the token to a remote host via SSH and starts
// `drift open --stdin --background` over there. The token is piped to
// the remote's stdin so it never lands in argv, clipboard, or shell
// history — neither here nor on the remote.
func deliverViaSSH(stdout, stderr interface{ Write(p []byte) (int, error) }, target string, res *token.IssueResult, noMount bool) error {
	if strings.ContainsAny(target, " \t\n") {
		return fmt.Errorf("--ssh: host %q has whitespace", target)
	}
	args := []string{target, "drift", "open", "--stdin", "--background"}
	if noMount {
		args = append(args, "--no-mount")
	}
	fmt.Fprintf(stderr, "✓ Token %s issued. Delivering to %s via SSH...\n", res.TID, target)
	c := exec.Command("ssh", args...)
	c.Stdin = strings.NewReader(res.Encoded + "\n")
	// Surface SSH stderr / stdout to the user so they can see auth failures
	// or "command not found" without re-running with --verbose.
	c.Stdout = stdout
	c.Stderr = stderr
	if err := c.Run(); err != nil {
		hint := ""
		// ssh returns exit code 127 when the remote command is not found.
		if exitCode(err) == 127 {
			hint = "  Remote `drift` not found in PATH. On the GPU host:\n" +
				"    macOS:  brew install rclone && brew install sufforest/tap/drift\n" +
				"    Linux:  install drift from https://github.com/sufforest/drift/releases\n" +
				"  Then retry this command.\n"
		}
		fmt.Fprintf(stderr,
			"\n✗ SSH delivery failed. The token was already issued (tid=%s).\n"+
				"  If you don't want it active, run: drift revoke %s\n%s",
			res.TID, res.TID, hint)
		return fmt.Errorf("ssh: %w", err)
	}
	fmt.Fprintf(stderr,
		"\n✓ Delivered. Remote will mount in the background.\n"+
			"  Revoke anytime: drift revoke %s\n", res.TID)
	return nil
}

// exitCode extracts the integer exit code from an exec.Command error,
// returning -1 if the error is not a clean exit-with-code failure.
func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func countNonEmpty(bools ...bool) int {
	n := 0
	for _, b := range bools {
		if b {
			n++
		}
	}
	return n
}
