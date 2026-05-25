package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/storage"
	"github.com/sufforest/drift/internal/workspace"
)

func linkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "link [pairing-token]",
		Short: "Add a new device to the workspace (multi-device pairing)",
		Long: `Three modes:

  drift link --new-device <name>
      (on primary) Mint a pairing token. Prints the token + a PID. Copy the
      token to the new device.

  drift link <pairing-token>
      (on new device) Decode + verify the pairing token, post a response,
      and display a Short Authentication String (SAS) for the user to
      compare with the SAS shown on the primary device. Then blocks
      until the primary confirms.

  drift link --confirm <pid>
      (on primary) Read the new device's posted response, display the
      same SAS as the new device, prompt for visual match (or accept
      --accept-sas <hex> non-interactively), and enroll the device.
      --expect-fingerprint <hex> is still supported as a legacy alternative.
`,
		Args: cobra.MaximumNArgs(1),
		RunE: runLink,
	}
	cmd.Flags().String("new-device", "", "(primary) Mint a pairing token for a new device with this human label")
	cmd.Flags().Duration("ttl", workspace.DefaultPairingTTL, "(primary, --new-device) Pairing token TTL")
	cmd.Flags().Bool("peer", false, "(primary, --new-device) Pair as a functional peer: shares parent R2 cred via the sealed handoff so the new device can drift mount / drift grant on its own. Use ONLY when the same human owns both devices. Mutex with --peer-bearer.")
	cmd.Flags().Bool("peer-bearer", false, "(primary, --new-device) DD-9 bearer-mode pair: hand off a short-lived (24h) revocable bearer cred instead of the raw parent. Mount-only on the peer; revocable workspace-side via `drift peer revoke` (no CF dashboard step). Requires --peer-compartments. Mutex with --peer.")
	cmd.Flags().StringSlice("peer-compartments", nil, "(primary, --new-device) Restrict the new device to these vols (comma-separated). Empty = full access (in v1 peer mode only — bearer mode requires non-empty). Implements DD-8 compartment scope.")
	cmd.Flags().String("confirm", "", "(primary) Confirm the response for this pairing id (pid)")
	cmd.Flags().String("expect-fingerprint", "", "(primary, --confirm) [legacy] Require the new device's fingerprint to equal this hex value. Prefer the SAS prompt.")
	cmd.Flags().String("accept-sas", "", "(primary, --confirm) Non-interactive: accept this pre-computed SAS hex (e.g. AB12-CD34). Skips the y/N prompt.")
	cmd.Flags().Bool("yes", false, "(primary, --confirm) Skip the SAS prompt and accept whatever SAS is computed. UNSAFE on shared/insecure side-channels — only use on a private LAN where you trust the response can't be MITM'd.")
	cmd.Flags().String("name", "", "(new device) Human label for this device (default: derived from key)")
	cmd.Flags().Bool("list", false, "(primary) List in-flight pairings")
	cmd.Flags().String("abort", "", "(primary) Cancel the in-flight pairing with this pid")
	return cmd
}

func runLink(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	newDevice, _ := cmd.Flags().GetString("new-device")
	confirmPID, _ := cmd.Flags().GetString("confirm")
	abortPID, _ := cmd.Flags().GetString("abort")
	listMode, _ := cmd.Flags().GetBool("list")

	// Count provided modes; require exactly one.
	modes := 0
	for _, set := range []bool{newDevice != "", confirmPID != "", abortPID != "", listMode, len(args) == 1} {
		if set {
			modes++
		}
	}
	if modes > 1 {
		return errors.New("--new-device, --confirm, --abort, --list, and <pairing-token> are mutually exclusive")
	}

	switch {
	case newDevice != "":
		return runLinkNew(ctx, cmd, newDevice)
	case confirmPID != "":
		return runLinkConfirm(ctx, cmd, confirmPID)
	case abortPID != "":
		return runLinkAbort(ctx, cmd, abortPID)
	case listMode:
		return runLinkList(ctx, cmd)
	case len(args) == 1:
		return runLinkClaim(ctx, cmd, args[0])
	default:
		return errors.New("specify one of: --new-device <name>, <pairing-token>, --confirm <pid>, --abort <pid>, --list")
	}
}

func runLinkList(ctx context.Context, cmd *cobra.Command) error {
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	pairs, err := ws.Pairings(ctx)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if len(pairs) == 0 {
		fmt.Fprintln(out, "no in-flight pairings")
		return nil
	}
	for _, p := range pairs {
		state := "pending"
		if p.Expired {
			state = "expired"
		}
		fmt.Fprintf(out, "%s  issued_by=%s  issued=%s  expires=%s  %s\n",
			p.PID, p.IssuedBy,
			p.IssuedAt.UTC().Format(time.RFC3339),
			p.ExpiresAt.UTC().Format(time.RFC3339),
			state)
	}
	return nil
}

func runLinkAbort(ctx context.Context, cmd *cobra.Command, pid string) error {
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	if err := ws.LinkAbort(ctx, pid); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ Aborted pairing %s (manifest stub + bucket artifacts removed)\n", pid)
	return nil
}

func runLinkNew(ctx context.Context, cmd *cobra.Command, name string) error {
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	ttl, _ := cmd.Flags().GetDuration("ttl")
	peer, _ := cmd.Flags().GetBool("peer")
	bearer, _ := cmd.Flags().GetBool("peer-bearer")
	scope, _ := cmd.Flags().GetStringSlice("peer-compartments")
	// CLI-side mutex: protocol layer also refuses, but giving the
	// error here means the user doesn't get a confusing "internal"
	// looking error.
	if peer && bearer {
		return errors.New("--peer and --peer-bearer are mutually exclusive (pick one mode)")
	}
	if bearer && len(scope) == 0 {
		return errors.New("--peer-bearer requires --peer-compartments (bearer-mode peers must have a declared scope)")
	}
	// DD-8 §5.2: scope on identity-only (non-peer/non-bearer) devices
	// is largely decorative — bearer tokens carry their own keys and
	// aren't gated by Device.CompartmentScope at redeem time. Warn so
	// the user understands the limitation instead of trusting a false
	// boundary.
	if len(scope) > 0 && !peer && !bearer {
		fmt.Fprintln(cmd.ErrOrStderr(),
			"warning: --peer-compartments on a non-peer pairing only restricts which CKs are sealed in the manifest for this device.\n"+
				"  It does NOT prevent the device from redeeming bearer tokens the primary mints for other compartments.\n"+
				"  For true scope enforcement on identity-only devices, scope each minted token (drift grant --scope X).")
	}
	res, err := ws.LinkInit(ctx, ttl, workspace.LinkInitOptions{
		PeerMode:         peer,
		BearerMode:       bearer,
		CompartmentScope: scope,
	})
	if err != nil {
		return err
	}
	mode := "identity-only (bearer)"
	switch {
	case peer:
		mode = "PEER — will receive parent R2 cred via sealed handoff (NOT revocable workspace-side; rotate R2 token in CF dashboard on compromise)"
	case bearer:
		mode = "PEER (DD-9 bearer) — will receive a 24h revocable bearer cred via sealed handoff; revocable workspace-side"
	}
	scopeLine := ""
	if len(scope) > 0 {
		scopeLine = fmt.Sprintf("  Compartment scope:    %v\n", scope)
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out,
		"✓ Pairing token issued (pid: %s, expires %s)\n"+
			"  Label for new device: %s\n"+
			"  Mode: %s\n"+
			"%s"+
			"\n%s\n\n"+
			"On the new device, run:\n"+
			"    drift link <token-above>\n"+
			"It will display a SAS (e.g. AB12-CD34). Then back here, run:\n"+
			"    drift link --confirm %s\n"+
			"and confirm the SAS shown matches.\n",
		res.PID, res.ExpiresAt.UTC().Format(time.RFC3339), name, mode, scopeLine, res.Encoded, res.PID,
	)
	return nil
}

func runLinkClaim(ctx context.Context, cmd *cobra.Command, encoded string) error {
	dir, err := stateDir(cmd)
	if err != nil {
		return err
	}
	state, err := workspace.NewState(dir)
	if err != nil {
		return err
	}
	deviceName, _ := cmd.Flags().GetString("name")

	out := cmd.OutOrStdout()
	fmt.Fprintln(out, "Decoding pairing token...")
	pt, err := workspace.DecodePairingToken(encoded)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "✓ Verified pairing token signature (master fingerprint pinned).\n")
	fmt.Fprintf(out, "  Workspace: %s\n", pt.WorkspaceID)
	fmt.Fprintf(out, "  Bucket:    %s @ %s\n", pt.Bucket.Name, pt.Bucket.Endpoint)

	res, err := workspace.LinkClaim(ctx, encoded, deviceName, workspace.LinkClaimOptions{
		State:        state,
		ProviderFor:  bearerProviderFactory,
		PollInterval: 5 * time.Second,
		Timeout:      10 * time.Minute,
		OnSAS: func(sas string) error {
			fmt.Fprintln(out, "")
			fmt.Fprintln(out, "┌─────────────────────────────────────────────────┐")
			fmt.Fprintf(out, "│  SAS (verify on your other device):  %s  │\n", sas)
			fmt.Fprintln(out, "└─────────────────────────────────────────────────┘")
			fmt.Fprintln(out, "")
			fmt.Fprintln(out, "On the primary device, run:")
			fmt.Fprintf(out, "    drift link --confirm <pid>\n")
			fmt.Fprintln(out, "When prompted there, confirm the SAS above matches.")
			fmt.Fprintln(out, "")
			fmt.Fprintln(out, "Posting response and waiting for primary to confirm...")
			return nil
		},
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out,
		"\n✓ Enrollment complete.\n"+
			"  Device id:          %s\n"+
			"  Device fingerprint: %s\n"+
			"  Verified SAS:       %s\n\n",
		res.DeviceID, res.DeviceFingerprint, res.SAS)
	switch {
	case res.PeerMode:
		fmt.Fprintln(out, "Mode: PEER — parent S3 cred received and stored locally.")
		fmt.Fprintln(out, "  You can now run `drift mount`, `drift grant`, etc. on this device.")
	case res.BearerMode:
		fmt.Fprintln(out, "Mode: PEER (DD-9 bearer) — short-lived revocable bearer cred received.")
		fmt.Fprintln(out, "  You can now `drift mount` within your scope. `drift grant` is not")
		fmt.Fprintln(out, "  available in this mode — ask the primary to mint tokens for other devices.")
		fmt.Fprintln(out, "  Your cred auto-refreshes; the primary can revoke it instantly via `drift peer revoke`.")
	default:
		fmt.Fprintln(out, "Mode: identity-only (bearer).")
		fmt.Fprintln(out, "  To use this workspace from this device, the primary must `drift grant` a token,")
		fmt.Fprintln(out, "  then run `drift open <token>` here.")
	}
	return nil
}

func runLinkConfirm(ctx context.Context, cmd *cobra.Command, pid string) error {
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	expect, _ := cmd.Flags().GetString("expect-fingerprint")
	acceptSAS, _ := cmd.Flags().GetString("accept-sas")
	skipPrompt, _ := cmd.Flags().GetBool("yes")
	out := cmd.OutOrStdout()

	// Build the interactive SAS callback. If --accept-sas is set, the
	// workspace-side comparison handles it; callback is unused. If --yes
	// is set, just print and continue. Otherwise prompt y/N when stdin
	// is a TTY; refuse non-interactively unless --accept-sas / --yes.
	var onSAS func(string) error
	if acceptSAS == "" && !skipPrompt {
		onSAS = func(sas string) error {
			fmt.Fprintln(out, "")
			fmt.Fprintln(out, "┌─────────────────────────────────────────────────┐")
			fmt.Fprintf(out, "│  SAS to verify on the new device:    %s  │\n", sas)
			fmt.Fprintln(out, "└─────────────────────────────────────────────────┘")
			fmt.Fprintln(out, "")
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return errors.New("stdin is not a TTY — pass --accept-sas <hex> or --yes")
			}
			fmt.Fprint(out, "Does the new device show the same SAS? [y/N]: ")
			reader := bufio.NewReader(os.Stdin)
			line, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("read user input: %w", err)
			}
			line = strings.TrimSpace(strings.ToLower(line))
			if line != "y" && line != "yes" {
				return errors.New("user did not confirm SAS")
			}
			return nil
		}
	}

	res, err := ws.LinkConfirm(ctx, pid, workspace.LinkConfirmOptions{
		ExpectFingerprint: expect,
		AcceptSAS:         acceptSAS,
		OnSAS:             onSAS,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(out,
		"✓ Confirmed pairing %s\n"+
			"  Enrolled device:    %s\n"+
			"  Device fingerprint: %s\n"+
			"  Verified SAS:       %s\n"+
			"  Vols re-sealed:     %d\n"+
			"  Manifest sequence:  %d\n",
		pid, res.DeviceID, res.DeviceFingerprint, res.SAS, res.ResealedCount, res.Sequence)
	return nil
}

// bearerProviderFactory builds a storage.Provider authed with the pairing
// token's embedded Cred. The bearer flow uses this for both `drift open`
// and `drift link <token>`.
func bearerProviderFactory(cred domain.S3Credential, bucket domain.BucketInfo) (storage.Provider, error) {
	return workspace.BuildS3Provider(context.Background(), bucket,
		cred.AccessKeyID, cred.SecretAccessKey, cred.SessionToken)
}
