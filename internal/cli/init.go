package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/recovery"
	"github.com/sufforest/drift/internal/storage"
	"github.com/sufforest/drift/internal/workspace"
)

func initCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a new workspace on an S3-compatible bucket",
		Long: `Generates a master keypair, writes the initial manifest, and registers this
device. Run with no flags to enter the guided dialog; supply --bucket
(and friends) for scripted use.

Parent provider credentials are loaded from:
  --parent-file PATH
  $DRIFT_ACCESS_KEY_ID + $DRIFT_SECRET_ACCESS_KEY
  $AWS_ACCESS_KEY_ID + $AWS_SECRET_ACCESS_KEY (fallback)
`,
		RunE: runInit,
	}
	cmd.Flags().String("bucket", "", "Bucket name")
	cmd.Flags().String("endpoint", "", "S3 endpoint URL (e.g. https://<acct>.r2.cloudflarestorage.com)")
	cmd.Flags().String("region", "auto", "Bucket region")
	cmd.Flags().String("provider", domain.ProviderR2, "Provider: r2, b2, s3, minio, wasabi")
	cmd.Flags().String("device-name", "", "Human label for this device (defaults to a random id)")
	cmd.Flags().String("parent-file", "", "Path to JSON file holding the parent provider credential")
	cmd.Flags().Bool("no-recovery", false, "Skip the recovery-passphrase prompt (recovery WILL NOT be available without one)")
	cmd.Flags().String("recovery-passphrase", "", "Passphrase to wrap the recovery blob (scripted use only)")
	cmd.Flags().Bool("allow-weak-passphrase", false, "Allow recovery passphrases below the strength gate (testing only)")
	cmd.Flags().String("default-vol", "", "Name of a vol to create after init (empty = skip)")
	cmd.Flags().Bool("quiet", false, "Never prompt — fail if a required value is missing")
	return cmd
}

func runInit(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()

	dir, err := stateDir(cmd)
	if err != nil {
		return err
	}
	state, err := workspace.NewState(dir)
	if err != nil {
		return err
	}
	if state.HasMaster() {
		return fmt.Errorf("workspace already initialized at %s — remove the directory to re-init", dir)
	}

	params, err := gatherInitParams(cmd)
	if err != nil {
		return err
	}

	parent, err := loadParentFromFlags(cmd, params.providerID)
	if err != nil {
		return fmt.Errorf("parent credential: %w", err)
	}
	if parent.Provider == "" {
		parent.Provider = params.providerID
	}

	bucketInfo := domain.BucketInfo{
		Provider: params.providerID,
		Endpoint: params.endpoint,
		Name:     params.bucket,
		Region:   params.region,
	}
	provider, err := workspace.BuildProviderFromParent(ctx, bucketInfo, parent)
	if err != nil {
		return err
	}
	caps, err := storage.ProbeCapabilities(ctx, provider)
	if err != nil {
		return fmt.Errorf("capability probe: %w", err)
	}
	writer := storage.SelectWriter(provider, caps, "")

	ws, err := workspace.Init(ctx, workspace.Options{
		State:    state,
		Provider: provider,
		Writer:   writer,
	}, workspace.InitParams{
		Bucket:     bucketInfo,
		Parent:     parent,
		DeviceName: params.deviceName,
	})
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out,
		"✓ Initialized workspace %s\n"+
			"  Device: %s (%s)\n"+
			"  Bucket: %s @ %s\n"+
			"  Concurrency: %s\n"+
			"  State:  %s\n",
		ws.Config.WorkspaceID,
		ws.Config.DeviceID, valueOr(params.deviceName, "auto-named"),
		params.bucket, params.endpoint,
		ws.Config.Concurrency,
		dir,
	)

	if err := maybeConfigureRecovery(ctx, cmd, ws); err != nil {
		fmt.Fprintf(out, "\n! Recovery not configured: %v\n", err)
		fmt.Fprintln(out, "  You can configure it later with `drift recovery rekey`.")
	}

	if params.defaultVol != "" {
		if err := ws.CompartmentCreate(ctx, params.defaultVol, domain.ModeMount); err != nil {
			fmt.Fprintf(out, "\n! Default vol %q not created: %v\n", params.defaultVol, err)
		} else {
			fmt.Fprintf(out, "✓ Created default vol %s (mount mode).\n", params.defaultVol)
		}
	}
	return nil
}

type initParams struct {
	bucket     string
	endpoint   string
	region     string
	providerID string
	deviceName string
	defaultVol string
}

// gatherInitParams resolves the params from flags first, then drops into
// an interactive dialog for anything missing (unless --quiet). Returns
// an actionable error in non-interactive contexts where a required value
// is still missing after flag-parsing.
func gatherInitParams(cmd *cobra.Command) (initParams, error) {
	quiet, _ := cmd.Flags().GetBool("quiet")
	p := initParams{}
	p.bucket, _ = cmd.Flags().GetString("bucket")
	p.endpoint, _ = cmd.Flags().GetString("endpoint")
	p.region, _ = cmd.Flags().GetString("region")
	p.providerID, _ = cmd.Flags().GetString("provider")
	p.deviceName, _ = cmd.Flags().GetString("device-name")
	p.defaultVol, _ = cmd.Flags().GetString("default-vol")

	interactive := !quiet && term.IsTerminal(int(os.Stdin.Fd()))
	out := cmd.OutOrStdout()

	missing := func(name string) string {
		return fmt.Sprintf("%s is required (pass --%s or run interactively)", name, name)
	}

	if interactive && (p.bucket == "" || p.endpoint == "" && p.providerID != domain.ProviderR2) {
		fmt.Fprintln(out, "Welcome to drift. A few questions to set up your workspace.")
	}

	if interactive {
		choice, err := promptProvider(p.providerID)
		if err != nil {
			return p, err
		}
		p.providerID = choice
	}

	switch p.providerID {
	case domain.ProviderR2:
		if p.endpoint == "" {
			if !interactive {
				return p, errors.New(missing("endpoint") + " — or pass --provider r2 with R2 account-id")
			}
			account, err := promptLine("R2 account ID (from Cloudflare dashboard): ")
			if err != nil {
				return p, err
			}
			account = strings.TrimSpace(account)
			if account == "" {
				return p, errors.New("R2 account ID required")
			}
			p.endpoint = fmt.Sprintf("https://%s.r2.cloudflarestorage.com", account)
			fmt.Fprintf(out, "→ endpoint = %s\n", p.endpoint)
		}
	default:
		if p.endpoint == "" {
			if !interactive {
				return p, errors.New(missing("endpoint"))
			}
			ep, err := promptLine("Endpoint URL: ")
			if err != nil {
				return p, err
			}
			p.endpoint = strings.TrimSpace(ep)
		}
	}

	if p.bucket == "" {
		if !interactive {
			return p, errors.New(missing("bucket"))
		}
		bkt, err := promptLine("Bucket name (must already exist): ")
		if err != nil {
			return p, err
		}
		p.bucket = strings.TrimSpace(bkt)
		if p.bucket == "" {
			return p, errors.New("bucket required")
		}
	}

	if interactive && p.deviceName == "" {
		hostname, _ := os.Hostname()
		def := hostname
		if def == "" {
			def = "auto"
		}
		name, err := promptLine(fmt.Sprintf("Device name [%s]: ", def))
		if err != nil {
			return p, err
		}
		name = strings.TrimSpace(name)
		if name == "" {
			name = def
		}
		if name != "auto" {
			p.deviceName = name
		}
	}

	if interactive && os.Getenv("DRIFT_KEYCHAIN") == "" {
		if promptYesNo("Store master/device keys in the OS keychain (DRIFT_KEYCHAIN=1)?", true) {
			_ = os.Setenv("DRIFT_KEYCHAIN", "1")
			fmt.Fprintln(out, "→ DRIFT_KEYCHAIN=1 set for this run. Add it to your shell profile to persist.")
		}
	}

	if interactive && p.defaultVol == "" {
		if promptYesNo("Create a default vol named 'main'?", true) {
			p.defaultVol = "main"
		}
	}

	return p, nil
}

// promptLine reads a single line from stdin, returning the trimmed string.
// Refuses on non-TTY stdin — callers must guard.
func promptLine(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	var s string
	_, err := fmt.Fscanln(os.Stdin, &s)
	if err != nil && err.Error() != "unexpected newline" {
		return "", err
	}
	return s, nil
}

// promptProvider asks which provider to use, defaulting to current.
func promptProvider(current string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return current, nil
	}
	fmt.Fprintf(os.Stderr, "Provider [r2/b2/s3/minio/wasabi] (default %s): ", current)
	var input string
	_, err := fmt.Fscanln(os.Stdin, &input)
	if err != nil && err.Error() != "unexpected newline" {
		return current, err
	}
	input = strings.ToLower(strings.TrimSpace(input))
	if input == "" {
		return current, nil
	}
	switch input {
	case "r2", "b2", "s3", "minio", "wasabi":
		return input, nil
	default:
		return "", fmt.Errorf("unknown provider %q", input)
	}
}

// maybeConfigureRecovery walks through the post-init recovery setup. The
// default is interactive opt-in (recommended). --no-recovery skips the
// prompt and emits an explicit warning; --recovery-passphrase makes it
// scriptable.
func maybeConfigureRecovery(ctx context.Context, cmd *cobra.Command, ws *workspace.Workspace) error {
	out := cmd.OutOrStdout()
	skip, _ := cmd.Flags().GetBool("no-recovery")
	if skip {
		fmt.Fprintln(out, "\n! Recovery passphrase skipped. If you lose every device,")
		fmt.Fprintln(out, "  this workspace will be unrecoverable.")
		return nil
	}
	allowWeak, _ := cmd.Flags().GetBool("allow-weak-passphrase")
	scripted, _ := cmd.Flags().GetString("recovery-passphrase")
	quiet, _ := cmd.Flags().GetBool("quiet")

	pass := scripted
	if pass == "" {
		if quiet || !term.IsTerminal(int(os.Stdin.Fd())) {
			// In quiet/non-interactive mode skip recovery rather than block.
			fmt.Fprintln(out, "\n! Recovery passphrase skipped (non-interactive run, no --recovery-passphrase).")
			return nil
		}
		fmt.Fprintln(out, "\nA recovery passphrase wraps the master key on the bucket")
		fmt.Fprintln(out, "so you can restore this workspace if every paired device is lost.")
		fmt.Fprintln(out, "Store it in a password manager — drift never sees it again.")
		if !promptYesNo("Set a recovery passphrase now?", true) {
			fmt.Fprintln(out, "\n! Recovery passphrase skipped. You can run `drift recovery rekey` later.")
			return nil
		}
		return promptAndSaveRecovery(ctx, ws, out, allowWeak)
	}
	if pass == "" {
		return errors.New("empty passphrase")
	}
	if err := ws.SaveRecovery(ctx, pass, recovery.WrapOptions{AllowWeakPassphrase: allowWeak}); err != nil {
		return err
	}
	fmt.Fprintln(out, "✓ Recovery configured.")
	return nil
}

// promptAndSaveRecovery loops the passphrase prompt up to N times on
// weak-passphrase rejection. Mismatch retry is already inside
// promptPassphraseConfirm. After N rejections we give up and let the
// user fix it later via `drift recovery rekey`.
func promptAndSaveRecovery(ctx context.Context, ws *workspace.Workspace, out io.Writer, allowWeak bool) error {
	for attempt := 1; attempt <= maxPassphraseAttempts; attempt++ {
		pass, err := promptPassphraseConfirm(
			"Recovery passphrase: ",
			"Confirm passphrase:  ",
		)
		if err != nil {
			return err
		}
		if pass == "" {
			return errors.New("empty passphrase")
		}
		err = ws.SaveRecovery(ctx, pass, recovery.WrapOptions{AllowWeakPassphrase: allowWeak})
		if err == nil {
			fmt.Fprintln(out, "✓ Recovery configured.")
			return nil
		}
		var weak *recovery.ErrWeakPassphrase
		if errors.As(err, &weak) {
			remaining := maxPassphraseAttempts - attempt
			fmt.Fprintf(os.Stderr, "Passphrase too weak (%.0f bits, need >= %.0f).\n",
				weak.Bits, recovery.MinPassphraseBits)
			if remaining > 0 {
				fmt.Fprintf(os.Stderr, "Try again (%d attempts left). Tip: four random words or a 20-char mix.\n", remaining)
				continue
			}
		}
		return err
	}
	return fmt.Errorf("recovery passphrase still weak after %d attempts — you can retry later with `drift recovery rekey`", maxPassphraseAttempts)
}

func valueOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
