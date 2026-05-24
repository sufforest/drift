package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/recovery"
	"github.com/sufforest/drift/internal/storage"
	"github.com/sufforest/drift/internal/workspace"
)

func recoverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recover",
		Short: "Restore a workspace on a fresh machine using the recovery passphrase",
		Long: `Bootstraps a workspace on a new device when every previously paired
device has been lost. Requires:

  1. The bucket name + endpoint + provider (from your cloud dashboard)
  2. The parent S3 credential (re-issued by your cloud provider)
  3. The recovery passphrase you set at drift init

The bucket-side recovery blob is fetched, decrypted with the passphrase,
and used to reconstruct the master key. This device is then enrolled as
a fresh peer; previously enrolled devices remain in the manifest but you
should drift device revoke any you no longer control.`,
		RunE: runRecover,
	}
	cmd.Flags().String("bucket", "", "Bucket name (required)")
	cmd.Flags().String("endpoint", "", "S3 endpoint URL (required)")
	cmd.Flags().String("region", "auto", "Bucket region")
	cmd.Flags().String("provider", domain.ProviderR2, "Provider: r2, b2, s3, minio, wasabi")
	cmd.Flags().String("device-name", "", "Human label for this device (defaults to a random id)")
	cmd.Flags().String("parent-file", "", "Path to JSON file holding the parent provider credential")
	cmd.Flags().String("passphrase", "", "Recovery passphrase (scripted use only; prefer the interactive prompt)")
	cmd.Flags().Bool("revoke-others", false, "Revoke every device in the manifest other than this one after recovery (use when you lost ALL prior devices)")
	_ = cmd.MarkFlagRequired("bucket")
	_ = cmd.MarkFlagRequired("endpoint")
	return cmd
}

func runRecover(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	out := cmd.OutOrStdout()

	dir, err := stateDir(cmd)
	if err != nil {
		return err
	}
	state, err := workspace.NewState(dir)
	if err != nil {
		return err
	}
	if state.HasMaster() {
		return fmt.Errorf("workspace already initialized at %s — recovery aborted to avoid overwriting (remove the directory if intentional)", dir)
	}

	bucket, _ := cmd.Flags().GetString("bucket")
	endpoint, _ := cmd.Flags().GetString("endpoint")
	region, _ := cmd.Flags().GetString("region")
	providerID, _ := cmd.Flags().GetString("provider")
	deviceName, _ := cmd.Flags().GetString("device-name")
	pass, _ := cmd.Flags().GetString("passphrase")

	parent, err := loadParentFromFlags(cmd, providerID)
	if err != nil {
		return fmt.Errorf("parent credential: %w", err)
	}
	if parent.Provider == "" {
		parent.Provider = providerID
	}

	if pass == "" {
		pass, err = promptPassphrase("Recovery passphrase: ")
		if err != nil {
			return err
		}
	}
	if pass == "" {
		return errors.New("recovery passphrase required")
	}

	bucketInfo := domain.BucketInfo{
		Provider: providerID,
		Endpoint: endpoint,
		Name:     bucket,
		Region:   region,
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

	ws, err := workspace.Recover(ctx, workspace.Options{
		State:    state,
		Provider: provider,
		Writer:   writer,
	}, workspace.RecoverParams{
		Bucket:     bucketInfo,
		Parent:     parent,
		Passphrase: pass,
		DeviceName: deviceName,
	})
	if err != nil {
		if errors.Is(err, recovery.ErrPassphrase) {
			return errors.New("passphrase did not decrypt the recovery blob — check capitalization, language input, paste of trailing whitespace")
		}
		if errors.Is(err, recovery.ErrNoBlob) {
			return errors.New("no recovery blob in this bucket — recovery was never configured on this workspace")
		}
		return err
	}

	fmt.Fprintf(out,
		"✓ Workspace recovered: %s\n"+
			"  New device: %s (%s)\n"+
			"  Bucket: %s @ %s\n"+
			"  State:  %s\n",
		ws.Config.WorkspaceID,
		ws.Config.DeviceID, valueOr(deviceName, "auto-named"),
		bucket, endpoint,
		dir,
	)

	revokeOthers, _ := cmd.Flags().GetBool("revoke-others")
	if revokeOthers {
		m, err := ws.Manifest(ctx)
		if err != nil {
			fmt.Fprintf(out, "\n! Could not fetch manifest to revoke other devices: %v\n", err)
		} else {
			revoked := 0
			for did := range m.Devices {
				if did == ws.Config.DeviceID || did == domain.MasterDeviceID {
					continue
				}
				if _, err := ws.DeviceRevoke(ctx, did, true); err != nil {
					fmt.Fprintf(out, "  ! revoke %s failed: %v\n", did, err)
					continue
				}
				fmt.Fprintf(out, "  ✓ revoked device %s (%s)\n", did, m.Devices[did].Name)
				revoked++
			}
			fmt.Fprintf(out, "Revoked %d device(s).\n", revoked)
		}
	}

	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Next steps:")
	if !revokeOthers {
		fmt.Fprintln(out, "  • Run `drift device list` to see previously enrolled devices.")
		fmt.Fprintln(out, "  • Run `drift device revoke <did>` for any device you no longer control.")
		fmt.Fprintln(out, "    (or re-run with --revoke-others to revoke everything but this device)")
	}
	fmt.Fprintln(out, "  • Run `drift recovery rekey` to rotate the recovery passphrase.")
	return nil
}

func recoveryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recovery",
		Short: "Manage the workspace recovery blob (rekey, disable, status)",
	}
	cmd.AddCommand(recoveryRekeyCmd(), recoveryDisableCmd(), recoveryStatusCmd(), recoveryTestCmd())
	return cmd
}

// recoveryTestCmd verifies that a passphrase can decrypt the current
// bucket blob WITHOUT going through the full recover flow. Lets a user
// confirm "the passphrase in my password manager still works" without
// re-bootstrapping anything. Decrypts the blob in memory and discards
// the key material.
func recoveryTestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Verify a passphrase can decrypt the recovery blob (no state changes)",
		Long: `Reads the recovery blob from the bucket and attempts to decrypt it
with the supplied passphrase. Nothing on disk or in the bucket changes
— this is a way to confirm your password manager entry still works
before you actually need it.`,
		RunE: runRecoveryTest,
	}
	cmd.Flags().String("passphrase", "", "Passphrase to test (scripted use only; prefer the interactive prompt)")
	return cmd
}

func runRecoveryTest(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	blob, err := workspace.FetchRecoveryBlob(ctx, ws.Provider)
	if err != nil {
		if errors.Is(err, recovery.ErrNoBlob) {
			return errors.New("no recovery blob on this bucket; run `drift recovery rekey` to configure one")
		}
		return err
	}
	pass, _ := cmd.Flags().GetString("passphrase")
	if pass == "" {
		pass, err = promptPassphrase("Recovery passphrase to test: ")
		if err != nil {
			return err
		}
	}
	mk, wid, err := recovery.Unwrap(blob, pass)
	if err != nil {
		if errors.Is(err, recovery.ErrPassphrase) {
			return errors.New("passphrase did NOT decrypt the blob — your stored copy is wrong, or the blob was rekeyed since")
		}
		return err
	}
	// Discard the recovered material — this command intentionally does
	// not return it. The wid match is a strong sanity check that we got
	// the right master.
	mk.SignPriv = nil
	for i := range mk.BoxPriv {
		mk.BoxPriv[i] = 0
	}
	for i := range mk.Root {
		mk.Root[i] = 0
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ Passphrase verified for workspace %s. Blob is decryptable.\n", wid)
	return nil
}

func recoveryRekeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rekey",
		Short: "Replace the recovery passphrase (rewraps the bucket blob with a new key)",
		RunE:  runRecoveryRekey,
	}
	cmd.Flags().String("passphrase", "", "New passphrase (scripted use only)")
	cmd.Flags().Bool("allow-weak-passphrase", false, "Allow passphrases below the strength gate (testing only)")
	return cmd
}

func runRecoveryRekey(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	allowWeak, _ := cmd.Flags().GetBool("allow-weak-passphrase")
	pass, _ := cmd.Flags().GetString("passphrase")
	out := cmd.OutOrStdout()
	if pass != "" {
		if err := ws.SaveRecovery(ctx, pass, recovery.WrapOptions{AllowWeakPassphrase: allowWeak}); err != nil {
			return err
		}
		fmt.Fprintln(out, "✓ Recovery passphrase updated.")
		return nil
	}
	// Interactive: same retry-on-weak treatment as init.
	for attempt := 1; attempt <= maxPassphraseAttempts; attempt++ {
		pp, err := promptPassphraseConfirm(
			"New recovery passphrase: ",
			"Confirm passphrase:      ",
		)
		if err != nil {
			return err
		}
		err = ws.SaveRecovery(ctx, pp, recovery.WrapOptions{AllowWeakPassphrase: allowWeak})
		if err == nil {
			fmt.Fprintln(out, "✓ Recovery passphrase updated.")
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
	return fmt.Errorf("recovery passphrase still weak after %d attempts", maxPassphraseAttempts)
}

func recoveryDisableCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "disable",
		Short: "Remove the recovery blob from the bucket",
		Long: `Deletes the passphrase-wrapped master backup from the bucket. After
this, losing every paired device means losing the workspace — recovery
will not be possible until you run drift recovery rekey again.`,
		RunE: runRecoveryDisable,
	}
	cmd.Flags().Bool("yes", false, "Skip confirmation prompt")
	return cmd
}

func runRecoveryDisable(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	confirm, _ := cmd.Flags().GetBool("yes")
	if !confirm {
		if !promptYesNo("Disable recovery? Losing all devices will be unrecoverable.", false) {
			return errors.New("aborted")
		}
	}
	if err := ws.DisableRecovery(ctx); err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), "✓ Recovery blob removed from bucket.")
	return nil
}

func recoveryStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report whether the workspace has a recovery blob configured",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := context.Background()
			ws, err := loadWorkspace(ctx, cmd)
			if err != nil {
				return err
			}
			ok, err := ws.RecoveryStatus(ctx)
			if err != nil {
				return err
			}
			if ok {
				fmt.Fprintln(cmd.OutOrStdout(), "Recovery: configured (.drift/recovery.enc present)")
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "Recovery: NOT configured — losing all devices will be unrecoverable")
			}
			return nil
		},
	}
}
