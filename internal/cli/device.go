package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

func deviceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "device",
		Short: "Manage enrolled devices",
	}
	cmd.AddCommand(
		deviceListCmd(),
		deviceRevokeCmd(),
		deviceRenameCmd(),
	)
	return cmd
}

func deviceRenameCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rename <device-id> <new-name>",
		Short: "Update a device's human-readable label in the manifest",
		Args:  cobra.ExactArgs(2),
		RunE:  runDeviceRename,
	}
}

func runDeviceRename(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	if err := ws.DeviceRename(ctx, args[0], args[1]); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ Renamed %s → %s\n", args[0], args[1])
	return nil
}

func deviceListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List enrolled devices",
		RunE:  runDeviceList,
	}
}

func runDeviceList(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	devices, err := ws.Devices(ctx)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	for _, d := range devices {
		marker := " "
		if d.IsThis {
			marker = "*"
		}
		fmt.Fprintf(out, "%s %-20s name=%s enrolled=%s last_seen=%s\n",
			marker, d.ID, d.Name,
			d.EnrolledAt.UTC().Format(time.RFC3339),
			d.LastSeen.UTC().Format(time.RFC3339),
		)
	}
	if len(devices) == 0 {
		fmt.Fprintln(out, "no devices (manifest is empty?)")
	}
	return nil
}

func deviceRevokeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke <device-id>",
		Short: "Remove a device from the manifest (rotates vol keys it had access to)",
		Long: `Removes the device's keys from the manifest. Tokens signed by this device
become unverifiable; honest clients reject them on next redemption.

By default, every vol the device had a sealed key for is rotated: a fresh
symmetric key is generated and re-sealed for the remaining devices. This
bounds the blast radius if the revoked device's local state leaked.

Honest caveat: existing encrypted chunks are NOT re-encrypted in v1.
Anyone holding the OLD vol key can still read them if they also have S3
access (which expires with their tokens).`,
		Args: cobra.ExactArgs(1),
		RunE: runDeviceRevoke,
	}
	cmd.Flags().Bool("no-rotate", false, "Skip vol key rotation (faster, but the revoked device's key remains valid for new writes)")
	return cmd
}

func runDeviceRevoke(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	noRotate, _ := cmd.Flags().GetBool("no-rotate")
	result, err := ws.DeviceRevoke(ctx, args[0], !noRotate)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "✓ Device %s removed from manifest\n", result.DeviceID)
	if len(result.RotatedCompartments) > 0 {
		fmt.Fprintf(out, "  Rotated vols: %v\n", result.RotatedCompartments)
		fmt.Fprintln(out, "  Existing chunks remain decryptable with the old key; new writes use the new key.")
	} else if !noRotate {
		fmt.Fprintln(out, "  No vols needed rotation (device had no sealed keys).")
	}
	return nil
}
