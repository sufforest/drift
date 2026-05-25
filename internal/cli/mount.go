package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufforest/drift/internal/mount"
	driftsync "github.com/sufforest/drift/internal/sync"
	"github.com/sufforest/drift/internal/workspace"
)

const directDaemonEnvVar = "DRIFT_MOUNT_DAEMON"

func mountCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mount [vol ...]",
		Short: "Mount workspace vols directly (primary device only, no bearer token)",
		Long: `Mounts the requested vols on the primary device using its parent S3
credential directly. Bypasses the grant/redeem token flow entirely —
no minted JWT, no credentials blob on the bucket, no revocation poll.
This is the cleanest UX for the primary's daily use of its own vols.

Pass one or more vol names. If you pass none, all vols in the manifest
are mounted/synced.

For mounting on a different machine (a GPU pod, second laptop, contractor),
use the bearer flow: drift grant → drift open <token>.`,
		RunE: runMount,
	}
	cmd.Flags().String("mount-base", "", "Mount root (default: ~/workspace)")
	cmd.Flags().Bool("ephemeral", false, "Disable on-disk cache (RAM/tmpfs only)")
	cmd.Flags().Bool("background", false, "Detach and run in the background; returns immediately")
	cmd.Flags().String("rclone", "", "Path to rclone binary (default: $PATH lookup)")
	cmd.Flags().String("cache-root", "", "Parent dir for VFS caches")
	cmd.Flags().Duration("sync-interval", 0, "Bisync cadence for sync-mode vols (default 60s; floor 10s)")
	return cmd
}

func runMount(cmd *cobra.Command, args []string) error {
	background, _ := cmd.Flags().GetBool("background")
	if background && os.Getenv(directDaemonEnvVar) == "" {
		return spawnMountDaemon(cmd, args)
	}

	dir, err := stateDir(cmd)
	if err != nil {
		return err
	}
	if err := workspace.AcquireSession(dir, workspace.SessionRecord{
		PID:       os.Getpid(),
		StartedAt: time.Now().UTC(),
	}); err != nil {
		return err
	}
	defer workspace.ClearSession(dir)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	// drift mount works on any device with an S3-talking credential:
	//   - parent.json: primary or DD-4 v1 peer
	//   - peercred.json: DD-9 bearer peer
	// Identity-only devices have neither and must use `drift open <token>`.
	if _, err := ws.State.LoadParent(); err != nil && !ws.State.HasPeerCred() {
		return errors.New("drift mount requires a credential on this device: parent S3 cred (primary / v1 peer) or a DD-9 bearer PeerCred — on identity-only devices, use `drift open <token>` instead")
	}

	base, _ := cmd.Flags().GetString("mount-base")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, "workspace")
	}
	ephemeral, _ := cmd.Flags().GetBool("ephemeral")
	rclonePath, _ := cmd.Flags().GetString("rclone")
	cacheRoot, _ := cmd.Flags().GetString("cache-root")
	syncInterval, _ := cmd.Flags().GetDuration("sync-interval")

	mounter := &mount.RcloneMounter{
		Binary:    rclonePath,
		CacheRoot: cacheRoot,
	}
	syncer := &driftsync.RcloneBisyncer{
		Binary:  rclonePath,
		WorkDir: cacheRoot,
	}

	sess, err := ws.MountDirect(ctx, workspace.DirectMountOptions{
		Mounter:      mounter,
		Syncer:       syncer,
		MountBase:    base,
		Ephemeral:    ephemeral,
		Vols:         args,
		SyncInterval: syncInterval,
	})
	if err != nil {
		return err
	}

	mps := make([]string, 0, len(sess.Mounts)+len(sess.Syncs))
	for _, h := range sess.Mounts {
		mps = append(mps, h.MountPoint())
	}
	for _, h := range sess.Syncs {
		mps = append(mps, h.LocalPath())
	}
	if err := workspace.SaveSession(dir, workspace.SessionRecord{
		PID:         os.Getpid(),
		TID:         "primary-direct",
		WorkspaceID: sess.WorkspaceID,
		MountPoints: mps,
		StartedAt:   time.Now().UTC(),
		Ephemeral:   ephemeral,
	}); err != nil {
		_ = sess.Close()
		return fmt.Errorf("write session file: %w", err)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "✓ Mounted workspace %s (direct mode, no bearer token)\n", sess.WorkspaceID)
	for _, h := range sess.Mounts {
		fmt.Fprintf(out, "  • %s → %s (mount)\n", h.Compartment(), h.MountPoint())
	}
	for _, h := range sess.Syncs {
		fmt.Fprintf(out, "  • %s → %s (sync)\n", h.Compartment(), h.LocalPath())
	}
	fmt.Fprintln(out, "Press ^C or run `drift close` to stop.")

	err = sess.Wait(ctx)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		fmt.Fprintln(out, "✓ Session closed.")
		return nil
	default:
		return err
	}
}

// spawnMountDaemon re-execs drift mount with the daemon env var set, then
// returns. Mirrors the open --background pattern.
func spawnMountDaemon(cmd *cobra.Command, vols []string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("daemon: locate executable: %w", err)
	}
	childArgs := append([]string{"mount"}, vols...)
	if v, _ := cmd.Flags().GetString("mount-base"); v != "" {
		childArgs = append(childArgs, "--mount-base", v)
	}
	if v, _ := cmd.Flags().GetString("rclone"); v != "" {
		childArgs = append(childArgs, "--rclone", v)
	}
	if v, _ := cmd.Flags().GetString("cache-root"); v != "" {
		childArgs = append(childArgs, "--cache-root", v)
	}
	if v, _ := cmd.Flags().GetBool("ephemeral"); v {
		childArgs = append(childArgs, "--ephemeral")
	}
	if v, _ := cmd.Flags().GetDuration("sync-interval"); v > 0 {
		childArgs = append(childArgs, "--sync-interval", v.String())
	}
	if v, _ := cmd.Flags().GetString("config"); v != "" {
		childArgs = append(childArgs, "--config", v)
	}

	child := exec.Command(exe, childArgs...)
	child.Env = append(os.Environ(), directDaemonEnvVar+"=1")
	child.Stdin = nil
	child.Stdout = nil
	child.Stderr = nil
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := child.Start(); err != nil {
		return fmt.Errorf("daemon start: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(),
		"Started drift mount in background (PID %d).\n"+
			"  Use `drift status` to inspect, `drift close` to stop.\n",
		child.Process.Pid)
	return nil
}
