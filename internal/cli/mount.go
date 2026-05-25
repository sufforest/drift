package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
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
		signalDaemonError(fmt.Sprintf("acquire session: %v", err))
		return err
	}
	defer workspace.ClearSession(dir)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		signalDaemonError(fmt.Sprintf("load workspace: %v", err))
		return err
	}
	// drift mount works on any device with an S3-talking credential:
	//   - parent.json: primary or DD-4 v1 peer
	//   - peercred.json: DD-9 bearer peer
	// Identity-only devices have neither and must use `drift open <token>`.
	if _, err := ws.State.LoadParent(); err != nil && !ws.State.HasPeerCred() {
		msg := "drift mount requires a credential on this device: parent S3 cred (primary / v1 peer) or a DD-9 bearer PeerCred — on identity-only devices, use `drift open <token>` instead"
		signalDaemonError(msg)
		return errors.New(msg)
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
		// In daemon mode, surface the actual error to the parent
		// via the readiness pipe; no-op when running in the
		// foreground.
		signalDaemonError(err.Error())
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
		signalDaemonError(fmt.Sprintf("write session file: %v", err))
		return fmt.Errorf("write session file: %w", err)
	}
	// Mount is observable + session file written. Tell the parent
	// the background spawn succeeded; the parent's pipe-read
	// unblocks and it returns success. The line below is a no-op
	// when running in the foreground.
	signalDaemonReady()

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

// spawnMountDaemon re-execs drift mount with the daemon env var set
// and waits for the child to signal mount readiness (or report a
// startup error) via a pipe before returning. This avoids the
// silent-failure mode where the parent reported "Started drift
// mount in background" while the child had already crashed from
// rclone returning "FUSE not supported when installed via Homebrew"
// or similar.
//
// Protocol over the pipe (fd 3 in the child):
//
//	"OK\n"        → mount became ready; safe to return success
//	"ERR: <msg>\n" → child encountered <msg> before SaveSession;
//	                  parent surfaces <msg> in its error return
//	EOF (closed)   → child exited without writing — usually means
//	                  it panicked or was killed; parent reports a
//	                  generic "exited without status" error
//
// Timeout: 30s. If the child neither signals nor exits within 30s,
// it's probably stuck (e.g., FUSE waiting for an approval that
// won't come). Parent kills it and reports the timeout.
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

	// Set up the readiness pipe BEFORE starting the child. Write end
	// goes to the child as ExtraFiles[0] (fd 3); read end stays with
	// the parent.
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("daemon: create readiness pipe: %w", err)
	}
	defer readEnd.Close()

	child := exec.Command(exe, childArgs...)
	child.Env = append(os.Environ(), directDaemonEnvVar+"=1")
	child.Stdin = nil
	child.Stdout = nil
	child.Stderr = nil
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	child.ExtraFiles = []*os.File{writeEnd}

	if err := child.Start(); err != nil {
		_ = writeEnd.Close()
		return fmt.Errorf("daemon start: %w", err)
	}
	// Parent must close its copy of the write end so EOF reaches the
	// reader when the child exits or closes its copy.
	_ = writeEnd.Close()

	// Read the readiness signal with a bounded deadline. Returning
	// from this scope releases readEnd via the defer above.
	type signalResult struct {
		line string
		err  error
	}
	resultCh := make(chan signalResult, 1)
	go func() {
		buf := make([]byte, 1024)
		n, err := readEnd.Read(buf)
		if err != nil {
			resultCh <- signalResult{err: err}
			return
		}
		resultCh <- signalResult{line: strings.TrimRight(string(buf[:n]), "\r\n")}
	}()

	select {
	case res := <-resultCh:
		if res.err != nil {
			// EOF or other read error — child exited without signaling.
			_ = child.Process.Kill()
			return fmt.Errorf("daemon: mount did not start (child exited without status; check that rclone supports `mount` on this platform — `drift doctor` will probe for the Homebrew-rclone-no-FUSE case): %w", res.err)
		}
		if strings.HasPrefix(res.line, "ERR: ") {
			_ = child.Process.Kill()
			return fmt.Errorf("daemon: %s", strings.TrimPrefix(res.line, "ERR: "))
		}
		if res.line != "OK" {
			_ = child.Process.Kill()
			return fmt.Errorf("daemon: unexpected readiness signal %q", res.line)
		}
		// Success path.
		fmt.Fprintf(cmd.OutOrStdout(),
			"Started drift mount in background (PID %d).\n"+
				"  Use `drift status` to inspect, `drift close` to stop.\n",
			child.Process.Pid)
		return nil
	case <-time.After(30 * time.Second):
		_ = child.Process.Kill()
		return errors.New("daemon: mount did not become ready within 30s — the FUSE mount may be waiting on a system permission prompt (macOS: approve macFUSE under Privacy & Security)")
	}
}

// signalDaemonReady writes "OK\n" to the parent's readiness pipe.
// No-op when not running as a daemon child. Called from the child's
// mount path after SaveSession returns; at that point the FUSE mount
// is observable on the filesystem and rclone has not crashed during
// startup.
func signalDaemonReady() {
	signalDaemonStatus("OK")
}

// signalDaemonError reports a startup error to the parent so the
// parent's spawnMountDaemon returns a useful error instead of a
// generic "child exited without status" message. Called from the
// child's mount path on any error path between AcquireSession and
// SaveSession.
func signalDaemonError(msg string) {
	signalDaemonStatus("ERR: " + msg)
}

// signalDaemonStatus is the shared writer for both ready + error
// signals. Opens fd 3 inherited from the parent's ExtraFiles[0]
// and writes one line. Idempotent and safe to call when not a
// daemon (fd 3 will be unset or the write will fail silently).
func signalDaemonStatus(line string) {
	if os.Getenv(directDaemonEnvVar) == "" {
		return
	}
	f := os.NewFile(uintptr(3), "drift-mount-daemon-ready")
	if f == nil {
		return
	}
	_, _ = f.Write([]byte(line + "\n"))
	_ = f.Close()
}
