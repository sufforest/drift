package cli

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/mount"
	driftsync "github.com/sufforest/drift/internal/sync"
	"github.com/sufforest/drift/internal/workspace"
)

// daemonEnvVar marks the child process spawned by `drift open --background`.
// When set, the foreground run does the actual mounting + polling; when
// unset, --background causes a fork-exec-detach and an immediate exit.
const daemonEnvVar = "DRIFT_DAEMON"

func openCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "open <token>",
		Short: "Redeem a capability token and mount authorized vols",
		Long: `Mounts every vol in the token via rclone (or the no-op mounter with
--no-mount). Foreground by default — blocks until ^C, revocation, or
expiry. With --background, returns immediately after spawning a detached
worker; use ` + "`drift close`" + ` or ` + "`drift status`" + ` to manage it.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runOpen,
	}
	cmd.Flags().String("mount-base", "", "Mount root (default: ~/workspace)")
	cmd.Flags().Bool("ephemeral", false, "Disable on-disk cache (RAM/tmpfs only)")
	cmd.Flags().Bool("no-mount", false, "Verify the token + start the revocation poller, but do not actually mount (useful for testing without rclone)")
	cmd.Flags().Bool("background", false, "Detach and run the mount + poller in the background; returns immediately")
	cmd.Flags().String("rclone", "", "Path to rclone binary (default: $PATH lookup)")
	cmd.Flags().String("cache-root", "", "Parent dir for VFS caches (default: /dev/shm/drift on Linux, system temp elsewhere)")
	cmd.Flags().Bool("stdin", false, "Read the token from stdin instead of argv (recommended over SSH — avoids exposing the token via ps + shell history)")
	cmd.Flags().String("token-file", "", "Read the token from this file (alternative to argv)")
	cmd.Flags().Duration("sync-interval", 0, "Bisync cadence for sync-mode vols (default 60s; minimum 10s). Lower = snappier sync, more S3 calls.")
	return cmd
}

// resolveToken picks the bearer token from one of: argv, --token-file, --stdin.
// Exactly one source must be provided; an empty argv with no --stdin / --token-file
// is treated as a usage error.
func resolveToken(cmd *cobra.Command, args []string) (string, error) {
	useStdin, _ := cmd.Flags().GetBool("stdin")
	tokenFile, _ := cmd.Flags().GetString("token-file")
	sources := 0
	if len(args) > 0 {
		sources++
	}
	if useStdin {
		sources++
	}
	if tokenFile != "" {
		sources++
	}
	switch sources {
	case 0:
		return "", errors.New("token required: pass it positionally, via --token-file <path>, or via --stdin")
	case 1:
	default:
		return "", errors.New("token: pick exactly one of positional, --token-file, --stdin")
	}
	switch {
	case len(args) > 0:
		return strings.TrimSpace(args[0]), nil
	case tokenFile != "":
		body, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", fmt.Errorf("read --token-file: %w", err)
		}
		return strings.TrimSpace(string(body)), nil
	default:
		// Refuse if stdin is a terminal — the user almost certainly
		// invoked `drift open --stdin` interactively by mistake and
		// would otherwise see a silent hung prompt.
		if isStdinTTY() {
			return "", errors.New("--stdin requires a piped token (drift open --stdin is meant for `... | drift open --stdin`, not interactive use)")
		}
		br := bufio.NewReader(os.Stdin)
		line, err := br.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("read --stdin: %w", err)
		}
		token := strings.TrimSpace(line)
		if token == "" {
			return "", errors.New("--stdin returned an empty token")
		}
		return token, nil
	}
}

// isStdinTTY returns true if drift was invoked with a terminal-attached
// stdin (as opposed to a piped or redirected input).
func isStdinTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func runOpen(cmd *cobra.Command, args []string) error {
	background, _ := cmd.Flags().GetBool("background")

	encoded, err := resolveToken(cmd, args)
	if err != nil {
		return err
	}

	// If --background was requested AND we're the parent (no daemon env
	// var set), spawn ourselves with DRIFT_DAEMON=1 and exit. The child
	// will fall through to the foreground branch.
	if background && os.Getenv(daemonEnvVar) == "" {
		return spawnDaemon(cmd, encoded)
	}

	dir, err := stateDir(cmd)
	if err != nil {
		return err
	}
	// AcquireSession atomically claims the single session slot. Two
	// concurrent `drift open --background` invocations race here — only
	// one O_EXCL create wins.
	if err := workspace.AcquireSession(dir, workspace.SessionRecord{
		PID:       os.Getpid(),
		StartedAt: time.Now().UTC(),
	}); err != nil {
		return err
	}
	// Make sure the lockfile is removed on every exit path — failure mid-
	// setup as well as orderly close.
	defer workspace.ClearSession(dir)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	bucket, controlCred, err := peekTokenForControl(encoded)
	if err != nil {
		return err
	}
	provider, err := workspace.BuildS3Provider(ctx, bucket,
		controlCred.AccessKeyID, controlCred.SecretAccessKey, controlCred.SessionToken)
	if err != nil {
		return err
	}

	base, _ := cmd.Flags().GetString("mount-base")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, "workspace")
	}
	ephemeral, _ := cmd.Flags().GetBool("ephemeral")
	noMount, _ := cmd.Flags().GetBool("no-mount")
	rclonePath, _ := cmd.Flags().GetString("rclone")
	cacheRoot, _ := cmd.Flags().GetString("cache-root")

	var mounter mount.Mounter
	var syncer driftsync.Syncer
	if noMount {
		mounter = mount.NewNoopMounter()
		syncer = driftsync.NewNoopSyncer()
	} else {
		mounter = &mount.RcloneMounter{
			Binary:    rclonePath,
			CacheRoot: cacheRoot,
		}
		syncer = &driftsync.RcloneBisyncer{
			Binary:  rclonePath,
			WorkDir: cacheRoot, // shares the cache-root parent; per-compartment subdir under it
		}
	}

	syncInterval, _ := cmd.Flags().GetDuration("sync-interval")
	sess, err := workspace.Redeem(ctx, encoded, workspace.RedeemOptions{
		Provider:     provider,
		Mounter:      mounter,
		Syncer:       syncer,
		MountBase:    base,
		Ephemeral:    ephemeral,
		SyncInterval: syncInterval,
	})
	if err != nil {
		return err
	}

	mps := make([]string, 0, len(sess.Mounts))
	for _, h := range sess.Mounts {
		mps = append(mps, h.MountPoint())
	}
	if err := workspace.SaveSession(dir, workspace.SessionRecord{
		PID:         os.Getpid(),
		TID:         sess.TID,
		WorkspaceID: sess.WorkspaceID,
		MountPoints: mps,
		StartedAt:   time.Now().UTC(),
		Ephemeral:   ephemeral,
	}); err != nil {
		_ = sess.Close()
		return fmt.Errorf("write session file: %w", err)
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "✓ Redeemed token %s (workspace %s)\n", sess.TID, sess.WorkspaceID)
	for _, h := range sess.Mounts {
		tag := ""
		if noMount {
			tag = " (no-mount)"
		}
		fmt.Fprintf(out, "  • %s → %s%s\n", h.Compartment(), h.MountPoint(), tag)
	}
	if res := sess.Result(); res != nil && !res.ExpiresAt.IsZero() {
		remaining := humanizeDuration(time.Until(res.ExpiresAt))
		fmt.Fprintf(out, "Token expires in %s (%s). drift will exit then.\n",
			remaining, res.ExpiresAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	fmt.Fprintln(out, "Polling for revocations. Press ^C or run `drift close` to stop.")

	err = sess.WaitContext(ctx)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// SIGINT / SIGTERM. Close already happened inside WaitContext.
		fmt.Fprintln(out, "✓ Session closed.")
		return nil
	case errors.Is(err, domain.ErrTokenRevoked):
		fmt.Fprintln(out, "✗ Token revoked. Unmounted.")
		return err
	default:
		return err
	}
}

// spawnDaemon re-execs drift with DRIFT_DAEMON=1 and a new session, then
// returns immediately. The child takes over the actual open flow. The
// token is piped via stdin rather than passed in argv so it does not
// show up under `ps auxww` on the host running the daemon.
func spawnDaemon(cmd *cobra.Command, token string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("daemon: locate executable: %w", err)
	}
	// Rebuild argv WITHOUT the --background flag (else child loops) and
	// WITHOUT the token (passed via stdin instead).
	childArgs := []string{"open", "--stdin"}
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
	if v, _ := cmd.Flags().GetBool("no-mount"); v {
		childArgs = append(childArgs, "--no-mount")
	}
	if v, _ := cmd.Flags().GetString("config"); v != "" {
		childArgs = append(childArgs, "--config", v)
	}

	child := exec.Command(exe, childArgs...)
	child.Env = append(os.Environ(), daemonEnvVar+"=1")
	// Detach: no controlling terminal, no inherited stdout/stderr. Stdin
	// is wired to a pipe so we can hand the token to the child once and
	// then close.
	pipe, err := child.StdinPipe()
	if err != nil {
		return fmt.Errorf("daemon stdin pipe: %w", err)
	}
	child.Stdout = nil
	child.Stderr = nil
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := child.Start(); err != nil {
		_ = pipe.Close()
		return fmt.Errorf("daemon start: %w", err)
	}
	if _, err := io.WriteString(pipe, token+"\n"); err != nil {
		_ = pipe.Close()
		return fmt.Errorf("write token to daemon: %w", err)
	}
	if err := pipe.Close(); err != nil {
		return fmt.Errorf("close daemon stdin: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(),
		"Started drift open in background (PID %d).\n"+
			"  Use `drift status` to inspect, `drift close` to stop.\n",
		child.Process.Pid)
	return nil
}

// peekTokenForControl decodes a token AND verifies its Ed25519 signature
// against the embedded IssuerPub before returning any field. This must
// happen before constructing an S3 client — otherwise a tampered Bucket
// or ControlCred drives outbound HTTP to attacker-controlled targets.
//
// Cross-checking IssuerPub against the manifest's device record still
// happens later in Redeem; that's the "is this issuer actually authorized
// in this workspace" check. The peek-time verification is purely about
// "is this token internally self-consistent before we make any network
// call with its embedded creds."
func peekTokenForControl(encoded string) (domain.BucketInfo, domain.S3Credential, error) {
	payload, sig, err := dcrypto.DecodeToken(encoded)
	if err != nil {
		return domain.BucketInfo{}, domain.S3Credential{}, err
	}
	var tok domain.Token
	if err := json.Unmarshal(payload, &tok); err != nil {
		return domain.BucketInfo{}, domain.S3Credential{}, fmt.Errorf("%w: %v", domain.ErrTokenMalformed, err)
	}
	if tok.Version != domain.TokenVersion {
		return domain.BucketInfo{}, domain.S3Credential{}, fmt.Errorf("%w: unsupported token version %d", domain.ErrTokenMalformed, tok.Version)
	}
	if len(tok.IssuerPub) != ed25519.PublicKeySize {
		return domain.BucketInfo{}, domain.S3Credential{}, fmt.Errorf("%w: missing or malformed IssuerPub", domain.ErrTokenMalformed)
	}
	if err := dcrypto.Verify(ed25519.PublicKey(tok.IssuerPub), payload, sig); err != nil {
		return domain.BucketInfo{}, domain.S3Credential{}, err
	}
	if tok.ControlCred.AccessKeyID == "" {
		return domain.BucketInfo{}, domain.S3Credential{}, errors.New("token missing ControlCred (was it minted by an older drift?)")
	}
	return tok.Bucket, tok.ControlCred, nil
}
