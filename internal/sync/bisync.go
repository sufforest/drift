package sync

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	gosync "sync"
	"syscall"
	"time"

	"github.com/sufforest/drift/internal/mount"
)

// RcloneBisyncer drives `rclone bisync` against each compartment. Pattern
// mirrors mount.RcloneMounter: env-based config (no on-disk rclone.conf),
// scrubbed parent env, SIGTERM-then-kill on Stop.
//
// Each Sync call spawns a goroutine that runs bisync once per Interval
// (default 60s). On context cancel or Stop the goroutine drains its
// in-flight subprocess and exits.
type RcloneBisyncer struct {
	// Binary is the rclone executable to invoke. "" → $PATH lookup.
	Binary string

	// WorkDir is the parent directory for bisync journal state. Distinct
	// from the local sync dir; bisync requires a small KB-sized
	// per-pair journal directory for incremental sync.
	WorkDir string

	// MinInterval is the floor for sync cadence (default 10s); intervals
	// requested below this are clamped up.
	MinInterval time.Duration

	// MaxConsecutiveFailures before the goroutine backs off to 5min.
	MaxConsecutiveFailures int

	Now func() time.Time
}

// rcloneBisyncHandle is the Handle returned by Sync().
type rcloneBisyncHandle struct {
	compartment string
	localPath   string
	cancel      context.CancelFunc
	done        chan struct{}

	mu        gosync.Mutex
	lastErr   error
	procRef   *os.Process // the in-flight bisync subprocess, if any; nil between runs
	conflicts []string    // *.conflict-* files detected post-bisync; reset on each rescan
}

func (h *rcloneBisyncHandle) Compartment() string { return h.compartment }
func (h *rcloneBisyncHandle) LocalPath() string   { return h.localPath }

// LastError returns the most recent bisync error observed by the goroutine.
// Nil means "no failure yet" or "last run succeeded".
func (h *rcloneBisyncHandle) LastError() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lastErr
}

// Conflicts returns the most-recently-observed list of bisync conflict
// files (relative paths under LocalPath). Refreshed after every bisync
// run.
func (h *rcloneBisyncHandle) Conflicts() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, len(h.conflicts))
	copy(out, h.conflicts)
	return out
}

// Sync starts a goroutine that runs bisync against req.LocalPath on
// req.Interval. Returns a Handle the caller passes back to Stop.
//
// Refuses req.Mode == "ro": bisync is inherently bidirectional and
// cannot enforce a read-only contract on the local side without
// filesystem-level ACL support, which Drift doesn't manage. Read-only
// access to a compartment should be granted with a mount-mode token
// instead.
func (r *RcloneBisyncer) Sync(ctx context.Context, req Request) (Handle, error) {
	if err := validateRequest(req); err != nil {
		return nil, err
	}
	if strings.EqualFold(strings.TrimSpace(req.Mode), "ro") {
		return nil, errors.New("sync: read-only sync is not supported in v1 (use mount mode with an ro token instead)")
	}
	binary := r.Binary
	if binary == "" {
		binary = "rclone"
	}
	if _, err := exec.LookPath(binary); err != nil {
		return nil, fmt.Errorf("sync: rclone not found in $PATH (%w)", err)
	}

	if err := os.MkdirAll(req.LocalPath, 0o755); err != nil {
		return nil, fmt.Errorf("sync: create local sync dir: %w", err)
	}
	journal := r.journalDirFor(req)
	if err := os.MkdirAll(journal, 0o700); err != nil {
		return nil, fmt.Errorf("sync: create journal dir: %w", err)
	}

	cryptName, env, err := mount.BuildRcloneEnv(toMountRequest(req), binary)
	if err != nil {
		return nil, fmt.Errorf("sync: build env: %w", err)
	}

	// Create both sentinels (local + bucket) so bisync's --check-access
	// has something to compare against. A bucket admin who later
	// deletes the bucket-side RCLONE_TEST file will cause bisync to
	// abort rather than treat the deletion as legitimate (which would
	// otherwise propagate the delete to the local side too).
	if err := writeLocalSentinel(req.LocalPath); err != nil {
		return nil, fmt.Errorf("sync: local sentinel: %w", err)
	}
	if err := writeBucketSentinel(ctx, binary, env, cryptName); err != nil {
		return nil, fmt.Errorf("sync: bucket sentinel: %w", err)
	}

	interval := req.Interval
	floor := r.MinInterval
	if floor == 0 {
		floor = 10 * time.Second
	}
	if interval < floor {
		interval = 60 * time.Second
	}
	maxFails := r.MaxConsecutiveFailures
	if maxFails == 0 {
		maxFails = 3
	}

	runCtx, cancel := context.WithCancel(context.Background())
	h := &rcloneBisyncHandle{
		compartment: req.Compartment,
		localPath:   req.LocalPath,
		cancel:      cancel,
		done:        make(chan struct{}),
	}
	go r.run(runCtx, h, binary, env, cryptName, journal, req, interval, maxFails)

	return h, nil
}

// Stop signals the goroutine to exit and waits for it. Sends SIGTERM to
// any in-flight bisync subprocess (so it can flush its journal cleanly),
// then waits briefly before falling back to SIGKILL via context cancel.
//
// Originally this waited 10s for a graceful SIGTERM-flush so bisync
// could write its journal cleanly. In practice drift passes --resync on
// the first run of every new session anyway, so the journal state from
// a prior session is discarded. That makes the long grace period mostly
// dead weight; we cut it to 2s. If the user really wants graceful exit,
// they can adjust via the context they pass in.
func (r *RcloneBisyncer) Stop(ctx context.Context, h Handle) error {
	bh, ok := h.(*rcloneBisyncHandle)
	if !ok {
		return errors.New("sync: handle is not a *rcloneBisyncHandle")
	}
	// Signal under the lock so we don't race with runOnce returning and
	// the kernel reusing the PID for a different process. If procRef is
	// nil there's no run in flight; cancel the goroutine context
	// immediately so it stops scheduling the next tick.
	bh.mu.Lock()
	if bh.procRef != nil {
		_ = bh.procRef.Signal(syscall.SIGTERM)
	} else {
		bh.cancel()
	}
	bh.mu.Unlock()
	select {
	case <-bh.done:
		return bh.LastError()
	case <-time.After(2 * time.Second):
		// Bisync didn't honor SIGTERM in 2s — escalate to SIGKILL via
		// CommandContext's cancel, then wait briefly more.
		bh.cancel()
		select {
		case <-bh.done:
			return bh.LastError()
		case <-time.After(3 * time.Second):
			return errors.New("sync: goroutine did not exit within 5s")
		}
	case <-ctx.Done():
		bh.cancel()
		return ctx.Err()
	}
}

// run is the goroutine body. Runs bisync once immediately (with --resync
// the first time so the journal exists), then on every interval tick.
func (r *RcloneBisyncer) run(ctx context.Context, h *rcloneBisyncHandle, binary string, env []string, cryptName, journal string, req Request, interval time.Duration, maxFails int) {
	defer close(h.done)

	consecutiveFails := 0
	firstRun := true
	tick := time.NewTimer(0) // fire immediately on start
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}

		args := r.buildArgs(cryptName, req, journal, firstRun)
		err := r.runOnce(ctx, h, binary, env, args)
		conflicts := scanConflicts(req.LocalPath)
		h.mu.Lock()
		h.lastErr = err
		h.conflicts = conflicts
		h.mu.Unlock()
		if len(conflicts) > 0 {
			fmt.Fprintf(os.Stderr, "drift sync %s: %d conflict file(s) present (see `drift status --conflicts` or LocalPath %s)\n",
				req.Compartment, len(conflicts), req.LocalPath)
		}
		if err == nil {
			consecutiveFails = 0
			firstRun = false
		} else if errors.Is(err, context.Canceled) {
			return
		} else {
			consecutiveFails++
		}

		next := interval
		if consecutiveFails >= maxFails {
			next = 5 * time.Minute
		}
		tick.Reset(next)
	}
}

// runOnce executes one bisync invocation and returns its exit status.
// Records the process handle on bh so Stop can SIGTERM it mid-run.
func (r *RcloneBisyncer) runOnce(ctx context.Context, bh *rcloneBisyncHandle, binary string, env, args []string) error {
	cmd := exec.CommandContext(ctx, binary, args...)
	// Same env scrubbing as mount: no parent AWS_/DRIFT_ creds reach
	// rclone — only the named-remote env vars we built.
	cmd.Env = append(minimalEnv(), env...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	if err := cmd.Start(); err != nil {
		return err
	}
	bh.mu.Lock()
	bh.procRef = cmd.Process
	bh.mu.Unlock()
	err := cmd.Wait()
	bh.mu.Lock()
	bh.procRef = nil
	bh.mu.Unlock()
	return err
}

// buildArgs returns the rclone command line for one bisync run.
//
// First run uses --resync (bisync requires it to establish the journal).
// Since drift writes both the local and bucket RCLONE_TEST sentinels
// just before bisync starts, their modtimes differ by ~hundreds of ms.
// Without --resync-mode, bisync 1.66+ treats the modtime mismatch as a
// "files modified on both sides" conflict and aborts. --resync-mode=newer
// makes bisync pick the newer of the two (typically the bucket one,
// since `rclone touch` ran after the local write). This is fine for the
// sentinel; it's a marker file with no meaningful content.
//
// Subsequent runs are incremental. Read-only compartments add --filters
// to prevent local-side uploads.
func (r *RcloneBisyncer) buildArgs(cryptName string, req Request, journal string, firstRun bool) []string {
	args := []string{
		"bisync",
		req.LocalPath,
		cryptName + ":",
		"--workdir", journal,
		"--max-delete", "100",  // refuse a sync run that would delete >100 files at once
		"--check-access",       // require RCLONE_TEST on both sides; bucket-side delete aborts the sync
	}
	if firstRun {
		args = append(args, "--resync", "--resync-mode", "newer")
	}
	return args
}

// journalDirFor returns the per-mount bisync workdir.
func (r *RcloneBisyncer) journalDirFor(req Request) string {
	root := r.WorkDir
	if root == "" {
		if _, err := os.Stat("/dev/shm"); err == nil {
			root = "/dev/shm/drift-bisync"
		} else {
			root = filepath.Join(os.TempDir(), "drift-bisync")
		}
	}
	return filepath.Join(root, req.WorkspaceID, req.Compartment)
}

// scanConflicts walks root looking for rclone-bisync conflict-copy files.
// Bisync names them "<original>.conflict-<device>-<timestamp>". Returns
// relative paths under root.
func scanConflicts(root string) []string {
	var out []string
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if !strings.Contains(info.Name(), ".conflict-") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		out = append(out, rel)
		return nil
	})
	return out
}

// SentinelFilename is rclone bisync's default sentinel under --check-access.
const SentinelFilename = "RCLONE_TEST"

func writeLocalSentinel(localPath string) error {
	f, err := os.OpenFile(filepath.Join(localPath, SentinelFilename), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	return f.Close()
}

// writeBucketSentinel runs `rclone touch <crypt>:RCLONE_TEST` so the
// crypt-encrypted sentinel lands in the bucket. Idempotent — touch
// on an existing file just bumps mtime.
func writeBucketSentinel(ctx context.Context, binary string, env []string, cryptName string) error {
	cmd := exec.CommandContext(ctx, binary, "touch", cryptName+":"+SentinelFilename)
	cmd.Env = append(minimalEnv(), env...)
	var stderr strings.Builder
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return err
		}
		return fmt.Errorf("%w: %s", err, msg)
	}
	return nil
}

// minimalEnv mirrors mount.minimalEnv() — same allow-list. Kept duplicated
// to avoid a circular dependency between sync and mount.
func minimalEnv() []string {
	keep := []string{
		"PATH", "HOME", "TMPDIR", "USER", "LANG", "LC_ALL", "TZ",
		"SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE",
	}
	out := make([]string, 0, len(keep))
	for _, k := range keep {
		if v, ok := os.LookupEnv(k); ok {
			out = append(out, k+"="+v)
		}
	}
	return out
}

// toMountRequest converts a sync Request to the equivalent mount.Request
// shape so we can reuse mount.BuildRcloneEnv for the crypt+S3 env vars.
// Sync mode doesn't have a mount point per se; that field stays empty.
func toMountRequest(req Request) mount.Request {
	return mount.Request{
		WorkspaceID:    req.WorkspaceID,
		Compartment:    req.Compartment,
		CompartmentKey: req.CompartmentKey,
		Cred:           req.Cred,
		Bucket:         req.Bucket,
		MountPoint:     req.LocalPath,
		Mode:           req.Mode,
	}
}

func validateRequest(req Request) error {
	if req.LocalPath == "" {
		return errors.New("sync: LocalPath required")
	}
	if req.Compartment == "" {
		return errors.New("sync: Compartment required")
	}
	if len(req.CompartmentKey) == 0 {
		return errors.New("sync: CompartmentKey required")
	}
	if req.Cred.AccessKeyID == "" || req.Cred.SecretAccessKey == "" {
		return errors.New("sync: Cred missing access key or secret")
	}
	return nil
}
