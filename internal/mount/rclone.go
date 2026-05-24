package mount

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// RcloneMounter spawns `rclone mount` as a subprocess and tears it down on
// Unmount. Credentials are passed via process env vars (not a config file)
// so they never touch disk.
//
// Required external binary: rclone in $PATH (or RcloneMounter.Binary set).
// macOS additionally needs macFUSE; Linux needs fuse3 + user_allow_other.
type RcloneMounter struct {
	// Binary is the path to the rclone executable. Defaults to "rclone"
	// resolved via $PATH.
	Binary string

	// CacheRoot is the parent directory for per-mount VFS caches. Should
	// be tmpfs on Linux (e.g. /dev/shm/drift); /tmp on macOS as a
	// fallback. Each mount gets its own subdirectory underneath.
	CacheRoot string

	// VFSCacheMode is the rclone --vfs-cache-mode argument. Defaults to
	// Default "full" — best balance for sporadic large-file reads.
	VFSCacheMode string

	// MountReadyTimeout is how long Mount() waits for the mountpoint to
	// be observable on the filesystem after starting rclone. Defaults to
	// 30s.
	MountReadyTimeout time.Duration

	// Now is the clock; overridable for tests.
	Now func() time.Time
}

// rcloneHandle is the Handle returned by RcloneMounter.Mount.
type rcloneHandle struct {
	cmd         *exec.Cmd
	mountPoint  string
	compartment string
	cachePath   string

	mu       sync.Mutex
	exited   bool
	exitErr  error
	exitOnce sync.Once
	waitCh   chan struct{}
}

func (h *rcloneHandle) MountPoint() string  { return h.mountPoint }
func (h *rcloneHandle) Compartment() string { return h.compartment }

// Mount configures the crypt+S3 remote via env vars and launches `rclone mount`.
// Returns once the mountpoint is observable on the filesystem (or
// MountReadyTimeout expires).
func (m *RcloneMounter) Mount(ctx context.Context, req Request) (Handle, error) {
	if err := validateRequest(req); err != nil {
		return nil, err
	}
	binary := m.Binary
	if binary == "" {
		binary = "rclone"
	}
	if _, err := exec.LookPath(binary); err != nil {
		return nil, fmt.Errorf("mount: rclone not found in $PATH (%w)", err)
	}

	if err := os.MkdirAll(req.MountPoint, 0o755); err != nil {
		return nil, fmt.Errorf("mount: create mountpoint %s: %w", req.MountPoint, err)
	}

	cachePath := m.cachePathFor(req)
	// In ephemeral mode we still need a cache-dir for rclone's in-flight
	// write spool, but the directory must be on a RAM-backed FS so it
	// disappears on power loss / kill. On Linux that's /dev/shm by
	// default; on macOS we fall back to system temp and explicitly mark
	// the path so the user sees what's going on.
	if err := os.MkdirAll(cachePath, 0o700); err != nil {
		return nil, fmt.Errorf("mount: create cache dir: %w", err)
	}

	cryptName, env, err := BuildRcloneEnv(req, binary)
	if err != nil {
		return nil, fmt.Errorf("mount: build env: %w", err)
	}
	args := m.buildArgs(req, cryptName, cachePath)

	cmd := exec.CommandContext(ctx, binary, args...)
	// Do NOT inherit the parent's full environment. The parent may hold
	// AWS_ACCESS_KEY_ID / DRIFT_* secrets that have no business in
	// rclone's process space. Pass only PATH + HOME + a small TLS/locale
	// allow-list (see minimalEnv) plus our crypt/S3 remote env vars.
	cmd.Env = append(minimalEnv(), env...)
	// Capture stderr so we can surface useful errors on early exit. stdout
	// is left attached so users running with --verbose see rclone logs.
	cmd.Stderr = os.Stderr
	cmd.Stdout = io.Discard

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("mount: start rclone: %w", err)
	}

	h := &rcloneHandle{
		cmd:         cmd,
		mountPoint:  req.MountPoint,
		compartment: req.Compartment,
		cachePath:   cachePath,
		waitCh:      make(chan struct{}),
	}
	go func() {
		err := cmd.Wait()
		h.mu.Lock()
		h.exited = true
		h.exitErr = err
		h.mu.Unlock()
		close(h.waitCh)
	}()

	timeout := m.MountReadyTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	if err := m.waitMountReady(ctx, req.MountPoint, timeout, h); err != nil {
		// Best-effort kill on startup failure.
		_ = m.Unmount(ctx, h)
		return nil, err
	}
	return h, nil
}

// Unmount sends SIGTERM, waits up to 10s, then SIGKILL. After the process
// exits the cache directory is securely wiped and removed.
func (m *RcloneMounter) Unmount(ctx context.Context, h Handle) error {
	rh, ok := h.(*rcloneHandle)
	if !ok {
		return fmt.Errorf("mount: handle is not a *rcloneHandle")
	}

	var stopErr error
	rh.exitOnce.Do(func() {
		rh.mu.Lock()
		alreadyExited := rh.exited
		proc := rh.cmd.Process
		rh.mu.Unlock()
		if alreadyExited || proc == nil {
			return
		}
		if err := proc.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			stopErr = fmt.Errorf("sigterm: %w", err)
		}

		select {
		case <-rh.waitCh:
		case <-time.After(10 * time.Second):
			if err := proc.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				stopErr = fmt.Errorf("kill: %w", err)
			}
			<-rh.waitCh
		case <-ctx.Done():
			return
		}
	})

	if rh.cachePath != "" {
		if err := SecureWipeDir(rh.cachePath); err != nil && stopErr == nil {
			stopErr = fmt.Errorf("secure wipe: %w", err)
		}
	}
	return stopErr
}

// waitMountReady polls the mountpoint for "is this a FUSE mount?" by
// checking if its parent inode differs from the mountpoint's own. Crude but
// avoids OS-specific syscalls.
func (m *RcloneMounter) waitMountReady(ctx context.Context, mp string, timeout time.Duration, h *rcloneHandle) error {
	parent := filepath.Dir(mp)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-h.waitCh:
			h.mu.Lock()
			err := h.exitErr
			h.mu.Unlock()
			return fmt.Errorf("rclone exited before mount became ready: %w", err)
		default:
		}
		mpInfo, mpErr := os.Stat(mp)
		parentInfo, parentErr := os.Stat(parent)
		if mpErr == nil && parentErr == nil {
			if mpStat, ok := mpInfo.Sys().(*syscall.Stat_t); ok {
				if pStat, ok := parentInfo.Sys().(*syscall.Stat_t); ok {
					if mpStat.Dev != pStat.Dev {
						return nil // distinct device id → it's mounted
					}
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("mount: %s did not become ready within %s", mp, timeout)
}

// cachePathFor returns the per-mount cache dir.
//
// On Linux /dev/shm is genuinely tmpfs; on macOS the system temp is
// disk-backed and SecureWipeDir is best-effort against SSD wear-leveling.
// Caller can override via RcloneMounter.CacheRoot to point at e.g. a
// hdiutil-backed RAM disk for true ephemerality.
func (m *RcloneMounter) cachePathFor(req Request) string {
	root := m.CacheRoot
	if root == "" {
		if _, err := os.Stat("/dev/shm"); err == nil {
			root = "/dev/shm/drift"
		} else {
			root = filepath.Join(os.TempDir(), "drift-cache")
		}
	}
	return filepath.Join(root, req.WorkspaceID, req.Compartment)
}

// CacheIsTmpfs reports whether the resolved cache dir for req lives on a
// RAM-backed filesystem. Used by the CLI to warn users that --ephemeral
// is best-effort on macOS unless they point CacheRoot at a RAM disk.
func (m *RcloneMounter) CacheIsTmpfs(req Request) bool {
	p := m.cachePathFor(req)
	// Linux /dev/shm is always tmpfs; on other OSes assume disk unless
	// the user has explicitly pointed somewhere they know is RAM.
	return strings.HasPrefix(p, "/dev/shm/")
}

// buildArgs returns the rclone command-line arguments. Exposed for tests via
// BuildRcloneArgs.
//
// Ephemeral mode switches to "writes" cache mode (which holds in-flight
// writes in memory) AND pins the cache dir to the tmpfs cachePath the
// caller provided. Without the explicit cache-dir, rclone defaults to
// ~/.cache/rclone — persistent disk that would survive `drift close`
// even with --ephemeral.
func (m *RcloneMounter) buildArgs(req Request, cryptName, cachePath string) []string {
	mode := m.VFSCacheMode
	if mode == "" {
		mode = "full"
	}
	if req.Ephemeral {
		mode = "writes"
	}
	args := []string{
		"mount",
		cryptName + ":",
		req.MountPoint,
		"--vfs-cache-mode", mode,
		"--allow-non-empty=false",
	}
	if req.Mode == "ro" {
		args = append(args, "--read-only")
	}
	if cachePath != "" {
		args = append(args, "--cache-dir", cachePath)
	}
	return args
}

// BuildRcloneArgs is the exported, deterministic argv builder for tests.
func BuildRcloneArgs(req Request, cryptName, cachePath string, vfsCacheMode string) []string {
	m := &RcloneMounter{VFSCacheMode: vfsCacheMode}
	return m.buildArgs(req, cryptName, cachePath)
}

// BuildRcloneEnv generates the env vars that configure rclone's S3 + crypt
// remotes inline. The function is exported so tests can assert the
// produced shape without invoking rclone.
//
// rcloneBinary is the path to `rclone` to invoke for `rclone obscure`.
// Pass "" to fall back to $PATH lookup. Honoring this matters when the
// user explicitly chose a binary via `drift open --rclone`.
//
// Two remotes are configured:
//
//   - <wsid>_s3   — S3 backend pointed at req.Bucket with req.Cred
//   - <wsid>_crypt — crypt remote layered on <wsid>_s3 at the compartment prefix
//
// The compartment key is base64-encoded then passed to `rclone obscure`
// via stdin; the resulting obscured form is the crypt password. A second
// derived key is used as the filename salt (password2).
func BuildRcloneEnv(req Request, rcloneBinary string) (cryptName string, env []string, err error) {
	if len(req.CompartmentKey) == 0 {
		return "", nil, errors.New("rclone: empty CompartmentKey")
	}
	tag := sanitizeID(req.WorkspaceID + "_" + req.Compartment)
	s3Name := "drift_s3_" + tag
	cryptName = "drift_crypt_" + tag

	s3Prefix := envPrefix(s3Name)
	cryptPrefix := envPrefix(cryptName)

	env = append(env,
		s3Prefix+"TYPE=s3",
		s3Prefix+"PROVIDER="+s3Provider(req.Bucket.Provider),
		s3Prefix+"REGION="+nonEmpty(req.Bucket.Region, "auto"),
		s3Prefix+"ACCESS_KEY_ID="+req.Cred.AccessKeyID,
		s3Prefix+"SECRET_ACCESS_KEY="+req.Cred.SecretAccessKey,
		// Skip rclone's "does the bucket exist?" probe before uploads.
		// Bearer creds are scoped to a prefix; they don't have HeadBucket
		// or CreateBucket permission. Without this, rclone tries
		// CreateBucket on first upload and R2 returns 403 AccessDenied.
		s3Prefix+"NO_CHECK_BUCKET=true",
	)
	if req.Cred.SessionToken != "" {
		env = append(env, s3Prefix+"SESSION_TOKEN="+req.Cred.SessionToken)
	}
	if req.Bucket.Endpoint != "" {
		env = append(env, s3Prefix+"ENDPOINT="+req.Bucket.Endpoint)
	}

	// Two passwords for crypt: encryption + filename (salt). Derive both
	// deterministically from the compartment key so the same compartment
	// always uses the same crypt scheme across devices.
	password, err := rcloneObscure(req.CompartmentKey, rcloneBinary)
	if err != nil {
		return "", nil, fmt.Errorf("obscure: %w", err)
	}
	// password2 is a separate value; rclone treats it as the filename
	// encryption salt. Derive it by XORing the compartment key with a
	// fixed label so it's distinct but determined by the same secret.
	salt := make([]byte, len(req.CompartmentKey))
	label := []byte("drift/v1/crypt/salt")
	for i := range salt {
		salt[i] = req.CompartmentKey[i] ^ label[i%len(label)]
	}
	password2, err := rcloneObscure(salt, rcloneBinary)
	if err != nil {
		return "", nil, fmt.Errorf("obscure salt: %w", err)
	}

	remote := s3Name + ":" + req.Bucket.Name + "/compartments/" + req.Compartment
	env = append(env,
		cryptPrefix+"TYPE=crypt",
		cryptPrefix+"REMOTE="+remote,
		cryptPrefix+"PASSWORD="+password,
		cryptPrefix+"PASSWORD2="+password2,
		cryptPrefix+"FILENAME_ENCRYPTION=standard",
		cryptPrefix+"DIRECTORY_NAME_ENCRYPTION=true",
	)
	return cryptName, env, nil
}

// envPrefix returns the rclone env-var prefix for a remote name. rclone
// upper-cases the name and replaces non-alphanumerics, so we pre-sanitize.
func envPrefix(remoteName string) string {
	return "RCLONE_CONFIG_" + strings.ToUpper(sanitizeID(remoteName)) + "_"
}

func sanitizeID(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func s3Provider(p string) string {
	switch strings.ToLower(p) {
	case "r2":
		return "Cloudflare"
	case "b2":
		return "Backblaze"
	case "minio":
		return "Minio"
	case "wasabi":
		return "Wasabi"
	default:
		return "AWS"
	}
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// minimalEnv returns a small allow-list of parent env vars rclone needs.
// Everything else (especially AWS_*/DRIFT_*/parent-provider creds) stays
// behind. TLS-related vars are required on hardened Linux setups and
// distroless containers, otherwise rclone fails with confusing
// certificate errors. TZ is included so file timestamps match the user's
// locale.
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

func validateRequest(req Request) error {
	if req.MountPoint == "" {
		return errors.New("mount: MountPoint required")
	}
	if req.Compartment == "" {
		return errors.New("mount: Compartment required")
	}
	if len(req.CompartmentKey) == 0 {
		return errors.New("mount: CompartmentKey required")
	}
	if req.Cred.AccessKeyID == "" || req.Cred.SecretAccessKey == "" {
		return errors.New("mount: Cred missing access key or secret")
	}
	return nil
}

// SecureWipeDir overwrites every regular file under root with random bytes
// of the same size, fsyncs, then removes everything. Best-effort: errors on
// individual files are reported but the walk continues.
//
// "Secure" is relative — on SSDs with FTL the bits may persist on spare
// blocks. For real defense, use tmpfs or a per-session encrypted overlay.
func SecureWipeDir(root string) error {
	var firstErr error
	walkErr := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil // best-effort
		}
		if info.IsDir() {
			return nil
		}
		if err := overwriteFile(path, info.Size()); err != nil && firstErr == nil {
			firstErr = err
		}
		return nil
	})
	if walkErr != nil && firstErr == nil {
		firstErr = walkErr
	}
	if err := os.RemoveAll(root); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

func overwriteFile(path string, size int64) error {
	if size <= 0 {
		return nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 64*1024)
	written := int64(0)
	for written < size {
		n := int64(len(buf))
		if n > size-written {
			n = size - written
		}
		if _, err := rand.Read(buf[:n]); err != nil {
			return err
		}
		if _, err := f.Write(buf[:n]); err != nil {
			return err
		}
		written += n
	}
	return f.Sync()
}

// rcloneObscure delegates to `rclone obscure -` (stdin form) to produce
// the obscured form of a password. Subprocessing avoids hardcoding rclone's
// AES key (which could change between rclone versions). Reading the
// plaintext from stdin instead of argv means the key never appears in
// `ps` output.
//
// binary is the rclone executable to invoke; the caller's --rclone flag
// takes precedence over $PATH lookup.
//
// The raw key bytes are base64-encoded first so a binary compartment key
// survives the stream as printable text; this b64 form is the actual
// "password" rclone uses for the crypt remote, used consistently
// everywhere downstream.
func rcloneObscure(plaintext []byte, binary string) (string, error) {
	if binary == "" {
		binary = "rclone"
	}
	resolved, err := exec.LookPath(binary)
	if err != nil {
		return "", fmt.Errorf("rclone not found at %q: %w", binary, err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(plaintext)
	cmd := exec.Command(resolved, "obscure", "-")
	cmd.Stdin = strings.NewReader(encoded + "\n")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("rclone obscure: %w", err)
	}
	return strings.TrimRight(string(out), "\n"), nil
}
