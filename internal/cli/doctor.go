package cli

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufforest/drift/internal/audit"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/keychain"
	"github.com/sufforest/drift/internal/workspace"
)

type checkStatus int

const (
	statusOK checkStatus = iota
	statusInfo
	statusWarn
	statusFail
)

type checkResult struct {
	name    string
	status  checkStatus
	detail  string
	suggest string
}

func doctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose drift configuration: tools, keys, bucket, sessions",
		Long: `Probes the local environment and the configured workspace for
common problems. Exit 0 if everything is healthy, 2 if only warnings
are present, 1 if any check fails. Output is colorized in a TTY,
plain otherwise.`,
		RunE: runDoctor,
	}
}

func runDoctor(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	color := isTTY(out)

	var results []checkResult
	results = append(results, checkRclone()...)
	results = append(results, checkFUSE()...)
	results = append(results, checkOSKeychain()...)

	dir, dirErr := stateDir(cmd)
	switch {
	case dirErr != nil:
		results = append(results, checkResult{name: "Workspace", status: statusFail, detail: dirErr.Error()})
	case !workspaceConfigured(dir):
		results = append(results, checkResult{
			name:    "Workspace",
			status:  statusInfo,
			detail:  fmt.Sprintf("no workspace in %s", dir),
			suggest: "Run `drift init` to bootstrap a workspace.",
		})
	default:
		results = append(results, checkWorkspace(ctx, cmd, dir)...)
	}

	printDoctor(out, results, color)

	fail, warn := tallyDoctor(results)
	if fail > 0 {
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true
		return errors.New("doctor: one or more checks failed")
	}
	if warn > 0 {
		os.Exit(2)
	}
	return nil
}

func checkRclone() []checkResult {
	path, err := exec.LookPath("rclone")
	if err != nil {
		return []checkResult{{
			name:    "rclone binary",
			status:  statusFail,
			detail:  "not found in PATH",
			suggest: "Install rclone — macOS: `brew install rclone`, Linux: `apt install rclone` or https://rclone.org/install",
		}}
	}
	out, err := exec.Command(path, "version").Output()
	if err != nil {
		return []checkResult{{
			name:   "rclone binary",
			status: statusWarn,
			detail: fmt.Sprintf("found at %s but `rclone version` failed: %v", path, err),
		}}
	}
	first := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	return []checkResult{{
		name:   "rclone binary",
		status: statusOK,
		detail: fmt.Sprintf("%s (%s)", first, path),
	}}
}

func checkFUSE() []checkResult {
	switch runtime.GOOS {
	case "darwin":
		if _, err := os.Stat("/Library/Filesystems/macfuse.fs"); err == nil {
			return []checkResult{{name: "FUSE", status: statusOK, detail: "macFUSE installed"}}
		}
		return []checkResult{{
			name:    "FUSE",
			status:  statusWarn,
			detail:  "macFUSE not detected",
			suggest: "Required for mount-mode vols. `brew install --cask macfuse` (reboot + approve in System Settings → Privacy & Security).",
		}}
	case "linux":
		for _, name := range []string{"fusermount3", "fusermount"} {
			if _, err := exec.LookPath(name); err == nil {
				return []checkResult{{name: "FUSE", status: statusOK, detail: name + " in PATH"}}
			}
		}
		return []checkResult{{
			name:    "FUSE",
			status:  statusWarn,
			detail:  "fusermount(3) not found",
			suggest: "Required for mount-mode vols. `apt install fuse3` or your distro's equivalent.",
		}}
	default:
		return []checkResult{{
			name:   "FUSE",
			status: statusWarn,
			detail: fmt.Sprintf("unsupported platform %s — mount-mode vols may not work", runtime.GOOS),
		}}
	}
}

func checkOSKeychain() []checkResult {
	enabled := os.Getenv("DRIFT_KEYCHAIN") != ""
	if keychain.Available() {
		detail := "reachable; DRIFT_KEYCHAIN unset (file-backed storage)"
		if enabled {
			detail = "reachable; DRIFT_KEYCHAIN enabled"
		}
		return []checkResult{{name: "OS keychain", status: statusOK, detail: detail}}
	}
	return []checkResult{{
		name:    "OS keychain",
		status:  statusInfo,
		detail:  "not reachable (likely headless / no dbus session)",
		suggest: "On a desktop, install gnome-keyring or run inside a session. On a server this is expected — file-backed storage will be used.",
	}}
}

func workspaceConfigured(dir string) bool {
	state, err := workspace.NewState(dir)
	if err != nil {
		return false
	}
	if _, err := state.LoadConfig(); err != nil {
		return false
	}
	return true
}

func checkWorkspace(ctx context.Context, cmd *cobra.Command, dir string) []checkResult {
	var results []checkResult

	state, err := workspace.NewState(dir)
	if err != nil {
		return []checkResult{{name: "workspace state", status: statusFail, detail: err.Error()}}
	}

	cfg, err := state.LoadConfig()
	if err != nil {
		return append(results, checkResult{
			name:    "local-config.json",
			status:  statusFail,
			detail:  err.Error(),
			suggest: "Run `drift init` to bootstrap, or `drift recover` if you have a recovery passphrase.",
		})
	}
	results = append(results, checkResult{
		name:   "local-config.json",
		status: statusOK,
		detail: fmt.Sprintf("workspace %s, device %s", cfg.WorkspaceID, cfg.DeviceID),
	})

	if state.HasMaster() {
		if _, err := state.LoadMaster(); err != nil {
			results = append(results, checkResult{name: "master key", status: statusFail, detail: err.Error()})
		} else {
			results = append(results, checkResult{name: "master key", status: statusOK, detail: "loaded"})
		}
	} else {
		results = append(results, checkResult{name: "master key", status: statusInfo, detail: "absent on this device (non-primary)"})
	}

	if !state.HasDevice() {
		results = append(results, checkResult{
			name:    "device key",
			status:  statusFail,
			detail:  "missing",
			suggest: "Device key is required. Re-pair this device or run `drift recover`.",
		})
		return results
	}
	if _, err := state.LoadDevice(); err != nil {
		results = append(results, checkResult{name: "device key", status: statusFail, detail: err.Error()})
		return results
	}
	results = append(results, checkResult{name: "device key", status: statusOK, detail: "loaded"})

	parent, err := state.LoadParent()
	if err != nil {
		results = append(results, checkResult{
			name:    "parent S3 cred",
			status:  statusFail,
			detail:  err.Error(),
			suggest: "Parent cred required to talk to the bucket. Update via `drift init` flags or restore from backup.",
		})
		return results
	}
	results = append(results, checkResult{
		name:   "parent S3 cred",
		status: statusOK,
		detail: fmt.Sprintf("provider %s, key %s…", parent.Provider, abbrev(parent.AccessKeyID, 8)),
	})

	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		results = append(results, checkResult{
			name:    "workspace load",
			status:  statusFail,
			detail:  err.Error(),
			suggest: "If the bucket is unreachable or creds are wrong, fix that first; otherwise inspect with --verbose.",
		})
		return results
	}

	exists, err := ws.Provider.Exists(ctx, domain.ManifestKey)
	if err != nil {
		results = append(results, checkResult{
			name:    "bucket reach",
			status:  statusFail,
			detail:  err.Error(),
			suggest: "Check bucket name, endpoint, parent cred validity, and network connectivity.",
		})
		return results
	}
	if !exists {
		results = append(results, checkResult{
			name:    "bucket reach",
			status:  statusFail,
			detail:  "manifest.enc missing on bucket",
			suggest: "Workspace metadata is gone from the bucket. `drift recover` may help; otherwise the workspace is lost.",
		})
		return results
	}
	results = append(results, checkResult{
		name:   "bucket reach",
		status: statusOK,
		detail: fmt.Sprintf("%s @ %s", cfg.Bucket.Name, cfg.Bucket.Endpoint),
	})

	m, err := ws.Manifest(ctx)
	if err != nil {
		results = append(results, checkResult{name: "manifest", status: statusFail, detail: err.Error()})
		return results
	}
	results = append(results, checkResult{
		name:   "manifest signature",
		status: statusOK,
		detail: fmt.Sprintf("verified; sequence %d, %d device(s), %d vol(s)", m.Sequence, len(m.Devices), len(m.Compartments)),
	})
	results = append(results, checkResult{
		name:   "trust root pin",
		status: statusOK,
		detail: "master sha256:" + abbrev(hex.EncodeToString(cfg.MasterFingerprint), 16) + "…",
	})

	cprk := ws.CPRK
	if cprk != nil {
		resolve := func(did string) ed25519.PublicKey {
			if d, ok := m.Devices[did]; ok {
				return ed25519.PublicKey(d.PublicKey)
			}
			return nil
		}
		entries, skipped, err := audit.List(ctx, ws.Provider, cfg.WorkspaceID, cprk, resolve)
		switch {
		case err != nil:
			results = append(results, checkResult{name: "audit log", status: statusWarn, detail: "list failed: " + err.Error()})
		default:
			if chainErr := audit.VerifyChain(entries); chainErr != nil {
				results = append(results, checkResult{
					name:    "audit chain",
					status:  statusFail,
					detail:  chainErr.Error(),
					suggest: "A break in the audit chain may indicate a forged or deleted entry. Inspect with `drift audit --verify`.",
				})
			} else {
				detail := fmt.Sprintf("%d entries", len(entries))
				if skipped > 0 {
					detail = fmt.Sprintf("%d entries (%d skipped, likely pre-CPRK-rotation)", len(entries), skipped)
				}
				results = append(results, checkResult{name: "audit chain", status: statusOK, detail: detail})
			}
		}
	}

	rec, err := workspace.LoadSession(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		results = append(results, checkResult{name: "background session", status: statusOK, detail: "none"})
	case err != nil:
		results = append(results, checkResult{name: "background session", status: statusWarn, detail: err.Error()})
	case !rec.SignalAlive():
		results = append(results, checkResult{
			name:    "background session",
			status:  statusWarn,
			detail:  fmt.Sprintf("stale (PID %d not running)", rec.PID),
			suggest: "Clean up with `drift close`.",
		})
	default:
		results = append(results, checkResult{
			name:   "background session",
			status: statusOK,
			detail: fmt.Sprintf("alive (PID %d, tid %s)", rec.PID, rec.TID),
		})
	}

	return results
}

func tallyDoctor(rs []checkResult) (fail, warn int) {
	for _, r := range rs {
		switch r.status {
		case statusFail:
			fail++
		case statusWarn:
			warn++
		}
	}
	return
}

func printDoctor(w io.Writer, rs []checkResult, color bool) {
	nameWidth := 0
	for _, r := range rs {
		if l := len(r.name); l > nameWidth {
			nameWidth = l
		}
	}
	for _, r := range rs {
		mark, reset := statusMark(r.status, color)
		fmt.Fprintf(w, "  %s %-*s  %s%s\n", mark, nameWidth, r.name, r.detail, reset)
		if r.suggest != "" && r.status != statusOK {
			fmt.Fprintf(w, "    %s%s%s\n", dim(color), "→ "+r.suggest, resetSeq(color))
		}
	}
	fail, warn := tallyDoctor(rs)
	fmt.Fprintln(w)
	switch {
	case fail > 0:
		fmt.Fprintf(w, "Result: %d failing, %d warning(s).\n", fail, warn)
	case warn > 0:
		fmt.Fprintf(w, "Result: all critical checks passed (%d warning(s)).\n", warn)
	default:
		fmt.Fprintln(w, "Result: all checks passed.")
	}
}

func statusMark(s checkStatus, color bool) (mark, reset string) {
	switch s {
	case statusOK:
		if color {
			return "\x1b[32m  ✓  \x1b[0m", ""
		}
		return "[ OK ]", ""
	case statusInfo:
		if color {
			return "\x1b[36m  i  \x1b[0m", ""
		}
		return "[INFO]", ""
	case statusWarn:
		if color {
			return "\x1b[33m  !  \x1b[0m", ""
		}
		return "[WARN]", ""
	case statusFail:
		if color {
			return "\x1b[31m  ✗  \x1b[0m", ""
		}
		return "[FAIL]", ""
	}
	return "     ", ""
}

func dim(color bool) string {
	if color {
		return "\x1b[2m"
	}
	return ""
}

func resetSeq(color bool) string {
	if color {
		return "\x1b[0m"
	}
	return ""
}

func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func abbrev(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
