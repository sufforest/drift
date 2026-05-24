package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufforest/drift/internal/keychain"
)

// autostart token entries live under a known keychain name so disable
// can find them without the user re-typing.
const autostartTokenKey = "autostart-token"

func autostartCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "autostart",
		Short: "Manage a per-user service that re-opens the workspace at login",
		Long: `Persists a long-lived bearer token in the OS keychain (required —
this command refuses if DRIFT_KEYCHAIN is not set) and installs a
platform-specific service that runs ` + "`drift open --background`" + ` at login.

macOS:  ~/Library/LaunchAgents/com.sufforest.drift.plist
Linux:  ~/.config/systemd/user/drift.service (systemd --user)

Disable removes both the service and the keychain token.`,
	}
	cmd.AddCommand(autostartEnableCmd(), autostartDisableCmd(), autostartStatusCmd(), autostartRunCmd())
	return cmd
}

func autostartEnableCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enable <token>",
		Short: "Install the login service using the supplied capability token",
		Args:  cobra.MaximumNArgs(1),
		RunE:  runAutostartEnable,
	}
	cmd.Flags().Bool("stdin", false, "Read token from stdin instead of argv")
	cmd.Flags().String("token-file", "", "Read token from file")
	return cmd
}

func runAutostartEnable(cmd *cobra.Command, args []string) error {
	if os.Getenv("DRIFT_KEYCHAIN") == "" {
		return errors.New("autostart requires DRIFT_KEYCHAIN=1 — refusing to store a long-lived token in a plaintext file")
	}
	if !keychain.Available() {
		return errors.New("autostart requires a reachable OS keychain (drift keychain reports it as unavailable)")
	}
	tok, err := resolveToken(cmd, args)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(tok, "drift1.") {
		return errors.New("autostart token doesn't look like a drift capability token (expected drift1. prefix)")
	}
	if err := keychain.Set(autostartTokenKey, []byte(tok)); err != nil {
		return fmt.Errorf("autostart: store token: %w", err)
	}
	switch runtime.GOOS {
	case "darwin":
		return installLaunchd(cmd.OutOrStdout())
	case "linux":
		return installSystemdUser(cmd.OutOrStdout())
	default:
		return fmt.Errorf("autostart not supported on %s", runtime.GOOS)
	}
}

func autostartDisableCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disable",
		Short: "Stop and remove the login service + keychain token",
		RunE:  runAutostartDisable,
	}
}

func runAutostartDisable(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()
	var firstErr error
	switch runtime.GOOS {
	case "darwin":
		if err := uninstallLaunchd(out); err != nil {
			firstErr = err
		}
	case "linux":
		if err := uninstallSystemdUser(out); err != nil {
			firstErr = err
		}
	default:
		firstErr = fmt.Errorf("autostart not supported on %s", runtime.GOOS)
	}
	if keychain.Available() {
		_ = keychain.Delete(autostartTokenKey)
		fmt.Fprintln(out, "✓ Keychain token cleared.")
	}
	return firstErr
}

func autostartStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Report whether autostart is installed",
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			path, exists, err := autostartPath()
			if err != nil {
				return err
			}
			if exists {
				fmt.Fprintf(out, "Service installed: %s\n", path)
			} else {
				fmt.Fprintf(out, "Service NOT installed (expected at %s)\n", path)
			}
			if keychain.Available() {
				if _, err := keychain.Get(autostartTokenKey); err == nil {
					fmt.Fprintln(out, "Keychain token: present")
				} else {
					fmt.Fprintln(out, "Keychain token: not present")
				}
			}
			return nil
		},
	}
}

func autostartPath() (string, bool, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false, err
	}
	var p string
	switch runtime.GOOS {
	case "darwin":
		p = filepath.Join(home, "Library", "LaunchAgents", "com.sufforest.drift.plist")
	case "linux":
		p = filepath.Join(home, ".config", "systemd", "user", "drift.service")
	default:
		return "", false, fmt.Errorf("autostart not supported on %s", runtime.GOOS)
	}
	_, err = os.Stat(p)
	return p, err == nil, nil
}

func installLaunchd(out interface{ Write([]byte) (int, error) }) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, "Library", "LaunchAgents")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, "com.sufforest.drift.plist")
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.sufforest.drift</string>
  <key>ProgramArguments</key>
  <array>
    <string>` + exe + `</string>
    <string>autostart</string>
    <string>run</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>DRIFT_KEYCHAIN</key>
    <string>1</string>
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <false/>
  <key>StandardOutPath</key>
  <string>` + filepath.Join(home, ".cache", "drift", "autostart.log") + `</string>
  <key>StandardErrorPath</key>
  <string>` + filepath.Join(home, ".cache", "drift", "autostart.err") + `</string>
</dict>
</plist>
`
	if err := os.MkdirAll(filepath.Join(home, ".cache", "drift"), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(plist), 0o644); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}
	// Try to load it now so the user doesn't have to log out.
	if err := exec.Command("launchctl", "load", path).Run(); err != nil {
		fmt.Fprintf(out, "✓ Wrote %s but `launchctl load` failed: %v\n", path, err)
		fmt.Fprintln(out, "  Run `launchctl load -w "+path+"` manually, or log out and back in.")
		return nil
	}
	fmt.Fprintf(out, "✓ Installed launchd agent: %s\n", path)
	fmt.Fprintln(out, "  Runs at login. Disable with `drift autostart disable`.")
	return nil
}

func uninstallLaunchd(out interface{ Write([]byte) (int, error) }) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, "Library", "LaunchAgents", "com.sufforest.drift.plist")
	if _, err := os.Stat(path); err == nil {
		_ = exec.Command("launchctl", "unload", path).Run()
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove plist: %w", err)
		}
		fmt.Fprintf(out, "✓ Removed %s\n", path)
	} else if os.IsNotExist(err) {
		fmt.Fprintln(out, "  No launchd agent installed.")
	} else {
		return err
	}
	return nil
}

func installSystemdUser(out interface{ Write([]byte) (int, error) }) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".config", "systemd", "user")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, "drift.service")
	unit := `[Unit]
Description=drift workspace bearer
After=default.target

[Service]
Type=simple
Environment=DRIFT_KEYCHAIN=1
ExecStart=` + exe + ` autostart run
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
`
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write unit: %w", err)
	}
	// systemctl --user daemon-reload + enable + start
	for _, args := range [][]string{
		{"--user", "daemon-reload"},
		{"--user", "enable", "drift.service"},
		{"--user", "start", "drift.service"},
	} {
		if err := exec.Command("systemctl", args...).Run(); err != nil {
			fmt.Fprintf(out, "✓ Wrote %s but `systemctl %s` failed: %v\n", path, strings.Join(args, " "), err)
			fmt.Fprintln(out, "  Run the systemctl commands manually, or check `systemctl --user status drift.service`.")
			return nil
		}
	}
	fmt.Fprintf(out, "✓ Installed + started systemd user unit: %s\n", path)
	return nil
}

func uninstallSystemdUser(out interface{ Write([]byte) (int, error) }) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path := filepath.Join(home, ".config", "systemd", "user", "drift.service")
	if _, err := os.Stat(path); err == nil {
		_ = exec.Command("systemctl", "--user", "stop", "drift.service").Run()
		_ = exec.Command("systemctl", "--user", "disable", "drift.service").Run()
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove unit: %w", err)
		}
		_ = exec.Command("systemctl", "--user", "daemon-reload").Run()
		fmt.Fprintf(out, "✓ Removed %s\n", path)
	} else if os.IsNotExist(err) {
		fmt.Fprintln(out, "  No systemd user unit installed.")
	} else {
		return err
	}
	return nil
}

// autostartRunCmd is the inner command invoked by the service unit. It
// reads the keychain token and execs `drift open --stdin --background`
// (no daemon detach — the service supervisor handles that).
func autostartRunCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "run",
		Short:  "Internal: invoked by the autostart service",
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !keychain.Available() {
				return errors.New("autostart: OS keychain unavailable; cannot retrieve token")
			}
			tok, err := keychain.Get(autostartTokenKey)
			if err != nil {
				return fmt.Errorf("autostart: load token: %w", err)
			}
			exe, err := os.Executable()
			if err != nil {
				return err
			}
			c := exec.Command(exe, "open", "--stdin")
			c.Stdin = strings.NewReader(string(tok) + "\n")
			c.Stdout = os.Stdout
			c.Stderr = os.Stderr
			c.Env = append(os.Environ(), "DRIFT_KEYCHAIN=1")
			return c.Run()
		},
	}
}
