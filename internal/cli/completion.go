package cli

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func completionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "completion",
		Short: "Shell tab-completion: generate or install completion scripts",
	}
	cmd.AddCommand(completionGenCmd(), completionInstallCmd())
	return cmd
}

// completionGenCmd is the lower-level primitive: emit the completion
// script for a named shell to stdout. Used by `drift completion install`
// internally and exposed for users who want to manage their own paths.
func completionGenCmd() *cobra.Command {
	return &cobra.Command{
		Use:                   "generate <bash|zsh|fish|powershell>",
		Aliases:               []string{"gen"},
		DisableFlagsInUseLine: true,
		Short:                 "Print the completion script for a shell to stdout",
		Long: `Emits the completion script for the named shell. Pipe to a file or
source it directly:

  drift completion generate zsh > ~/.zsh/completions/_drift   # install
  source <(drift completion generate zsh)                      # one-shot

For automatic installation, use ` + "`drift completion install`" + ` instead.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return generateCompletion(cmd.Root(), args[0], os.Stdout)
		},
	}
}

func completionInstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Detect your shell and install completion automatically",
		Long: `Detects your shell from $SHELL, picks the appropriate completion
directory, and writes the script there. If the directory isn't already
loaded by your shell, prints the one line you need to add to your shell
rc file.

Supported shells: bash, zsh, fish. PowerShell users should use
` + "`drift completion generate powershell`" + ` and follow PowerShell's docs.`,
		RunE: runCompletionInstall,
	}
	cmd.Flags().String("shell", "", "Override shell detection (bash, zsh, or fish)")
	cmd.Flags().String("dir", "", "Override install directory")
	return cmd
}

func runCompletionInstall(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()

	shell, _ := cmd.Flags().GetString("shell")
	if shell == "" {
		shell = detectShell()
	}
	if shell == "" {
		return fmt.Errorf("could not detect shell from $SHELL; pass --shell explicitly (bash, zsh, fish)")
	}
	switch shell {
	case "bash", "zsh", "fish":
	default:
		return fmt.Errorf("unsupported shell %q; supported: bash, zsh, fish", shell)
	}

	dirOverride, _ := cmd.Flags().GetString("dir")
	target, rcHint, err := completionInstallPath(shell, dirOverride)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(target), err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".drift-completion-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := generateCompletion(cmd.Root(), shell, tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}
	if err := os.Rename(tmpPath, target); err != nil {
		return fmt.Errorf("rename to %s: %w", target, err)
	}

	fmt.Fprintf(out, "✓ Installed %s completion script\n", shell)
	fmt.Fprintf(out, "  → %s\n", target)
	if rcHint != "" {
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Add to your shell rc file (one-time):")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "  "+rcHint)
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Then open a new shell. Tab-completion will work for drift commands.")
	} else {
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Open a new shell to activate. Or for the current session:")
		switch shell {
		case "bash":
			fmt.Fprintln(out, "  source", target)
		case "zsh":
			fmt.Fprintln(out, "  autoload -U compinit && compinit")
		case "fish":
			fmt.Fprintf(out, "  source %s\n", target)
		}
	}
	return nil
}

// generateCompletion emits the completion script for shell to w. shell
// must be one of bash/zsh/fish/powershell.
func generateCompletion(root *cobra.Command, shell string, w io.Writer) error {
	switch shell {
	case "bash":
		return root.GenBashCompletion(w)
	case "zsh":
		return root.GenZshCompletion(w)
	case "fish":
		return root.GenFishCompletion(w, true)
	case "powershell", "pwsh":
		return root.GenPowerShellCompletionWithDesc(w)
	default:
		return fmt.Errorf("unsupported shell: %q (expected bash, zsh, fish, or powershell)", shell)
	}
}

// detectShell reads $SHELL and returns "bash" / "zsh" / "fish" if it
// matches one of those. Empty string if not detectable.
func detectShell() string {
	sh := os.Getenv("SHELL")
	if sh == "" {
		return ""
	}
	base := filepath.Base(sh)
	switch base {
	case "bash", "zsh", "fish":
		return base
	}
	return ""
}

// completionInstallPath returns (target, rcHint).
// rcHint is non-empty if the user needs to add a line to their shell
// rc file to make the directory's contents load automatically.
func completionInstallPath(shell, dirOverride string) (target, rcHint string, err error) {
	if dirOverride != "" {
		return filepath.Join(dirOverride, completionFilename(shell)), "", nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	switch shell {
	case "zsh":
		// Prefer brew's site-functions if available — auto-loaded by
		// brew's zsh setup without any rc edit. Otherwise fall back to
		// ~/.zsh/completions and tell the user to extend fpath.
		if brewSite := brewZshSiteFunctions(); brewSite != "" {
			return filepath.Join(brewSite, "_drift"), "", nil
		}
		dir := filepath.Join(home, ".zsh", "completions")
		hint := `fpath=("` + dir + `" $fpath); autoload -U compinit && compinit`
		return filepath.Join(dir, "_drift"), hint, nil
	case "bash":
		// XDG user-local bash-completion path; works as long as the
		// user has the bash-completion package and a recent bash.
		dir := filepath.Join(home, ".local", "share", "bash-completion", "completions")
		hint := ""
		// Older bashes (e.g. macOS's stock 3.x) don't auto-load. If we
		// detect that, suggest sourcing explicitly. The check is cheap
		// — read $BASH_VERSION.
		if v := os.Getenv("BASH_VERSION"); v != "" && strings.HasPrefix(v, "3.") {
			hint = `[ -f ` + filepath.Join(dir, "drift") + ` ] && source ` + filepath.Join(dir, "drift")
		}
		return filepath.Join(dir, "drift"), hint, nil
	case "fish":
		dir := filepath.Join(home, ".config", "fish", "completions")
		return filepath.Join(dir, "drift.fish"), "", nil
	default:
		return "", "", fmt.Errorf("unsupported shell: %s", shell)
	}
}

func completionFilename(shell string) string {
	switch shell {
	case "zsh":
		return "_drift"
	case "fish":
		return "drift.fish"
	default:
		return "drift"
	}
}

// brewZshSiteFunctions returns the path to brew's zsh site-functions
// directory (which is in zsh's fpath by default after brew install),
// or "" if brew isn't installed.
func brewZshSiteFunctions() string {
	prefix, err := exec.Command("brew", "--prefix").Output()
	if err != nil {
		return ""
	}
	p := strings.TrimSpace(string(prefix))
	if p == "" {
		return ""
	}
	candidate := filepath.Join(p, "share", "zsh", "site-functions")
	if st, err := os.Stat(candidate); err == nil && st.IsDir() {
		return candidate
	}
	return ""
}
