package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestCheckRcloneMountSupport_homebrewBuild simulates a Homebrew
// rclone binary by writing a shell script that prints the not-
// supported banner. The doctor check should flag it as failure.
func TestCheckRcloneMountSupport_homebrewBuild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test relies on /bin/sh wrappers")
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "rclone")
	script := `#!/bin/sh
# Reproduce Homebrew-rclone's behavior when 'help mount' is invoked:
# print the same banner the real broken build prints.
if [ "$1" = "help" ] && [ "$2" = "mount" ]; then
  echo "rclone mount is not supported on MacOS when rclone is installed via Homebrew. Please install the rclone binaries available at https://rclone.org/downloads/ instead if you want to use the rclone mount command"
  exit 1
fi
if [ "$1" = "version" ]; then
  echo "rclone v1.69.0"
  echo "- os/type:    darwin"
  echo "- os/arch:    arm64"
  exit 0
fi
exit 0
`
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	results := checkRcloneMountSupport(fake)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.status != statusFail {
		t.Errorf("Homebrew-rclone should yield statusFail, got %v (detail=%q)", r.status, r.detail)
	}
	if r.suggest == "" {
		t.Error("failure result should include a remediation suggest")
	}
}

// TestCheckRcloneMountSupport_workingBuild simulates an upstream
// rclone that supports the mount subcommand. Doctor should report OK.
func TestCheckRcloneMountSupport_workingBuild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test relies on /bin/sh wrappers")
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "rclone")
	script := `#!/bin/sh
if [ "$1" = "help" ] && [ "$2" = "mount" ]; then
  echo "Usage: rclone mount remote:path /path/to/mountpoint [flags]"
  echo "Mount the remote as a file system."
  exit 0
fi
if [ "$1" = "version" ]; then
  echo "rclone v1.69.0"
  echo "- os/type:    linux"
  echo "- os/arch:    amd64"
  exit 0
fi
exit 0
`
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	results := checkRcloneMountSupport(fake)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].status != statusOK {
		t.Errorf("upstream rclone should yield statusOK, got %v (detail=%q)", results[0].status, results[0].detail)
	}
}

// TestCheckRcloneMountSupport_homebrewTagInVersion handles the case
// where the not-supported banner format shifts in a future rclone
// release but the version string still self-identifies as Homebrew.
// The check should at least warn.
func TestCheckRcloneMountSupport_homebrewTagInVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test relies on /bin/sh wrappers")
	}
	dir := t.TempDir()
	fake := filepath.Join(dir, "rclone")
	// Help mount succeeds (no banner) but version mentions Homebrew.
	script := `#!/bin/sh
if [ "$1" = "help" ] && [ "$2" = "mount" ]; then
  echo "Usage: rclone mount ..."
  exit 0
fi
if [ "$1" = "version" ]; then
  echo "rclone v1.69.0-homebrew"
  echo "- tag:        homebrew"
  exit 0
fi
exit 0
`
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	results := checkRcloneMountSupport(fake)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].status != statusWarn {
		t.Errorf("rclone with homebrew tag should yield statusWarn, got %v", results[0].status)
	}
}
