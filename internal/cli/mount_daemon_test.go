package cli

import (
	"os"
	"testing"
)

// TestSignalDaemonStatus_noopWhenNotDaemon: the signal helpers must
// be safe to call from foreground (non-daemon) code paths. They
// check the daemon env var before touching fd 3, so the call is a
// no-op when running normally. End-to-end signaling between parent
// and child is exercised by scripts/e2e.sh.
func TestSignalDaemonStatus_noopWhenNotDaemon(t *testing.T) {
	old := os.Getenv(directDaemonEnvVar)
	_ = os.Unsetenv(directDaemonEnvVar)
	t.Cleanup(func() { _ = os.Setenv(directDaemonEnvVar, old) })

	// Just verify they don't panic and don't try to write to fd 3
	// (which in a test process is typically closed or unrelated).
	signalDaemonReady()
	signalDaemonError("any message")
	signalDaemonStatus("arbitrary")
}
