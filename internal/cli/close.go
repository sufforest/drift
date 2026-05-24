package cli

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufforest/drift/internal/workspace"
)

func closeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "close",
		Short: "Stop a backgrounded `drift open` session (flushes + unmounts + wipes cache)",
		Long:  `Reads the session file written by ` + "`drift open --background`" + `, sends SIGTERM to the worker, and waits for it to clean up.`,
		RunE:  runClose,
	}
	cmd.Flags().Duration("timeout", 15*time.Second, "How long to wait for the worker to exit before falling back to SIGKILL")
	return cmd
}

func runClose(cmd *cobra.Command, _ []string) error {
	dir, err := stateDir(cmd)
	if err != nil {
		return err
	}
	rec, err := workspace.LoadSession(dir)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("no active drift session (nothing to close)")
	}
	if err != nil {
		return err
	}
	if !rec.SignalAlive() {
		fmt.Fprintln(cmd.OutOrStdout(), "session file points at a dead PID; cleaning up.")
		return workspace.ClearSession(dir)
	}

	timeout, _ := cmd.Flags().GetDuration("timeout")
	proc, _ := os.FindProcess(rec.PID)
	if err := proc.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("sigterm pid %d: %w", rec.PID, err)
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !rec.SignalAlive() {
			fmt.Fprintf(cmd.OutOrStdout(), "✓ Closed session (PID %d, tid %s)\n", rec.PID, rec.TID)
			_ = workspace.ClearSession(dir)
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	// Timeout: escalate to SIGKILL.
	if err := proc.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("sigkill pid %d: %w", rec.PID, err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ Force-killed session (PID %d, tid %s)\n", rec.PID, rec.TID)
	_ = workspace.ClearSession(dir)
	return nil
}
