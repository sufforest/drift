package workspace

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

var _ = errors.Is // keep errors imported for AcquireSession

// SessionFile is the on-disk record of a live `drift open --background`.
// One per state dir; v1 supports at most one active session.
const SessionFile = "session.json"

// SessionRecord is what drift open writes and drift close reads.
type SessionRecord struct {
	PID         int       `json:"pid"`
	TID         string    `json:"tid"`
	WorkspaceID string    `json:"workspace_id"`
	MountPoints []string  `json:"mount_points"`
	StartedAt   time.Time `json:"started_at"`
	Ephemeral   bool      `json:"ephemeral"`
}

// SaveSession writes the record at $stateDir/session.json. Overwrites any
// existing file; v1 enforces only-one-session via AcquireSession at the
// start of `drift open --background`.
//
// Mode is 0600 — the file holds tid + mountpoints, which on a multi-user
// host could help an attacker target the running drift process. Not
// world-readable.
func SaveSession(stateDir string, r SessionRecord) error {
	body, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(stateDir, SessionFile), body, 0o600)
}

// AcquireSession atomically claims the single session slot for this state
// dir by creating session.json with O_CREATE|O_EXCL. If an existing
// session.json points at a dead PID, it's cleaned up first; if it points
// at a live PID, AcquireSession returns an error.
//
// SaveSession alone would race between two concurrent
// `drift open --background` invocations — both could pass the SignalAlive
// check, both write session.json, both think they own the slot.
func AcquireSession(stateDir string, r SessionRecord) error {
	path := filepath.Join(stateDir, SessionFile)

	// If session.json exists and points at a dead PID, sweep it.
	if existing, err := LoadSession(stateDir); err == nil {
		if existing.SignalAlive() {
			return fmt.Errorf("a drift session is already running (PID %d, tid %s); use `drift close` first", existing.PID, existing.TID)
		}
		_ = ClearSession(stateDir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	body, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("another drift open already claimed this state dir")
		}
		return err
	}
	defer f.Close()
	if _, err := f.Write(body); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

// LoadSession returns the session record, or os.ErrNotExist if none is
// active. Callers should treat a stale-PID record (process no longer
// running) as "no session" and call ClearSession.
func LoadSession(stateDir string) (*SessionRecord, error) {
	body, err := os.ReadFile(filepath.Join(stateDir, SessionFile))
	if err != nil {
		return nil, err
	}
	var r SessionRecord
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("parse session.json: %w", err)
	}
	return &r, nil
}

// ClearSession removes the session record. Safe to call when no session
// exists.
func ClearSession(stateDir string) error {
	err := os.Remove(filepath.Join(stateDir, SessionFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// SignalAlive returns true if the recorded PID is still running. Uses
// signal(0) which is universally a liveness probe on Unix systems.
func (r *SessionRecord) SignalAlive() bool {
	if r.PID <= 0 {
		return false
	}
	proc, err := os.FindProcess(r.PID)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}
