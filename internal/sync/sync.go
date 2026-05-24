// Package sync runs periodic rclone bisync against compartments whose
// manifest entry has Mode == "sync". Mirrors the structure of
// internal/mount: a Syncer interface, a NoopSyncer for tests, and a
// RcloneBisyncer that drives the real subprocess.
//
// v1 ships the interface + Noop. The real bisync wrapper lands once the
// mount layer's rclone-subprocess pattern proves out in production.
package sync

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sufforest/drift/internal/domain"
)

// Request describes one compartment to sync.
type Request struct {
	WorkspaceID    string
	Compartment    string
	CompartmentKey []byte
	Cred           domain.S3Credential
	Bucket         domain.BucketInfo
	LocalPath      string

	// Interval is how often the syncer wakes to run bisync. Defaults to
	// 60s; an fsnotify watcher in the production path bumps this when
	// it sees a local write.
	Interval time.Duration

	// Mode is "rw" or "ro" — drives whether bisync uses --read-only.
	Mode string
}

// Handle is an opaque reference to one running sync goroutine.
type Handle interface {
	Compartment() string
	LocalPath() string

	// Conflicts returns the relative paths of any bisync conflict-copy
	// files currently present under LocalPath. Conflict copies are
	// named `<original>.conflict-<device>-<timestamp>` by rclone bisync
	// after a bidirectional collision; users typically resolve them by
	// reading both sides and picking a winner.
	Conflicts() []string
}

// Syncer manages the lifecycle of compartment sync goroutines. Like
// mount.Mounter, implementations must be safe for concurrent use across
// compartments.
type Syncer interface {
	Sync(ctx context.Context, req Request) (Handle, error)
	Stop(ctx context.Context, h Handle) error
}

// --- NoopSyncer ---

// NoopSyncer records Sync/Stop calls without spawning bisync. Suitable
// for unit tests of the workspace orchestration layer.
type NoopSyncer struct {
	mu      sync.Mutex
	active  map[string]Request
	history []Event
}

// Event is one entry in NoopSyncer.History.
type Event struct {
	Op          string // "sync" or "stop"
	Compartment string
	LocalPath   string
}

func NewNoopSyncer() *NoopSyncer { return &NoopSyncer{active: map[string]Request{}} }

type noopHandle struct {
	compartment string
	localPath   string
}

func (h noopHandle) Compartment() string { return h.compartment }
func (h noopHandle) LocalPath() string   { return h.localPath }
func (h noopHandle) Conflicts() []string { return nil }

func (n *NoopSyncer) Sync(_ context.Context, req Request) (Handle, error) {
	if req.LocalPath == "" {
		return nil, errors.New("sync: LocalPath required")
	}
	if req.Compartment == "" {
		return nil, errors.New("sync: Compartment required")
	}
	if len(req.CompartmentKey) == 0 {
		return nil, errors.New("sync: CompartmentKey required")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, exists := n.active[req.LocalPath]; exists {
		return nil, fmt.Errorf("sync: %s already syncing", req.LocalPath)
	}
	n.active[req.LocalPath] = req
	n.history = append(n.history, Event{Op: "sync", Compartment: req.Compartment, LocalPath: req.LocalPath})
	return noopHandle{compartment: req.Compartment, localPath: req.LocalPath}, nil
}

func (n *NoopSyncer) Stop(_ context.Context, h Handle) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.active[h.LocalPath()]; !ok {
		return fmt.Errorf("sync: %s not active", h.LocalPath())
	}
	delete(n.active, h.LocalPath())
	n.history = append(n.history, Event{Op: "stop", Compartment: h.Compartment(), LocalPath: h.LocalPath()})
	return nil
}

func (n *NoopSyncer) Active() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]string, 0, len(n.active))
	for k := range n.active {
		out = append(out, k)
	}
	return out
}

func (n *NoopSyncer) History() []Event {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]Event, len(n.history))
	copy(out, n.history)
	return out
}
