// Package mount abstracts the data-plane: turning a compartment key + scoped
// S3 credential into a usable filesystem.
//
// v1 ships with a NoopMounter for testing. The real implementation (rclone
// subprocess with the crypt remote and FUSE mount) lives behind this
// interface so the workspace layer is testable without rclone+FUSE present.
package mount

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/sufforest/drift/internal/domain"
)

// Request describes one compartment to mount.
type Request struct {
	WorkspaceID    string
	Compartment    string
	CompartmentKey []byte
	Cred           domain.S3Credential
	Bucket         domain.BucketInfo
	MountPoint     string

	// Ephemeral disables on-disk cache (RAM only).
	Ephemeral bool

	// Mode is "rw" or "ro" — informs rclone mount flags.
	Mode string
}

// Handle is an opaque reference to one running mount, returned by Mount and
// passed back to Unmount. Implementations are free to embed whatever state
// they need; callers only invoke MountPoint and (via Mounter) Unmount.
type Handle interface {
	MountPoint() string
	Compartment() string
}

// Mounter manages the lifecycle of compartment mounts. Implementations must
// be safe for concurrent use across compartments.
type Mounter interface {
	Mount(ctx context.Context, req Request) (Handle, error)
	Unmount(ctx context.Context, h Handle) error
}

// --- NoopMounter ---

// NoopMounter records every Mount/Unmount call without touching the
// filesystem. Suitable for unit tests of the workspace orchestration layer.
type NoopMounter struct {
	mu      sync.Mutex
	mounts  map[string]Request // mountpoint → request
	history []Event
}

// Event is one entry in NoopMounter.History.
type Event struct {
	Op          string // "mount" or "unmount"
	Compartment string
	MountPoint  string
}

// NewNoopMounter constructs an empty NoopMounter.
func NewNoopMounter() *NoopMounter {
	return &NoopMounter{mounts: make(map[string]Request)}
}

// noopHandle is the Handle implementation for NoopMounter.
type noopHandle struct {
	mountPoint  string
	compartment string
}

func (h noopHandle) MountPoint() string  { return h.mountPoint }
func (h noopHandle) Compartment() string { return h.compartment }

// Mount records the request and returns a Handle.
func (n *NoopMounter) Mount(_ context.Context, req Request) (Handle, error) {
	if req.MountPoint == "" {
		return nil, errors.New("mount: MountPoint required")
	}
	if req.Compartment == "" {
		return nil, errors.New("mount: Compartment required")
	}
	if len(req.CompartmentKey) == 0 {
		return nil, errors.New("mount: CompartmentKey required")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, exists := n.mounts[req.MountPoint]; exists {
		return nil, fmt.Errorf("mount: %s already mounted", req.MountPoint)
	}
	n.mounts[req.MountPoint] = req
	n.history = append(n.history, Event{Op: "mount", Compartment: req.Compartment, MountPoint: req.MountPoint})
	return noopHandle{mountPoint: req.MountPoint, compartment: req.Compartment}, nil
}

// Unmount removes the recorded mount.
func (n *NoopMounter) Unmount(_ context.Context, h Handle) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.mounts[h.MountPoint()]; !ok {
		return fmt.Errorf("unmount: %s not mounted", h.MountPoint())
	}
	delete(n.mounts, h.MountPoint())
	n.history = append(n.history, Event{Op: "unmount", Compartment: h.Compartment(), MountPoint: h.MountPoint()})
	return nil
}

// Active returns the mountpoints currently held. Order undefined.
func (n *NoopMounter) Active() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]string, 0, len(n.mounts))
	for mp := range n.mounts {
		out = append(out, mp)
	}
	return out
}

// History returns the ordered list of mount/unmount events for assertions
// in tests.
func (n *NoopMounter) History() []Event {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]Event, len(n.history))
	copy(out, n.history)
	return out
}
