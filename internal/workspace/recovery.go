package workspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/recovery"
)

// SaveRecovery wraps this workspace's master key under the supplied
// passphrase and uploads the blob to the bucket. Overwrites any existing
// blob — callers wanting to refuse overwrite should check FetchRecoveryBlob
// first.
//
// Refuses if this device has no master key (e.g. a paired secondary).
func (w *Workspace) SaveRecovery(ctx context.Context, passphrase string, opts recovery.WrapOptions) error {
	if w.Master == nil {
		return errors.New("recovery: this device has no master key; only the primary can configure recovery")
	}
	blob, err := recovery.Wrap(w.Master, w.Config.WorkspaceID, passphrase, opts)
	if err != nil {
		return err
	}
	body, err := json.Marshal(blob)
	if err != nil {
		return fmt.Errorf("recovery: marshal blob: %w", err)
	}
	if err := w.Provider.Put(ctx, domain.RecoveryKey, body); err != nil {
		return fmt.Errorf("recovery: upload: %w", err)
	}
	_ = w.auditEmitter().Emit(ctx, domain.AuditKindRecoveryConfigured, w.Config.WorkspaceID, map[string]any{
		"argon_time":   blob.Time,
		"argon_memory": blob.Memory,
	})
	return nil
}

// DisableRecovery removes the recovery blob from the bucket. Idempotent —
// returns nil if no blob exists.
func (w *Workspace) DisableRecovery(ctx context.Context) error {
	exists, err := w.Provider.Exists(ctx, domain.RecoveryKey)
	if err != nil {
		return fmt.Errorf("recovery: probe: %w", err)
	}
	if !exists {
		return nil
	}
	if err := w.Provider.Delete(ctx, domain.RecoveryKey); err != nil {
		return fmt.Errorf("recovery: delete: %w", err)
	}
	_ = w.auditEmitter().Emit(ctx, domain.AuditKindRecoveryDisabled, w.Config.WorkspaceID, nil)
	return nil
}

// RecoveryStatus reports whether a recovery blob currently exists. Cheap —
// a single HEAD on the bucket.
func (w *Workspace) RecoveryStatus(ctx context.Context) (bool, error) {
	return w.Provider.Exists(ctx, domain.RecoveryKey)
}

// FetchRecoveryBlob downloads the bucket-side blob, if present. Returns
// recovery.ErrNoBlob if absent.
func FetchRecoveryBlob(ctx context.Context, provider storageProvider) (*recovery.Blob, error) {
	exists, err := provider.Exists(ctx, domain.RecoveryKey)
	if err != nil {
		return nil, fmt.Errorf("recovery: probe: %w", err)
	}
	if !exists {
		return nil, recovery.ErrNoBlob
	}
	body, err := provider.Get(ctx, domain.RecoveryKey)
	if err != nil {
		return nil, fmt.Errorf("recovery: fetch: %w", err)
	}
	var b recovery.Blob
	if err := json.Unmarshal(body, &b); err != nil {
		return nil, fmt.Errorf("recovery: parse blob: %w", err)
	}
	return &b, nil
}

// storageProvider is the narrow surface FetchRecoveryBlob needs from
// storage.Provider; keeping it tight avoids dragging the entire interface
// into recovery-flow consumers.
type storageProvider interface {
	Exists(ctx context.Context, key string) (bool, error)
	Get(ctx context.Context, key string) ([]byte, error)
}
