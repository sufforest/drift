package workspace

import (
	"context"
	"errors"
	"fmt"

	driftcreds "github.com/sufforest/drift/internal/credentials"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/storage"
)

// ParentSetOptions configures the parent-credential replacement.
type ParentSetOptions struct {
	// Provider is the storage provider id (e.g. "r2", "s3", "b2"). If
	// empty, the existing parent's provider is preserved. The bucket /
	// endpoint / region come from the local workspace config and are
	// never changed here — this command only swaps credentials.
	Provider string

	// AccessKeyID + SecretAccessKey are the new credentials.
	AccessKeyID     string
	SecretAccessKey string

	// SkipVerify disables the live HEAD probe against the bucket. The
	// default is to verify: we build an S3 provider with the new cred
	// and HEAD the workspace's manifest key. If the HEAD returns 403 or
	// any auth error, we refuse to overwrite the existing cred. This
	// prevents the user from losing access if they typo'd the new
	// secret.
	SkipVerify bool

	// ProviderFor is the factory used to build the verification
	// provider from the candidate cred. nil → BuildProviderFromParent
	// (the production path). Tests inject a stub that returns an in-
	// memory provider so the verify step doesn't require live network.
	ProviderFor func(ctx context.Context, bucket domain.BucketInfo, parent *driftcreds.Parent) (storage.Provider, error)
}

// ParentSetResult summarizes what changed.
type ParentSetResult struct {
	OldAccessKeyID string
	NewAccessKeyID string
	Provider       string
	Verified       bool
}

// ParentSet replaces this device's stored parent S3 credential. The
// credential lives in the device's local keychain — this is a per-device
// operation, NOT a workspace-wide setting.
//
// Master-only, by design: the parent cred is the most powerful credential
// drift holds (full bucket Object R/W in the typical setup). Restricting
// updates to the primary keeps the blast radius contained even when peer
// devices are paired in peer mode. A peer whose parent cred needs
// updating should `drift link --new-device` again on the primary with
// the rotated parent already in place.
//
// Flow:
//  1. Validate inputs.
//  2. Build a fresh S3 provider using the new cred against the existing
//     bucket info from local config.
//  3. HEAD the workspace's manifest key to confirm auth + path access.
//     Refuse to overwrite the existing cred if this fails (default;
//     skippable via SkipVerify for genuinely-offline rotation).
//  4. SaveParent to the local keychain.
//  5. Emit a parent.set audit entry so the workspace records the change.
func (w *Workspace) ParentSet(ctx context.Context, opts ParentSetOptions) (*ParentSetResult, error) {
	if w.Master == nil {
		return nil, errors.New("workspace: only the primary device can replace the parent credential")
	}
	if opts.AccessKeyID == "" {
		return nil, errors.New("workspace: ParentSet requires AccessKeyID")
	}
	if opts.SecretAccessKey == "" {
		return nil, errors.New("workspace: ParentSet requires SecretAccessKey")
	}

	existing, err := w.State.LoadParent()
	if err != nil {
		return nil, fmt.Errorf("load existing parent cred: %w", err)
	}
	provider := opts.Provider
	if provider == "" {
		provider = existing.Provider
	}

	result := &ParentSetResult{
		OldAccessKeyID: existing.AccessKeyID,
		NewAccessKeyID: opts.AccessKeyID,
		Provider:       provider,
	}

	updated := &driftcreds.Parent{
		Provider:        provider,
		AccessKeyID:     opts.AccessKeyID,
		SecretAccessKey: opts.SecretAccessKey,
	}

	// Verify the new credential actually works against this workspace's
	// bucket before persisting it. Without this, a typo in the secret
	// silently bricks the workspace: the device retains a saved cred
	// that R2 rejects, and the user can't `drift mount` or `drift grant`
	// until they manually fix it.
	if !opts.SkipVerify {
		providerFor := opts.ProviderFor
		if providerFor == nil {
			providerFor = func(ctx context.Context, b domain.BucketInfo, p *driftcreds.Parent) (storage.Provider, error) {
				return BuildProviderFromParent(ctx, b, p)
			}
		}
		probeProvider, err := providerFor(ctx, w.Config.Bucket, updated)
		if err != nil {
			return nil, fmt.Errorf("build verification provider: %w", err)
		}
		// HEAD the manifest. This requires (a) the cred to authenticate,
		// (b) the cred to have read access on the bucket. Both are
		// preconditions for the cred to be useful as a parent.
		//
		// Use Exists() rather than Get() so we don't waste bandwidth.
		// We don't care whether the manifest is present — only that the
		// auth round-trip succeeds.
		if _, err := probeProvider.Exists(ctx, domain.ManifestKey); err != nil {
			return nil, fmt.Errorf("parent verification failed (new cred cannot access bucket %s): %w — re-run with --skip-verify only if you're certain the cred is correct and the failure is transient", w.Config.Bucket.Name, err)
		}
		result.Verified = true
	}

	if err := w.State.SaveParent(updated); err != nil {
		return nil, fmt.Errorf("save parent: %w", err)
	}

	_ = w.auditEmitter().Emit(ctx, domain.AuditKindParentSet, w.Config.DeviceID, map[string]any{
		"old_access_key_id_prefix": prefix(existing.AccessKeyID, 6),
		"new_access_key_id_prefix": prefix(opts.AccessKeyID, 6),
		"provider":                 provider,
		"verified":                 result.Verified,
	})

	return result, nil
}

// prefix returns the first n runes of s. Used for audit-log fingerprints
// so we can correlate cred changes without storing full key IDs in
// plaintext audit entries.
func prefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
