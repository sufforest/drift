package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/sufforest/drift/internal/domain"
)

// CapabilityProbeKey is the object Drift uses to test conditional-write
// support. It lives under .drift/ so a misconfigured bucket policy reveals
// itself early.
const CapabilityProbeKey = ".drift/.capability-probe"

// Capabilities is the result of ProbeCapabilities.
type Capabilities struct {
	// ConditionalPut is true iff the provider supports both If-Match and
	// If-None-Match with correct semantics (412 on mismatch, success
	// otherwise). Determines which ReadModifyWriter the workspace selects.
	ConditionalPut bool
}

// ProbeCapabilities runs a small, idempotent test against the backend to
// decide which concurrency strategy to use. The probe leaves no objects
// behind on success.
//
// The probe is intentionally cheap (~3 API calls) so it can run on every
// `drift open`, which lets workspaces transparently pick up provider feature
// upgrades / regressions over time.
func ProbeCapabilities(ctx context.Context, p Provider) (Capabilities, error) {
	// 1. Create-if-not-exists. Clean up any leftover from a prior crashed
	//    probe first, so the create path is always exercised.
	_ = p.Delete(ctx, CapabilityProbeKey) // ignore ErrObjectNotFound
	etag, err := p.PutIfNotExists(ctx, CapabilityProbeKey, []byte("probe-v1"))
	if errors.Is(err, domain.ErrConditionalUnsupported) {
		return Capabilities{ConditionalPut: false}, nil
	}
	if err != nil {
		return Capabilities{}, fmt.Errorf("probe create: %w", err)
	}

	// 2. Conditional update with the correct ETag must succeed.
	newETag, err := p.PutConditional(ctx, CapabilityProbeKey, []byte("probe-v2"), etag)
	if errors.Is(err, domain.ErrConditionalUnsupported) {
		_ = p.Delete(ctx, CapabilityProbeKey)
		return Capabilities{ConditionalPut: false}, nil
	}
	if err != nil {
		return Capabilities{}, fmt.Errorf("probe update: %w", err)
	}

	// 3. Conditional update with the stale ETag must fail with 412.
	if _, err := p.PutConditional(ctx, CapabilityProbeKey, []byte("probe-v3"), etag); err == nil {
		_ = p.Delete(ctx, CapabilityProbeKey)
		return Capabilities{}, fmt.Errorf("provider accepted stale If-Match; refusing to trust conditional PUT")
	} else if !errors.Is(err, domain.ErrPreconditionFailed) {
		// Unexpected error; treat as no conditional support, but bubble it.
		_ = p.Delete(ctx, CapabilityProbeKey)
		return Capabilities{}, fmt.Errorf("probe stale-update: %w", err)
	}

	// Cleanup. The current ETag is newETag; use it to confirm DELETE works.
	_ = newETag
	if err := p.Delete(ctx, CapabilityProbeKey); err != nil {
		return Capabilities{}, fmt.Errorf("probe cleanup: %w", err)
	}
	return Capabilities{ConditionalPut: true}, nil
}

// SelectWriter returns the appropriate ReadModifyWriter for caps. deviceID
// is required for the lock-object writer; pass an empty string when caps
// guarantee ConditionalPut and the lock writer will never be used.
//
// The lock-object branch is unsigned by default. Callers that hold a
// device signing key + verifier should use SelectWriterWithLockAuth so a
// bucket admin cannot DoS the workspace by planting a fresh-looking lock.
func SelectWriter(p Provider, caps Capabilities, deviceID string) ReadModifyWriter {
	return SelectWriterWithLockAuth(p, caps, deviceID, nil, nil)
}

// SelectWriterWithLockAuth is SelectWriter with explicit lock signer +
// verifier wired in. Use it from any code path that has the device signing
// key handy (workspace.Init / Load, cli bootstrap).
func SelectWriterWithLockAuth(p Provider, caps Capabilities, deviceID string, signer LockSigner, verifier LockVerifier) ReadModifyWriter {
	if caps.ConditionalPut {
		return NewConditionalPutWriter(p)
	}
	w := NewLockObjectWriter(p, deviceID)
	w.LockSigner = signer
	w.MatchingVerifier = verifier
	return w
}

// ConcurrencyLabel maps Capabilities to the string recorded in
// Manifest.Concurrency.
func (c Capabilities) ConcurrencyLabel() string {
	if c.ConditionalPut {
		return domain.ConcurrencyConditionalPut
	}
	return domain.ConcurrencyLockObject
}
