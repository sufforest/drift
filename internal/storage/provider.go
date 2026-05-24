// Package storage abstracts the S3-compatible blob backend used for the
// workspace bucket. Higher layers (workspace, token, mount) talk to the
// Provider interface; this package contains both a real S3 implementation
// (aws-sdk-go-v2) and an in-memory fake for tests.
//
// Concurrency strategies build on top of the Provider via the
// ReadModifyWriter interface in concurrency.go.
package storage

import (
	"context"
)

// Provider is the minimal blob API Drift requires from any backend.
//
// Implementations should map provider-specific errors to the sentinels in
// internal/domain so callers can errors.Is them without inspecting strings:
//
//   - 404 / object missing       → domain.ErrObjectNotFound
//   - 412 PreconditionFailed     → domain.ErrPreconditionFailed
//   - 501 (B2 conditional)       → domain.ErrConditionalUnsupported
//   - network / 5xx              → domain.ErrProviderUnavailable
type Provider interface {
	Put(ctx context.Context, key string, data []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, prefix string) ([]string, error)
	Exists(ctx context.Context, key string) (bool, error)

	// GetWithETag returns the object body and its current ETag. ETag is an
	// opaque token whose only contract is: a later PutConditional with the
	// same string is guaranteed to succeed if and only if no other write
	// occurred in between.
	GetWithETag(ctx context.Context, key string) (data []byte, etag string, err error)

	// PutConditional writes data only if the current object's ETag matches
	// the provided one. Returns domain.ErrPreconditionFailed on mismatch.
	// Returns domain.ErrConditionalUnsupported if the provider does not
	// implement compare-and-swap (B2).
	PutConditional(ctx context.Context, key string, data []byte, etag string) (newETag string, err error)

	// PutIfNotExists creates the object only if it does not yet exist
	// (If-None-Match: *). Returns domain.ErrPreconditionFailed if present.
	// Returns domain.ErrConditionalUnsupported on B2.
	PutIfNotExists(ctx context.Context, key string, data []byte) (newETag string, err error)
}
