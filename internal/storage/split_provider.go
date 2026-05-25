package storage

import (
	"context"
	"strings"

	"github.com/sufforest/drift/internal/domain"
)

// SplitProvider routes Provider calls to one of two backing providers
// based on the bucket key. It implements DD-10's split-credential
// pattern: a bearer peer holds two scoped credentials (a RW Data cred
// for compartment data + an RO Control cred for the workspace control
// plane), and SplitProvider routes each Get/Put/etc. to the cred that
// has the right permissions.
//
// When Control is nil (the AWS-STS / R2-server-mint future, where one
// cred can carry per-path scope policy), every operation routes to
// Data — there's no second cred to use.
//
// Routing rule (isControlKey): manifest.enc, revocations.enc, and
// anything under .drift/peers/ go to Control. Everything else
// (compartment data + future paths) goes to Data.
//
// Important consequence: drift code that tries to PUT a control-plane
// key from a bearer peer hits Control, which is RO at the R2 layer,
// which returns 403. That's defense-in-depth — even if drift's own
// logic accidentally tried to write the manifest from a bearer (it
// doesn't, but bugs happen), R2 enforces the boundary.
type SplitProvider struct {
	Data    Provider
	Control Provider // may be nil; then Data handles everything
}

// NewSplitProvider returns a SplitProvider. control may be nil.
func NewSplitProvider(data, control Provider) *SplitProvider {
	return &SplitProvider{Data: data, Control: control}
}

// isControlKey returns true if the given bucket key should be served
// by the Control cred. Update DD-10 §5 if this list changes.
func (s *SplitProvider) isControlKey(key string) bool {
	if s.Control == nil {
		return false
	}
	if key == domain.ManifestKey || key == domain.RevocationsKey {
		return true
	}
	if strings.HasPrefix(key, domain.PeersDir) {
		return true
	}
	return false
}

// route returns the appropriate Provider for the given key.
func (s *SplitProvider) route(key string) Provider {
	if s.isControlKey(key) {
		return s.Control
	}
	return s.Data
}

func (s *SplitProvider) Put(ctx context.Context, key string, data []byte) error {
	return s.route(key).Put(ctx, key, data)
}

func (s *SplitProvider) Get(ctx context.Context, key string) ([]byte, error) {
	return s.route(key).Get(ctx, key)
}

func (s *SplitProvider) Delete(ctx context.Context, key string) error {
	return s.route(key).Delete(ctx, key)
}

func (s *SplitProvider) Exists(ctx context.Context, key string) (bool, error) {
	return s.route(key).Exists(ctx, key)
}

// List routes by prefix the same way single-key operations route by
// key. This keeps behavior consistent for any control-plane list use
// case (for example listing under .drift/peers/) while preserving the
// existing compartment-data behavior on Data.
func (s *SplitProvider) List(ctx context.Context, prefix string) ([]string, error) {
	return s.route(prefix).List(ctx, prefix)
}

func (s *SplitProvider) GetWithETag(ctx context.Context, key string) ([]byte, string, error) {
	return s.route(key).GetWithETag(ctx, key)
}

func (s *SplitProvider) PutConditional(ctx context.Context, key string, data []byte, etag string) (string, error) {
	return s.route(key).PutConditional(ctx, key, data, etag)
}

func (s *SplitProvider) PutIfNotExists(ctx context.Context, key string, data []byte) (string, error) {
	return s.route(key).PutIfNotExists(ctx, key, data)
}
