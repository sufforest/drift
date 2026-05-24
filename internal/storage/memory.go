package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"

	"github.com/sufforest/drift/internal/domain"
)

// MemoryProvider is an in-memory Provider used by tests and as a reference
// implementation. ETags are content-addressed (SHA-256 prefix) which matches
// S3's behavior for non-multipart PUTs: identical content yields identical
// ETags, distinct content yields distinct ETags.
//
// It supports all conditional operations (no B2 simulation). For B2-like
// tests, wrap it with NoConditionalProvider below.
type MemoryProvider struct {
	mu      sync.RWMutex
	objects map[string]memObject
}

type memObject struct {
	data []byte
	etag string
}

// NewMemoryProvider returns an empty in-memory Provider.
func NewMemoryProvider() *MemoryProvider {
	return &MemoryProvider{objects: make(map[string]memObject)}
}

func etagOf(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:16])
}

func (m *MemoryProvider) Put(_ context.Context, key string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[key] = memObject{data: append([]byte(nil), data...), etag: etagOf(data)}
	return nil
}

func (m *MemoryProvider) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	obj, ok := m.objects[key]
	if !ok {
		return nil, domain.ErrObjectNotFound
	}
	return append([]byte(nil), obj.data...), nil
}

func (m *MemoryProvider) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.objects[key]; !ok {
		return domain.ErrObjectNotFound
	}
	delete(m.objects, key)
	return nil
}

func (m *MemoryProvider) List(_ context.Context, prefix string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0)
	for k := range m.objects {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out, nil
}

func (m *MemoryProvider) Exists(_ context.Context, key string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.objects[key]
	return ok, nil
}

func (m *MemoryProvider) GetWithETag(_ context.Context, key string) ([]byte, string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	obj, ok := m.objects[key]
	if !ok {
		return nil, "", domain.ErrObjectNotFound
	}
	return append([]byte(nil), obj.data...), obj.etag, nil
}

func (m *MemoryProvider) PutConditional(_ context.Context, key string, data []byte, etag string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.objects[key]
	// If-Match with no current object → precondition fails (S3 semantics).
	if !ok || cur.etag != etag {
		return "", domain.ErrPreconditionFailed
	}
	newETag := etagOf(data)
	m.objects[key] = memObject{data: append([]byte(nil), data...), etag: newETag}
	return newETag, nil
}

func (m *MemoryProvider) PutIfNotExists(_ context.Context, key string, data []byte) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.objects[key]; exists {
		return "", domain.ErrPreconditionFailed
	}
	newETag := etagOf(data)
	m.objects[key] = memObject{data: append([]byte(nil), data...), etag: newETag}
	return newETag, nil
}

// NoConditionalProvider wraps a Provider and rejects all conditional
// operations with domain.ErrConditionalUnsupported. Use it to simulate
// B2-style backends in tests of the capability probe and lock-object
// fallback.
type NoConditionalProvider struct{ Provider }

func (n *NoConditionalProvider) PutConditional(_ context.Context, _ string, _ []byte, _ string) (string, error) {
	return "", domain.ErrConditionalUnsupported
}

func (n *NoConditionalProvider) PutIfNotExists(_ context.Context, _ string, _ []byte) (string, error) {
	return "", domain.ErrConditionalUnsupported
}
