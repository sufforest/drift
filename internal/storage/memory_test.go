package storage

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/sufforest/drift/internal/domain"
)

func TestMemoryProvider_PutGetExistsDelete(t *testing.T) {
	ctx := context.Background()
	p := NewMemoryProvider()

	if ok, err := p.Exists(ctx, "k"); err != nil || ok {
		t.Fatalf("Exists on empty: ok=%v err=%v", ok, err)
	}

	if err := p.Put(ctx, "k", []byte("v1")); err != nil {
		t.Fatal(err)
	}

	got, err := p.Get(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("v1")) {
		t.Fatalf("Get returned %q, want %q", got, "v1")
	}

	if ok, _ := p.Exists(ctx, "k"); !ok {
		t.Fatal("Exists should be true after Put")
	}

	if err := p.Delete(ctx, "k"); err != nil {
		t.Fatal(err)
	}

	_, err = p.Get(ctx, "k")
	if !errors.Is(err, domain.ErrObjectNotFound) {
		t.Fatalf("Get after Delete: want ErrObjectNotFound, got %v", err)
	}

	if err := p.Delete(ctx, "k"); !errors.Is(err, domain.ErrObjectNotFound) {
		t.Fatalf("Delete of missing: want ErrObjectNotFound, got %v", err)
	}
}

func TestMemoryProvider_List(t *testing.T) {
	ctx := context.Background()
	p := NewMemoryProvider()
	_ = p.Put(ctx, ".drift/manifest.enc", []byte("m"))
	_ = p.Put(ctx, ".drift/revocations.enc", []byte("r"))
	_ = p.Put(ctx, "compartments/foo/data", []byte("d"))

	keys, err := p.List(ctx, ".drift/")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d (%v)", len(keys), keys)
	}
}

func TestMemoryProvider_Conditional(t *testing.T) {
	ctx := context.Background()
	p := NewMemoryProvider()

	// PutIfNotExists on empty → succeeds.
	etag, err := p.PutIfNotExists(ctx, "k", []byte("v1"))
	if err != nil {
		t.Fatal(err)
	}
	if etag == "" {
		t.Fatal("expected non-empty ETag")
	}

	// PutIfNotExists when present → ErrPreconditionFailed.
	_, err = p.PutIfNotExists(ctx, "k", []byte("v2"))
	if !errors.Is(err, domain.ErrPreconditionFailed) {
		t.Fatalf("expected ErrPreconditionFailed, got %v", err)
	}

	// GetWithETag returns the ETag from PutIfNotExists.
	_, gotETag, err := p.GetWithETag(ctx, "k")
	if err != nil {
		t.Fatal(err)
	}
	if gotETag != etag {
		t.Fatalf("etag mismatch: %q vs %q", gotETag, etag)
	}

	// PutConditional with correct ETag → succeeds.
	newETag, err := p.PutConditional(ctx, "k", []byte("v2"), etag)
	if err != nil {
		t.Fatal(err)
	}
	if newETag == etag {
		t.Fatal("etag should change on update of distinct content")
	}

	// PutConditional with stale ETag → fails.
	_, err = p.PutConditional(ctx, "k", []byte("v3"), etag)
	if !errors.Is(err, domain.ErrPreconditionFailed) {
		t.Fatalf("expected ErrPreconditionFailed on stale ETag, got %v", err)
	}

	// PutConditional on missing → fails.
	_, err = p.PutConditional(ctx, "missing", []byte("v"), "any")
	if !errors.Is(err, domain.ErrPreconditionFailed) {
		t.Fatalf("expected ErrPreconditionFailed on missing, got %v", err)
	}
}

func TestNoConditionalProvider(t *testing.T) {
	ctx := context.Background()
	p := &NoConditionalProvider{Provider: NewMemoryProvider()}

	if _, err := p.PutIfNotExists(ctx, "k", []byte("v")); !errors.Is(err, domain.ErrConditionalUnsupported) {
		t.Fatalf("expected ErrConditionalUnsupported, got %v", err)
	}
	if _, err := p.PutConditional(ctx, "k", []byte("v"), "etag"); !errors.Is(err, domain.ErrConditionalUnsupported) {
		t.Fatalf("expected ErrConditionalUnsupported, got %v", err)
	}
	// Unconditional ops still work via the embedded Provider.
	if err := p.Put(ctx, "k", []byte("v")); err != nil {
		t.Fatal(err)
	}
}
