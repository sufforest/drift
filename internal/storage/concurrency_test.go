package storage

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sufforest/drift/internal/domain"
)

// --- ConditionalPutWriter ---

func TestConditionalPutWriter_coldStart(t *testing.T) {
	ctx := context.Background()
	p := NewMemoryProvider()
	w := NewConditionalPutWriter(p)

	called := false
	err := w.ReadModifyWrite(ctx, "k", func(cur []byte) ([]byte, error) {
		called = true
		if cur != nil {
			t.Fatalf("expected cur=nil on cold start, got %q", cur)
		}
		return []byte("first"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("mutator was not called")
	}
	got, _ := p.Get(ctx, "k")
	if string(got) != "first" {
		t.Fatalf("stored %q, want %q", got, "first")
	}
}

func TestConditionalPutWriter_update(t *testing.T) {
	ctx := context.Background()
	p := NewMemoryProvider()
	w := NewConditionalPutWriter(p)
	_ = p.Put(ctx, "k", []byte("v1"))

	err := w.ReadModifyWrite(ctx, "k", func(cur []byte) ([]byte, error) {
		return append(cur, []byte("+update")...), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := p.Get(ctx, "k")
	if string(got) != "v1+update" {
		t.Fatalf("got %q", got)
	}
}

func TestConditionalPutWriter_mutatorError(t *testing.T) {
	ctx := context.Background()
	w := NewConditionalPutWriter(NewMemoryProvider())
	sentinel := errors.New("boom")
	err := w.ReadModifyWrite(ctx, "k", func(_ []byte) ([]byte, error) { return nil, sentinel })
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel, got %v", err)
	}
}

func TestConditionalPutWriter_retryOnConflict(t *testing.T) {
	ctx := context.Background()
	p := NewMemoryProvider()
	_ = p.Put(ctx, "k", []byte("v1"))
	w := NewConditionalPutWriter(p)

	var calls int32
	err := w.ReadModifyWrite(ctx, "k", func(cur []byte) ([]byte, error) {
		n := atomic.AddInt32(&calls, 1)
		// On the first call, simulate a concurrent writer that overwrote
		// the object after we read.
		if n == 1 {
			_ = p.Put(ctx, "k", []byte("racer"))
		}
		return []byte(string(cur) + "-applied"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls < 2 {
		t.Fatalf("expected at least one retry, mutator called %d times", calls)
	}
	got, _ := p.Get(ctx, "k")
	if string(got) != "racer-applied" {
		t.Fatalf("got %q", got)
	}
}

func TestConditionalPutWriter_giveUpAfterMaxRetries(t *testing.T) {
	ctx := context.Background()
	p := NewMemoryProvider()
	_ = p.Put(ctx, "k", []byte("v0"))
	w := NewConditionalPutWriter(p)
	w.MaxRetries = 2

	var raceN int32
	err := w.ReadModifyWrite(ctx, "k", func(_ []byte) ([]byte, error) {
		// Mutator always races, and writes distinct content each time so
		// the ETag changes between our read and our PutConditional.
		n := atomic.AddInt32(&raceN, 1)
		_ = p.Put(ctx, "k", []byte("racer-" + string(rune('0'+n))))
		return []byte("loser"), nil
	})
	if !errors.Is(err, domain.ErrManifestConflict) {
		t.Fatalf("expected ErrManifestConflict, got %v", err)
	}
}

// --- LockObjectWriter ---

func TestLockObjectWriter_basicRMW(t *testing.T) {
	ctx := context.Background()
	p := NewMemoryProvider()
	w := NewLockObjectWriter(p, "dev-1")
	w.AcquireDelay = 0

	err := w.ReadModifyWrite(ctx, "k", func(cur []byte) ([]byte, error) {
		if cur != nil {
			t.Fatal("expected nil on cold start")
		}
		return []byte("hello"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := p.Get(ctx, "k")
	if string(got) != "hello" {
		t.Fatalf("got %q", got)
	}
	// Lock should have been cleaned up.
	if ok, _ := p.Exists(ctx, "k.lock"); ok {
		t.Fatal("lock object still present after RMW")
	}
}

func TestLockObjectWriter_b2Fallback(t *testing.T) {
	ctx := context.Background()
	// B2-like: no conditional support.
	p := &NoConditionalProvider{Provider: NewMemoryProvider()}
	w := NewLockObjectWriter(p, "dev-1")
	w.AcquireDelay = 0

	err := w.ReadModifyWrite(ctx, "k", func(_ []byte) ([]byte, error) { return []byte("ok"), nil })
	if err != nil {
		t.Fatalf("ReadModifyWrite on B2-style: %v", err)
	}
	got, _ := p.Get(ctx, "k")
	if string(got) != "ok" {
		t.Fatalf("got %q", got)
	}
}

func TestLockObjectWriter_blocksOnFreshLock(t *testing.T) {
	ctx := context.Background()
	p := NewMemoryProvider()
	// Pre-place a fresh lock from a different device.
	now := time.Now()
	body, _ := json.Marshal(lockBody{
		DeviceID:  "other",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Minute),
		Nonce:     "x",
	})
	_ = p.Put(ctx, "k.lock", body)

	w := NewLockObjectWriter(p, "dev-1")
	w.AcquireDelay = 1 * time.Millisecond
	w.MaxAttempts = 3

	err := w.ReadModifyWrite(ctx, "k", func(_ []byte) ([]byte, error) { return []byte("never"), nil })
	if !errors.Is(err, domain.ErrLockHeld) {
		t.Fatalf("expected ErrLockHeld, got %v", err)
	}
	got, _ := p.Get(ctx, "k")
	if got != nil {
		t.Fatalf("k should not have been written, got %q", got)
	}
}

func TestLockObjectWriter_breaksStaleLock(t *testing.T) {
	ctx := context.Background()
	p := NewMemoryProvider()
	// Pre-place an expired lock.
	now := time.Now().Add(-1 * time.Hour)
	body, _ := json.Marshal(lockBody{
		DeviceID:  "ghost",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Minute),
		Nonce:     "x",
	})
	_ = p.Put(ctx, "k.lock", body)

	w := NewLockObjectWriter(p, "dev-1")
	w.AcquireDelay = 0

	err := w.ReadModifyWrite(ctx, "k", func(_ []byte) ([]byte, error) { return []byte("ok"), nil })
	if err != nil {
		t.Fatalf("expected stale lock to be broken, got %v", err)
	}
	got, _ := p.Get(ctx, "k")
	if string(got) != "ok" {
		t.Fatalf("got %q", got)
	}
}

func TestLockObjectWriter_serializesConcurrentWriters(t *testing.T) {
	ctx := context.Background()
	p := NewMemoryProvider()
	const N = 8
	var wg sync.WaitGroup

	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			w := NewLockObjectWriter(p, "dev-"+string(rune('A'+id)))
			w.AcquireDelay = 1 * time.Millisecond
			w.MaxAttempts = 200
			_ = w.ReadModifyWrite(ctx, "counter", func(cur []byte) ([]byte, error) {
				// Treat body as int written via fmt; here we just append.
				return append(cur, byte('a'+id)), nil
			})
		}(i)
	}
	wg.Wait()

	got, _ := p.Get(ctx, "counter")
	if len(got) != N {
		t.Fatalf("expected %d bytes after %d serialized writers, got %d (%q)", N, N, len(got), got)
	}
}

func TestLockObjectWriter_requiresDeviceID(t *testing.T) {
	w := NewLockObjectWriter(NewMemoryProvider(), "")
	err := w.ReadModifyWrite(context.Background(), "k", func(_ []byte) ([]byte, error) { return nil, nil })
	if err == nil {
		t.Fatal("expected error on empty DeviceID")
	}
}
