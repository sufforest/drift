package storage

import (
	"context"
	"testing"

	"github.com/sufforest/drift/internal/domain"
)

func TestProbeCapabilities_supported(t *testing.T) {
	ctx := context.Background()
	p := NewMemoryProvider()

	caps, err := ProbeCapabilities(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if !caps.ConditionalPut {
		t.Fatal("expected ConditionalPut=true for MemoryProvider")
	}
	// Probe should clean up after itself.
	if ok, _ := p.Exists(ctx, CapabilityProbeKey); ok {
		t.Fatal("probe left .capability-probe behind")
	}
	if caps.ConcurrencyLabel() != domain.ConcurrencyConditionalPut {
		t.Fatalf("unexpected label: %s", caps.ConcurrencyLabel())
	}
}

func TestProbeCapabilities_unsupported(t *testing.T) {
	ctx := context.Background()
	p := &NoConditionalProvider{Provider: NewMemoryProvider()}

	caps, err := ProbeCapabilities(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if caps.ConditionalPut {
		t.Fatal("expected ConditionalPut=false for NoConditionalProvider")
	}
	if caps.ConcurrencyLabel() != domain.ConcurrencyLockObject {
		t.Fatalf("unexpected label: %s", caps.ConcurrencyLabel())
	}
}

func TestSelectWriter(t *testing.T) {
	p := NewMemoryProvider()
	if _, ok := SelectWriter(p, Capabilities{ConditionalPut: true}, "").(*ConditionalPutWriter); !ok {
		t.Fatal("expected *ConditionalPutWriter for ConditionalPut=true")
	}
	if _, ok := SelectWriter(p, Capabilities{ConditionalPut: false}, "dev").(*LockObjectWriter); !ok {
		t.Fatal("expected *LockObjectWriter for ConditionalPut=false")
	}
}

func TestProbeCapabilities_priorCleanupSucceeds(t *testing.T) {
	ctx := context.Background()
	p := NewMemoryProvider()
	// Leave a leftover probe object from a "previous run".
	_ = p.Put(ctx, CapabilityProbeKey, []byte("leftover"))

	caps, err := ProbeCapabilities(ctx, p)
	if err != nil {
		t.Fatalf("probe should clean up leftovers and succeed: %v", err)
	}
	if !caps.ConditionalPut {
		t.Fatal("expected ConditionalPut=true")
	}
}
