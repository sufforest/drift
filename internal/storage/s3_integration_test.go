//go:build integration

// Integration tests for storage.S3Provider against a real MinIO instance.
//
// Run with:
//
//	docker compose -f test/docker-compose.yaml up -d
//	go test -tags=integration -count=1 ./internal/storage/...
//	docker compose -f test/docker-compose.yaml down -v
//
// Or use `make test-integration` which wraps all three steps.
package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/sufforest/drift/internal/domain"
)

const (
	minioEndpoint  = "http://127.0.0.1:9000"
	minioAccessKey = "drift-test"
	minioSecretKey = "drift-test-secret"
	minioBucket    = "drift-test"
)

// newMinIOProvider wires an S3Provider at the MinIO bucket and clears any
// objects from a previous test run under the per-test prefix.
func newMinIOProvider(t *testing.T) *S3Provider {
	t.Helper()
	ctx := context.Background()

	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(awscreds.NewStaticCredentialsProvider(minioAccessKey, minioSecretKey, "")),
	)
	if err != nil {
		t.Fatalf("aws config: %v", err)
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(minioEndpoint)
		o.UsePathStyle = true
	})
	p := NewS3Provider(client, minioBucket)

	// Per-test prefix so parallel tests don't collide.
	prefix := testPrefix(t)
	t.Cleanup(func() {
		keys, err := p.List(context.Background(), prefix)
		if err != nil {
			return
		}
		for _, k := range keys {
			_ = p.Delete(context.Background(), k)
		}
	})
	return p
}

// testPrefix returns a per-test key prefix, isolating concurrent runs.
func testPrefix(t *testing.T) string {
	name := strings.ReplaceAll(t.Name(), "/", "_")
	return fmt.Sprintf("integration/%s/", name)
}

// keyIn returns prefix + suffix; reduces boilerplate.
func keyIn(prefix, suffix string) string { return prefix + suffix }

// --- basic CRUD ---

func TestIntegration_S3_CRUD(t *testing.T) {
	ctx := context.Background()
	p := newMinIOProvider(t)
	prefix := testPrefix(t)
	k := keyIn(prefix, "hello.txt")

	if err := p.Put(ctx, k, []byte("hello drift")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := p.Get(ctx, k)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, []byte("hello drift")) {
		t.Fatalf("Get body mismatch: %q", got)
	}
	exists, err := p.Exists(ctx, k)
	if err != nil || !exists {
		t.Fatalf("Exists = (%v, %v)", exists, err)
	}
	if err := p.Delete(ctx, k); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := p.Get(ctx, k); !errors.Is(err, domain.ErrObjectNotFound) {
		t.Fatalf("Get after Delete: want ErrObjectNotFound, got %v", err)
	}
	if err := p.Delete(ctx, k); !errors.Is(err, domain.ErrObjectNotFound) {
		t.Fatalf("Delete of missing: want ErrObjectNotFound, got %v", err)
	}
}

func TestIntegration_S3_ListPrefix(t *testing.T) {
	ctx := context.Background()
	p := newMinIOProvider(t)
	prefix := testPrefix(t)

	for _, k := range []string{"a", "b", "sub/c"} {
		if err := p.Put(ctx, prefix+k, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := p.List(ctx, prefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d (%v)", len(keys), keys)
	}
}

// --- conditional PUT (MinIO supports If-Match / If-None-Match) ---

func TestIntegration_S3_PutIfNotExists(t *testing.T) {
	ctx := context.Background()
	p := newMinIOProvider(t)
	k := keyIn(testPrefix(t), "create-once")

	etag, err := p.PutIfNotExists(ctx, k, []byte("first"))
	if err != nil {
		t.Fatalf("first PutIfNotExists: %v", err)
	}
	if etag == "" {
		t.Fatal("expected non-empty etag")
	}

	if _, err := p.PutIfNotExists(ctx, k, []byte("second")); !errors.Is(err, domain.ErrPreconditionFailed) {
		t.Fatalf("second PutIfNotExists should be ErrPreconditionFailed, got %v", err)
	}
}

func TestIntegration_S3_PutConditional(t *testing.T) {
	ctx := context.Background()
	p := newMinIOProvider(t)
	k := keyIn(testPrefix(t), "cas")

	etag, err := p.PutIfNotExists(ctx, k, []byte("v1"))
	if err != nil {
		t.Fatal(err)
	}

	// Stale etag → 412.
	if _, err := p.PutConditional(ctx, k, []byte("v2"), "stale-etag-deadbeef"); !errors.Is(err, domain.ErrPreconditionFailed) {
		t.Fatalf("stale If-Match: want ErrPreconditionFailed, got %v", err)
	}
	// Correct etag → succeeds; returns the new etag.
	newETag, err := p.PutConditional(ctx, k, []byte("v2"), etag)
	if err != nil {
		t.Fatalf("conditional update: %v", err)
	}
	if newETag == "" || newETag == etag {
		t.Fatalf("new etag = %q, prev etag = %q", newETag, etag)
	}

	body, _, err := p.GetWithETag(ctx, k)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, []byte("v2")) {
		t.Fatalf("Get returned %q, want v2", body)
	}
}

// --- capability probe ---

func TestIntegration_ProbeCapabilities_minioSupportsConditional(t *testing.T) {
	ctx := context.Background()
	p := newMinIOProvider(t)

	caps, err := ProbeCapabilities(ctx, p)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if !caps.ConditionalPut {
		t.Fatal("MinIO should support conditional PUT (recent releases)")
	}
	// Probe should clean up after itself.
	if ok, _ := p.Exists(ctx, CapabilityProbeKey); ok {
		t.Fatal("probe left .capability-probe behind")
	}
}

// --- concurrent writers via ConditionalPutWriter ---

func TestIntegration_ConditionalPutWriter_serializesRacers(t *testing.T) {
	ctx := context.Background()
	p := newMinIOProvider(t)
	k := keyIn(testPrefix(t), "counter")

	const N = 6
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := NewConditionalPutWriter(p)
			w.MaxRetries = 100 // be generous; MinIO RTT is real
			_ = w.ReadModifyWrite(ctx, k, func(cur []byte) ([]byte, error) {
				return append(cur, '.'), nil
			})
		}()
	}
	wg.Wait()

	body, err := p.Get(ctx, k)
	if err != nil {
		t.Fatalf("Get final: %v", err)
	}
	if len(body) != N {
		t.Fatalf("expected %d serialized writes, got %d (%q)", N, len(body), body)
	}
}

// --- lock-object writer also works against a real provider ---
// (Even though MinIO supports conditional PUT, the lock-object path must
// remain functional for B2 deploys.)
//
// We can't *force* MinIO to behave like B2, so we test the writer's normal
// path: acquire lock → mutate → release. The actual B2-fallback branch is
// unit-tested with NoConditionalProvider.

func TestIntegration_LockObjectWriter_basic(t *testing.T) {
	ctx := context.Background()
	p := newMinIOProvider(t)
	k := keyIn(testPrefix(t), "locked")

	w := NewLockObjectWriter(p, "test-device")
	w.AcquireDelay = 50 * time.Millisecond
	w.MaxAttempts = 5

	err := w.ReadModifyWrite(ctx, k, func(cur []byte) ([]byte, error) {
		if cur != nil {
			t.Fatal("expected nil on cold start")
		}
		return []byte("locked-write"), nil
	})
	if err != nil {
		t.Fatalf("ReadModifyWrite: %v", err)
	}
	got, _ := p.Get(ctx, k)
	if string(got) != "locked-write" {
		t.Fatalf("got %q", got)
	}
	// Lock should have been deleted.
	if ok, _ := p.Exists(ctx, k+".lock"); ok {
		t.Fatal("lock object left behind")
	}
}
