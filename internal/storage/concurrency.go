package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sufforest/drift/internal/domain"
)

// Mutator transforms the current object body into the next one. `current` is
// nil if the object did not exist (cold-start path). Returning the same bytes
// is fine; the writer always issues a PUT.
type Mutator func(current []byte) (next []byte, err error)

// ReadModifyWriter serializes mutations to a single object so concurrent
// writers do not overwrite each other. Two implementations are provided:
// ConditionalPutWriter (R2/AWS/MinIO/Wasabi) and LockObjectWriter (B2 and
// any provider that fails capability probing).
type ReadModifyWriter interface {
	ReadModifyWrite(ctx context.Context, key string, mutate Mutator) error
}

// ConditionalPutWriter implements RMW via S3 If-Match. It retries up to
// MaxRetries times on precondition failure (default 3). On the first call
// when the object does not exist, it uses PutIfNotExists (If-None-Match: *).
type ConditionalPutWriter struct {
	Provider   Provider
	MaxRetries int
}

// NewConditionalPutWriter constructs the writer with sensible defaults.
func NewConditionalPutWriter(p Provider) *ConditionalPutWriter {
	return &ConditionalPutWriter{Provider: p, MaxRetries: 3}
}

func (w *ConditionalPutWriter) ReadModifyWrite(ctx context.Context, key string, mutate Mutator) error {
	maxAttempts := w.MaxRetries
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		cur, etag, err := w.Provider.GetWithETag(ctx, key)
		switch {
		case errors.Is(err, domain.ErrObjectNotFound):
			// Cold start: create with If-None-Match: *.
			next, mErr := mutate(nil)
			if mErr != nil {
				return mErr
			}
			if _, err := w.Provider.PutIfNotExists(ctx, key, next); err == nil {
				return nil
			} else if errors.Is(err, domain.ErrPreconditionFailed) {
				lastErr = err
				continue // raced with another creator; retry from GET
			} else {
				return fmt.Errorf("create %s: %w", key, err)
			}
		case err != nil:
			return fmt.Errorf("read %s: %w", key, err)
		default:
			next, mErr := mutate(cur)
			if mErr != nil {
				return mErr
			}
			if _, err := w.Provider.PutConditional(ctx, key, next, etag); err == nil {
				return nil
			} else if errors.Is(err, domain.ErrPreconditionFailed) {
				lastErr = err
				continue // raced; retry from GET
			} else {
				return fmt.Errorf("write %s: %w", key, err)
			}
		}
	}
	return fmt.Errorf("%w: gave up after %d attempts: %v", domain.ErrManifestConflict, maxAttempts, lastErr)
}

// LockObjectWriter is the universal fallback when the backend does not
// support conditional writes (B2). It writes a small lock object before
// reading + writing the target, then deletes the lock when done. Locks
// carry a TTL so a crashed writer does not block updates forever.
//
// LockSigner, if set, signs each lock body with an Ed25519 key. A
// MatchingVerifier on the same writer rejects lock collisions whose body
// fails to verify. Without lock signing, a bucket admin can DoS the
// workspace by writing a fresh-looking lock that nobody can dislodge
// until TTL expiry.
type LockObjectWriter struct {
	Provider     Provider
	DeviceID     string
	LockTTL      time.Duration // how long a lock is considered fresh
	AcquireDelay time.Duration // sleep between lock-acquire retries
	MaxAttempts  int           // total lock-acquire attempts
	Now          func() time.Time

	// LockSigner signs the JSON body of locks this writer issues.
	// MatchingVerifier authenticates locks held by OTHER writers when we
	// observe a collision. Both are optional — if either is nil locks
	// are unsigned and any fresh-TTL lock is respected, which leaves the
	// workspace open to a bucket-admin DoS.
	LockSigner       LockSigner
	MatchingVerifier LockVerifier
}

// LockSigner produces an Ed25519 signature over the bytes the lock writer
// commits to disk. Callers in workspace pass their device key.
type LockSigner func(body []byte) (signature []byte, err error)

// LockVerifier verifies a lock signature using deviceID to look up the
// signing key. Returning a non-nil error rejects the lock as unauthorized
// (the writer treats it as stale).
type LockVerifier func(deviceID string, body, signature []byte) error

// NewLockObjectWriter constructs the writer with conservative defaults:
// 30s lock TTL, 10 acquire attempts at 1s intervals.
func NewLockObjectWriter(p Provider, deviceID string) *LockObjectWriter {
	return &LockObjectWriter{
		Provider:     p,
		DeviceID:     deviceID,
		LockTTL:      30 * time.Second,
		AcquireDelay: 1 * time.Second,
		MaxAttempts:  10,
		Now:          time.Now,
	}
}

// lockBody is the JSON payload of a lock object. Signature is the Ed25519
// signature over a canonical byte form of the other fields (see
// lockSigningBytes), produced by LockSigner.
type lockBody struct {
	DeviceID  string    `json:"device_id"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Nonce     string    `json:"nonce"`
	Signature []byte    `json:"sig,omitempty"`
}

// lockSigningBytes is the canonical byte form signed by LockSigner. Plain
// text rather than JSON so a future marshaller change does not invalidate
// existing signatures.
func lockSigningBytes(b lockBody) []byte {
	return []byte(fmt.Sprintf("drift/v1/lock|%s|%d|%d|%s",
		b.DeviceID, b.IssuedAt.UnixNano(), b.ExpiresAt.UnixNano(), b.Nonce))
}

func lockKey(targetKey string) string { return targetKey + ".lock" }

func (w *LockObjectWriter) ReadModifyWrite(ctx context.Context, key string, mutate Mutator) error {
	if w.DeviceID == "" {
		return errors.New("storage: LockObjectWriter requires a non-empty DeviceID")
	}
	lk := lockKey(key)
	ourNonce, err := w.acquireLock(ctx, lk)
	if err != nil {
		return err
	}
	defer func() {
		// Best-effort cleanup. If this fails the lock TTL still bounds the
		// next writer's wait. We don't surface the error to keep the user
		// path clean — the next writer will detect the stale lock.
		_ = w.Provider.Delete(ctx, lk)
	}()

	cur, err := w.Provider.Get(ctx, key)
	if err != nil && !errors.Is(err, domain.ErrObjectNotFound) {
		return fmt.Errorf("read %s: %w", key, err)
	}
	next, err := mutate(cur) // cur is nil if not found, which is the cold-start signal
	if err != nil {
		return err
	}
	// Re-confirm we still hold the lock right before the write. If the
	// lock's TTL elapsed mid-mutation (slow JSON, paused process),
	// another writer may have legitimately taken over — clobbering
	// their write would be silent corruption.
	if err := w.verifyOwnership(ctx, lk, ourNonce); err != nil {
		return fmt.Errorf("lost lock during mutate: %w", err)
	}
	if err := w.Provider.Put(ctx, key, next); err != nil {
		return fmt.Errorf("write %s: %w", key, err)
	}
	return nil
}

// verifyOwnership reads the current lock object and confirms its nonce
// still matches ours. Returns ErrLockHeld if someone else (or stale lock
// cleanup) replaced it.
func (w *LockObjectWriter) verifyOwnership(ctx context.Context, lk, ourNonce string) error {
	body, err := w.Provider.Get(ctx, lk)
	if err != nil {
		return fmt.Errorf("re-read lock: %w", err)
	}
	var got lockBody
	if err := json.Unmarshal(body, &got); err != nil {
		return fmt.Errorf("decode lock: %w", err)
	}
	if got.Nonce != ourNonce {
		return domain.ErrLockHeld
	}
	if w.Now().After(got.ExpiresAt) {
		return fmt.Errorf("%w: TTL elapsed mid-write", domain.ErrLockHeld)
	}
	return nil
}

// acquireLock attempts to take the lock at lk. On B2 (no conditional create)
// it falls back to plain PUT + re-read. On every conflict it checks
// whether the existing lock is expired OR fails signature verification —
// both are treated as stale and broken — and otherwise waits. Returns
// the nonce we committed on success.
func (w *LockObjectWriter) acquireLock(ctx context.Context, lk string) (nonce string, err error) {
	now := w.Now()
	nonce = fmt.Sprintf("%d-%s", now.UnixNano(), w.DeviceID)
	body := lockBody{
		DeviceID:  w.DeviceID,
		IssuedAt:  now,
		ExpiresAt: now.Add(w.LockTTL),
		Nonce:     nonce,
	}
	if w.LockSigner != nil {
		sig, sErr := w.LockSigner(lockSigningBytes(body))
		if sErr != nil {
			return "", fmt.Errorf("sign lock: %w", sErr)
		}
		body.Signature = sig
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	for attempt := 0; attempt < w.MaxAttempts; attempt++ {
		// Try the conditional path first.
		if _, perr := w.Provider.PutIfNotExists(ctx, lk, payload); perr == nil {
			return nonce, nil
		} else if errors.Is(perr, domain.ErrConditionalUnsupported) {
			// B2 fallback: plain PUT then re-read to detect races.
			if pErr := w.Provider.Put(ctx, lk, payload); pErr != nil {
				return "", fmt.Errorf("acquire lock (b2): %w", pErr)
			}
			read, rerr := w.Provider.Get(ctx, lk)
			if rerr != nil {
				return "", fmt.Errorf("verify lock (b2): %w", rerr)
			}
			var got lockBody
			if jErr := json.Unmarshal(read, &got); jErr != nil {
				return "", fmt.Errorf("decode lock: %w", jErr)
			}
			if got.Nonce == nonce {
				return nonce, nil
			}
			// Lost the race; another writer overwrote us. Fall through.
		} else if !errors.Is(perr, domain.ErrPreconditionFailed) {
			return "", fmt.Errorf("acquire lock: %w", perr)
		}

		// Lock exists. Check whether it has expired or is forged.
		existing, gErr := w.Provider.Get(ctx, lk)
		if gErr != nil {
			if errors.Is(gErr, domain.ErrObjectNotFound) {
				continue // releaser beat us to it; retry acquire
			}
			return "", fmt.Errorf("inspect lock: %w", gErr)
		}
		var held lockBody
		if jErr := json.Unmarshal(existing, &held); jErr != nil {
			// Treat unparseable locks as stale.
			_ = w.Provider.Delete(ctx, lk)
			continue
		}
		if w.Now().After(held.ExpiresAt) {
			_ = w.Provider.Delete(ctx, lk)
			continue
		}
		// A bucket admin can otherwise plant a "fresh" unsigned lock to
		// DoS the workspace. Verify the lock's signature against a
		// known device key (provided by the caller via MatchingVerifier).
		// If verification fails, treat as stale and break it.
		if w.MatchingVerifier != nil {
			body := held
			body.Signature = nil
			if vErr := w.MatchingVerifier(held.DeviceID, lockSigningBytes(body), held.Signature); vErr != nil {
				_ = w.Provider.Delete(ctx, lk)
				continue
			}
		}

		// Fresh, properly-signed lock held by someone else. Back off.
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(w.AcquireDelay):
		}
	}
	return "", domain.ErrLockHeld
}
