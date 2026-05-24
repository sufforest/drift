// Package audit emits + verifies signed, encrypted control-plane events
// under .drift/audit/. Each entry is a separate object so concurrent
// writers cannot collide; per-device hash chains make bucket-side
// deletions detectable.
package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/storage"
)

// State is the small per-device record needed to chain entries. The
// caller (workspace) persists this between Emit calls.
type State struct {
	LastSequence uint64
	LastHash     []byte
}

// Emitter holds the dependencies Emit needs.
type Emitter struct {
	Provider    storage.Provider
	WorkspaceID string
	DeviceID    string
	DeviceSign  ed25519.PrivateKey
	CPRK        []byte
	Now         func() time.Time

	// Load returns the current chain state for this device. Returning a
	// zero State + nil error means "no prior entries; this is the first".
	Load func() (State, error)
	// Save persists the chain head after a successful Emit.
	Save func(State) error
	// Release is called on every Emit exit path (success OR failure) so
	// the workspace can drop the per-state-dir flock. Must be safe to
	// call multiple times; the workspace's implementation no-ops after
	// the first call.
	Release func()
}

// Emit builds, signs, encrypts, and uploads a single audit entry, then
// advances the device's chain head via Save.
//
// Release is invoked on EVERY exit path (success or failure) so a per-
// state-dir flock held by Load doesn't leak when an upload or marshal
// fails. The Emitter wrapper in workspace makes Release idempotent.
func (e *Emitter) Emit(ctx context.Context, kind, subject string, details any) error {
	if e.WorkspaceID == "" || e.DeviceID == "" || e.CPRK == nil {
		return errors.New("audit: emitter not fully configured")
	}
	if e.Release != nil {
		defer e.Release()
	}
	state, err := e.Load()
	if err != nil {
		return fmt.Errorf("load chain head: %w", err)
	}
	now := e.now()
	nonce := make([]byte, 4)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}
	entryID := buildEntryID(now, e.DeviceID, nonce)

	var detailsBytes []byte
	if details != nil {
		var err error
		detailsBytes, err = json.Marshal(details)
		if err != nil {
			return fmt.Errorf("marshal details: %w", err)
		}
	}

	entry := domain.AuditEntry{
		Version:     1,
		EntryID:     entryID,
		WorkspaceID: e.WorkspaceID,
		DeviceID:    e.DeviceID,
		Sequence:    state.LastSequence + 1,
		PrevHash:    state.LastHash,
		OccurredAt:  now,
		Kind:        kind,
		Subject:     subject,
		Details:     detailsBytes,
	}
	signBody, err := canonicalSigningBytes(entry)
	if err != nil {
		return err
	}
	entry.Signature = dcrypto.Sign(e.DeviceSign, signBody)

	plaintext, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal entry: %w", err)
	}
	cipher, err := dcrypto.Encrypt(e.CPRK, plaintext, domain.AuditAADFor(e.WorkspaceID, entryID))
	if err != nil {
		return fmt.Errorf("encrypt entry: %w", err)
	}
	// PutIfNotExists makes overwrites of an existing entry impossible,
	// so a bucket admin cannot silently replace one entry's body with
	// another's. Falls back to plain Put on backends without
	// conditional support; on those backends the chain-verify check is
	// the only tamper signal.
	if _, err := e.Provider.PutIfNotExists(ctx, domain.AuditEntryKey(entryID), cipher); err != nil {
		if errors.Is(err, domain.ErrConditionalUnsupported) {
			if pErr := e.Provider.Put(ctx, domain.AuditEntryKey(entryID), cipher); pErr != nil {
				return fmt.Errorf("upload entry: %w", pErr)
			}
		} else {
			return fmt.Errorf("upload entry: %w", err)
		}
	}

	// Advance chain head: hash the just-uploaded entry's canonical body
	// so the NEXT entry's PrevHash chains correctly.
	h := sha256.Sum256(signBody)
	return e.Save(State{
		LastSequence: entry.Sequence,
		LastHash:     h[:],
	})
}

func (e *Emitter) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// canonicalSigningBytes returns the byte form the signature covers.
// Excludes the Signature field; everything else is canonical-JSON.
func canonicalSigningBytes(e domain.AuditEntry) ([]byte, error) {
	clone := e
	clone.Signature = nil
	return json.Marshal(clone)
}

// buildEntryID returns "<unix_nano (18-digit zero-padded)>-<did>-<hex(nonce)>"
// so lexicographic List order matches temporal order — useful for
// list-with-prefix scans on a date range.
func buildEntryID(t time.Time, deviceID string, nonce []byte) string {
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(t.UnixNano()))
	return fmt.Sprintf("%018d-%s-%s", t.UnixNano(), deviceID, hex.EncodeToString(nonce))
}

// Decrypted is a parsed + verified audit entry returned by List.
type Decrypted struct {
	Entry      domain.AuditEntry
	VerifyErr  error // non-nil if signature or chain failed
}

// List returns every audit entry decryptable with cprk under prefix,
// sorted by EntryID (== temporal order). Each entry's signature is
// verified against the device's pubkey resolved by resolveDevicePub.
//
// Entries that fail to decrypt under cprk are reported via skipped, NOT
// silently dropped. A non-zero skipped count after a CPRK rotation
// reveals an informational gap — entries from before the rotation are
// invisible under the current key.
func List(ctx context.Context, p storage.Provider, workspaceID string, cprk []byte, resolveDevicePub func(deviceID string) ed25519.PublicKey) (entries []Decrypted, skipped int, err error) {
	keys, err := p.List(ctx, domain.AuditDir)
	if err != nil {
		return nil, 0, err
	}
	out := make([]Decrypted, 0, len(keys))
	for _, k := range keys {
		body, err := p.Get(ctx, k)
		if err != nil {
			skipped++
			continue
		}
		entryID := strippedEntryID(k)
		plain, err := dcrypto.Decrypt(cprk, body, domain.AuditAADFor(workspaceID, entryID))
		if err != nil {
			// Entry not for us (e.g. different CPRK epoch). Count
			// rather than drop so callers can surface "N entries
			// invisible to current key".
			skipped++
			continue
		}
		var entry domain.AuditEntry
		if err := json.Unmarshal(plain, &entry); err != nil {
			out = append(out, Decrypted{Entry: entry, VerifyErr: fmt.Errorf("parse: %w", err)})
			continue
		}
		// Verify signature against the resolved device pubkey.
		pub := resolveDevicePub(entry.DeviceID)
		verifyErr := error(nil)
		if pub == nil {
			verifyErr = fmt.Errorf("%w: device %s pubkey not resolvable", domain.ErrSignatureInvalid, entry.DeviceID)
		} else {
			signBody, err := canonicalSigningBytes(entry)
			if err != nil {
				verifyErr = err
			} else {
				verifyErr = dcrypto.Verify(pub, signBody, entry.Signature)
			}
		}
		out = append(out, Decrypted{Entry: entry, VerifyErr: verifyErr})
	}
	return out, skipped, nil
}

// VerifyChain returns the first chain-gap or out-of-order error found
// among entries. The grouping is per-DeviceID: each device's entries
// must form an unbroken hash chain in Sequence order. Caller-supplied
// ordering of entries is ignored — VerifyChain sorts by (DeviceID,
// Sequence) internally before checking.
func VerifyChain(entries []Decrypted) error {
	perDevice := map[string][]domain.AuditEntry{}
	for _, e := range entries {
		if e.VerifyErr != nil {
			continue
		}
		perDevice[e.Entry.DeviceID] = append(perDevice[e.Entry.DeviceID], e.Entry)
	}
	for did, list := range perDevice {
		sortBySequence(list)
		var prevHash []byte
		for i, entry := range list {
			expectedSeq := uint64(i + 1)
			if entry.Sequence != expectedSeq {
				return fmt.Errorf("device %s entry %d has sequence %d, want %d", did, i, entry.Sequence, expectedSeq)
			}
			if !bytes.Equal(entry.PrevHash, prevHash) {
				return fmt.Errorf("device %s chain gap at seq %d", did, entry.Sequence)
			}
			signBody, _ := canonicalSigningBytes(entry)
			h := sha256.Sum256(signBody)
			prevHash = h[:]
		}
	}
	return nil
}

func sortBySequence(entries []domain.AuditEntry) {
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && entries[j-1].Sequence > entries[j].Sequence; j-- {
			entries[j-1], entries[j] = entries[j], entries[j-1]
		}
	}
}

func strippedEntryID(key string) string {
	if len(key) <= len(domain.AuditDir) {
		return ""
	}
	rest := key[len(domain.AuditDir):]
	if len(rest) >= 4 && rest[len(rest)-4:] == ".enc" {
		return rest[:len(rest)-4]
	}
	return rest
}
