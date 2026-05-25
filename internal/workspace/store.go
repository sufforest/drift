// Package workspace is the orchestration layer: it ties the local on-disk
// state (this file) to the bucket-side control plane (manifest, revocations,
// credentials) and the data-plane mount.
//
// v1 stores all device state in plain JSON files under the config dir at
// chmod 0600. OS-keychain integration is deferred.
package workspace

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/credentials"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/keychain"
)

// SecretFileMode is the only acceptable permission mode for files that hold
// key material. Stricter than 0600 (no group/world bits at all).
const SecretFileMode os.FileMode = 0o600

// State is the on-disk state of one workspace on one device.
//
// Files written to baseDir:
//
//	config.json   — workspace metadata (bucket, endpoint, workspace id)
//	master.json   — MasterKey JSON (primary device only)
//	device.json   — DeviceKey JSON
//	parent.json   — parent provider credential (FileProvider format)
//
// The primary device has all four files; a future `drift link`-ed secondary
// device has only device.json + config.json + parent.json.
type State struct {
	BaseDir string
}

// LocalConfig is the per-device, per-workspace metadata. Distinct from
// domain.Config, which is a richer multi-workspace config layered on top
// (v1 ships with a single workspace per state dir).
//
// MinManifestSequence and MinRevocationsSequence are the floor values this
// device has observed. The workspace refuses to load manifest/revocations
// objects whose Sequence is lower. Bumped after every successful read or
// write, persisted via SaveConfig.
type LocalConfig struct {
	WorkspaceID            string            `json:"workspace_id"`
	DeviceID               string            `json:"device_id"`
	Bucket                 domain.BucketInfo `json:"bucket"`
	Concurrency            string            `json:"concurrency"` // "conditional_put" / "lock_object"
	MinManifestSequence    uint64            `json:"min_manifest_sequence"`
	MinRevocationsSequence uint64            `json:"min_revocations_sequence"`

	// MasterFingerprint is SHA-256 of the workspace master Ed25519 pubkey,
	// pinned at init or at drift link time. The workspace refuses to load
	// any manifest whose master pseudo-device pubkey hashes to a different
	// value — defends against bucket-admin workspace-fork attacks.
	MasterFingerprint []byte `json:"master_fingerprint"`

	// CPRKEpoch is the HKDF epoch the cached CPRK was derived under.
	// Bumped on `drift rotate cprk`. Primary devices re-derive from
	// master.Root + epoch; secondaries fetch a sealed handoff blob.
	CPRKEpoch uint64 `json:"cprk_epoch"`

	// LastObservedRotation is the highest master-rotation sequence this
	// device has walked through. On every Manifest() read, if the
	// manifest's MasterRotationSequence is higher, the device walks the
	// announcement chain forward to update its pinned fingerprint.
	LastObservedRotation uint64 `json:"last_observed_rotation"`
}

// masterFile is the on-disk representation of a MasterKey. The struct lives
// in this file (not internal/crypto) because crypto/MasterKey holds raw
// arrays whose JSON shape we'd rather pin here.
type masterFile struct {
	SignPriv []byte `json:"sign_priv"` // ed25519 private key (64 bytes)
	BoxPriv  []byte `json:"box_priv"`  // x25519 scalar (32 bytes)
	Root     []byte `json:"root"`      // 32-byte HKDF IKM
}

// deviceFile is the on-disk representation of a DeviceKey.
type deviceFile struct {
	SignPriv []byte `json:"sign_priv"`
	BoxPriv  []byte `json:"box_priv"`
}

// NewState constructs a State pointing at baseDir. baseDir is created at
// chmod 0700 if it does not exist; existing dirs are left alone.
func NewState(baseDir string) (*State, error) {
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", baseDir, err)
	}
	return &State{BaseDir: baseDir}, nil
}

// DefaultStateDir returns $XDG_CONFIG_HOME/drift, falling back to
// $HOME/.config/drift.
func DefaultStateDir() (string, error) {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "drift"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "drift"), nil
}

func (s *State) path(name string) string { return filepath.Join(s.BaseDir, name) }

// HasMaster returns true if the master key file is present (i.e., this is
// the workspace's primary device).
func (s *State) HasMaster() bool {
	_, err := os.Stat(s.path("master.json"))
	return err == nil
}

// HasDevice returns true if a device key file exists locally.
func (s *State) HasDevice() bool {
	_, err := os.Stat(s.path("device.json"))
	return err == nil
}

// auditStateFile is the local cache of the audit chain head for this device.
type auditStateFile struct {
	LastSequence uint64 `json:"last_sequence"`
	LastHash     []byte `json:"last_hash"`
}

// LoadAuditState returns the current chain head (zero state if no entries
// have been emitted yet from this device).
func (s *State) LoadAuditState() (uint64, []byte, error) {
	body, err := os.ReadFile(s.path("audit-state.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil, nil
		}
		return 0, nil, err
	}
	var f auditStateFile
	if err := json.Unmarshal(body, &f); err != nil {
		return 0, nil, err
	}
	return f.LastSequence, f.LastHash, nil
}

// SaveAuditState persists the chain head at chmod 0600. Not sensitive
// per se, but contains usage patterns worth protecting from world reads.
func (s *State) SaveAuditState(seq uint64, hash []byte) error {
	body, err := json.MarshalIndent(auditStateFile{LastSequence: seq, LastHash: hash}, "", "  ")
	if err != nil {
		return err
	}
	return writeSecret(s.path("audit-state.json"), body)
}

// AuditChainLock acquires an OS-level advisory exclusive lock on a per-
// state-dir audit-chain file. Holding the returned function means no
// other process under the same state dir can run an Emit critical
// section. Caller must defer the returned function.
//
// Two concurrent `drift` invocations sharing one state dir would
// otherwise race on Load → upload → Save, producing duplicate Sequence
// numbers that VerifyChain interprets as tampering.
func (s *State) AuditChainLock() (release func(), err error) {
	lockPath := s.path("audit-state.lock")
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("flock audit-state: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

// SaveCPRK persists the Control Plane Read Key for a secondary device
// that received it during pairing (primary devices derive it from
// master.json on demand). Mode 0600.
func (s *State) SaveCPRK(cprk []byte) error {
	return writeSecret(s.path("cprk.key"), cprk)
}

// LoadCPRK returns the persisted CPRK. Returns os.ErrNotExist on a primary
// device (which derives the key fresh) or a fully-uninitialized state.
func (s *State) LoadCPRK() ([]byte, error) {
	return readSecret(s.path("cprk.key"))
}

// SaveMaster writes the master key at chmod 0600. Refuses to overwrite an
// existing file to avoid accidental key loss; callers wanting to rotate
// should remove the old file first.
func (s *State) SaveMaster(m *dcrypto.MasterKey) error {
	if _, err := os.Stat(s.path("master.json")); err == nil {
		return errors.New("workspace: master.json already exists; refusing to overwrite")
	}
	body, err := json.Marshal(masterFile{
		SignPriv: []byte(m.SignPriv),
		BoxPriv:  m.BoxPriv[:],
		Root:     m.Root[:],
	})
	if err != nil {
		return fmt.Errorf("marshal master: %w", err)
	}
	return writeSecret(s.path("master.json"), body)
}

// RestoreMaster copies a rotated-out master backup (at chmod 0000) back
// into the live master.json slot. Refuses if a live master.json already
// exists — caller must pass force=true to overwrite.
//
// After restore, callers must recompute LocalConfig.MasterFingerprint
// from the restored key. This function does NOT touch the bucket-side
// rotation announcement chain: a workspace that rotated master and then
// restored the old master locally is in a contradictory state until the
// bucket is also reverted; document via the CLI.
func (s *State) RestoreMaster(backupPath string, force bool) (*dcrypto.MasterKey, error) {
	if _, err := os.Stat(s.path("master.json")); err == nil && !force {
		return nil, errors.New("workspace: master.json already exists; pass --force to overwrite")
	}
	body, err := os.ReadFile(backupPath)
	if err != nil {
		return nil, fmt.Errorf("read backup: %w", err)
	}
	var f masterFile
	if err := json.Unmarshal(body, &f); err != nil {
		return nil, fmt.Errorf("backup is not a valid master key file: %w", err)
	}
	if len(f.SignPriv) != ed25519.PrivateKeySize ||
		len(f.BoxPriv) != dcrypto.X25519KeySize ||
		len(f.Root) != dcrypto.RootSecretSize {
		return nil, errors.New("backup contains malformed key material")
	}
	m := &dcrypto.MasterKey{SignPriv: ed25519.PrivateKey(f.SignPriv)}
	copy(m.BoxPriv[:], f.BoxPriv)
	copy(m.Root[:], f.Root)
	if err := writeSecret(s.path("master.json"), body); err != nil {
		return nil, fmt.Errorf("write restored master: %w", err)
	}
	return m, nil
}

// RotateMaster archives the existing master.json under a timestamped
// backup name (chmod 0000 so the user can recover but can't open by
// accident) and writes the new master in its place. Used by
// `drift rotate master`.
func (s *State) RotateMaster(newMaster *dcrypto.MasterKey, when time.Time) error {
	existing := s.path("master.json")
	if _, err := os.Stat(existing); err == nil {
		backup := s.path("master.json.rotated-" + when.UTC().Format("2006-01-02T150405Z"))
		if err := os.Rename(existing, backup); err != nil {
			return fmt.Errorf("backup old master: %w", err)
		}
		if err := os.Chmod(backup, 0o000); err != nil {
			// Non-fatal: file is renamed; mode tightening is hygiene.
			_ = err
		}
	}
	body, err := json.Marshal(masterFile{
		SignPriv: []byte(newMaster.SignPriv),
		BoxPriv:  newMaster.BoxPriv[:],
		Root:     newMaster.Root[:],
	})
	if err != nil {
		return fmt.Errorf("marshal new master: %w", err)
	}
	return writeSecret(s.path("master.json"), body)
}

// LoadMaster reads the master key. Returns os.ErrNotExist if absent so the
// caller can distinguish "primary device" from "secondary device".
func (s *State) LoadMaster() (*dcrypto.MasterKey, error) {
	body, err := readSecret(s.path("master.json"))
	if err != nil {
		return nil, err
	}
	var f masterFile
	if err := json.Unmarshal(body, &f); err != nil {
		return nil, fmt.Errorf("parse master.json: %w", err)
	}
	if len(f.SignPriv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("master.json: sign_priv length %d, want %d", len(f.SignPriv), ed25519.PrivateKeySize)
	}
	if len(f.BoxPriv) != dcrypto.X25519KeySize {
		return nil, fmt.Errorf("master.json: box_priv length %d, want %d", len(f.BoxPriv), dcrypto.X25519KeySize)
	}
	if len(f.Root) != dcrypto.RootSecretSize {
		return nil, fmt.Errorf("master.json: root length %d, want %d", len(f.Root), dcrypto.RootSecretSize)
	}
	m := &dcrypto.MasterKey{SignPriv: ed25519.PrivateKey(f.SignPriv)}
	copy(m.BoxPriv[:], f.BoxPriv)
	copy(m.Root[:], f.Root)
	return m, nil
}

// SaveDevice writes the device key at chmod 0600. Like SaveMaster, refuses
// to overwrite.
func (s *State) SaveDevice(d *dcrypto.DeviceKey) error {
	if _, err := os.Stat(s.path("device.json")); err == nil {
		return errors.New("workspace: device.json already exists; refusing to overwrite")
	}
	body, err := json.Marshal(deviceFile{
		SignPriv: []byte(d.SignPriv),
		BoxPriv:  d.BoxPriv[:],
	})
	if err != nil {
		return fmt.Errorf("marshal device: %w", err)
	}
	return writeSecret(s.path("device.json"), body)
}

// LoadDevice reads the device key.
func (s *State) LoadDevice() (*dcrypto.DeviceKey, error) {
	body, err := readSecret(s.path("device.json"))
	if err != nil {
		return nil, err
	}
	var f deviceFile
	if err := json.Unmarshal(body, &f); err != nil {
		return nil, fmt.Errorf("parse device.json: %w", err)
	}
	if len(f.SignPriv) != ed25519.PrivateKeySize || len(f.BoxPriv) != dcrypto.X25519KeySize {
		return nil, errors.New("device.json: corrupt key sizes")
	}
	d := &dcrypto.DeviceKey{SignPriv: ed25519.PrivateKey(f.SignPriv)}
	copy(d.BoxPriv[:], f.BoxPriv)
	return d, nil
}

// SaveConfig writes the workspace metadata. Overwrite-safe.
func (s *State) SaveConfig(c LocalConfig) error {
	body, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	// 0600: contains MasterFingerprint + per-device sequence floors that
	// would otherwise leak workspace topology to other local users on
	// multi-user hosts.
	return os.WriteFile(s.path("config.json"), body, 0o600)
}

// LoadConfig reads the workspace metadata.
func (s *State) LoadConfig() (*LocalConfig, error) {
	body, err := os.ReadFile(s.path("config.json"))
	if err != nil {
		return nil, err
	}
	var c LocalConfig
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, fmt.Errorf("parse config.json: %w", err)
	}
	return &c, nil
}

// LoadParent returns the parent provider credential from parent.json.
// Routes through readSecret so the keychain marker is honored when
// DRIFT_KEYCHAIN=1 was active at write time. Permission check is in
// readSecret; JSON parsing is here.
func (s *State) LoadParent() (*credentials.Parent, error) {
	body, err := readSecret(s.path("parent.json"))
	if err != nil {
		return nil, err
	}
	var p credentials.Parent
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("parse %s: %w", s.path("parent.json"), err)
	}
	if p.AccessKeyID == "" || p.SecretAccessKey == "" {
		return nil, fmt.Errorf("credentials: %s is missing access_key_id or secret_access_key", s.path("parent.json"))
	}
	return &p, nil
}

// SaveParent writes a parent credential at chmod 0600.
func (s *State) SaveParent(p *credentials.Parent) error {
	body, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal parent: %w", err)
	}
	return writeSecret(s.path("parent.json"), body)
}

// HasPeerCred reports whether this state dir holds a DD-9 bearer-mode
// PeerCred. Used by daily-use code paths (mount, grant) to detect which
// pairing mode this device is in:
//   - parent.json present → v1 peer or primary
//   - peercred.json present → DD-9 bearer peer
//   - neither → identity-only (must redeem bearer tokens)
func (s *State) HasPeerCred() bool {
	_, err := os.Stat(s.path("peercred.json"))
	return err == nil
}

// LoadPeerCred returns the DD-9 bearer-mode PeerCred from peercred.json,
// routed through readSecret (keychain-aware). Callers must
// VerifyPeerCred against the workspace's master pubkey before using.
func (s *State) LoadPeerCred() (*credentials.PeerCred, error) {
	body, err := readSecret(s.path("peercred.json"))
	if err != nil {
		return nil, err
	}
	var p credentials.PeerCred
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("parse %s: %w", s.path("peercred.json"), err)
	}
	return &p, nil
}

// SavePeerCred writes a DD-9 bearer-mode PeerCred at chmod 0600 (or to
// keychain if DRIFT_KEYCHAIN=1).
func (s *State) SavePeerCred(p *credentials.PeerCred) error {
	body, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal peercred: %w", err)
	}
	return writeSecret(s.path("peercred.json"), body)
}

// useKeychain returns true if DRIFT_KEYCHAIN is set to "1" / "true".
// Opt-in for v1; default remains file-backed (chmod 0600) to keep the
// install path zero-prompt. Future versions may probe + default-on.
func useKeychain() bool {
	v := os.Getenv("DRIFT_KEYCHAIN")
	return v == "1" || v == "true" || v == "TRUE"
}

// secretKey is the keychain entry name for a given on-disk secret path.
// Hashes the path so multiple state dirs on the same machine get
// distinct keychain entries without leaking the absolute path.
func secretKey(path string) string {
	h := sha256.Sum256([]byte(path))
	return "secret:" + hex.EncodeToString(h[:8]) + ":" + filepath.Base(path)
}

// writeSecret writes body with permissions == SecretFileMode atomically.
// "Atomic" here means write to a temp file in the same dir, then rename —
// readers never observe a half-written file.
//
// When DRIFT_KEYCHAIN=1 is set, the body is stored in the OS keychain
// instead and the on-disk file is left empty (mode 0600) as a marker so
// readSecret knows to look in the keychain. Hybrid mode lets per-secret
// migration happen incrementally.
func writeSecret(path string, body []byte) error {
	if useKeychain() {
		if err := keychain.Set(secretKey(path), body); err != nil {
			return fmt.Errorf("keychain: %w", err)
		}
		// Still write a small marker file so HasMaster()/HasDevice()
		// existence checks keep working. Body is empty (just the
		// keychain-indirection signal).
		return writeFileSecret(path, []byte("# drift: stored in OS keychain\n"))
	}
	return writeFileSecret(path, body)
}

func writeFileSecret(path string, body []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".drift-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		// If we got here without renaming, clean up. Ignore errors.
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(SecretFileMode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// readSecret loads a secret, refusing to read if the on-disk
// permissions are looser than SecretFileMode. When the marker file
// indicates the body lives in the OS keychain, fetches from there.
func readSecret(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if mode := st.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("%s has permissive mode %o (want 0600); refusing to read", path, mode)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if isKeychainMarker(body) {
		return keychain.Get(secretKey(path))
	}
	return body, nil
}

func isKeychainMarker(body []byte) bool {
	const marker = "# drift: stored in OS keychain"
	return len(body) >= len(marker) && string(body[:len(marker)]) == marker
}
