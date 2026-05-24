// Package keychain wraps the OS-level secret store (macOS Keychain,
// GNOME Keyring / SecretService on Linux, Windows Credential Manager) so
// Drift can move master / device / parent keys off plaintext disk.
//
// v1 of Drift ships with file-backed key storage at chmod 0600. This
// package is the foundation for moving to a keychain-backed store
// (DD-3 §3 open decisions); the State implementation reads the
// DRIFT_KEYCHAIN env var (or future config flag) to opt in.
//
// All entries are namespaced under a single "drift" service so a user
// can audit/revoke Drift's stored secrets in one place via the OS UI.
package keychain

import (
	"encoding/base64"
	"errors"

	"github.com/zalando/go-keyring"
)

// Service is the keychain service identifier used for every Drift entry.
const Service = "drift"

// ErrNotFound matches the wrapped library's "no entry" sentinel so callers
// can distinguish "no value yet" from "OS error".
var ErrNotFound = keyring.ErrNotFound

// Available returns true if an OS-level secret store is reachable. On
// servers / CI containers without a desktop session, this typically
// returns false and callers should fall back to file-backed storage.
//
// We probe by attempting a get-then-delete round-trip on a sentinel
// entry; any error from the underlying library is treated as
// "unavailable".
func Available() bool {
	const probe = "drift-keychain-probe"
	if err := keyring.Set(Service, probe, "ok"); err != nil {
		return false
	}
	got, err := keyring.Get(Service, probe)
	_ = keyring.Delete(Service, probe)
	return err == nil && got == "ok"
}

// Set stores raw bytes under (Service, name). Bytes are base64-encoded
// because the wrapped library only accepts strings and some backends
// (notably Windows Credential Manager) garble non-printable bytes.
func Set(name string, value []byte) error {
	if name == "" {
		return errors.New("keychain: name required")
	}
	encoded := base64.RawStdEncoding.EncodeToString(value)
	return keyring.Set(Service, name, encoded)
}

// Get returns the bytes previously stored under name, or ErrNotFound.
func Get(name string) ([]byte, error) {
	encoded, err := keyring.Get(Service, name)
	if err != nil {
		return nil, err
	}
	return base64.RawStdEncoding.DecodeString(encoded)
}

// Delete removes the entry under name. Returns nil if the entry did not
// exist; treats "not found" as success because callers typically use
// Delete for cleanup and don't care.
func Delete(name string) error {
	err := keyring.Delete(Service, name)
	if err == ErrNotFound {
		return nil
	}
	return err
}
