package domain

import (
	"fmt"
	"path"
)

// Canonical bucket paths. These are intentionally hard-coded so a misbehaving
// client cannot relocate the control plane out from under another device.
const (
	DriftPrefix      = ".drift/"
	ManifestKey      = ".drift/manifest.enc"
	RevocationsKey   = ".drift/revocations.enc"
	CredentialsDir   = ".drift/credentials/"
	CompartmentsRoot = "compartments/"
	// RecoveryKey holds an optional passphrase-wrapped backup of the master
	// signing key. Present only if the operator opted in at init or via
	// `drift recovery rekey`. Single-slot per workspace.
	RecoveryKey = ".drift/recovery.enc"
)

// CredentialsKeyFor returns the object key for a token's encrypted credentials
// blob.
func CredentialsKeyFor(tid string) string {
	return path.Join(CredentialsDir, tid+".enc")
}

// CompartmentPrefix returns the bucket prefix that holds the data-plane
// chunks for a compartment. Callers must validate name via
// ValidCompartmentName first — without that, "..", "../foo", or "" all
// silently escape the compartments root.
func CompartmentPrefix(name string) string {
	return path.Join(CompartmentsRoot, name) + "/"
}

// ValidCompartmentName returns nil if name is safe to use as a compartment
// identifier and as a path segment. Rules:
//   - 1–64 characters
//   - first char is [a-z0-9]
//   - subsequent chars are [a-z0-9_-]
//
// Intentionally tight — relaxing later is safe, tightening later would
// break existing workspaces. Without this check a user creating
// compartment ".." silently grants every minted DataCred RW over the
// entire compartments/ root.
func ValidCompartmentName(name string) error {
	if len(name) == 0 || len(name) > 64 {
		return fmt.Errorf("drift: compartment name must be 1–64 chars, got %d", len(name))
	}
	for i, r := range name {
		valid := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if i > 0 {
			valid = valid || r == '-' || r == '_'
		}
		if !valid {
			return fmt.Errorf("drift: compartment name %q invalid at position %d (allow [a-z0-9] then [a-z0-9_-])", name, i)
		}
	}
	return nil
}
