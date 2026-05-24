// Package manifest provides encode / sign / verify / encrypt / decrypt for
// the workspace manifest. Pure functions over domain.Manifest; the storage
// layer handles I/O and concurrency.
package manifest

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/domain"
)

// AADFor returns the AAD bound into the manifest ciphertext.
// Includes the workspace id so a bucket admin who copies a signed manifest
// from workspace A's bucket into workspace B's bucket sees an AEAD failure
// on decrypt rather than a successful (cross-workspace) load.
//
// "drift/v2/manifest" version prefix means clients reading a v1-AAD blob
// (no wid) fail loudly.
func AADFor(workspaceID string) []byte {
	return []byte("drift/v2/manifest|" + workspaceID)
}

// canonicalForSigning returns the bytes Ed25519 signs over. We zero out the
// Signature / SignedBy fields before serializing so a verifier can recompute
// the same bytes without modeling "what was the byte layout before signing".
func canonicalForSigning(m *domain.Manifest) ([]byte, error) {
	copy := *m
	copy.Signature = nil
	copy.SignedBy = ""
	return json.Marshal(&copy)
}

// Sign updates m.Signature and m.SignedBy in place. The signer is identified
// by deviceID; the verifier must look up that device in m.Devices to fetch
// the matching public key.
func Sign(m *domain.Manifest, deviceID string, priv ed25519.PrivateKey) error {
	m.SignedBy = deviceID
	m.Signature = nil
	body, err := canonicalForSigning(m)
	if err != nil {
		return fmt.Errorf("canonicalize manifest: %w", err)
	}
	m.Signature = dcrypto.Sign(priv, body)
	return nil
}

// Verify checks the manifest signature against the SignedBy device's public
// key in m.Devices. Returns domain.ErrSignatureInvalid on any failure path.
func Verify(m *domain.Manifest) error {
	dev, ok := m.Devices[m.SignedBy]
	if !ok {
		return fmt.Errorf("%w: signing device %q not in manifest", domain.ErrDeviceUnknown, m.SignedBy)
	}
	if len(m.Signature) == 0 {
		return fmt.Errorf("%w: manifest has no signature", domain.ErrSignatureInvalid)
	}
	body, err := canonicalForSigning(m)
	if err != nil {
		return err
	}
	if err := dcrypto.Verify(ed25519.PublicKey(dev.PublicKey), body, m.Signature); err != nil {
		return err
	}
	// Enrollment chain: every non-master device must carry a master-signed
	// enrollment cert. The master pubkey is read from Manifest.Devices —
	// callers separately verify it against a pinned fingerprint (which is
	// what makes self-referential forgery infeasible).
	master, ok := m.Devices[domain.MasterDeviceID]
	if !ok {
		return fmt.Errorf("%w: manifest has no master pseudo-device", domain.ErrDeviceUnknown)
	}
	masterPub := ed25519.PublicKey(master.PublicKey)
	for did, d := range m.Devices {
		if did == domain.MasterDeviceID {
			continue
		}
		e, ok := m.Enrollments[did]
		if !ok {
			return fmt.Errorf("%w: device %q lacks an enrollment cert", domain.ErrSignatureInvalid, did)
		}
		if err := VerifyEnrollment(e, d, masterPub); err != nil {
			return fmt.Errorf("enrollment for %s: %w", did, err)
		}
	}
	return nil
}

// Encrypt serializes the manifest and seals it with the workspace CPRK.
// Caller should call Sign first; Encrypt does not sign on its behalf so the
// signing identity remains explicit. The workspace_id is read from m and
// bound into the AEAD's AAD.
func Encrypt(m *domain.Manifest, cprk []byte) ([]byte, error) {
	body, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	return dcrypto.Encrypt(cprk, body, AADFor(m.WorkspaceID))
}

// Decrypt inverts Encrypt. workspaceID is the bearer's expectation of which
// workspace this manifest belongs to; it's bound into the AAD so a bucket
// admin who substitutes another workspace's manifest fails decryption.
// Callers should invoke Verify on the returned manifest separately.
func Decrypt(ciphertext, cprk []byte, workspaceID string) (*domain.Manifest, error) {
	body, err := dcrypto.Decrypt(cprk, ciphertext, AADFor(workspaceID))
	if err != nil {
		return nil, fmt.Errorf("decrypt manifest: %w", err)
	}
	var m domain.Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("unmarshal manifest: %w", err)
	}
	if m.WorkspaceID != workspaceID {
		return nil, fmt.Errorf("manifest: workspace_id mismatch (expected %q, got %q)", workspaceID, m.WorkspaceID)
	}
	return &m, nil
}
