package workspace

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/sufforest/drift/internal/credentials"
	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/manifest"
	"github.com/sufforest/drift/internal/storage"
)

// LinkClaimOptions wires the dependencies LinkClaim needs.
//
// ProviderFor is a factory the caller passes so we can construct an S3
// provider from the pairing token's narrow Cred (which has only enough
// scope to GET manifest + GET/PUT pairings/<pid>/*). Tests inject a
// memory-provider-returning closure here so they don't need real S3.
type LinkClaimOptions struct {
	State       *State
	ProviderFor func(cred domain.S3Credential, bucket domain.BucketInfo) (storage.Provider, error)
	Now         func() time.Time

	// PollInterval is how often LinkClaim re-checks the bucket for the
	// primary's handoff blob. Defaults to 5s; tests shorten it.
	PollInterval time.Duration

	// Timeout caps how long LinkClaim blocks waiting for the primary.
	// Defaults to 10 minutes.
	Timeout time.Duration

	// OnSAS, if non-nil, is invoked once with the transcript-bound Short
	// Authentication String the instant the secondary has all inputs to
	// compute it (right after the PairingResponse has been built, before
	// it's posted). The CLI uses this to display the SAS so the user can
	// visually compare it against what the primary's `--confirm` step
	// shows. Returning an error aborts the link before any bucket write.
	OnSAS func(sas string) error
}

// LinkClaimResult is what the new device gets after a successful pairing.
// DeviceFingerprint is hex-encoded SHA-256 of the device's Ed25519 signing
// pubkey; the user shows it to the primary so the primary can verify
// `drift link --confirm --expect-fingerprint <hex>`.
type LinkClaimResult struct {
	DeviceID          string
	WorkspaceID       string
	DeviceFingerprint string
	// SAS is the Short Authentication String displayed during the
	// handshake (8-hex-char dash-separated, e.g. "AB12-CD34"). Echoed
	// in the result so the CLI can re-display it in the final summary.
	SAS string
	// PeerMode is true if the primary included its parent S3 cred in
	// the handoff and this device saved it locally. Means this device
	// can now do drift mount / drift grant on its own.
	PeerMode bool
	// BearerMode (DD-9) is true if the primary issued a bearer-mode
	// PeerCred for this device. The peer can drift mount within its
	// scope but cannot drift grant. Mutually exclusive with PeerMode.
	BearerMode bool
}

// LinkClaim runs the new-device side of the pairing protocol:
//
//  1. Decode + verify the pairing token against its embedded master pub.
//  2. Self-consistency: MasterFP must equal SHA-256(IssuerPub).
//  3. Generate or load this device's keypair.
//  4. Post a response with a challenge signature.
//  5. Save partial local state (device.json + config with pinned MasterFP).
//  6. Poll for the primary's handoff blob.
//  7. Unseal handoff with own box priv → CPRK + master pubkey.
//  8. Fetch + verify the manifest; cross-check master pubkey hashes to FP.
//  9. Persist CPRK + finalize config.
func LinkClaim(ctx context.Context, encoded, deviceName string, opts LinkClaimOptions) (*LinkClaimResult, error) {
	if opts.State == nil {
		return nil, errors.New("workspace: LinkClaim requires State")
	}
	if opts.ProviderFor == nil {
		return nil, errors.New("workspace: LinkClaim requires ProviderFor factory")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.PollInterval == 0 {
		opts.PollInterval = 5 * time.Second
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Minute
	}

	// 1+2: decode + verify.
	pt, err := DecodePairingToken(encoded)
	if err != nil {
		return nil, err
	}
	if opts.Now().After(pt.ExpiresAt) {
		return nil, fmt.Errorf("pairing token expired at %s", pt.ExpiresAt.UTC().Format(time.RFC3339))
	}

	// Refuse to overwrite an existing master.json — that would silently
	// turn a primary device into a secondary.
	if opts.State.HasMaster() {
		return nil, errors.New("workspace: this state dir holds a master key; refusing to drift link over it (use a fresh --config dir)")
	}

	// 3: generate (or reuse) device key. Device id is derived from the
	// signing pubkey so re-running LinkClaim with the same token is
	// idempotent.
	var dev *dcrypto.DeviceKey
	if opts.State.HasDevice() {
		dev, err = opts.State.LoadDevice()
		if err != nil {
			return nil, fmt.Errorf("load existing device key: %w", err)
		}
	} else {
		dev, err = dcrypto.GenerateDeviceKey()
		if err != nil {
			return nil, fmt.Errorf("generate device key: %w", err)
		}
		if err := opts.State.SaveDevice(dev); err != nil {
			return nil, err
		}
	}
	deviceID := deriveDeviceID(dev.SignPub())
	if deviceName == "" {
		deviceName = deviceID
	}
	devBox, err := dev.BoxPub()
	if err != nil {
		return nil, err
	}

	// 4: build response + challenge sig.
	resp := domain.PairingResponse{
		PID:           pt.PID,
		DeviceID:      deviceID,
		Name:          deviceName,
		DeviceSignPub: dev.SignPub(),
		DeviceBoxPub:  devBox[:],
		ChallengeSig:  dcrypto.Sign(dev.SignPriv, pt.Challenge),
	}
	respBody, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshal response: %w", err)
	}

	// Compute the Short Authentication String from the full pairing
	// transcript. Both the primary and the secondary derive this from
	// the same inputs; the user compares the two screens. Notify the
	// caller now (before any bucket write) so a SAS-mismatch can abort
	// without leaving artifacts in the bucket.
	sas := ComputeSAS(pt.IssuerPub, pt.PID, dev.SignPub(), devBox[:], pt.Challenge)
	if opts.OnSAS != nil {
		if err := opts.OnSAS(sas); err != nil {
			return nil, fmt.Errorf("sas verification: %w", err)
		}
	}

	readProvider, err := opts.ProviderFor(pt.ReadCred, pt.Bucket)
	if err != nil {
		return nil, fmt.Errorf("build read provider: %w", err)
	}
	writeProvider, err := opts.ProviderFor(pt.WriteCred, pt.Bucket)
	if err != nil {
		return nil, fmt.Errorf("build write provider: %w", err)
	}
	if err := writeProvider.Put(ctx, domain.PairingResponseKey(pt.PID), respBody); err != nil {
		return nil, fmt.Errorf("upload response: %w", err)
	}

	// 5: save partial local config so a crash here is recoverable. Note
	// the empty Concurrency — we'll fill it after we can decrypt the
	// manifest in step 8.
	cfg := LocalConfig{
		WorkspaceID:       pt.WorkspaceID,
		DeviceID:          deviceID,
		Bucket:            pt.Bucket,
		MasterFingerprint: append([]byte(nil), pt.MasterFP...),
	}
	if err := opts.State.SaveConfig(cfg); err != nil {
		return nil, err
	}

	// 6: poll for the primary's handoff. Sealed blob is opaque to anyone
	// who doesn't hold the new device's box priv.
	handoff, err := awaitHandoff(ctx, readProvider, pt.PID, opts)
	if err != nil {
		return nil, err
	}

	// 7: unseal handoff.
	plain, err := dcrypto.Open(devBox, dev.BoxPriv, handoff)
	if err != nil {
		return nil, fmt.Errorf("unseal handoff: %w", err)
	}
	var ho domain.PairingHandoff
	if err := json.Unmarshal(plain, &ho); err != nil {
		return nil, fmt.Errorf("parse handoff: %w", err)
	}
	// Sanity check: master pubkey in the handoff must hash to the
	// fingerprint we pinned from the pairing token.
	gotFP := sha256.Sum256(ho.MasterPub)
	if !bytes.Equal(gotFP[:], pt.MasterFP) {
		return nil, fmt.Errorf("%w: handoff master pub does not match pinned fingerprint", domain.ErrSignatureInvalid)
	}

	// 8: fetch + verify the manifest under the freshly-received CPRK.
	body, err := readProvider.Get(ctx, domain.ManifestKey)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	m, err := manifest.Decrypt(body, ho.CPRK, pt.WorkspaceID)
	if err != nil {
		return nil, err
	}
	if err := manifest.Verify(m); err != nil {
		return nil, err
	}
	if err := assertMasterFingerprint(m, cfg.MasterFingerprint); err != nil {
		return nil, err
	}
	if _, ok := m.Devices[deviceID]; !ok {
		return nil, fmt.Errorf("manifest does not yet record this device (id=%s) — primary may have aborted the pairing", deviceID)
	}

	// 9: persist CPRK + finalize config.
	if err := opts.State.SaveCPRK(ho.CPRK); err != nil {
		return nil, fmt.Errorf("save cprk: %w", err)
	}
	cfg.Concurrency = m.Concurrency
	cfg.MinManifestSequence = m.Sequence
	if err := opts.State.SaveConfig(cfg); err != nil {
		return nil, err
	}

	// 10: peer mode — if the primary included the parent S3 cred in the
	// handoff, save it locally so this device can drift mount / drift
	// grant on its own. Without this the device is identity-only.
	peerMode := false
	if ho.Parent != nil {
		parent := &credentials.Parent{
			Provider:        ho.Parent.Provider,
			AccessKeyID:     ho.Parent.AccessKeyID,
			SecretAccessKey: ho.Parent.SecretAccessKey,
		}
		if err := opts.State.SaveParent(parent); err != nil {
			return nil, fmt.Errorf("save peer parent cred: %w", err)
		}
		peerMode = true
	}

	// 11: DD-9 bearer mode — if the primary issued a PeerCred and sealed
	// it in the handoff, unmarshal it, verify the Ed25519 signature
	// against the master pubkey we just learned (and pinned the FP of
	// in step 5), and save to keychain. Bearer mode is mutually
	// exclusive with v1 peer mode (the primary enforces this at
	// LinkInit) so we never have both ho.Parent AND ho.PeerCred.
	bearerMode := false
	if len(ho.PeerCred) > 0 {
		if peerMode {
			return nil, errors.New("handoff carries BOTH parent cred AND PeerCred — refusing to choose; primary must pick one mode")
		}
		var pc credentials.PeerCred
		if err := json.Unmarshal(ho.PeerCred, &pc); err != nil {
			return nil, fmt.Errorf("parse PeerCred from handoff: %w", err)
		}
		// Verify the signature under the master pubkey we just unsealed.
		// MasterPub was already cross-checked against the pinned FP in
		// step 7, so trusting it here is consistent with the rest of the
		// pairing trust chain.
		if err := credentials.VerifyPeerCred(pc, ed25519.PublicKey(ho.MasterPub)); err != nil {
			return nil, fmt.Errorf("PeerCred from handoff failed verification: %w", err)
		}
		// Sanity: the cred's DeviceID must match the device we just
		// enrolled. Otherwise the primary minted a cred for someone
		// else and the handoff is misrouted.
		if pc.DeviceID != deviceID {
			return nil, fmt.Errorf("PeerCred DeviceID %s does not match this device %s — refusing to save", pc.DeviceID, deviceID)
		}
		if err := opts.State.SavePeerCred(&pc); err != nil {
			return nil, fmt.Errorf("save bearer PeerCred: %w", err)
		}
		bearerMode = true
	}

	fpRaw := sha256.Sum256(dev.SignPub())
	return &LinkClaimResult{
		DeviceID:          deviceID,
		WorkspaceID:       pt.WorkspaceID,
		DeviceFingerprint: hex.EncodeToString(fpRaw[:]),
		SAS:               sas,
		PeerMode:          peerMode,
		BearerMode:        bearerMode,
	}, nil
}

// DecodePairingToken parses + verifies a pairing token. Returns the
// validated payload struct. Verification:
//   1. Wire format
//   2. Ed25519 signature against embedded IssuerPub
//   3. MasterFP matches SHA-256(IssuerPub) — self-consistency
func DecodePairingToken(encoded string) (*domain.PairingToken, error) {
	payload, sig, err := dcrypto.DecodePairing(encoded)
	if err != nil {
		return nil, err
	}
	var pt domain.PairingToken
	if err := json.Unmarshal(payload, &pt); err != nil {
		return nil, fmt.Errorf("%w: %v", domain.ErrTokenMalformed, err)
	}
	if pt.Version != domain.PairingVersion {
		return nil, fmt.Errorf("%w: unsupported pairing version %d", domain.ErrTokenMalformed, pt.Version)
	}
	if len(pt.IssuerPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: missing or malformed IssuerPub", domain.ErrTokenMalformed)
	}
	if err := dcrypto.Verify(ed25519.PublicKey(pt.IssuerPub), payload, sig); err != nil {
		return nil, err
	}
	expectedFP := sha256.Sum256(pt.IssuerPub)
	if !bytes.Equal(expectedFP[:], pt.MasterFP) {
		return nil, fmt.Errorf("%w: MasterFP does not match IssuerPub", domain.ErrTokenMalformed)
	}
	return &pt, nil
}

// awaitHandoff polls the bucket for the primary's handoff blob. Errors
// other than NotFound are returned immediately; NotFound is the expected
// "primary hasn't confirmed yet" case. The loop also checks for an
// abort flag written by the primary when SAS verification fails on
// their side, so the secondary fails fast instead of waiting the full
// timeout.
func awaitHandoff(ctx context.Context, provider storage.Provider, pid string, opts LinkClaimOptions) ([]byte, error) {
	deadline := opts.Now().Add(opts.Timeout)
	for {
		// Check abort flag first. If the primary rejected the SAS, they
		// write this marker; we surface a clear message rather than
		// hanging the secondary's terminal until Timeout.
		if _, err := provider.Get(ctx, domain.PairingAbortKey(pid)); err == nil {
			return nil, fmt.Errorf("pairing aborted by primary device (SAS mismatch or user declined at confirm prompt)")
		}
		body, err := provider.Get(ctx, domain.PairingHandoffKey(pid))
		if err == nil {
			return body, nil
		}
		if !errors.Is(err, domain.ErrObjectNotFound) {
			return nil, fmt.Errorf("fetch handoff: %w", err)
		}
		if !opts.Now().Before(deadline) {
			return nil, fmt.Errorf("pairing timed out — primary did not confirm within %s", opts.Timeout)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(opts.PollInterval):
		}
	}
}

// deriveDeviceID returns a deterministic id from the device's Ed25519
// signing pubkey. Deterministic so re-running LinkClaim with the same
// token + same device key produces the same id (idempotent retries).
func deriveDeviceID(signPub []byte) string {
	h := sha256.Sum256(signPub)
	return "dev_" + hex.EncodeToString(h[:4])
}

// suppress unused-import warning when build configuration drops os usage.
var _ = os.ErrNotExist
