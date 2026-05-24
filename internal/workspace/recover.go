package workspace

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/sufforest/drift/internal/credentials"
	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/manifest"
	"github.com/sufforest/drift/internal/recovery"
)

// RecoverParams describes a recovery bootstrap on a fresh machine.
type RecoverParams struct {
	Bucket     domain.BucketInfo
	Parent     *credentials.Parent
	Passphrase string
	DeviceName string
}

// Recover bootstraps a workspace on a fresh machine using a passphrase
// previously configured via SaveRecovery. The flow:
//
//  1. Fetch the recovery blob from the bucket
//  2. Decrypt it with the passphrase → master key + workspace id
//  3. Derive CPRK and fetch the current manifest
//  4. Generate a new device key + master-signed enrollment
//  5. Re-seal every compartment key for the new device, using the
//     master's box priv on the master pseudo-device seal
//  6. Upload the new manifest, persist local state
//
// The state dir must not already contain a master.json — Recover refuses
// to overwrite to avoid accidental key loss.
func Recover(ctx context.Context, o Options, params RecoverParams) (*Workspace, error) {
	if err := requireOptions(o); err != nil {
		return nil, err
	}
	if params.Parent == nil {
		return nil, errors.New("recovery: parent credential required")
	}
	if params.Bucket.Name == "" {
		return nil, errors.New("recovery: bucket name required")
	}
	if params.Passphrase == "" {
		return nil, errors.New("recovery: passphrase required")
	}
	if o.State.HasMaster() {
		return nil, errors.New("recovery: this state dir already has a master.json; refusing to overwrite")
	}

	blob, err := FetchRecoveryBlob(ctx, o.Provider)
	if err != nil {
		return nil, err
	}
	master, wid, err := recovery.Unwrap(blob, params.Passphrase)
	if err != nil {
		return nil, err
	}
	masterFP := masterFingerprint(master.SignPub())

	// Derive CPRK at epoch 0 first; if the workspace has rotated CPRK we
	// fall through to the per-epoch search below.
	cprk, err := dcrypto.DeriveCPRK(master.Root, wid, 0)
	if err != nil {
		return nil, err
	}

	body, err := o.Provider.Get(ctx, domain.ManifestKey)
	if err != nil {
		return nil, fmt.Errorf("recovery: fetch manifest: %w", err)
	}
	m, usedCPRK, usedEpoch, err := decryptManifestSearchingEpochs(body, master, wid, cprk)
	if err != nil {
		return nil, err
	}
	if err := manifest.Verify(m); err != nil {
		return nil, fmt.Errorf("recovery: verify manifest: %w", err)
	}
	if err := assertMasterFingerprint(m, masterFP); err != nil {
		return nil, fmt.Errorf("recovery: manifest's pinned master fingerprint does not match the recovered master — bucket may be under a different workspace or post master-rotation that we can't follow: %w", err)
	}

	// Forge a new device key + master-signed enrollment cert.
	device, err := dcrypto.GenerateDeviceKey()
	if err != nil {
		return nil, fmt.Errorf("recovery: generate device key: %w", err)
	}
	devBoxPub, err := device.BoxPub()
	if err != nil {
		return nil, err
	}
	newDID := "dev_" + shortID(8)
	deviceName := params.DeviceName
	if deviceName == "" {
		deviceName = newDID
	}
	now := optionsNow(o)
	enrollment := manifest.SignEnrollment(
		newDID, now.UnixNano(),
		device.SignPub(), devBoxPub[:],
		master.SignPriv,
	)

	// Re-seal compartment keys: use master's box priv to open the seal
	// stored against the master pseudo-device, then seal for the new
	// device. This works because Init / CompartmentCreate seal for every
	// device in m.Devices, including the master pseudo-device entry.
	masterBoxPub, err := master.BoxPub()
	if err != nil {
		return nil, err
	}
	resealed := 0
	for name, c := range m.Compartments {
		sealedForMaster, ok := c.EncryptedKeys[domain.MasterDeviceID]
		if !ok {
			return nil, fmt.Errorf("recovery: compartment %q has no seal for master — cannot re-seal for new device", name)
		}
		plain, err := dcrypto.Open(masterBoxPub, master.BoxPriv, sealedForMaster)
		if err != nil {
			return nil, fmt.Errorf("recovery: open compartment %q seal: %w", name, err)
		}
		sealedForNew, err := dcrypto.SealFor(devBoxPub, plain)
		if err != nil {
			return nil, fmt.Errorf("recovery: re-seal compartment %q: %w", name, err)
		}
		if c.EncryptedKeys == nil {
			c.EncryptedKeys = map[string][]byte{}
		}
		c.EncryptedKeys[newDID] = sealedForNew
		m.Compartments[name] = c
		resealed++
	}

	m.Devices[newDID] = domain.Device{
		ID:         newDID,
		Name:       deviceName,
		PublicKey:  device.SignPub(),
		EncryptKey: devBoxPub[:],
		EnrolledAt: now,
		LastSeen:   now,
	}
	if m.Enrollments == nil {
		m.Enrollments = map[string]domain.Enrollment{}
	}
	m.Enrollments[newDID] = enrollment
	m.UpdatedAt = now
	m.Sequence++
	if err := manifest.Sign(m, newDID, device.SignPriv); err != nil {
		return nil, fmt.Errorf("recovery: sign manifest: %w", err)
	}
	updated, err := manifest.Encrypt(m, usedCPRK)
	if err != nil {
		return nil, fmt.Errorf("recovery: encrypt manifest: %w", err)
	}
	if err := o.Provider.Put(ctx, domain.ManifestKey, updated); err != nil {
		return nil, fmt.Errorf("recovery: upload manifest: %w", err)
	}

	// Persist local state. Order mirrors Init: parent → device → master → config.
	if err := o.State.SaveParent(params.Parent); err != nil {
		return nil, fmt.Errorf("recovery: save parent: %w", err)
	}
	if err := o.State.SaveDevice(device); err != nil {
		return nil, fmt.Errorf("recovery: save device: %w", err)
	}
	if err := o.State.SaveMaster(master); err != nil {
		return nil, fmt.Errorf("recovery: save master: %w", err)
	}
	cfg := LocalConfig{
		WorkspaceID:         wid,
		DeviceID:            newDID,
		Bucket:              params.Bucket,
		Concurrency:         m.Concurrency,
		MinManifestSequence: m.Sequence,
		MasterFingerprint:   masterFP,
		CPRKEpoch:           usedEpoch,
	}
	if err := o.State.SaveConfig(cfg); err != nil {
		return nil, fmt.Errorf("recovery: save config: %w", err)
	}

	ws := &Workspace{
		State:    o.State,
		Provider: o.Provider,
		Writer:   o.Writer,
		Mounter:  o.Mounter,
		Master:   master,
		Device:   device,
		Config:   &cfg,
		CPRK:     usedCPRK,
		now:      optionsNowFunc(o),
	}
	_ = ws.auditEmitter().Emit(ctx, domain.AuditKindRecoveryRestored, wid, map[string]any{
		"new_device_id":         newDID,
		"resealed_compartments": resealed,
	})
	return ws, nil
}

// decryptManifestSearchingEpochs tries epoch 0 first, then walks 1..N
// (capped at 16) in case CPRK has been rotated since the recovery blob
// was written. This is a recovery-only convenience — normal Manifest()
// uses the epoch recorded in LocalConfig.
func decryptManifestSearchingEpochs(body []byte, master *dcrypto.MasterKey, wid string, initial []byte) (*domain.Manifest, []byte, uint64, error) {
	const maxEpoch = 16
	if m, err := manifest.Decrypt(body, initial, wid); err == nil {
		return m, initial, 0, nil
	}
	for epoch := uint64(1); epoch <= maxEpoch; epoch++ {
		cprk, err := dcrypto.DeriveCPRK(master.Root, wid, epoch)
		if err != nil {
			return nil, nil, 0, err
		}
		if m, err := manifest.Decrypt(body, cprk, wid); err == nil {
			return m, cprk, epoch, nil
		}
	}
	return nil, nil, 0, fmt.Errorf("recovery: manifest does not decrypt under any CPRK epoch 0..%d — workspace may be too old, or master key is wrong", maxEpoch)
}

// unused import guard for ed25519 — keep so future field-width checks
// don't trigger an unused warning when added.
var _ = ed25519.PrivateKeySize
