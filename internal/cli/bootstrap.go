package cli

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/credentials"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/storage"
	"github.com/sufforest/drift/internal/workspace"
)

// stateDir returns the directory holding local workspace state. Resolution
// order:
//
//  1. --config <dir>    explicit path
//  2. --workspace <n>   ~/.config/drift/workspaces/<n>/
//  3. ~/.config/drift/current pointer file content
//  4. ~/.config/drift/  (legacy single-workspace layout)
func stateDir(cmd *cobra.Command) (string, error) {
	if c, _ := cmd.Flags().GetString("config"); c != "" {
		return c, nil
	}
	root, err := workspace.DefaultStateDir()
	if err != nil {
		return "", err
	}
	if ws, _ := cmd.Flags().GetString("workspace"); ws != "" {
		return workspace.WorkspaceStateDir(root, ws)
	}
	if pinned, ok := workspace.CurrentWorkspace(root); ok {
		return workspace.WorkspaceStateDir(root, pinned)
	}
	return root, nil
}

// loadWorkspace constructs a workspace.Workspace for an existing primary
// device. The Provider is the real S3 client driven by the parent
// credential persisted at `drift init`. The lock-object writer (used on
// providers without conditional PUT, e.g. B2) is wired with signer +
// verifier here so the device's signing key authenticates locks.
func loadWorkspace(ctx context.Context, cmd *cobra.Command) (*workspace.Workspace, error) {
	dir, err := stateDir(cmd)
	if err != nil {
		return nil, err
	}
	state, err := workspace.NewState(dir)
	if err != nil {
		return nil, err
	}
	cfg, err := state.LoadConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no workspace in %s; run `drift init` first", dir)
		}
		return nil, err
	}
	parent, err := state.LoadParent()
	if err != nil {
		return nil, err
	}
	device, err := state.LoadDevice()
	if err != nil {
		return nil, err
	}
	provider, err := workspace.BuildProviderFromParent(ctx, cfg.Bucket, parent)
	if err != nil {
		return nil, err
	}
	// Build the writer with lock-signing wired up; the closure over
	// `cfg`/`device` is read-only at this point. Lock signatures cover
	// the canonical bytes produced by storage.lockSigningBytes; lookup
	// of verifying keys re-reads the manifest each time so a freshly-
	// enrolled device's locks verify correctly.
	signer, verifier := lockAuthFor(cfg.DeviceID, device, provider, cfg)
	writer, err := selectWriter(ctx, provider, cfg, signer, verifier)
	if err != nil {
		return nil, err
	}
	return workspace.Load(ctx, workspace.Options{
		State:    state,
		Provider: provider,
		Writer:   writer,
	})
}

// selectWriter picks the ReadModifyWriter for the workspace. Probes and
// then honors a sticky floor: if the recorded concurrency is
// "conditional_put" but the probe now claims it isn't supported, refuse
// to silently downgrade. A bucket admin temporarily breaking conditional
// PUT (to force the lock-object fallback) would otherwise be enough to
// win the lock-ownership race during a mutation.
//
// signer + verifier are optional; if non-nil they're wired into the
// lock-object writer so locks are Ed25519-signed.
func selectWriter(ctx context.Context, provider storage.Provider, cfg *workspace.LocalConfig, signer storage.LockSigner, verifier storage.LockVerifier) (storage.ReadModifyWriter, error) {
	allowDowngrade := os.Getenv("DRIFT_ALLOW_DOWNGRADE") == "1"
	caps, err := storage.ProbeCapabilities(ctx, provider)
	if err != nil {
		// Probe failed entirely (network blip). Fall back to recorded
		// preference; the bucket admin can't cause this without also
		// causing every other read/write to fail, so it's not a
		// downgrade vector.
		if cfg != nil && cfg.Concurrency == domain.ConcurrencyConditionalPut {
			return storage.SelectWriterWithLockAuth(provider, storage.Capabilities{ConditionalPut: true}, cfg.DeviceID, signer, verifier), nil
		}
		if cfg != nil && cfg.Concurrency != "" {
			return storage.SelectWriterWithLockAuth(provider, storage.Capabilities{ConditionalPut: false}, cfg.DeviceID, signer, verifier), nil
		}
		return nil, fmt.Errorf("capability probe: %w", err)
	}
	if cfg != nil && cfg.Concurrency == domain.ConcurrencyConditionalPut && !caps.ConditionalPut && !allowDowngrade {
		return nil, fmt.Errorf("provider previously supported conditional PUT but now does not; refusing to downgrade to lock-object (set DRIFT_ALLOW_DOWNGRADE=1 if intentional)")
	}
	deviceID := ""
	if cfg != nil {
		deviceID = cfg.DeviceID
	}
	return storage.SelectWriterWithLockAuth(provider, caps, deviceID, signer, verifier), nil
}

// lockAuthFor returns a signer + verifier pair for the lock-object writer.
// v1 supports only the primary device, so the verifier accepts a lock only
// when it's signed by THIS device — anything else is treated as forgery
// and broken. Once `drift link` lands and there are multiple legitimate
// signers, the verifier should consult the manifest's device list.
func lockAuthFor(deviceID string, device *dcrypto.DeviceKey, provider storage.Provider, cfg *workspace.LocalConfig) (storage.LockSigner, storage.LockVerifier) {
	if device == nil || cfg == nil {
		return nil, nil
	}
	signer := storage.LockSigner(func(body []byte) ([]byte, error) {
		return dcrypto.Sign(device.SignPriv, body), nil
	})
	pub := device.SignPriv.Public().(ed25519.PublicKey)
	verifier := storage.LockVerifier(func(holderID string, body, sig []byte) error {
		if holderID != deviceID {
			return fmt.Errorf("lock auth: holder %q is not this device (v1 supports a single primary)", holderID)
		}
		if len(sig) == 0 {
			return errors.New("lock auth: no signature")
		}
		if !ed25519.Verify(pub, body, sig) {
			return errors.New("lock auth: signature does not verify against this device")
		}
		return nil
	})
	return signer, verifier
}

// loadParentFromFlags loads the parent provider credential for `drift init`,
// looking at the --parent-file flag, $DRIFT_ACCESS_KEY_ID + DRIFT_SECRET_ACCESS_KEY,
// then $AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY.
func loadParentFromFlags(cmd *cobra.Command, providerID string) (*credentials.Parent, error) {
	if path, _ := cmd.Flags().GetString("parent-file"); path != "" {
		return (&credentials.FileProvider{Path: path}).Load()
	}
	env := &credentials.EnvironmentProvider{ProviderID: providerID}
	return env.Load()
}
