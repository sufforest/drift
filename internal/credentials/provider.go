package credentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// Parent is a parent provider credential — the long-lived account-level secret
// the user holds in their keychain. v1 stores it file-backed; v1.1 will add
// OS-keychain providers (zalando/go-keyring).
//
// Never log, print, or marshal Parent outside the provider chain.
type Parent struct {
	Provider        string `json:"provider"`   // "r2", "b2", "s3", etc.
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	// AccountID is optional R2/B2 metadata (not a secret on its own).
	AccountID string `json:"account_id,omitempty"`
}

// ParentProvider supplies the parent credential for the issuing device. The
// chain pattern (try env, then file, etc.) is implemented in Chain below.
type ParentProvider interface {
	Load() (*Parent, error)
	Name() string
}

// EnvironmentProvider loads parent creds from process environment variables.
// AWS-style names are accepted so users can reuse their existing shell setup.
type EnvironmentProvider struct {
	// ProviderID is recorded into Parent.Provider for downstream code that
	// switches on it (e.g., picking a Minter).
	ProviderID string
}

func (e *EnvironmentProvider) Name() string { return "environment" }

func (e *EnvironmentProvider) Load() (*Parent, error) {
	id := os.Getenv("DRIFT_ACCESS_KEY_ID")
	secret := os.Getenv("DRIFT_SECRET_ACCESS_KEY")
	if id == "" {
		id = os.Getenv("AWS_ACCESS_KEY_ID")
	}
	if secret == "" {
		secret = os.Getenv("AWS_SECRET_ACCESS_KEY")
	}
	if id == "" || secret == "" {
		return nil, errors.New("credentials: no parent creds in environment")
	}
	return &Parent{
		Provider:        e.ProviderID,
		AccessKeyID:     id,
		SecretAccessKey: secret,
		AccountID:       os.Getenv("DRIFT_ACCOUNT_ID"),
	}, nil
}

// FileProvider loads parent creds from a JSON file. v1 default.
//
// File format:
//
//	{
//	  "provider": "r2",
//	  "access_key_id": "...",
//	  "secret_access_key": "...",
//	  "account_id": "abc123"  // optional
//	}
//
// The file should be `chmod 0600`. FileProvider warns (via the returned
// error) if it finds the file readable by others.
type FileProvider struct {
	Path string
}

func (f *FileProvider) Name() string { return "file:" + f.Path }

func (f *FileProvider) Load() (*Parent, error) {
	st, err := os.Stat(f.Path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", f.Path, err)
	}
	if mode := st.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("credentials: %s has permissive mode %o (want 0600); refusing to load", f.Path, mode)
	}
	body, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", f.Path, err)
	}
	var p Parent
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("parse %s: %w", f.Path, err)
	}
	if p.AccessKeyID == "" || p.SecretAccessKey == "" {
		return nil, fmt.Errorf("credentials: %s is missing access_key_id or secret_access_key", f.Path)
	}
	return &p, nil
}

// Chain tries providers in order and returns the first successful load. The
// last error is wrapped if all fail, so callers can see why each layer
// declined.
type Chain struct{ Providers []ParentProvider }

func (c *Chain) Name() string { return "chain" }

func (c *Chain) Load() (*Parent, error) {
	var lastErr error
	for _, p := range c.Providers {
		got, err := p.Load()
		if err == nil {
			return got, nil
		}
		lastErr = fmt.Errorf("%s: %w", p.Name(), err)
	}
	if lastErr == nil {
		return nil, errors.New("credentials: empty provider chain")
	}
	return nil, lastErr
}
