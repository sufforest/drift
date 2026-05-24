package domain

// Provider identifiers used in WorkspaceConfig.Provider.
const (
	ProviderR2     = "r2"
	ProviderB2     = "b2"
	ProviderS3     = "s3"
	ProviderMinIO  = "minio"
	ProviderWasabi = "wasabi"
)

// Credential provider identifiers used in WorkspaceConfig.CredentialProvider.
// Per the open-decisions resolution, v1 uses file-based storage. The "keyring"
// option is reserved for v1.1 when zalando/go-keyring is added.
const (
	CredProviderEnvironment = "environment"
	CredProviderFile        = "file"    // encrypted file under config dir (v1 default)
	CredProviderKeyring     = "keyring" // reserved for v1.1
	CredProviderStatic      = "static"  // inline in config, with warning
)

// Config is the user's local config at ~/.config/drift/config.yaml.
type Config struct {
	DefaultWorkspace string                     `yaml:"default_workspace"`
	Workspaces       map[string]WorkspaceConfig `yaml:"workspaces"`
}

// WorkspaceConfig is one entry under Config.Workspaces.
type WorkspaceConfig struct {
	Provider           string            `yaml:"provider"`
	Bucket             string            `yaml:"bucket"`
	Endpoint           string            `yaml:"endpoint"`
	Region             string            `yaml:"region"`
	CredentialProvider string            `yaml:"credential_provider"`
	CredentialConfig   map[string]string `yaml:"credential_config,omitempty"`
}
