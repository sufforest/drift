package domain

import "time"

// TokenVersion is the current wire-format version. v2 added the
// MasterFingerprint field so bearers can pin the workspace's trust root
// from the token alone.
const TokenVersion = 2

// TokenPrefix is the human-readable scheme prefix written by EncodeToken.
const TokenPrefix = "drift1"

// BucketInfo describes how to reach the workspace bucket. Embedded in tokens
// so a redeeming host can connect without prior configuration.
type BucketInfo struct {
	Provider string `json:"provider"` // "r2", "b2", "s3", "minio", "wasabi"
	Endpoint string `json:"endpoint"`
	Name     string `json:"name"`
	Region   string `json:"region"`
}

// Token is the pasteable capability the user copies between machines.
//
// IssuerPub is the Ed25519 public key of the device that minted this token
// and is the *self-asserted trust anchor* for verification. Bearers verify
// the token signature against IssuerPub FIRST, before using any other
// field — including Bucket and ControlCred, which drive outbound network
// behavior and would otherwise be SSRF / credential-exfiltration vectors.
// After fetching the manifest, the bearer cross-checks that IssuerPub
// matches a known device in the workspace; only then is the token
// considered fully authorized.
//
// The Token carries a narrowly-scoped ControlCred so the bearer can read
// (and only read) the three control-plane objects they need: the manifest,
// the revocations list, and their own credentials blob. The bearer's full
// data-plane credential (DataCred) lives encrypted-at-rest in that blob.
//
// Splitting the credential this way means the bearer's S3 access can never
// write to .drift/*, even if extracted and used directly via boto3/rclone.
type Token struct {
	Version           int          `json:"v"`
	TID               string       `json:"tid"`
	WorkspaceID       string       `json:"wid"`
	Bucket            BucketInfo   `json:"bucket"`
	RedemptionCode    []byte       `json:"rc"`   // 32 random bytes
	ControlCred       S3Credential `json:"cc"`   // GET-only on .drift/{manifest,revocations,credentials/<tid>}.enc
	IssuerPub         []byte       `json:"ipub"` // Ed25519 pubkey of issuing device; cross-checked against manifest at redeem time
	MasterFingerprint []byte       `json:"mfp"`  // SHA-256 of workspace master Ed25519 pubkey; pinned trust root
}

// S3Credential is a scoped, time-bounded set of S3 credentials minted by the
// issuing device. v1 uses R2 local JWT signing.
type S3Credential struct {
	AccessKeyID     string    `json:"access_key_id"`
	SecretAccessKey string    `json:"secret_access_key"`
	SessionToken    string    `json:"session_token,omitempty"`
	Expires         time.Time `json:"expires"`
}

// CompartmentGrant is what a token gives the bearer for one compartment.
type CompartmentGrant struct {
	Key  []byte `json:"key"`  // symmetric compartment key
	Mode string `json:"mode"` // TokenModeRW or TokenModeRO
}

// TokenCredentials is stored at .drift/credentials/<tid>.enc, encrypted with
// the redemption code from the matching Token.
//
// DataCred is the bearer's data-plane credential: scoped strictly to the
// authorized compartment prefixes with no .drift/* access. The mount layer
// uses this for rclone reads/writes.
type TokenCredentials struct {
	DataCred     S3Credential                `json:"dc"`
	Compartments map[string]CompartmentGrant `json:"compartments"`
	CPRK         []byte                      `json:"cprk"` // control plane read key
	ExpiresAt    time.Time                   `json:"exp"`
	IssuedAt     time.Time                   `json:"iat"`
	IssuedBy     string                      `json:"iss"`
}
