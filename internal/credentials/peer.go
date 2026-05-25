package credentials

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// PeerCredVersion is the wire-format version for serialized PeerCred
// blobs. Bumped to 2 in DD-10 (split-credential shape: Data + optional
// Control). Verification refuses unknown versions; v1 (DD-9) creds
// produce ErrPeerCredOutdated so the operator gets a clear "re-pair"
// instruction instead of a confusing signature failure.
const PeerCredVersion = 2

// ErrPeerCredOutdated is returned when a PeerCred on disk is from a
// schema version older than PeerCredVersion. The operator must re-pair
// the device to upgrade. Wrapping makes it errors.Is-detectable so
// CLI bootstrap can surface a specific message.
var ErrPeerCredOutdated = errors.New("credentials: PeerCred is from an older schema version — re-pair the device")

// ScopedCredSet is one S3-shaped credential triple plus the bucket
// metadata needed to construct an S3 client from it. Each cred is the
// output of a single Minter.Mint call (one R2 JWT, one STS session
// token, or one B2 application key — provider-agnostic shape).
type ScopedCredSet struct {
	AccessKeyID     string `json:"ak"`
	SecretAccessKey string `json:"sk"`
	SessionToken    string `json:"session"`
	Endpoint        string `json:"endpoint"`
	Bucket          string `json:"bucket"`
}

// PeerCred is the long-lived, master-signed bearer credential issued
// to a peer device under DD-9 + DD-10. It carries up to TWO scoped
// credentials:
//
//   - Data: read-write on the peer's compartments/<vol>/* paths.
//     Always populated. This is what rclone uses for mount/sync.
//
//   - Control: read-only on .drift/manifest.enc + .drift/revocations.enc
//     + .drift/peers/<deviceID>/refresh.enc. Optional (nil OK).
//     Populated by backends that can't express per-path scope in one
//     cred (R2 local-sign, B2). Backends that CAN (AWS STS, GCS access
//     tokens, R2 server-mint with `actions`) populate only Data and
//     leave Control nil; SplitProvider routes everything through Data.
//
// The Ed25519 IssuerSig binds the entire body (both creds + metadata)
// to the workspace's master key. Substitution of either cred or the
// flip from "has Control" to "no Control" invalidates the signature
// (the hasControl bit is canonicalized into the signing body).
//
// PeerCred is a SECRET — never log, print, or transmit unsealed.
type PeerCred struct {
	Version   int            `json:"v"`
	DeviceID  string         `json:"did"`
	JTI       string         `json:"jti"` // outer identity; revocations.enc tracks this
	Scope     []string       `json:"scope"`
	Mode      string         `json:"mode"`
	Data      ScopedCredSet  `json:"data"`
	Control   *ScopedCredSet `json:"control,omitempty"`
	IssuedAt  time.Time      `json:"iat"`
	ExpiresAt time.Time      `json:"exp"`
	RefreshAt time.Time      `json:"refresh_at"`
	IssuerSig []byte         `json:"sig"`
}

// PeerCredSigningBytes returns the canonical byte sequence that the
// master priv signs over. Length-prefixed, ordered, domain-tagged.
// Includes a hasControl bit so the presence-or-absence of the Control
// cred is bound into the signature (an attacker can't strip Control
// from a serialized PeerCred and have the result still verify).
//
// Fields are listed explicitly rather than via reflection so any
// future schema bump must update both Sign and Verify in lockstep —
// silent drift between issuance and validation is impossible.
func PeerCredSigningBytes(p PeerCred) []byte {
	var buf []byte
	buf = appendLP(buf, []byte("drift/v1/peercred")) // domain tag retained from v1 for upgrade-friendliness
	buf = appendLPUint64(buf, uint64(p.Version))
	buf = appendLP(buf, []byte(p.DeviceID))
	buf = appendLP(buf, []byte(p.JTI))
	for _, s := range p.Scope {
		buf = appendLP(buf, []byte(s))
	}
	buf = appendLP(buf, []byte("__scope_end__"))
	buf = appendLP(buf, []byte(p.Mode))
	// Data cred (always present).
	buf = appendScopedCred(buf, p.Data)
	// hasControl bit + optional Control cred.
	if p.Control == nil {
		buf = appendLP(buf, []byte{0})
	} else {
		buf = appendLP(buf, []byte{1})
		buf = appendScopedCred(buf, *p.Control)
	}
	buf = appendLPUint64(buf, uint64(p.IssuedAt.UnixNano()))
	buf = appendLPUint64(buf, uint64(p.ExpiresAt.UnixNano()))
	buf = appendLPUint64(buf, uint64(p.RefreshAt.UnixNano()))
	return buf
}

// appendScopedCred encodes one ScopedCredSet into buf with each field
// length-prefixed. Used twice if Control is present.
func appendScopedCred(buf []byte, c ScopedCredSet) []byte {
	buf = appendLP(buf, []byte(c.AccessKeyID))
	buf = appendLP(buf, []byte(c.SecretAccessKey))
	buf = appendLP(buf, []byte(c.SessionToken))
	buf = appendLP(buf, []byte(c.Endpoint))
	buf = appendLP(buf, []byte(c.Bucket))
	return buf
}

// SignPeerCred signs the canonical body of p with masterPriv and
// returns a copy of p with IssuerSig populated.
func SignPeerCred(p PeerCred, masterPriv ed25519.PrivateKey) PeerCred {
	body := PeerCredSigningBytes(p)
	digest := sha256.Sum256(body)
	p.IssuerSig = ed25519.Sign(masterPriv, digest[:])
	return p
}

// VerifyPeerCred checks p.IssuerSig under masterPub. Returns nil if
// the signature is valid AND the version is recognized AND core
// fields are populated. Returns ErrPeerCredOutdated (wrapped) for
// pre-DD-10 versions so the CLI can prompt the operator to re-pair.
// Any other failure returns a generic wrapped error — refuse to use
// the cred on any verify error.
func VerifyPeerCred(p PeerCred, masterPub ed25519.PublicKey) error {
	if p.Version < PeerCredVersion {
		return fmt.Errorf("%w (found version %d, current is %d)", ErrPeerCredOutdated, p.Version, PeerCredVersion)
	}
	if p.Version != PeerCredVersion {
		return fmt.Errorf("credentials: unsupported PeerCred version %d (want %d)", p.Version, PeerCredVersion)
	}
	if p.DeviceID == "" || p.JTI == "" {
		return errors.New("credentials: PeerCred is missing required core fields")
	}
	if p.Data.AccessKeyID == "" || p.Data.SecretAccessKey == "" || p.Data.SessionToken == "" {
		return errors.New("credentials: PeerCred Data cred missing required fields")
	}
	if p.Control != nil {
		if p.Control.AccessKeyID == "" || p.Control.SecretAccessKey == "" || p.Control.SessionToken == "" {
			return errors.New("credentials: PeerCred Control cred missing required fields")
		}
	}
	if len(p.IssuerSig) != ed25519.SignatureSize {
		return fmt.Errorf("credentials: PeerCred IssuerSig wrong size (got %d, want %d)", len(p.IssuerSig), ed25519.SignatureSize)
	}
	body := PeerCredSigningBytes(p)
	digest := sha256.Sum256(body)
	if !ed25519.Verify(masterPub, digest[:], p.IssuerSig) {
		return errors.New("credentials: PeerCred signature does not verify under provided master pubkey")
	}
	return nil
}

// IsExpired reports whether p is past its ExpiresAt as of now.
func (p PeerCred) IsExpired(now time.Time) bool {
	return !now.Before(p.ExpiresAt)
}

// NeedsRefresh reports whether p has crossed its RefreshAt boundary.
func (p PeerCred) NeedsRefresh(now time.Time) bool {
	return !now.Before(p.RefreshAt)
}

// appendLP appends a length-prefixed byte slice (4-byte BE length
// followed by the bytes) to buf.
func appendLP(buf, b []byte) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(b)))
	buf = append(buf, lenBuf[:]...)
	buf = append(buf, b...)
	return buf
}

// appendLPUint64 appends a fixed-width 8-byte BE uint64 prefixed by
// its 4-byte length (always 8).
func appendLPUint64(buf []byte, v uint64) []byte {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], 8)
	buf = append(buf, lenBuf[:]...)
	var vBuf [8]byte
	binary.BigEndian.PutUint64(vBuf[:], v)
	buf = append(buf, vBuf[:]...)
	return buf
}
