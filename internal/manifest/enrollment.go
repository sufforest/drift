package manifest

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"time"

	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/domain"
)

func unixNanoTime(n int64) time.Time { return time.Unix(0, n).UTC() }

// EnrollmentSigningBytes is the canonical byte form signed by master.
// Layout: "drift/v1/enroll|" + did + "|" + signed_at_unix_nano(8B BE)
// + "|" + b64(sign_pub) + "|" + b64(box_pub)
//
// Plain text (not JSON) so a future marshaller change does not invalidate
// existing signatures.
func EnrollmentSigningBytes(deviceID string, signedAtUnixNano int64, signPub, boxPub []byte) []byte {
	signB64 := base64.RawURLEncoding.EncodeToString(signPub)
	boxB64 := base64.RawURLEncoding.EncodeToString(boxPub)
	buf := make([]byte, 0, 64+len(deviceID)+len(signB64)+len(boxB64))
	buf = append(buf, "drift/v1/enroll|"...)
	buf = append(buf, deviceID...)
	buf = append(buf, '|')
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(signedAtUnixNano))
	buf = append(buf, ts[:]...)
	buf = append(buf, '|')
	buf = append(buf, signB64...)
	buf = append(buf, '|')
	buf = append(buf, boxB64...)
	return buf
}

// SignEnrollment builds an Enrollment certifying that masterPriv attests to
// (deviceID, signPub, boxPub) at signedAtUnixNano. Master is the trust
// root: the holder of masterPriv is the only entity that can produce
// enrollments accepted by Verify.
func SignEnrollment(deviceID string, signedAtUnixNano int64, signPub, boxPub []byte, masterPriv ed25519.PrivateKey) domain.Enrollment {
	body := EnrollmentSigningBytes(deviceID, signedAtUnixNano, signPub, boxPub)
	sig := dcrypto.Sign(masterPriv, body)
	return domain.Enrollment{
		DeviceID:  deviceID,
		SignedAt:  unixNanoTime(signedAtUnixNano),
		MasterSig: sig,
	}
}

// VerifyEnrollment confirms the enrollment cert matches the (device's
// recorded public keys) under the master's pubkey. Returns
// domain.ErrSignatureInvalid on mismatch.
func VerifyEnrollment(e domain.Enrollment, dev domain.Device, masterPub ed25519.PublicKey) error {
	if e.DeviceID != dev.ID {
		return fmt.Errorf("%w: enrollment id %q does not match device id %q",
			domain.ErrSignatureInvalid, e.DeviceID, dev.ID)
	}
	body := EnrollmentSigningBytes(e.DeviceID, e.SignedAt.UnixNano(), dev.PublicKey, dev.EncryptKey)
	return dcrypto.Verify(masterPub, body, e.MasterSig)
}
