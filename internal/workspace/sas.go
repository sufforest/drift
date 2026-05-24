package workspace

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// SASDomain is the domain-separation tag mixed into every Short
// Authentication String computation. Bumping it invalidates any
// hypothetical pre-computed rainbow table and segregates SAS hashes
// from any other use of SHA-256 on the same inputs.
const SASDomain = "drift-sas-v1"

// ComputeSAS derives an 8-hex-character Short Authentication String
// from the pairing transcript: every input either side of the handshake
// independently knows.
//
// Both devices compute this and display it. The user compares the two
// screens. Any MITM that substitutes a key produces a different SAS
// because every transcript field is mixed in.
//
// Format is "ABCD-EF12" (32 bits, 4.29 billion values). Sufficient for
// a one-shot per-pairing comparison: any pre-image attack must also
// produce a working PairingResponse signed under the attacker's key,
// which makes 2^32 grinding cost-prohibitive in practice.
//
// All inputs are length-prefixed (2-byte big-endian) so distinct
// transcripts cannot accidentally collide via boundary ambiguity
// (e.g., concatenating fields of different lengths). The domain tag
// further isolates SAS hashes from any other SHA-256 use.
func ComputeSAS(masterPub []byte, pid string, devSignPub, devBoxPub, challenge []byte) string {
	h := sha256.New()
	writeSASField(h, []byte(SASDomain))
	writeSASField(h, masterPub)
	writeSASField(h, []byte(pid))
	writeSASField(h, devSignPub)
	writeSASField(h, devBoxPub)
	writeSASField(h, challenge)
	sum := h.Sum(nil)
	return fmt.Sprintf("%02X%02X-%02X%02X", sum[0], sum[1], sum[2], sum[3])
}

func writeSASField(h interface{ Write(p []byte) (int, error) }, b []byte) {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(b)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write(b)
}
