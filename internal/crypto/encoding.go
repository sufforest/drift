package crypto

import (
	"fmt"
	"strings"

	"github.com/mr-tron/base58"

	"github.com/sufforest/drift/internal/domain"
)

// Wire format: "<prefix>.<base58(payload)>.<base58(signature)>".

// EncodeToken renders a capability token as the pasteable string Drift
// accepts on `drift open`.
func EncodeToken(payload, signature []byte) string {
	return encodeWithPrefix(domain.TokenPrefix, payload, signature)
}

// DecodeToken parses an encoded capability token. Returns
// domain.ErrTokenMalformed for any structural problem.
func DecodeToken(s string) (payload, signature []byte, err error) {
	return decodeWithPrefix(domain.TokenPrefix, s)
}

// EncodePairing renders a pairing token as the pasteable string `drift
// link` accepts. Distinct prefix from EncodeToken so capability redeemers
// reject pairing tokens up front and vice-versa.
func EncodePairing(payload, signature []byte) string {
	return encodeWithPrefix(domain.PairingPrefix, payload, signature)
}

// DecodePairing parses an encoded pairing token.
func DecodePairing(s string) (payload, signature []byte, err error) {
	return decodeWithPrefix(domain.PairingPrefix, s)
}

func encodeWithPrefix(prefix string, payload, signature []byte) string {
	var sb strings.Builder
	sb.Grow(len(prefix) + 2 + 2*((len(payload)+len(signature))*138/100))
	sb.WriteString(prefix)
	sb.WriteByte('.')
	sb.WriteString(base58.Encode(payload))
	sb.WriteByte('.')
	sb.WriteString(base58.Encode(signature))
	return sb.String()
}

func decodeWithPrefix(prefix, s string) (payload, signature []byte, err error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("%w: expected 3 dot-separated fields, got %d", domain.ErrTokenMalformed, len(parts))
	}
	if parts[0] != prefix {
		return nil, nil, fmt.Errorf("%w: unknown prefix %q", domain.ErrTokenMalformed, parts[0])
	}
	payload, err = base58.Decode(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: payload: %v", domain.ErrTokenMalformed, err)
	}
	signature, err = base58.Decode(parts[2])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: signature: %v", domain.ErrTokenMalformed, err)
	}
	return payload, signature, nil
}
