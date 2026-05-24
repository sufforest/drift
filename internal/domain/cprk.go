package domain

// CPRKDir is the bucket prefix that holds per-device sealed CPRK handoffs.
const CPRKDir = ".drift/cprk/"

// CPRKKeyFor returns the bucket key where the primary stores the sealed
// CPRK for the named device. Overwritten on every `drift rotate cprk`;
// the latest blob is always the current epoch.
func CPRKKeyFor(deviceID string) string {
	return CPRKDir + deviceID + ".enc"
}

// CPRKHandoff is the plaintext (pre-sealed-box) struct the primary writes
// to a secondary device's CPRK blob. The receiver opens with their own
// X25519 priv key and updates local state.
type CPRKHandoff struct {
	Epoch     uint64 `json:"epoch"`
	CPRK      []byte `json:"cprk"`
	MasterPub []byte `json:"master_pub"`
}
