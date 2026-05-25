package workspace

import (
	"testing"
	"time"

	"github.com/sufforest/drift/internal/credentials"
)

// TestPeerCredStore_saveLoadRoundtrip: SavePeerCred + LoadPeerCred
// preserves every field of a PeerCred. Catches accidental field
// drops in JSON marshaling.
func TestPeerCredStore_saveLoadRoundtrip(t *testing.T) {
	state, err := NewState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	orig := &credentials.PeerCred{
		Version:  credentials.PeerCredVersion,
		DeviceID: "dev_xyz",
		JTI:      "jti_1",
		Scope:    []string{"main"},
		Mode:     "rw",
		Data: credentials.ScopedCredSet{
			AccessKeyID:     "AK",
			SecretAccessKey: "SK",
			SessionToken:    "data-session",
			Endpoint:        "https://abc.r2.cloudflarestorage.com",
			Bucket:          "drift-test",
		},
		Control: &credentials.ScopedCredSet{
			AccessKeyID:     "AK",
			SecretAccessKey: "CTRL_SK",
			SessionToken:    "ctrl-session",
			Endpoint:        "https://abc.r2.cloudflarestorage.com",
			Bucket:          "drift-test",
		},
		IssuedAt:  now,
		ExpiresAt: now.Add(24 * time.Hour),
		RefreshAt: now.Add(12 * time.Hour),
		IssuerSig: []byte{1, 2, 3, 4},
	}
	if err := state.SavePeerCred(orig); err != nil {
		t.Fatalf("SavePeerCred: %v", err)
	}
	if !state.HasPeerCred() {
		t.Fatal("HasPeerCred should be true after Save")
	}
	got, err := state.LoadPeerCred()
	if err != nil {
		t.Fatalf("LoadPeerCred: %v", err)
	}
	if got.DeviceID != orig.DeviceID ||
		got.JTI != orig.JTI ||
		got.Mode != orig.Mode ||
		got.Data.AccessKeyID != orig.Data.AccessKeyID ||
		got.Data.SecretAccessKey != orig.Data.SecretAccessKey ||
		got.Data.SessionToken != orig.Data.SessionToken ||
		got.Data.Endpoint != orig.Data.Endpoint ||
		got.Data.Bucket != orig.Data.Bucket {
		t.Errorf("Data field mismatch after roundtrip: orig=%+v got=%+v", orig, got)
	}
	if got.Control == nil {
		t.Fatal("Control cred dropped in roundtrip")
	}
	if got.Control.AccessKeyID != orig.Control.AccessKeyID ||
		got.Control.SecretAccessKey != orig.Control.SecretAccessKey ||
		got.Control.SessionToken != orig.Control.SessionToken {
		t.Errorf("Control field mismatch: orig=%+v got=%+v", orig.Control, got.Control)
	}
	if !got.IssuedAt.Equal(orig.IssuedAt) || !got.ExpiresAt.Equal(orig.ExpiresAt) || !got.RefreshAt.Equal(orig.RefreshAt) {
		t.Error("time fields drifted in roundtrip")
	}
	if len(got.Scope) != 1 || got.Scope[0] != "main" {
		t.Errorf("scope drift: %v", got.Scope)
	}
	if len(got.IssuerSig) != 4 {
		t.Errorf("IssuerSig drift: %v", got.IssuerSig)
	}
}

// TestPeerCredStore_hasPeerCredFalseInitially
func TestPeerCredStore_hasPeerCredFalseInitially(t *testing.T) {
	state, err := NewState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if state.HasPeerCred() {
		t.Error("HasPeerCred on fresh state dir must be false")
	}
}
