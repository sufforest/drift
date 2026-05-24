package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveToken_positional(t *testing.T) {
	cmd := openCmd()
	got, err := resolveToken(cmd, []string{"drift1.abcdef"})
	if err != nil {
		t.Fatalf("resolveToken: %v", err)
	}
	if got != "drift1.abcdef" {
		t.Errorf("got %q", got)
	}
}

func TestResolveToken_tokenFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "tok.txt")
	if err := os.WriteFile(tmp, []byte("drift1.fromfile\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cmd := openCmd()
	_ = cmd.Flags().Set("token-file", tmp)
	got, err := resolveToken(cmd, nil)
	if err != nil {
		t.Fatalf("resolveToken: %v", err)
	}
	if got != "drift1.fromfile" {
		t.Errorf("got %q", got)
	}
}

func TestResolveToken_noSource(t *testing.T) {
	cmd := openCmd()
	_, err := resolveToken(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "token required") {
		t.Errorf("expected token-required error, got %v", err)
	}
}

func TestResolveToken_conflictingSources(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "tok.txt")
	_ = os.WriteFile(tmp, []byte("x"), 0o600)
	cmd := openCmd()
	_ = cmd.Flags().Set("token-file", tmp)
	_, err := resolveToken(cmd, []string{"argv-token"})
	if err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Errorf("expected mutual-exclusion error, got %v", err)
	}
}
