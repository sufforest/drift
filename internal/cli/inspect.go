package cli

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	dcrypto "github.com/sufforest/drift/internal/crypto"
	"github.com/sufforest/drift/internal/credentials"
	"github.com/sufforest/drift/internal/domain"
)

func inspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect <token>",
		Short: "Decode a capability or pairing token, print its claimed fields",
		Long: `Verifies the embedded Ed25519 signature against the self-asserted IssuerPub
before printing anything. A tampered token is refused.

Does NOT touch the bucket or the local workspace state — useful for
inspecting a token from a different workspace, or for confirming the
master fingerprint matches what you expect before running drift open.

With --raw, prints the raw session-token + JWT bytes alongside the
decoded view. Use this to compare against an authoritative spec when
debugging credential rejection by the storage provider.`,
		Args: cobra.ExactArgs(1),
		RunE: runInspect,
	}
	cmd.Flags().Bool("raw", false, "Also print the raw session token + JWT bytes")
	return cmd
}

func runInspect(cmd *cobra.Command, args []string) error {
	encoded := args[0]
	switch {
	case strings.HasPrefix(encoded, domain.PairingPrefix+"."):
		return inspectPairing(cmd, encoded)
	case strings.HasPrefix(encoded, domain.TokenPrefix+"."):
		return inspectCapability(cmd, encoded)
	default:
		return fmt.Errorf("unknown token prefix; expected %q or %q", domain.TokenPrefix, domain.PairingPrefix)
	}
}

func inspectCapability(cmd *cobra.Command, encoded string) error {
	payload, sig, err := dcrypto.DecodeToken(encoded)
	if err != nil {
		return err
	}
	var tok domain.Token
	if err := json.Unmarshal(payload, &tok); err != nil {
		return fmt.Errorf("%w: %v", domain.ErrTokenMalformed, err)
	}
	if len(tok.IssuerPub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: missing or malformed IssuerPub", domain.ErrTokenMalformed)
	}
	if err := dcrypto.Verify(ed25519.PublicKey(tok.IssuerPub), payload, sig); err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Kind:           capability token (v%d)\n", tok.Version)
	fmt.Fprintf(out, "TID:            %s\n", tok.TID)
	fmt.Fprintf(out, "WorkspaceID:    %s\n", tok.WorkspaceID)
	fmt.Fprintf(out, "Bucket:         %s @ %s (%s)\n", tok.Bucket.Name, tok.Bucket.Endpoint, tok.Bucket.Provider)
	fmt.Fprintf(out, "IssuerPub:      ed25519:%x\n", sha256.Sum256(tok.IssuerPub))
	fmt.Fprintf(out, "MasterFP:       %x\n", tok.MasterFingerprint)
	fmt.Fprintln(out, "Signature:      verified ✓")
	fmt.Fprintln(out, "")
	raw, _ := cmd.Flags().GetBool("raw")
	printCredSummary(out, "ControlCred", tok.ControlCred, raw)
	return nil
}

func inspectPairing(cmd *cobra.Command, encoded string) error {
	payload, sig, err := dcrypto.DecodePairing(encoded)
	if err != nil {
		return err
	}
	var pt domain.PairingToken
	if err := json.Unmarshal(payload, &pt); err != nil {
		return fmt.Errorf("%w: %v", domain.ErrTokenMalformed, err)
	}
	if len(pt.IssuerPub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: missing IssuerPub", domain.ErrTokenMalformed)
	}
	if err := dcrypto.Verify(ed25519.PublicKey(pt.IssuerPub), payload, sig); err != nil {
		return err
	}
	expectFP := sha256.Sum256(pt.IssuerPub)
	if string(expectFP[:]) != string(pt.MasterFP) {
		return fmt.Errorf("%w: MasterFP does not match IssuerPub", domain.ErrTokenMalformed)
	}

	out := cmd.OutOrStdout()
	expiresIn := time.Until(pt.ExpiresAt).Round(time.Second)
	fmt.Fprintf(out, "Kind:        pairing token (v%d)\n", pt.Version)
	fmt.Fprintf(out, "PID:         %s\n", pt.PID)
	fmt.Fprintf(out, "WorkspaceID: %s\n", pt.WorkspaceID)
	fmt.Fprintf(out, "Bucket:      %s @ %s (%s)\n", pt.Bucket.Name, pt.Bucket.Endpoint, pt.Bucket.Provider)
	fmt.Fprintf(out, "MasterFP:    %x  (== SHA-256(IssuerPub), self-consistent)\n", pt.MasterFP)
	fmt.Fprintf(out, "ExpiresAt:   %s  (in %s)\n", pt.ExpiresAt.UTC().Format(time.RFC3339), expiresIn)
	fmt.Fprintln(out, "Signature:   verified ✓")
	fmt.Fprintln(out, "")
	raw, _ := cmd.Flags().GetBool("raw")
	printCredSummary(out, "ReadCred", pt.ReadCred, raw)
	printCredSummary(out, "WriteCred", pt.WriteCred, raw)
	return nil
}

// printCredSummary writes a human-readable summary of an S3Credential. For
// R2 minted creds, decodes the embedded JWT and prints its scope so the
// reader can see what the cred is actually authorized to do.
//
// With showRaw, prints a STRUCTURAL diagnostic safe to share: lengths,
// presence checks, and the claim shape. The actual secret material
// (AccessKeyID, iss claim, JWT bytes, session token bytes, signature)
// is redacted so the output can be pasted into a bug report or chat.
func printCredSummary(out interface{ Write(p []byte) (int, error) }, label string, cred domain.S3Credential, showRaw bool) {
	fmt.Fprintf(out, "%s:\n", label)
	fmt.Fprintf(out, "  AccessKeyID:   %s\n", redactPrefix(cred.AccessKeyID, 4))
	fmt.Fprintf(out, "  Expires:       %s\n", cred.Expires.UTC().Format(time.RFC3339))
	jwt, err := credentials.DecodeR2SessionToken(cred.SessionToken)
	if err != nil {
		fmt.Fprintf(out, "  (session token decode error: %v)\n", err)
		return
	}
	if showRaw {
		fmt.Fprintf(out, "  SessionToken:  <base64, %d chars>\n", len(cred.SessionToken))
		fmt.Fprintf(out, "  SessionToken first 8 chars: %q (should base64-decode to start with 'jwt/')\n", firstN(cred.SessionToken, 8))
		// Show JWT shape without exposing signature bytes.
		parts := splitN(jwt, ".", 3)
		if len(parts) == 3 {
			fmt.Fprintf(out, "  JWT shape:     header(%d).payload(%d).signature(%d) chars\n",
				len(parts[0]), len(parts[1]), len(parts[2]))
		}
	}
	claims, _, _, err := credentials.DecodeR2JWT(jwt)
	if err != nil {
		fmt.Fprintf(out, "  (JWT decode error: %v)\n", err)
		return
	}
	if showRaw {
		// Pretty-print the claims with iss redacted (it's the parent
		// access key ID — actual secret). Everything else is either
		// derived from public info or a structural field name.
		redacted := claims
		redacted.Issuer = redactPrefix(claims.Issuer, 4)
		body, _ := json.MarshalIndent(redacted, "  ", "  ")
		fmt.Fprintf(out, "  Claims (iss redacted):\n  %s\n", string(body))
	}
	if claims.Issuer != "" {
		fmt.Fprintf(out, "  iss:           %s\n", redactPrefix(claims.Issuer, 4))
	}
	if claims.Subject != "" {
		fmt.Fprintf(out, "  sub:           %s\n", claims.Subject)
	}
	if claims.Audience != "" {
		fmt.Fprintf(out, "  aud:           %s\n", claims.Audience)
	}
	fmt.Fprintf(out, "  iat / exp:     %d / %d (ttl %ds)\n", claims.IssuedAt, claims.ExpiresAt, claims.ExpiresAt-claims.IssuedAt)
	if claims.Bucket != "" {
		fmt.Fprintf(out, "  Bucket:        %s\n", claims.Bucket)
	}
	if claims.Scope != "" {
		fmt.Fprintf(out, "  Scope:         %s\n", claims.Scope)
	}
	if claims.Paths != nil {
		if len(claims.Paths.PrefixPaths) > 0 {
			fmt.Fprintf(out, "  PrefixPaths:   %v\n", claims.Paths.PrefixPaths)
		}
		if len(claims.Paths.ObjectPaths) > 0 {
			fmt.Fprintf(out, "  ObjectPaths:   %v\n", claims.Paths.ObjectPaths)
		}
	}
}

// suppress unused-import errors when build configuration drops references.
var _ = errors.Is

// redactPrefix returns the first `keep` chars of s followed by an ellipsis.
// If s is short, returns "<empty>" or its full content.
func redactPrefix(s string, keep int) string {
	if s == "" {
		return "<empty>"
	}
	if len(s) <= keep {
		return s + "…"
	}
	return s[:keep] + "…(redacted)"
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func splitN(s, sep string, n int) []string {
	return strings.SplitN(s, sep, n)
}
