package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// peerCmd groups DD-9 bearer-peer operations: revoke (immediately
// kills workspace-side access to a bearer-paired device), refresh (re-
// mints a peer's PeerCred, planned for Phase 7), list / status
// (planned for Phase 8).
func peerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "peer",
		Short: "Manage DD-9 bearer-mode peers (revoke, refresh, list)",
		Long: `Bearer-mode peers (created via 'drift link --new-device --peer-bearer')
hold a short-lived, master-signed PeerCred instead of the raw parent R2
cred. The 'drift peer' commands manage these creds workspace-side:

  drift peer revoke <peer-id>
      Flip the manifest record to revoked + append the JTI to
      revocations.enc. The peer's next mount fails immediately; any
      already-running mount notices within one revocations-poll cycle
      (~15s) and starts refusing operations.

      Full lock-out of the underlying R2 JWT requires either waiting
      for its expiry (24h default) or running 'drift parent set' to
      rotate the parent token (invalidates every JWT signed under the
      old secret).`,
	}
	cmd.AddCommand(peerRevokeCmd(), peerListCmd(), peerStatusCmd(), peerRefreshCmd())
	return cmd
}

// peerRefreshCmd has two modes determined by argument count:
//   drift peer refresh <peer-id>   (primary) → mint + seal + upload
//   drift peer refresh             (peer)    → fetch + verify + save
func peerRefreshCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "refresh [peer-id]",
		Short: "Refresh a DD-9 bearer-mode peer's cred (primary: mint new + upload; peer: fetch + save)",
		Long: `Two modes:

  drift peer refresh <peer-id>   (primary side)
    Mints a fresh 24h PeerCred for the named peer, seals it for that
    peer's X25519 pubkey, and uploads to peers/<id>/refresh.enc. The
    new JTI is recorded in the manifest immediately; the peer's old
    cred starts failing JTI-mismatch checks at mount time.

  drift peer refresh              (peer side)
    Fetches the sealed refresh blob from the bucket, verifies its
    signature against the workspace master pub, and replaces the
    local peercred.json. Refuses if no blob is present (ask the
    primary first) or if any verification step fails.

Run the primary command first; then run the peer command on the
target device (or wait for its next mount, which can be made to
auto-refresh in a future enhancement).`,
		Args: cobra.MaximumNArgs(1),
		RunE: runPeerRefresh,
	}
}

func runPeerRefresh(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if len(args) == 1 {
		// Primary path.
		res, err := ws.PeerRefreshMint(ctx, args[0])
		if err != nil {
			return err
		}
		fmt.Fprintf(out,
			"✓ Refreshed peer %s\n"+
				"  Old JTI: %s\n"+
				"  New JTI: %s\n"+
				"  Expires: %s\n\n"+
				"On the peer device, run:\n"+
				"    drift peer refresh\n"+
				"to pull the new cred. The peer's old cred will fail at mount until then.\n",
			res.DeviceID, res.OldJTI, res.NewJTI, res.ExpiresAt)
		return nil
	}
	// Peer path.
	res, err := ws.PeerRefreshFetch(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(out,
		"✓ Pulled refreshed PeerCred\n"+
			"  Old JTI: %s\n"+
			"  New JTI: %s\n",
		res.OldJTI, res.NewJTI)
	return nil
}

func peerListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "(primary) Show all DD-9 bearer-mode peers in the workspace",
		RunE:  runPeerList,
	}
}

func runPeerList(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	peers, err := ws.PeerList(ctx)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if len(peers) == 0 {
		fmt.Fprintln(out, "no bearer-mode peers (use `drift link --new-device <name> --peer-bearer --peer-compartments ...` to pair one)")
		return nil
	}
	for _, p := range peers {
		state := "active"
		switch {
		case p.Revoked:
			state = "REVOKED"
		case p.Expired:
			state = "EXPIRED"
		case p.NeedsRefresh:
			state = "needs-refresh"
		}
		fmt.Fprintf(out,
			"%s  name=%s  jti=%s  scope=%s  expires=%s  %s\n",
			p.DeviceID,
			p.Name,
			p.JTI,
			strings.Join(p.Scope, ","),
			p.ExpiresAt.UTC().Format(time.RFC3339),
			state,
		)
	}
	return nil
}

func peerStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "(any device) Show local DD-9 PeerCred state — scope, expiry, revocation",
		RunE:  runPeerStatus,
	}
}

func runPeerStatus(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	s, err := ws.PeerStatus(ctx)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if !s.HasPeerCred {
		fmt.Fprintln(out, "This device is not bearer-mode (no peercred.json present).")
		fmt.Fprintln(out, "Either it's the primary, a v1 --peer device (parent-cred mode), or identity-only.")
		return nil
	}
	// Status priority: signature-invalid is the worst (cred is bogus);
	// otherwise the manifest-gate states matter (revoked, expired);
	// then soft warnings (needs refresh, stale JTI). The "unknown"
	// signature state is reported separately as "offline" because the
	// most common cause is that the cred can't reach R2 to fetch the
	// manifest.
	state := "ok"
	switch {
	case s.SignatureChecked && !s.SignatureValid:
		state = "SIGNATURE INVALID — refuse to use"
	case s.ManifestRevoked:
		state = "REVOKED by primary"
	case s.Expired:
		state = "EXPIRED — refresh required"
	case s.NeedsRefresh:
		state = "needs refresh (past half-life)"
	case s.ManifestJTI != "" && s.ManifestJTI != s.JTI:
		state = fmt.Sprintf("STALE — manifest has newer JTI %s", s.ManifestJTI)
	case !s.SignatureChecked:
		state = "offline — could not verify against manifest"
	}
	sigField := "<not checked: manifest unreachable>"
	if s.SignatureChecked {
		sigField = fmt.Sprintf("%v", s.SignatureValid)
	}
	fmt.Fprintf(out,
		"Bearer-mode PeerCred for %s\n"+
			"  Status:           %s\n"+
			"  JTI:              %s\n"+
			"  Scope:            %s\n"+
			"  Issued:           %s\n"+
			"  Refresh after:    %s\n"+
			"  Expires:          %s\n"+
			"  Signature valid:  %s\n",
		s.DeviceID,
		state,
		s.JTI,
		strings.Join(s.Scope, ","),
		s.IssuedAt.UTC().Format(time.RFC3339),
		s.RefreshAt.UTC().Format(time.RFC3339),
		s.ExpiresAt.UTC().Format(time.RFC3339),
		sigField,
	)
	if s.ManifestSyncErr != nil {
		fmt.Fprintf(out, "  (manifest sync failed: %v — Revoked status unknown)\n", s.ManifestSyncErr)
	} else {
		fmt.Fprintf(out, "  Manifest revoked: %v\n", s.ManifestRevoked)
	}
	return nil
}

func peerRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <peer-id>",
		Short: "Revoke a DD-9 bearer-mode peer (workspace-side; instant)",
		Args:  cobra.ExactArgs(1),
		RunE:  runPeerRevoke,
	}
}

func runPeerRevoke(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	deviceID := args[0]
	res, err := ws.PeerRevoke(ctx, deviceID)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if res.AlreadyRevoked {
		fmt.Fprintf(out, "✓ Peer %s already revoked (no-op)\n  JTI: %s\n", deviceID, res.JTI)
		return nil
	}
	fmt.Fprintf(out,
		"✓ Revoked peer %s\n"+
			"  JTI:               %s\n"+
			"  Manifest sequence: %d\n\n"+
			"The peer's next 'drift mount' will be refused immediately.\n"+
			"Any already-running mount notices within ~15s.\n\n"+
			"For absolute cutoff against R2 (the JWT may still work\n"+
			"against R2 until its embedded expiry), follow up with:\n"+
			"    drift parent set    # rotate the R2 token in CF dashboard first\n",
		deviceID, res.JTI, res.Sequence)
	return nil
}
