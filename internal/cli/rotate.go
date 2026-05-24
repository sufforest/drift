package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

func rotateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate workspace keys (vol / cprk / master)",
		Long:  `Three subcommands with distinct scope. See the per-subcommand help for the threat model each one defends against.`,
	}
	cmd.AddCommand(rotateCompartmentCmd())
	cmd.AddCommand(rotateCPRKCmd())
	cmd.AddCommand(rotateMasterCmd())
	return cmd
}

func rotateMasterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "master",
		Short: "Rotate the workspace master signing key (nuclear option)",
		Long: `Generates a fresh master keypair, signs an announcement that chains
old → new with both signatures, re-signs every enrollment cert under the
new master, and revokes every outstanding token.

Other enrolled devices pick up the new master automatically on their next
manifest poll — they walk the rotation announcement chain forward and
update their pinned MasterFingerprint.

Run this when master.json was exfiltrated or you suspect it might have
been. The old master.json is renamed locally (chmod 0000) so a panicked
user can recover the original.

CAVEAT: if you previously configured a recovery passphrase, the bucket
blob at .drift/recovery.enc still wraps the OLD master. Recovery from a
fresh machine will land on the old master and walk the announcement
chain forward — that works, but the chain is capped at 256 steps. After
heavy rotation history, run ` + "`drift recovery rekey`" + ` to re-wrap the blob
under the current master.`,
		RunE: runRotateMaster,
	}
	cmd.Flags().Bool("force", false, "Skip confirmation")
	return cmd
}

func runRotateMaster(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	if force, _ := cmd.Flags().GetBool("force"); !force {
		fmt.Fprintln(cmd.OutOrStdout(),
			"This rotates the workspace master signing key. EVERY outstanding\n"+
				"token becomes invalid; EVERY enrolled device must pick up the new\n"+
				"master fingerprint via the rotation announcement chain.\n\n"+
				"The old master.json is backed up locally at chmod 0000. Re-run\n"+
				"with --force to confirm.")
		return nil
	}
	res, err := ws.RotateMaster(ctx)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out,
		"✓ Rotated master (rotation seq %d, manifest seq %d)\n"+
			"  Re-enrolled %d device(s).\n"+
			"  Revoked %d outstanding tokens.\n"+
			"  New fingerprint: %x\n",
		res.RotationSequence, res.ManifestSequence,
		len(res.ReEnrolledDevices), len(res.RevokedTokens),
		res.NewFingerprint)
	return nil
}

func rotateCPRKCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cprk",
		Short: "Rotate the Control Plane Read Key (manifest encryption)",
		Long: `Derives a fresh CPRK under a new HKDF epoch, re-encrypts the manifest
under the new key, writes per-device sealed handoff blobs, and revokes
every outstanding token (they embed the old CPRK).

Other enrolled devices pick up the new CPRK automatically on their next
manifest read — they detect the AEAD failure under the old key and fetch
.drift/cprk/<did>.enc to re-key.

Run this when a token's credentials blob may have leaked (e.g. a bearer
device was lost while a token was still in TTL).`,
		RunE: runRotateCPRK,
	}
	cmd.Flags().Bool("force", false, "Skip confirmation")
	return cmd
}

func runRotateCPRK(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	if force, _ := cmd.Flags().GetBool("force"); !force {
		fmt.Fprintln(cmd.OutOrStdout(),
			"This rotates the Control Plane Read Key. EVERY outstanding token\n"+
				"becomes invalid. Every other enrolled device must be online (or\n"+
				"come online later) to fetch the new key.\n\n"+
				"Re-run with --force to confirm.")
		return nil
	}
	res, err := ws.RotateCPRK(ctx)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out,
		"✓ Rotated CPRK (epoch %d → %d, manifest seq %d)\n"+
			"  Sealed handoff blobs for %d device(s).\n"+
			"  Revoked %d outstanding tokens.\n",
		res.OldEpoch, res.NewEpoch, res.Sequence, len(res.SealedDevices), len(res.RevokedTokens))
	return nil
}

func rotateCompartmentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "vol <name>",
		Aliases: []string{"compartment"},
		Short:   "Rotate a vol's encryption key",
		Long: `Generates a fresh symmetric key for the named vol, re-seals it for every
enrolled device, and revokes every outstanding token whose scope includes
this vol.

Existing chunks under compartments/<name>/ remain decryptable with the OLD
key. Anyone holding the old key keeps read access to data written before
the rotation. v1 does not re-encrypt past chunks.`,
		Args: cobra.ExactArgs(1),
		RunE: runRotateCompartment,
	}
	cmd.Flags().Bool("force", false, "Skip confirmation")
	return cmd
}

func runRotateCompartment(cmd *cobra.Command, args []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	if force, _ := cmd.Flags().GetBool("force"); !force {
		fmt.Fprintf(cmd.OutOrStdout(),
			"This rotates vol %q. Every outstanding token granting it\n"+
				"becomes invalid. Existing chunks remain decryptable by anyone\n"+
				"holding the OLD key.\n\n"+
				"Re-run with --force to confirm.\n", args[0])
		return nil
	}
	res, err := ws.CompartmentRotate(ctx, args[0])
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out,
		"✓ Rotated vol %s (KeyVersion %d → %d, manifest seq %d)\n",
		res.Compartment, res.OldKeyVersion, res.NewKeyVersion, res.Sequence)
	if len(res.RevokedTokens) == 0 {
		fmt.Fprintln(out, "  No outstanding tokens needed revocation.")
		return nil
	}
	fmt.Fprintf(out, "  Revoked %d tokens that granted this vol:\n", len(res.RevokedTokens))
	for _, tid := range res.RevokedTokens {
		fmt.Fprintf(out, "    %s\n", tid)
	}
	return nil
}
