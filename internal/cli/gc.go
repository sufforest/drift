package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufforest/drift/internal/workspace"
)

func gcCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gc",
		Short: "Sweep orphaned chunks and revoked-expired credential blobs",
		Long: `Removes:
  • chunks where the parent vol no longer exists in the manifest
  • .drift/credentials/<tid>.enc for tokens past expiry + grace period (default 7d)

Safe to interrupt; re-runs pick up where they stopped. Use --dry-run to preview.`,
		RunE: runGC,
	}
	cmd.Flags().Bool("dry-run", false, "Print what would be deleted without touching anything")
	cmd.Flags().Duration("grace", 7*24*time.Hour, "Keep revoked/expired credential blobs for this long past their nominal expiry")
	cmd.Flags().Duration("audit-older-than", 0, "Also delete audit entries older than this duration (e.g. 90d). Default 0 = keep all.")
	return cmd
}

func runGC(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	grace, _ := cmd.Flags().GetDuration("grace")

	report, err := ws.GC(ctx, workspace.GCOptions{
		CredentialsGracePeriod: grace,
		DryRun:                 dryRun,
	})
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	action := "Would delete"
	if !dryRun {
		action = "Deleted"
	}
	fmt.Fprintf(out, "%s %d objects (%d vol chunks, %d credential blobs)\n",
		action, report.Deleted+len(report.OrphanedCompartmentChunks)*boolInt(dryRun)+len(report.OrphanedCredentialBlobs)*boolInt(dryRun),
		len(report.OrphanedCompartmentChunks), len(report.OrphanedCredentialBlobs))
	if dryRun {
		for _, k := range report.OrphanedCompartmentChunks {
			fmt.Fprintf(out, "  - %s\n", k)
		}
		for _, k := range report.OrphanedCredentialBlobs {
			fmt.Fprintf(out, "  - %s\n", k)
		}
	}

	auditAge, _ := cmd.Flags().GetDuration("audit-older-than")
	if auditAge > 0 {
		if dryRun {
			fmt.Fprintln(out, "  (--dry-run does not preview audit GC; re-run without --dry-run)")
			return nil
		}
		auditRes, err := ws.AuditGC(ctx, auditAge)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "Audit GC: scanned %d, deleted %d entries older than %s\n",
			auditRes.Scanned, len(auditRes.Deleted), auditAge)
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
