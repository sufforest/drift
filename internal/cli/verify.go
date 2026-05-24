package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
)

func verifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Verify manifest signature and provider capabilities",
		Long:  `Decrypts and verifies the workspace manifest, then re-probes the provider's concurrency capability. Non-destructive; no bucket writes.`,
		RunE:  runVerify,
	}
}

func runVerify(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	report, err := ws.Verify(ctx)
	if err != nil && report == nil {
		return err
	}
	out := cmd.OutOrStdout()
	check := func(ok bool) string {
		if ok {
			return "✓"
		}
		return "✗"
	}
	fmt.Fprintf(out, "%s Manifest signature\n", check(report.ManifestSignature))
	fmt.Fprintf(out, "%s Provider reachable\n", check(report.ProviderReachable))
	fmt.Fprintf(out, "%s Conditional PUT supported\n", check(report.ConditionalPut))
	fmt.Fprintf(out, "  Devices:      %d\n", report.NumDevices)
	fmt.Fprintf(out, "  Vols:         %d\n", report.NumCompartments)
	fmt.Fprintf(out, "  Active tokens: %d\n", report.NumActiveTokens)
	for _, n := range report.Notes {
		fmt.Fprintf(out, "  note: %s\n", n)
	}
	if err != nil {
		return err
	}
	if !report.ManifestSignature || !report.ProviderReachable {
		return fmt.Errorf("verify failed")
	}
	return nil
}
