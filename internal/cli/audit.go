package cli

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufforest/drift/internal/audit"
)

func auditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show signed control-plane events (token grants, revocations, etc)",
		RunE:  runAudit,
	}
	cmd.Flags().Bool("verify", false, "Cryptographically verify the per-device hash chain")
	cmd.Flags().String("kind", "", "Filter by event kind (e.g. token.grant)")
	cmd.Flags().Int("limit", 50, "Maximum entries to show")
	cmd.Flags().Bool("json", false, "Output one JSON object per line instead of human-readable")
	return cmd
}

func runAudit(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	m, err := ws.Manifest(ctx)
	if err != nil {
		return err
	}
	resolveDevicePub := func(did string) ed25519.PublicKey {
		if dev, ok := m.Devices[did]; ok {
			return ed25519.PublicKey(dev.PublicKey)
		}
		return nil
	}
	entries, skipped, err := audit.List(ctx, ws.Provider, ws.Config.WorkspaceID, ws.CPRK, resolveDevicePub)
	if err != nil {
		return err
	}
	verify, _ := cmd.Flags().GetBool("verify")
	if skipped > 0 {
		if verify {
			// Under --verify, skipped entries are a verification
			// failure — the chain check below only inspects the
			// decryptable subset, so a CPRK-rotation-as-erasure
			// attack would otherwise produce a false "chains
			// intact" result. Surface as a hard fail.
			return fmt.Errorf("audit verify: %d entries invisible to the current CPRK (cannot prove they weren't tampered or deleted)", skipped)
		}
		fmt.Fprintf(cmd.OutOrStdout(),
			"  ⓘ  %d entries are invisible to the current CPRK (likely from a prior epoch — see `drift rotate cprk` history)\n",
			skipped)
	}
	// Sort by EntryID prefix (matches temporal order).
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Entry.EntryID < entries[j].Entry.EntryID
	})

	if verify {
		if err := audit.VerifyChain(entries); err != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "✗ chain verification failed: %v\n", err)
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "✓ per-device chains intact")
	}

	kindFilter, _ := cmd.Flags().GetString("kind")
	limit, _ := cmd.Flags().GetInt("limit")
	jsonOut, _ := cmd.Flags().GetBool("json")
	if limit <= 0 || limit > len(entries) {
		limit = len(entries)
	}
	start := len(entries) - limit
	if start < 0 {
		start = 0
	}
	out := cmd.OutOrStdout()
	for _, e := range entries[start:] {
		if kindFilter != "" && e.Entry.Kind != kindFilter {
			continue
		}
		if jsonOut {
			b, _ := json.Marshal(e.Entry)
			fmt.Fprintln(out, string(b))
			continue
		}
		marker := "✓"
		if e.VerifyErr != nil {
			marker = "✗"
		}
		fmt.Fprintf(out, "%s %s  %s  %s  subject=%s",
			marker,
			e.Entry.OccurredAt.UTC().Format(time.RFC3339),
			e.Entry.DeviceID,
			e.Entry.Kind,
			e.Entry.Subject)
		if len(e.Entry.Details) > 0 {
			fmt.Fprintf(out, "  details=%s", strings.TrimSpace(string(e.Entry.Details)))
		}
		fmt.Fprintln(out)
	}
	return nil
}
