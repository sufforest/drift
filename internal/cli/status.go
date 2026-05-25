package cli

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufforest/drift/internal/audit"
	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/workspace"
)

func statusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show workspace state: devices, vols, tokens, session, recent audit",
		RunE:  runStatus,
	}
	cmd.Flags().Bool("plain", false, "Suppress colors + Unicode tree characters even on a TTY")
	cmd.Flags().Int("audit-limit", 5, "Number of recent audit events to display (0 to hide)")
	return cmd
}

func runStatus(cmd *cobra.Command, _ []string) error {
	ctx := context.Background()
	ws, err := loadWorkspace(ctx, cmd)
	if err != nil {
		return err
	}
	s, err := ws.Status(ctx)
	if err != nil {
		return err
	}
	m, err := ws.Manifest(ctx)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	plain, _ := cmd.Flags().GetBool("plain")
	color := isTTY(out) && !plain

	t := newTreePrinter(out, color)
	t.title(fmt.Sprintf("Workspace %s", s.WorkspaceID))
	t.kv("Storage", fmt.Sprintf("%s @ %s (%s)", s.Bucket.Name, s.Bucket.Endpoint, s.Bucket.Provider))
	t.kv("Trust root", fmt.Sprintf("master sha256:%s…", abbrev(hex.EncodeToString(ws.Config.MasterFingerprint), 16)))
	t.kv("This device", s.DeviceID)
	t.kv("Concurrency", s.Concurrency)
	t.blank()

	// Devices section
	devs := make([]domain.Device, 0, len(m.Devices))
	for did, d := range m.Devices {
		if did == domain.MasterDeviceID {
			continue
		}
		devs = append(devs, d)
	}
	sort.Slice(devs, func(i, j int) bool { return devs[i].EnrolledAt.Before(devs[j].EnrolledAt) })
	t.section("Devices", len(devs))
	for i, d := range devs {
		isLast := i == len(devs)-1
		marker := d.ID
		if d.ID == s.DeviceID {
			marker = d.ID + " (this device)"
		}
		t.row(isLast, fmt.Sprintf("%s — %s, enrolled %s",
			marker,
			valueOr(d.Name, "unnamed"),
			d.EnrolledAt.UTC().Format("2006-01-02")))
	}
	t.blank()

	// Vols section
	comps := make([]workspace.CompartmentStatus, len(s.Compartments))
	copy(comps, s.Compartments)
	sort.Slice(comps, func(i, j int) bool { return comps[i].Name < comps[j].Name })
	t.section("Vols", len(comps))
	if len(comps) == 0 {
		t.row(true, "(none — create one with `drift vol create <name>`)")
	}
	for i, c := range comps {
		isLast := i == len(comps)-1
		t.row(isLast, fmt.Sprintf("%-12s mode=%s key_version=%d", c.Name, c.Mode, c.KeyVersion))
	}
	t.blank()

	// Tokens section — only show TRULY active (not revoked, not expired).
	// Revoked tokens linger in the manifest as issuance history; honest
	// bearers respect revocations.enc regardless. `drift tokens --all`
	// surfaces the full list including revoked.
	now := time.Now()
	revoked, _ := ws.RevokedTokens(ctx) // ignore error; we just show what we can
	active := make([]workspace.TokenInfo, 0, len(s.Tokens))
	hiddenCount := 0
	for _, tok := range s.Tokens {
		if tok.Expired || revoked[tok.TID] {
			hiddenCount++
			continue
		}
		active = append(active, tok)
	}
	sort.Slice(active, func(i, j int) bool { return active[i].ExpiresAt.Before(active[j].ExpiresAt) })
	t.section("Active tokens", len(active))
	if len(active) == 0 {
		t.row(true, "(none)")
	}
	for i, tok := range active {
		isLast := i == len(active)-1
		t.row(isLast, fmt.Sprintf("%s  scope=%v  mode=%s  expires %s",
			tok.TID, tok.Scope, tok.Mode, humanizeUntil(tok.ExpiresAt, now)))
	}
	if hiddenCount > 0 {
		t.row(true, fmt.Sprintf("(%d revoked/expired hidden — `drift tokens --all` to see)", hiddenCount))
	}
	t.blank()

	// Session
	dir, _ := stateDir(cmd)
	rec, err := workspace.LoadSession(dir)
	t.section("Background session", -1)
	switch {
	case errors.Is(err, os.ErrNotExist):
		t.row(true, "(none — no `drift open` running)")
	case err != nil:
		t.row(true, fmt.Sprintf("error reading session file: %v", err))
	case !rec.SignalAlive():
		t.row(true, fmt.Sprintf("stale (PID %d not running) — clean up with `drift close`", rec.PID))
	default:
		t.row(false, fmt.Sprintf("PID %d  tid=%s  started %s", rec.PID, rec.TID, humanizeAgo(rec.StartedAt, now)))
		for i, mp := range rec.MountPoints {
			isLast := i == len(rec.MountPoints)-1
			t.row(isLast, "mounted: "+mp)
		}
	}
	t.blank()

	// Recent audit (best-effort — skip on error rather than fail status)
	auditLimit, _ := cmd.Flags().GetInt("audit-limit")
	if auditLimit > 0 && ws.CPRK != nil {
		resolve := func(did string) ed25519.PublicKey {
			if d, ok := m.Devices[did]; ok {
				return ed25519.PublicKey(d.PublicKey)
			}
			return nil
		}
		entries, _, err := audit.List(ctx, ws.Provider, ws.Config.WorkspaceID, ws.CPRK, resolve)
		if err == nil {
			recent := lastN(entries, auditLimit)
			t.section("Recent audit", len(recent))
			for i, e := range recent {
				isLast := i == len(recent)-1
				t.row(isLast, fmt.Sprintf("%s  %s  %s",
					humanizeAgo(e.Entry.OccurredAt, now),
					e.Entry.Kind,
					e.Entry.Subject))
			}
		}
	}

	return nil
}

// lastN returns the last n elements of a slice, sorted by OccurredAt asc.
func lastN(entries []audit.Decrypted, n int) []audit.Decrypted {
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Entry.OccurredAt.Before(entries[j].Entry.OccurredAt)
	})
	if len(entries) <= n {
		return entries
	}
	return entries[len(entries)-n:]
}

// --- tree printer ---

type treePrinter struct {
	w     io.Writer
	color bool
}

func newTreePrinter(w io.Writer, color bool) *treePrinter {
	return &treePrinter{w: w, color: color}
}

func (t *treePrinter) title(s string) {
	if t.color {
		fmt.Fprintf(t.w, "\x1b[1m%s\x1b[0m\n", s)
		return
	}
	fmt.Fprintln(t.w, s)
}

func (t *treePrinter) kv(label, value string) {
	if t.color {
		fmt.Fprintf(t.w, "  \x1b[2m%-14s\x1b[0m %s\n", label, value)
		return
	}
	fmt.Fprintf(t.w, "  %-14s %s\n", label, value)
}

func (t *treePrinter) section(name string, count int) {
	suffix := ""
	if count >= 0 {
		suffix = fmt.Sprintf(" (%d)", count)
	}
	if t.color {
		fmt.Fprintf(t.w, "\x1b[1m%s%s\x1b[0m\n", name, suffix)
		return
	}
	fmt.Fprintf(t.w, "%s%s\n", name, suffix)
}

func (t *treePrinter) row(isLast bool, line string) {
	mark := "├─"
	if isLast {
		mark = "└─"
	}
	if !canUnicode() {
		mark = "  -"
		if isLast {
			mark = "  -"
		}
	}
	fmt.Fprintf(t.w, "  %s %s\n", mark, line)
}

func (t *treePrinter) blank() {
	fmt.Fprintln(t.w)
}

// canUnicode reports whether the terminal/locale plausibly supports the
// box-drawing characters used by treePrinter. Honors LANG/LC_ALL.
func canUnicode() bool {
	for _, k := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		v := os.Getenv(k)
		if v == "" {
			continue
		}
		if hasUTF8Hint(v) {
			return true
		}
	}
	// Most modern terminals default to UTF-8; only "C"/"POSIX" locales
	// reliably can't render. Be optimistic.
	return true
}

func hasUTF8Hint(s string) bool {
	for i := 0; i+5 <= len(s); i++ {
		if s[i] == 'U' && s[i+1] == 'T' && s[i+2] == 'F' && (s[i+3] == '-' || s[i+3] == '8') {
			return true
		}
	}
	return false
}

// --- time helpers ---

func humanizeUntil(t, now time.Time) string {
	d := t.Sub(now)
	if d <= 0 {
		return "expired"
	}
	return "in " + humanizeDuration(d)
}

func humanizeAgo(t, now time.Time) string {
	d := now.Sub(t)
	if d < 0 {
		return "just now"
	}
	return humanizeDuration(d) + " ago"
}

func humanizeDuration(d time.Duration) string {
	if d < time.Minute {
		return "<1m"
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		h := int(d.Hours())
		m := int(d.Minutes()) - h*60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh%dm", h, m)
	}
	days := int(d.Hours() / 24)
	if days < 30 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dd+", days)
}
