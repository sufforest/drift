package workspace

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sufforest/drift/internal/domain"
	"github.com/sufforest/drift/internal/storage"
)

// driveHandshake runs a full primary/secondary pairing handshake against
// an in-memory provider, threading the supplied claim and confirm
// options through. Returns (claimResult, claimErr, confirmResult, confirmErr).
// Tests can inspect any combination.
func driveHandshake(t *testing.T, claimOpts LinkClaimOptions, confirmOpts LinkConfirmOptions) (*LinkClaimResult, error, *LinkConfirmResult, error) {
	t.Helper()
	ctx := context.Background()
	primary, prov := newPrimary(t)
	if err := primary.CompartmentCreate(ctx, "shared", domain.ModeMount); err != nil {
		t.Fatal(err)
	}

	init, err := primary.LinkInit(ctx, 5*time.Minute)
	if err != nil {
		t.Fatalf("LinkInit: %v", err)
	}

	newState, err := NewState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	claimOpts.State = newState
	if claimOpts.ProviderFor == nil {
		claimOpts.ProviderFor = func(_ domain.S3Credential, _ domain.BucketInfo) (storage.Provider, error) { return prov, nil }
	}
	if claimOpts.Now == nil {
		claimOpts.Now = primary.now
	}
	if claimOpts.PollInterval == 0 {
		claimOpts.PollInterval = 5 * time.Millisecond
	}
	if claimOpts.Timeout == 0 {
		claimOpts.Timeout = 5 * time.Second
	}

	var claimRes *LinkClaimResult
	var claimErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		claimRes, claimErr = LinkClaim(ctx, init.Encoded, "desktop-tower", claimOpts)
	}()

	// Wait for response to land or for the claim goroutine to exit.
	respKey := domain.PairingResponseKey(init.PID)
	deadline := time.Now().Add(2 * time.Second)
	posted := false
waitLoop:
	for time.Now().Before(deadline) {
		if exists, _ := prov.Exists(ctx, respKey); exists {
			posted = true
			break
		}
		// If claim already errored (e.g. OnSAS rejected), stop waiting.
		// Labeled break: a bare `break` would only exit the select, not
		// the for loop — staticcheck SA4011.
		select {
		case <-claimExited(&wg):
			break waitLoop
		default:
		}
		time.Sleep(2 * time.Millisecond)
	}

	var confirmRes *LinkConfirmResult
	var confirmErr error
	if posted {
		confirmRes, confirmErr = primary.LinkConfirm(ctx, init.PID, confirmOpts)
	}
	wg.Wait()
	return claimRes, claimErr, confirmRes, confirmErr
}

// claimExited is a small helper that returns a channel which closes
// when the supplied WaitGroup hits zero. Lets the harness break out
// of its polling loop early if the claim goroutine already gave up.
func claimExited(wg *sync.WaitGroup) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	return done
}

// TestLinkSAS_happyPath: both sides compute the same SAS, primary
// accepts via OnSAS returning nil, enrollment completes.
func TestLinkSAS_happyPath(t *testing.T) {
	var secondarySAS string
	claimOpts := LinkClaimOptions{
		OnSAS: func(s string) error {
			secondarySAS = s
			return nil
		},
	}
	var primarySAS string
	confirmOpts := LinkConfirmOptions{
		OnSAS: func(s string) error {
			primarySAS = s
			return nil
		},
	}

	claimRes, claimErr, confirmRes, confirmErr := driveHandshake(t, claimOpts, confirmOpts)
	if claimErr != nil {
		t.Fatalf("LinkClaim: %v", claimErr)
	}
	if confirmErr != nil {
		t.Fatalf("LinkConfirm: %v", confirmErr)
	}
	if secondarySAS == "" || primarySAS == "" {
		t.Fatalf("OnSAS never called: secondary=%q primary=%q", secondarySAS, primarySAS)
	}
	if secondarySAS != primarySAS {
		t.Fatalf("SAS mismatch — handshake is supposed to be transcript-bound. secondary=%s primary=%s", secondarySAS, primarySAS)
	}
	if claimRes.SAS != secondarySAS {
		t.Fatalf("LinkClaimResult.SAS = %q, want %q", claimRes.SAS, secondarySAS)
	}
	if confirmRes.SAS != primarySAS {
		t.Fatalf("LinkConfirmResult.SAS = %q, want %q", confirmRes.SAS, primarySAS)
	}
	// SAS format sanity
	if len(claimRes.SAS) != 9 || claimRes.SAS[4] != '-' {
		t.Errorf("SAS shape: %q", claimRes.SAS)
	}
}

// TestLinkSAS_primaryRejects: primary's OnSAS returns an error
// (simulating user typing "no" at the prompt). The handshake must
// abort cleanly: no manifest mutation, secondary fails fast via the
// abort flag, no enrollment cert appears for the would-be device.
func TestLinkSAS_primaryRejects(t *testing.T) {
	ctx := context.Background()
	primary, prov := newPrimary(t)
	if err := primary.CompartmentCreate(ctx, "shared", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	init, err := primary.LinkInit(ctx, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	// Capture manifest sequence BEFORE the attempted handshake.
	before, err := primary.Manifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	beforeSeq := before.Sequence

	newState, _ := NewState(t.TempDir())
	var claimRes *LinkClaimResult
	var claimErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		claimRes, claimErr = LinkClaim(ctx, init.Encoded, "rogue", LinkClaimOptions{
			State:        newState,
			ProviderFor:  func(_ domain.S3Credential, _ domain.BucketInfo) (storage.Provider, error) { return prov, nil },
			Now:          primary.now,
			PollInterval: 2 * time.Millisecond,
			Timeout:      3 * time.Second,
		})
	}()

	// Wait for response to land.
	respKey := domain.PairingResponseKey(init.PID)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if exists, _ := prov.Exists(ctx, respKey); exists {
			break
		}
		time.Sleep(time.Millisecond)
	}

	// Primary rejects the SAS.
	_, confirmErr := primary.LinkConfirm(ctx, init.PID, LinkConfirmOptions{
		OnSAS: func(_ string) error {
			return errUserDeclined
		},
	})
	if confirmErr == nil {
		t.Fatal("LinkConfirm should have errored on OnSAS rejection")
	}
	if !strings.Contains(confirmErr.Error(), "sas verification declined") {
		t.Errorf("expected confirm error to mention SAS verification, got: %v", confirmErr)
	}

	// Secondary should fail fast due to the abort flag, not wait timeout.
	wg.Wait()
	if claimErr == nil {
		t.Fatal("LinkClaim should have failed due to abort flag")
	}
	if !strings.Contains(claimErr.Error(), "aborted by primary") {
		t.Errorf("claim error should mention 'aborted by primary', got: %v", claimErr)
	}
	if claimRes != nil {
		t.Errorf("claim result should be nil on abort, got %+v", claimRes)
	}

	// Manifest sequence must not have advanced. The device must NOT be
	// enrolled. The pairing stub must STILL be present (so the user can
	// retry without re-running LinkInit).
	after, err := primary.Manifest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Sequence != beforeSeq {
		t.Errorf("manifest sequence advanced from %d to %d on rejected pairing — should have been a no-op", beforeSeq, after.Sequence)
	}
	if _, ok := after.Pairings[init.PID]; !ok {
		t.Error("pairing stub should still be present after a SAS rejection (so user can retry)")
	}
	// And the abort flag must be visible in the bucket.
	if exists, _ := prov.Exists(ctx, domain.PairingAbortKey(init.PID)); !exists {
		t.Error("abort flag must be written to bucket on SAS rejection")
	}
	// The response.json should be cleaned up so the next attempt doesn't
	// see stale state.
	if exists, _ := prov.Exists(ctx, respKey); exists {
		t.Error("response.json should be deleted after SAS rejection")
	}
}

// TestLinkSAS_acceptSASMismatchAborts: --accept-sas <wrong> at the
// primary aborts the same way as OnSAS rejection.
func TestLinkSAS_acceptSASMismatchAborts(t *testing.T) {
	ctx := context.Background()
	primary, prov := newPrimary(t)
	init, err := primary.LinkInit(ctx, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	newState, _ := NewState(t.TempDir())
	var wg sync.WaitGroup
	wg.Add(1)
	var claimErr error
	go func() {
		defer wg.Done()
		_, claimErr = LinkClaim(ctx, init.Encoded, "x", LinkClaimOptions{
			State:        newState,
			ProviderFor:  func(_ domain.S3Credential, _ domain.BucketInfo) (storage.Provider, error) { return prov, nil },
			Now:          primary.now,
			PollInterval: 2 * time.Millisecond,
			Timeout:      3 * time.Second,
		})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if exists, _ := prov.Exists(ctx, domain.PairingResponseKey(init.PID)); exists {
			break
		}
		time.Sleep(time.Millisecond)
	}

	_, confirmErr := primary.LinkConfirm(ctx, init.PID, LinkConfirmOptions{
		AcceptSAS: "0000-0000", // deliberately wrong
	})
	if confirmErr == nil {
		t.Fatal("LinkConfirm should have errored on AcceptSAS mismatch")
	}
	if !strings.Contains(confirmErr.Error(), "sas mismatch") {
		t.Errorf("expected confirm error to mention 'sas mismatch', got: %v", confirmErr)
	}
	wg.Wait()
	if claimErr == nil || !strings.Contains(claimErr.Error(), "aborted by primary") {
		t.Errorf("secondary should have failed fast via abort flag, got: %v", claimErr)
	}
}

// TestLinkSAS_acceptSASCorrectProceeds: --accept-sas <correct> bypasses
// the prompt and enrolls successfully.
func TestLinkSAS_acceptSASCorrectProceeds(t *testing.T) {
	ctx := context.Background()
	primary, prov := newPrimary(t)
	if err := primary.CompartmentCreate(ctx, "shared", domain.ModeMount); err != nil {
		t.Fatal(err)
	}
	init, err := primary.LinkInit(ctx, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	// First, drive the claim halfway so we can read the SAS the
	// secondary computes, then pass it as --accept-sas.
	var secondarySAS string
	newState, _ := NewState(t.TempDir())
	var wg sync.WaitGroup
	wg.Add(1)
	var claimRes *LinkClaimResult
	var claimErr error
	go func() {
		defer wg.Done()
		claimRes, claimErr = LinkClaim(ctx, init.Encoded, "x", LinkClaimOptions{
			State:        newState,
			ProviderFor:  func(_ domain.S3Credential, _ domain.BucketInfo) (storage.Provider, error) { return prov, nil },
			Now:          primary.now,
			PollInterval: 2 * time.Millisecond,
			Timeout:      5 * time.Second,
			OnSAS:        func(s string) error { secondarySAS = s; return nil },
		})
	}()
	// Wait until the response is posted — that means OnSAS was invoked
	// and the SAS is captured.
	respKey := domain.PairingResponseKey(init.PID)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if exists, _ := prov.Exists(ctx, respKey); exists {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if secondarySAS == "" {
		wg.Wait()
		t.Fatalf("secondary never invoked OnSAS; claim err: %v", claimErr)
	}

	confirmRes, confirmErr := primary.LinkConfirm(ctx, init.PID, LinkConfirmOptions{
		AcceptSAS: secondarySAS,
	})
	if confirmErr != nil {
		t.Fatalf("LinkConfirm with correct --accept-sas should have succeeded, got: %v", confirmErr)
	}
	wg.Wait()
	if claimErr != nil {
		t.Fatalf("claim failed: %v", claimErr)
	}
	if claimRes.SAS != confirmRes.SAS {
		t.Fatalf("SAS mismatch: claim=%s confirm=%s", claimRes.SAS, confirmRes.SAS)
	}
	if confirmRes.SAS != secondarySAS {
		t.Fatalf("confirm SAS %s != captured secondary SAS %s", confirmRes.SAS, secondarySAS)
	}
}

// TestLinkSAS_legacyFingerprintFlowStillWorks: with no SAS options
// supplied (legacy flow), pairing still completes — backward compat.
// This guards against accidentally making SAS mandatory and breaking
// existing scripts that rely on the --expect-fingerprint path.
func TestLinkSAS_legacyFingerprintFlowStillWorks(t *testing.T) {
	claimRes, claimErr, confirmRes, confirmErr := driveHandshake(t, LinkClaimOptions{}, LinkConfirmOptions{})
	if claimErr != nil {
		t.Fatalf("claim: %v", claimErr)
	}
	if confirmErr != nil {
		t.Fatalf("confirm: %v", confirmErr)
	}
	if claimRes.SAS == "" {
		t.Error("LinkClaimResult.SAS should always be populated")
	}
	if confirmRes.SAS == "" {
		t.Error("LinkConfirmResult.SAS should always be populated")
	}
	if claimRes.SAS != confirmRes.SAS {
		t.Errorf("SAS still must match in legacy flow: %s vs %s", claimRes.SAS, confirmRes.SAS)
	}
}

// errUserDeclined is the sentinel test error used to simulate a user
// answering "no" at the SAS prompt. Defined here so the same value
// is reused across the rejection-path tests.
var errUserDeclined = errPlain("user declined SAS")

type errPlain string

func (e errPlain) Error() string { return string(e) }
