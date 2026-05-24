package sync

import (
	"context"
	"testing"

	"github.com/sufforest/drift/internal/domain"
)

func sampleRequest() Request {
	return Request{
		WorkspaceID:    "wks_t",
		Compartment:    "code",
		CompartmentKey: []byte("0123456789abcdef0123456789abcdef"),
		Cred:           domain.S3Credential{AccessKeyID: "AK", SecretAccessKey: "SK"},
		Bucket:         domain.BucketInfo{Name: "b"},
		LocalPath:      "/tmp/code",
	}
}

func TestNoopSyncer_recordsStartAndStop(t *testing.T) {
	ctx := context.Background()
	s := NewNoopSyncer()
	h, err := s.Sync(ctx, sampleRequest())
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Active(); len(got) != 1 {
		t.Fatalf("expected 1 active, got %v", got)
	}
	if err := s.Stop(ctx, h); err != nil {
		t.Fatal(err)
	}
	if got := s.Active(); len(got) != 0 {
		t.Fatalf("expected 0 active after Stop, got %v", got)
	}
	hist := s.History()
	if len(hist) != 2 || hist[0].Op != "sync" || hist[1].Op != "stop" {
		t.Fatalf("unexpected history: %v", hist)
	}
}

func TestNoopSyncer_doubleSyncFails(t *testing.T) {
	ctx := context.Background()
	s := NewNoopSyncer()
	if _, err := s.Sync(ctx, sampleRequest()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sync(ctx, sampleRequest()); err == nil {
		t.Fatal("expected double-sync on same path to fail")
	}
}

func TestRcloneBisyncer_buildArgs(t *testing.T) {
	r := &RcloneBisyncer{}
	req := Request{
		WorkspaceID: "wks_t", Compartment: "code", LocalPath: "/tmp/code",
	}
	first := r.buildArgs("crypt", req, "/tmp/journal", true)
	if !containsArg(first, "--resync") {
		t.Errorf("first run should include --resync, got %v", first)
	}
	if !containsPair(first, "--workdir", "/tmp/journal") {
		t.Errorf("missing --workdir, got %v", first)
	}
	if !containsPair(first, "--max-delete", "100") {
		t.Errorf("missing --max-delete safety bound, got %v", first)
	}
	if !containsArg(first, "--check-access") {
		t.Errorf("--check-access (sentinel file defense) must be present, got %v", first)
	}

	subsequent := r.buildArgs("crypt", req, "/tmp/journal", false)
	if containsArg(subsequent, "--resync") {
		t.Errorf("subsequent run should NOT include --resync, got %v", subsequent)
	}
}

func TestRcloneBisyncer_validateRequest(t *testing.T) {
	for _, mutate := range []func(*Request){
		func(r *Request) { r.LocalPath = "" },
		func(r *Request) { r.Compartment = "" },
		func(r *Request) { r.CompartmentKey = nil },
		func(r *Request) { r.Cred.AccessKeyID = "" },
		func(r *Request) { r.Cred.SecretAccessKey = "" },
	} {
		req := sampleRequest()
		req.Cred.AccessKeyID = "AK"
		req.Cred.SecretAccessKey = "SK"
		mutate(&req)
		if err := validateRequest(req); err == nil {
			t.Errorf("expected validation error for %+v", req)
		}
	}
}

func containsArg(args []string, needle string) bool {
	for _, a := range args {
		if a == needle {
			return true
		}
	}
	return false
}

func containsPair(args []string, key, val string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == key && args[i+1] == val {
			return true
		}
	}
	return false
}

func TestNoopSyncer_validation(t *testing.T) {
	ctx := context.Background()
	s := NewNoopSyncer()
	for _, mutate := range []func(*Request){
		func(r *Request) { r.LocalPath = "" },
		func(r *Request) { r.Compartment = "" },
		func(r *Request) { r.CompartmentKey = nil },
	} {
		req := sampleRequest()
		mutate(&req)
		if _, err := s.Sync(ctx, req); err == nil {
			t.Errorf("expected validation error for %+v", req)
		}
	}
}
