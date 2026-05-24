package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestDoctorTally(t *testing.T) {
	rs := []checkResult{
		{status: statusOK},
		{status: statusOK},
		{status: statusWarn},
		{status: statusInfo},
		{status: statusFail},
		{status: statusFail},
	}
	fail, warn := tallyDoctor(rs)
	if fail != 2 {
		t.Fatalf("fail = %d, want 2", fail)
	}
	if warn != 1 {
		t.Fatalf("warn = %d, want 1", warn)
	}
}

func TestDoctorPrint_plainMode(t *testing.T) {
	rs := []checkResult{
		{name: "rclone", status: statusOK, detail: "v1.74"},
		{name: "FUSE", status: statusWarn, detail: "missing", suggest: "install fuse3"},
		{name: "manifest", status: statusFail, detail: "signature invalid"},
	}
	var buf bytes.Buffer
	printDoctor(&buf, rs, false)
	out := buf.String()
	for _, want := range []string{"[ OK ]", "[WARN]", "[FAIL]", "→ install fuse3", "Result: 1 failing, 1 warning"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Errorf("plain mode contained ANSI escapes:\n%s", out)
	}
}

func TestDoctorPrint_colorMode(t *testing.T) {
	rs := []checkResult{{name: "x", status: statusOK, detail: "ok"}}
	var buf bytes.Buffer
	printDoctor(&buf, rs, true)
	if !strings.Contains(buf.String(), "\x1b[32m") {
		t.Errorf("color mode missing green ANSI:\n%s", buf.String())
	}
}

func TestDoctorAbbrev(t *testing.T) {
	if got := abbrev("abcdef", 3); got != "abc" {
		t.Errorf("abbrev = %q, want abc", got)
	}
	if got := abbrev("abc", 10); got != "abc" {
		t.Errorf("abbrev short = %q, want abc", got)
	}
}
