package main

import (
	"strings"
	"testing"

	"github.com/haruotsu/dns-aid-go/internal/version"
)

// The expected output is derived from version.String() instead of a golden
// file: tagpr rewrites internal/version/version.go on every release, and a
// hard-coded version would fail the release PR's CI.
func TestVersionCommand(t *testing.T) {
	stdout, stderr, code := runCLI("version")

	if code != 0 {
		t.Errorf("exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}
	want := "dnsaid version " + version.String() + "\n"
	if stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
}

func TestVersionCommandRejectsArgs(t *testing.T) {
	stdout, stderr, code := runCLI("version", "extra")

	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("stderr = %q, want usage text", stderr)
	}
}
