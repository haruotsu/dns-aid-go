package main

// CLI integration tests (PR-8, R-CLI-1/3): each test runs the command
// in-process against an in-process DNS server serving a testdata zone
// fixture (N-7) and compares output against golden files.
//
// Test list:
// - [ ] discover with no arguments fails with usage (exit 1)
// - [ ] discover zone_full prints the human summary (golden, exit 0)
// - [ ] discover zone_full --json prints agents[]+errors[] (golden, exit 0)
// - [ ] discover zone_partial warns on stderr per failed agent, exit 0
// - [ ] discover zone_partial --json records errors[] (golden)
// - [ ] discover zone_index_only finds 0 agents, exit 1
// - [ ] discover against a zone without an index exits 2 (ErrIndexNotFound)
// - [ ] discover --name picks a single agent (golden)
// - [ ] discover --name of an unknown agent exits 3 (ErrAgentNotFound)
// - [ ] discover --protocol filters the index entries
// - [ ] discover --require-dnssec without AD exits 4 (ErrDNSSECRequired)
// - [ ] discover --require-dnssec with AD succeeds and shows dnssec:ok
// - [ ] invalid DNSAID_TIMEOUT fails with exit 1
// - [ ] unknown flag fails with usage (exit 1)

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/haruotsu/dns-aid-go/internal/fixture"
	"github.com/haruotsu/dns-aid-go/internal/resolver/resolvertest"
)

var update = flag.Bool("update", false, "rewrite golden files with the current output")

// startZone serves the named testdata zone fixture from an in-process DNS
// server and points DNSAID_RESOLVER at it.
func startZone(t *testing.T, zoneName string, opts ...resolvertest.Option) {
	t.Helper()
	zone, err := fixture.Zone(zoneName)
	if err != nil {
		t.Fatalf("fixture.Zone(%q): %v", zoneName, err)
	}
	srv, err := resolvertest.New(zone, opts...)
	if err != nil {
		t.Fatalf("resolvertest.New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	t.Setenv("DNSAID_RESOLVER", srv.Addr)
}

// runCLI executes the CLI in-process and captures its output.
func runCLI(args ...string) (stdout, stderr string, code int) {
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return out.String(), errOut.String(), code
}

// checkGolden compares got with the named golden file; -update rewrites it.
func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("update golden %s: %v", path, err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run with -update to create): %v", path, err)
	}
	if got != string(want) {
		t.Errorf("output differs from %s:\n--- want\n%s\n--- got\n%s", path, want, got)
	}
}

func TestDiscoverNoArgsFailsWithUsage(t *testing.T) {
	stdout, stderr, code := runCLI("discover")

	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("stderr should contain usage, got:\n%s", stderr)
	}
}
