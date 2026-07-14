package main

// CLI integration tests (R-CLI-1/3): each test runs the command in-process
// against an in-process DNS server serving a testdata zone fixture (N-7) and
// compares output against golden files (regenerate with -update).

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
	// A DNSAID_TIMEOUT leaking in from the developer's environment must not
	// change test behavior; empty means "use the default".
	t.Setenv("DNSAID_TIMEOUT", "")
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

func TestDiscoverZoneFullHuman(t *testing.T) {
	startZone(t, "zone_full")

	stdout, stderr, code := runCLI("discover", "example.com")

	if code != 0 {
		t.Errorf("exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}
	checkGolden(t, "discover_full_human.golden", stdout)
}

func TestDiscoverZoneFullJSON(t *testing.T) {
	startZone(t, "zone_full")

	stdout, stderr, code := runCLI("discover", "example.com", "--json")

	if code != 0 {
		t.Errorf("exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want empty", stderr)
	}
	checkGolden(t, "discover_full_json.golden", stdout)
}

func TestDiscoverZonePartialWarnsAndSucceeds(t *testing.T) {
	startZone(t, "zone_partial")

	stdout, stderr, code := runCLI("discover", "example.com")

	if code != 0 {
		t.Errorf("exit code = %d, want 0 (partial success, R-DISC-5)", code)
	}
	for _, fqdn := range []string{"legacy.example.com", "ghost.example.com"} {
		if !strings.Contains(stderr, "WARN") || !strings.Contains(stderr, fqdn) {
			t.Errorf("stderr should warn about %s, got:\n%s", fqdn, stderr)
		}
	}
	checkGolden(t, "discover_partial_human.golden", stdout)
}

func TestDiscoverZonePartialJSONRecordsErrors(t *testing.T) {
	startZone(t, "zone_partial")

	stdout, _, code := runCLI("discover", "example.com", "--json")

	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	checkGolden(t, "discover_partial_json.golden", stdout)
}

func TestDiscoverZoneIndexOnlyFails(t *testing.T) {
	startZone(t, "zone_index_only")

	stdout, stderr, code := runCLI("discover", "example.com")

	if code != 1 {
		t.Errorf("exit code = %d, want 1 (index entries but zero agents)", code)
	}
	if !strings.Contains(stdout, "FOUND 0 agents") {
		t.Errorf("stdout should report zero agents, got:\n%s", stdout)
	}
	if !strings.Contains(stderr, "WARN") || !strings.Contains(stderr, "chat.example.com") {
		t.Errorf("stderr should warn about chat.example.com, got:\n%s", stderr)
	}
}

func TestDiscoverIndexNotFoundExitCode(t *testing.T) {
	startZone(t, "zone_full")

	_, stderr, code := runCLI("discover", "other.example")

	if code != 2 {
		t.Errorf("exit code = %d, want 2 (ErrIndexNotFound)", code)
	}
	if !strings.Contains(stderr, "agent index not found") {
		t.Errorf("stderr should name the missing index, got:\n%s", stderr)
	}
}

func TestDiscoverNameSelectsSingleAgent(t *testing.T) {
	startZone(t, "zone_full")

	stdout, stderr, code := runCLI("discover", "example.com", "--name", "billing")

	if code != 0 {
		t.Errorf("exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, "FOUND 1 agent at example.com") {
		t.Errorf("stdout should report exactly one agent, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "billing.example.com") || strings.Contains(stdout, "chat.example.com") {
		t.Errorf("stdout should list only billing, got:\n%s", stdout)
	}
}

func TestDiscoverNameNotFoundExitCode(t *testing.T) {
	startZone(t, "zone_full")

	_, stderr, code := runCLI("discover", "example.com", "--name", "nonexistent")

	if code != 3 {
		t.Errorf("exit code = %d, want 3 (ErrAgentNotFound)", code)
	}
	if !strings.Contains(stderr, "agent not found") {
		t.Errorf("stderr should report the missing agent, got:\n%s", stderr)
	}
}

func TestDiscoverProtocolFilters(t *testing.T) {
	startZone(t, "zone_full")

	stdout, _, code := runCLI("discover", "example.com", "--protocol", "a2a")

	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout, "billing.example.com") || strings.Contains(stdout, "chat.example.com") {
		t.Errorf("stdout should list only the a2a agent, got:\n%s", stdout)
	}
}

func TestDiscoverRequireDNSSECWithoutAD(t *testing.T) {
	startZone(t, "zone_full")

	_, stderr, code := runCLI("discover", "example.com", "--require-dnssec")

	if code != 4 {
		t.Errorf("exit code = %d, want 4 (ErrDNSSECRequired)", code)
	}
	if !strings.Contains(stderr, "DNSSEC") {
		t.Errorf("stderr should mention DNSSEC, got:\n%s", stderr)
	}
}

func TestDiscoverRequireDNSSECWithAD(t *testing.T) {
	startZone(t, "zone_full", resolvertest.WithAD())

	stdout, stderr, code := runCLI("discover", "example.com", "--require-dnssec")

	if code != 0 {
		t.Errorf("exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, "[dnssec:ok]") || strings.Contains(stdout, "unvalidated") {
		t.Errorf("stdout should mark every agent dnssec:ok, got:\n%s", stdout)
	}
}

func TestDiscoverInvalidTimeoutFails(t *testing.T) {
	for _, timeout := range []string{"not-a-duration", "-5s", "0s"} {
		t.Run(timeout, func(t *testing.T) {
			startZone(t, "zone_full")
			t.Setenv("DNSAID_TIMEOUT", timeout)

			_, stderr, code := runCLI("discover", "example.com")

			if code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
			if !strings.Contains(stderr, "DNSAID_TIMEOUT") {
				t.Errorf("stderr should name DNSAID_TIMEOUT, got:\n%s", stderr)
			}
		})
	}
}

func TestDiscoverProtocolWithoutMatchSucceedsEmpty(t *testing.T) {
	startZone(t, "zone_full")

	stdout, stderr, code := runCLI("discover", "example.com", "--protocol", "nomatch")

	if code != 0 {
		t.Errorf("exit code = %d, want 0 (no match is not a failure, stderr: %s)", code, stderr)
	}
	if !strings.Contains(stdout, "FOUND 0 agents") {
		t.Errorf("stdout should report zero agents, got:\n%s", stdout)
	}
}

func TestDiscoverIndexNotFoundJSONKeepsStdoutEmpty(t *testing.T) {
	startZone(t, "zone_full")

	stdout, _, code := runCLI("discover", "other.example", "--json")

	if code != 2 {
		t.Errorf("exit code = %d, want 2", code)
	}
	if stdout != "" {
		t.Errorf("stdout must stay empty on failure so JSON consumers never parse a partial document, got:\n%s", stdout)
	}
}

func TestDiscoverValidTimeoutSucceeds(t *testing.T) {
	startZone(t, "zone_full")
	t.Setenv("DNSAID_TIMEOUT", "2s")

	_, stderr, code := runCLI("discover", "example.com")

	if code != 0 {
		t.Errorf("exit code = %d, want 0 (stderr: %s)", code, stderr)
	}
}

func TestUnknownFlagFailsWithUsage(t *testing.T) {
	_, stderr, code := runCLI("discover", "example.com", "--no-such-flag")

	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "Usage:") {
		t.Errorf("stderr should contain usage, got:\n%s", stderr)
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
