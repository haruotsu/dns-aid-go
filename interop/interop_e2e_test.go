//go:build interop

package interop

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/haruotsu/dns-aid-go/internal/fixture"
	"github.com/haruotsu/dns-aid-go/internal/resolver/resolvertest"
)

// commandTimeout bounds one CLI invocation. The reference implementation
// performs real (blocked) HTTP fetch attempts for cap documents and agent
// cards, so it needs headroom over the pure-DNS Go CLI.
const commandTimeout = 60 * time.Second

// TestDiscoverMatchesReferenceImplementation serves each fixture zone from
// an in-process DNS server, runs `dnsaid discover` and the reference
// implementation's `dns-aid discover` against it, and requires the
// normalized JSON results to be identical (R-CORE-2, N-1).
//
// It needs the reference CLI on PATH (or at $INTEROP_REF_CLI):
//
//	pip install "dns-aid[cli]"
//	go test -tags interop ./interop/
func TestDiscoverMatchesReferenceImplementation(t *testing.T) {
	goCLI := buildGoCLI(t)
	refCLI := referenceCLI(t)
	pythonPath := sitecustomizePath(t)

	cases := []struct {
		zone string
		// wantAgents guards against a harness bug that would make both
		// implementations return an empty (and trivially equal) result.
		wantAgents int
	}{
		{"zone_full", 3},
		{"zone_index_only", 0},
		{"zone_partial", 1},
		{"zone_custom_params", 1},
		{"zone_badcap", 1},
	}
	for _, tc := range cases {
		t.Run(tc.zone, func(t *testing.T) {
			zone, err := fixture.Zone(tc.zone)
			if err != nil {
				t.Fatalf("load fixture: %v", err)
			}
			srv, err := resolvertest.New(zone)
			if err != nil {
				t.Fatalf("start DNS server: %v", err)
			}
			defer srv.Close() //nolint:errcheck // best-effort test cleanup

			goResult := runGoCLI(t, goCLI, srv.Addr)
			refResult := runReferenceCLI(t, refCLI, pythonPath, srv.Addr)

			if len(goResult.Agents) != tc.wantAgents {
				t.Errorf("dnsaid found %d agents, want %d", len(goResult.Agents), tc.wantAgents)
			}
			if len(refResult.Agents) != tc.wantAgents {
				t.Errorf("reference found %d agents, want %d", len(refResult.Agents), tc.wantAgents)
			}
			for _, d := range Diff(goResult, refResult) {
				t.Errorf("dnsaid vs reference: %s", d)
			}
		})
	}
}

// buildGoCLI compiles cmd/dnsaid into a temporary directory, so the test
// always exercises the working tree's CLI.
func buildGoCLI(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "dnsaid")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/haruotsu/dns-aid-go/cmd/dnsaid")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build dnsaid: %v\n%s", err, out)
	}
	return bin
}

// referenceCLI locates the reference implementation's CLI: $INTEROP_REF_CLI
// if set, otherwise "dns-aid" on PATH.
func referenceCLI(t *testing.T) string {
	t.Helper()
	cli := os.Getenv("INTEROP_REF_CLI")
	if cli == "" {
		cli = "dns-aid"
	}
	path, err := exec.LookPath(cli)
	if err != nil {
		t.Fatalf(`reference CLI %q not found: install it with pip install "dns-aid[cli]" or set INTEROP_REF_CLI`, cli)
	}
	return path
}

// sitecustomizePath returns the absolute directory of the sitecustomize.py
// that redirects the reference implementation's DNS queries (see that file).
func sitecustomizePath(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("sitecustomize")
	if err != nil {
		t.Fatalf("resolve sitecustomize dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "sitecustomize.py")); err != nil {
		t.Fatalf("sitecustomize.py not found: %v", err)
	}
	return dir
}

func runGoCLI(t *testing.T, bin, dnsAddr string) Doc {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "discover", "example.com", "--json")
	cmd.Env = append(os.Environ(), "DNSAID_RESOLVER="+dnsAddr)
	out, err := cmd.Output()
	// A discovery where every indexed agent failed exits non-zero by
	// design (zone_index_only); the comparison below still needs the
	// JSON document it printed, so only non-exit errors are fatal.
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("run dnsaid: %v", err)
	}
	if exitErr != nil {
		t.Logf("dnsaid exited %d (stderr: %s)", exitErr.ExitCode(), exitErr.Stderr)
	}

	doc, err := NormalizeGo(out)
	if err != nil {
		t.Fatalf("normalize dnsaid output: %v\noutput:\n%s", err, out)
	}
	return doc
}

func runReferenceCLI(t *testing.T, bin, pythonPath, dnsAddr string) Doc {
	t.Helper()
	host, port, err := net.SplitHostPort(dnsAddr)
	if err != nil {
		t.Fatalf("split DNS server address: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "discover", "example.com", "--json")
	// Prepend to any existing PYTHONPATH so our sitecustomize.py wins.
	if existing := os.Getenv("PYTHONPATH"); existing != "" {
		pythonPath += string(os.PathListSeparator) + existing
	}
	cmd.Env = append(os.Environ(),
		"PYTHONPATH="+pythonPath,
		"INTEROP_DNS_HOST="+host,
		"INTEROP_DNS_PORT="+port,
	)
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("run reference CLI: %v\nstderr:\n%s\nstdout:\n%s", err, exitErr.Stderr, out)
		}
		t.Fatalf("run reference CLI: %v", err)
	}

	doc, err := NormalizeRef(out)
	if err != nil {
		t.Fatalf("normalize reference output: %v\noutput:\n%s", err, out)
	}
	return doc
}
