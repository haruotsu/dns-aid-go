package fixture_test

import (
	"testing"

	"github.com/miekg/dns"

	"github.com/haruotsu/dns-aid-go/internal/fixture"
	"github.com/haruotsu/dns-aid-go/internal/resolver/resolvertest"
)

// serveZone loads the named zone fixture into an in-process DNS server and
// returns its address. The server is shut down when the test finishes.
func serveZone(t *testing.T, name string) string {
	t.Helper()
	zone, err := fixture.Zone(name)
	if err != nil {
		t.Fatalf("fixture.Zone(%q): %v", name, err)
	}
	srv, err := resolvertest.New(zone)
	if err != nil {
		t.Fatalf("resolvertest.New(%q): %v", name, err)
	}
	t.Cleanup(func() { srv.Close() }) //nolint:errcheck
	return srv.Addr
}

// exchange sends a single question to addr and returns the response.
func exchange(t *testing.T, addr, fqdn string, qtype uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(fqdn, qtype)
	r, err := dns.Exchange(m, addr)
	if err != nil {
		t.Fatalf("Exchange(%s %s): %v", fqdn, dns.TypeToString[qtype], err)
	}
	return r
}

// Every fixture zone must load into the in-process DNS server and serve its
// agent index TXT record (OSS-03 §7.1).
func TestZonesLoadAndServeIndex(t *testing.T) {
	tests := []struct {
		zone      string
		wantIndex string
	}{
		{"zone_full", "agents=chat:mcp,billing:a2a,support:https"},
		{"zone_index_only", "agents=chat:mcp"},
		{"zone_partial", "agents=chat:mcp,legacy:a2a,ghost:https"},
		{"zone_custom_params", "agents=booking:mcp"},
		{"zone_badcap", "agents=chat:mcp"},
	}
	for _, tt := range tests {
		t.Run(tt.zone, func(t *testing.T) {
			addr := serveZone(t, tt.zone)

			r := exchange(t, addr, "_index._agents.example.com.", dns.TypeTXT)
			if r.Rcode != dns.RcodeSuccess {
				t.Fatalf("Rcode = %s, want NOERROR", dns.RcodeToString[r.Rcode])
			}
			if len(r.Answer) != 1 {
				t.Fatalf("len(Answer) = %d, want 1", len(r.Answer))
			}
			txt, ok := r.Answer[0].(*dns.TXT)
			if !ok {
				t.Fatalf("Answer[0] = %T, want *dns.TXT", r.Answer[0])
			}
			if len(txt.Txt) != 1 || txt.Txt[0] != tt.wantIndex {
				t.Errorf("index TXT = %q, want [%q]", txt.Txt, tt.wantIndex)
			}
		})
	}
}
