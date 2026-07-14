package fixture_test

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/haruotsu/dns-aid-go/internal/fixture"
	"github.com/haruotsu/dns-aid-go/internal/record"
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

// svcbParams queries fqdn's SVCB record on addr and returns its draft
// private-use parameters.
func svcbParams(t *testing.T, addr, fqdn string) record.SVCBParams {
	t.Helper()
	r := exchange(t, addr, fqdn, dns.TypeSVCB)
	if len(r.Answer) != 1 {
		t.Fatalf("len(Answer) = %d, want 1", len(r.Answer))
	}
	svcb, ok := r.Answer[0].(*dns.SVCB)
	if !ok {
		t.Fatalf("Answer[0] = %T, want *dns.SVCB", r.Answer[0])
	}
	params, err := record.ParseSVCBParams(svcb.Value)
	if err != nil {
		t.Fatalf("ParseSVCBParams: %v", err)
	}
	return params
}

// capDocDigest returns the raw base64url SHA-256 of the cap document
// fixture, the digest convention of the draft's cap-sha256 parameter.
func capDocDigest(t *testing.T) string {
	t.Helper()
	doc, err := fixture.Read("capdoc_chat.json")
	if err != nil {
		t.Fatalf("fixture.Read: %v", err)
	}
	sum := sha256.Sum256(doc)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// zone_full's cap-sha256 must match the cap document fixture so that
// capability fetching (R-DISC-4) can verify it end to end.
func TestZoneFullCapSHA256MatchesCapDoc(t *testing.T) {
	addr := serveZone(t, "zone_full")
	params := svcbParams(t, addr, "chat.example.com.")

	if params.Cap == "" {
		t.Error("cap (key65400) is empty, want a cap document URI")
	}
	if want := capDocDigest(t); params.CapSHA256 != want {
		t.Errorf("cap-sha256 = %q, want %q (digest of capdoc_chat.json)", params.CapSHA256, want)
	}
}

// zone_badcap's cap-sha256 must NOT match the cap document fixture, so it
// can prove that mismatch detection (ErrCapMismatch) triggers.
func TestZoneBadcapCapSHA256Mismatches(t *testing.T) {
	addr := serveZone(t, "zone_badcap")
	params := svcbParams(t, addr, "chat.example.com.")

	if params.Cap == "" {
		t.Error("cap (key65400) is empty, want a cap document URI")
	}
	if params.CapSHA256 == "" {
		t.Error("cap-sha256 (key65401) is empty, want a mismatching digest")
	}
	if got := capDocDigest(t); params.CapSHA256 == got {
		t.Errorf("cap-sha256 = %q matches capdoc_chat.json, want a mismatch", got)
	}
}

// zone_index_only has an index entry but no agent records: the agent's SVCB
// query must yield NXDOMAIN ("one index entry, zero agents", R-DISC-3).
func TestZoneIndexOnlyHasNoAgentRecords(t *testing.T) {
	addr := serveZone(t, "zone_index_only")

	r := exchange(t, addr, "chat.example.com.", dns.TypeSVCB)
	if r.Rcode != dns.RcodeNameError {
		t.Errorf("chat SVCB Rcode = %s, want NXDOMAIN", dns.RcodeToString[r.Rcode])
	}
}

// zone_partial mixes a complete agent (chat), a TXT-only agent (legacy,
// NODATA on SVCB) and an indexed-but-absent agent (ghost, NXDOMAIN), the
// three shapes discover's partial success must handle (R-DISC-5).
func TestZonePartialAgentShapes(t *testing.T) {
	addr := serveZone(t, "zone_partial")

	r := exchange(t, addr, "chat.example.com.", dns.TypeSVCB)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Errorf("chat SVCB: Rcode = %s, len(Answer) = %d; want NOERROR with 1 answer",
			dns.RcodeToString[r.Rcode], len(r.Answer))
	}

	r = exchange(t, addr, "legacy.example.com.", dns.TypeSVCB)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Errorf("legacy SVCB: Rcode = %s, len(Answer) = %d; want NOERROR with 0 answers (NODATA)",
			dns.RcodeToString[r.Rcode], len(r.Answer))
	}
	r = exchange(t, addr, "legacy.example.com.", dns.TypeTXT)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Errorf("legacy TXT: Rcode = %s, len(Answer) = %d; want NOERROR with 1 answer",
			dns.RcodeToString[r.Rcode], len(r.Answer))
	}

	r = exchange(t, addr, "ghost.example.com.", dns.TypeSVCB)
	if r.Rcode != dns.RcodeNameError {
		t.Errorf("ghost SVCB: Rcode = %s, want NXDOMAIN", dns.RcodeToString[r.Rcode])
	}
}

// zone_custom_params carries every draft private-use parameter
// key65400-65405 with the expected logical values (R-CORE-3).
func TestZoneCustomParamsCarriesAllDraftKeys(t *testing.T) {
	addr := serveZone(t, "zone_custom_params")
	params := svcbParams(t, addr, "booking.example.com.")

	want := record.SVCBParams{
		Cap:       "https://mcp.example.com/.well-known/agent-cap.json",
		CapSHA256: capDocDigest(t),
		BAP:       "mcp/1,a2a/1",
		Policy:    "https://example.com/agent-policy",
		Realm:     "production",
		Sig:       "c2lnLXBsYWNlaG9sZGVy",
	}
	if params.Cap != want.Cap {
		t.Errorf("cap = %q, want %q", params.Cap, want.Cap)
	}
	if params.CapSHA256 != want.CapSHA256 {
		t.Errorf("cap-sha256 = %q, want %q", params.CapSHA256, want.CapSHA256)
	}
	if params.BAP != want.BAP {
		t.Errorf("bap = %q, want %q", params.BAP, want.BAP)
	}
	if params.Policy != want.Policy {
		t.Errorf("policy = %q, want %q", params.Policy, want.Policy)
	}
	if params.Realm != want.Realm {
		t.Errorf("realm = %q, want %q", params.Realm, want.Realm)
	}
	if params.Sig != want.Sig {
		t.Errorf("sig = %q, want %q", params.Sig, want.Sig)
	}
	if len(params.Unknown) != 0 {
		t.Errorf("Unknown = %v, want none", params.Unknown)
	}
}

// zoneFiles returns the basenames (without extension) of every .zone file
// in the testdata directory, so fixture-wide tests automatically cover
// zones added later.
func zoneFiles(t *testing.T) []string {
	t.Helper()
	dir, err := fixture.Dir()
	if err != nil {
		t.Fatalf("fixture.Dir: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, "*.zone"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no .zone fixtures found")
	}
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, strings.TrimSuffix(filepath.Base(m), ".zone"))
	}
	return names
}

// Fixtures must not reference real domains or organizations: every owner
// name, SVCB target and URI host has to stay within example.com (N-7, N-8).
func TestFixturesUseOnlyExampleDomains(t *testing.T) {
	uriHost := regexp.MustCompile(`https?://([^/"\s]+)`)

	for _, name := range zoneFiles(t) {
		t.Run(name, func(t *testing.T) {
			zone, err := fixture.Zone(name)
			if err != nil {
				t.Fatalf("fixture.Zone: %v", err)
			}

			zp := dns.NewZoneParser(strings.NewReader(zone), "", "")
			for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
				if owner := rr.Header().Name; !strings.HasSuffix(owner, ".example.com.") && owner != "example.com." {
					t.Errorf("owner %q is outside example.com", owner)
				}
				if svcb, ok := rr.(*dns.SVCB); ok {
					if target := svcb.Target; !strings.HasSuffix(target, ".example.com.") && target != "example.com." {
						t.Errorf("SVCB target %q is outside example.com", target)
					}
				}
			}
			if err := zp.Err(); err != nil {
				t.Fatalf("parse zone: %v", err)
			}

			for _, m := range uriHost.FindAllStringSubmatch(zone, -1) {
				host := m[1]
				if host != "example.com" && !strings.HasSuffix(host, ".example.com") {
					t.Errorf("URI host %q is outside example.com", host)
				}
			}
		})
	}
}

// Every zone's agent index must parse with record.ParseIndexTXT so the
// fixtures stay in sync with the index grammar (R-DISC-1).
func TestZoneIndexesParse(t *testing.T) {
	for _, name := range zoneFiles(t) {
		t.Run(name, func(t *testing.T) {
			addr := serveZone(t, name)

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
			entries, err := record.ParseIndexTXT(txt.Txt...)
			if err != nil {
				t.Fatalf("ParseIndexTXT(%q): %v", txt.Txt, err)
			}
			if len(entries) == 0 {
				t.Error("index parses to zero entries, want at least one")
			}
		})
	}
}

// A fixture name that does not exist must surface a clear error rather
// than an empty zone.
func TestZoneUnknownNameFails(t *testing.T) {
	_, err := fixture.Zone("zone_does_not_exist")
	if err == nil {
		t.Fatal("Zone(zone_does_not_exist): err = nil, want error")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v, want a wrapped fs.ErrNotExist", err)
	}
}

// Fixture names must stay inside the testdata directory: path traversal
// ("../go.mod") and absolute paths must be rejected instead of reading
// arbitrary files.
func TestReadRejectsNonLocalPath(t *testing.T) {
	for _, name := range []string{"../go.mod", "/etc/hosts"} {
		if _, err := fixture.Read(name); err == nil {
			t.Errorf("Read(%q): err = nil, want error for non-local path", name)
		}
	}
	if _, err := fixture.Zone("../fixture/fixture"); err == nil {
		t.Error(`Zone("../fixture/fixture"): err = nil, want error for non-local path`)
	}
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
