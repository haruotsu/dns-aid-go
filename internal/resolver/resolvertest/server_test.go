package resolvertest_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/haruotsu/dns-aid-go/internal/resolver/resolvertest"
)

const exampleZone = `
$ORIGIN example.com.
$TTL 300
_index._agents TXT "agents=chat:mcp,billing:a2a"
chat           SVCB 1 chat.example.com. alpn="mcp" port=443 key65400="https://example.com/cap.json"
chat           TXT  "capabilities=chat,assistant"
`

func TestServerServesTXT(t *testing.T) {
	srv, err := resolvertest.New(exampleZone)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Close()

	m := new(dns.Msg)
	m.SetQuestion("_index._agents.example.com.", dns.TypeTXT)
	r, err := dns.Exchange(m, srv.Addr)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

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
	want := "agents=chat:mcp,billing:a2a"
	if len(txt.Txt) != 1 || txt.Txt[0] != want {
		t.Errorf("Txt = %q, want [%q]", txt.Txt, want)
	}
}

func TestServerServesSVCB(t *testing.T) {
	srv, err := resolvertest.New(exampleZone)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Close()

	m := new(dns.Msg)
	m.SetQuestion("chat.example.com.", dns.TypeSVCB)
	r, err := dns.Exchange(m, srv.Addr)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("Rcode = %s, want NOERROR", dns.RcodeToString[r.Rcode])
	}
	if len(r.Answer) != 1 {
		t.Fatalf("len(Answer) = %d, want 1", len(r.Answer))
	}
	svcb, ok := r.Answer[0].(*dns.SVCB)
	if !ok {
		t.Fatalf("Answer[0] = %T, want *dns.SVCB", r.Answer[0])
	}
	if svcb.Target != "chat.example.com." {
		t.Errorf("Target = %q, want %q", svcb.Target, "chat.example.com.")
	}
	if len(svcb.Value) != 3 {
		t.Errorf("len(Value) = %d, want 3 (alpn, port, key65400)", len(svcb.Value))
	}
}

// bigZone holds one RRset far larger than a 512-octet plain-UDP response.
func bigZone() string {
	var b strings.Builder
	b.WriteString("$ORIGIN example.com.\n$TTL 300\n")
	for i := 0; i < 30; i++ {
		fmt.Fprintf(&b, "big TXT \"%03d-%s\"\n", i, strings.Repeat("x", 100))
	}
	return b.String()
}

func TestServerTruncatesUDPAndServesFullOverTCP(t *testing.T) {
	srv, err := resolvertest.New(bigZone())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Close()

	m := new(dns.Msg)
	m.SetQuestion("big.example.com.", dns.TypeTXT)

	r, err := dns.Exchange(m, srv.Addr)
	if err != nil {
		t.Fatalf("UDP Exchange: %v", err)
	}
	if !r.Truncated {
		t.Error("UDP response: Truncated = false, want true")
	}

	tcp := &dns.Client{Net: "tcp"}
	r, _, err = tcp.Exchange(m, srv.Addr)
	if err != nil {
		t.Fatalf("TCP Exchange: %v", err)
	}
	if r.Truncated {
		t.Error("TCP response: Truncated = true, want false")
	}
	if len(r.Answer) != 30 {
		t.Errorf("TCP len(Answer) = %d, want 30", len(r.Answer))
	}
}

func TestServerAuthenticatedData(t *testing.T) {
	srv, err := resolvertest.New(exampleZone, resolvertest.WithAD())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Close()

	// A DO=1 query simulates a security-aware client behind a validating
	// resolver: the response must carry the AD flag.
	m := new(dns.Msg)
	m.SetQuestion("chat.example.com.", dns.TypeSVCB)
	m.SetEdns0(4096, true)
	r, err := dns.Exchange(m, srv.Addr)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if !r.AuthenticatedData {
		t.Error("AuthenticatedData = false, want true for DO=1 query on WithAD server")
	}

	// Without DO or AD in the query, a validating resolver does not set AD.
	m = new(dns.Msg)
	m.SetQuestion("chat.example.com.", dns.TypeSVCB)
	r, err = dns.Exchange(m, srv.Addr)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if r.AuthenticatedData {
		t.Error("AuthenticatedData = true, want false for plain query")
	}
}

func TestServerNoADByDefault(t *testing.T) {
	srv, err := resolvertest.New(exampleZone)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Close()

	m := new(dns.Msg)
	m.SetQuestion("chat.example.com.", dns.TypeSVCB)
	m.SetEdns0(4096, true)
	r, err := dns.Exchange(m, srv.Addr)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if r.AuthenticatedData {
		t.Error("AuthenticatedData = true, want false without WithAD")
	}
}

func TestServerNXDomain(t *testing.T) {
	srv, err := resolvertest.New(exampleZone)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Close()

	m := new(dns.Msg)
	m.SetQuestion("nonexistent.example.com.", dns.TypeTXT)
	r, err := dns.Exchange(m, srv.Addr)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if r.Rcode != dns.RcodeNameError {
		t.Errorf("Rcode = %s, want NXDOMAIN", dns.RcodeToString[r.Rcode])
	}
}

func TestServerNoData(t *testing.T) {
	srv, err := resolvertest.New(exampleZone)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Close()

	// The name exists (has TXT and SVCB) but has no A record.
	m := new(dns.Msg)
	m.SetQuestion("chat.example.com.", dns.TypeA)
	r, err := dns.Exchange(m, srv.Addr)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		t.Errorf("Rcode = %s, want NOERROR (NODATA)", dns.RcodeToString[r.Rcode])
	}
	if len(r.Answer) != 0 {
		t.Errorf("len(Answer) = %d, want 0", len(r.Answer))
	}
}
