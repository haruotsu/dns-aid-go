package resolver_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/haruotsu/dns-aid-go/internal/resolver"
	"github.com/haruotsu/dns-aid-go/internal/resolver/resolvertest"
)

const exampleZone = `
$ORIGIN example.com.
$TTL 300
_index._agents TXT "agents=chat:mcp,billing:a2a"
chat           SVCB 1 chat.example.com. alpn="mcp" port=443 key65400="https://example.com/cap.json"
chat           TXT  "capabilities=chat,assistant" "version=1.2.0"
`

func newTestClient(t *testing.T, opts ...resolvertest.Option) *resolver.Client {
	t.Helper()
	srv, err := resolvertest.New(exampleZone, opts...)
	if err != nil {
		t.Fatalf("resolvertest.New: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	c, err := resolver.NewClient(resolver.Config{Server: srv.Addr})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestClientLookupTXT(t *testing.T) {
	c := newTestClient(t)

	resp, err := c.LookupTXT(context.Background(), "_index._agents.example.com")
	if err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}

	if len(resp.Records) != 1 {
		t.Fatalf("len(Records) = %d, want 1", len(resp.Records))
	}
	want := "agents=chat:mcp,billing:a2a"
	if len(resp.Records[0]) != 1 || resp.Records[0][0] != want {
		t.Errorf("Records[0] = %q, want [%q]", resp.Records[0], want)
	}
}

func TestClientLookupTXTKeepsCharacterStrings(t *testing.T) {
	c := newTestClient(t)

	resp, err := c.LookupTXT(context.Background(), "chat.example.com")
	if err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}

	// One TXT record with two character-strings must stay one record so
	// the caller can concatenate per record (RFC 1035).
	if len(resp.Records) != 1 {
		t.Fatalf("len(Records) = %d, want 1", len(resp.Records))
	}
	if len(resp.Records[0]) != 2 {
		t.Errorf("len(Records[0]) = %d, want 2 character-strings", len(resp.Records[0]))
	}
}

func TestClientLookupTXTNXDomain(t *testing.T) {
	c := newTestClient(t)

	_, err := c.LookupTXT(context.Background(), "nonexistent.example.com")
	if !errors.Is(err, resolver.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestClientLookupTXTNoData(t *testing.T) {
	c := newTestClient(t)

	// _index._agents exists but has no SVCB; the SVCB query for it is NODATA.
	_, err := c.QuerySVCB(context.Background(), "_index._agents.example.com")
	if !errors.Is(err, resolver.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestClientQuerySVCB(t *testing.T) {
	c := newTestClient(t)

	resp, err := c.QuerySVCB(context.Background(), "chat.example.com")
	if err != nil {
		t.Fatalf("QuerySVCB: %v", err)
	}

	if len(resp.Records) != 1 {
		t.Fatalf("len(Records) = %d, want 1", len(resp.Records))
	}
	rec := resp.Records[0]
	if rec.Target != "chat.example.com." {
		t.Errorf("Target = %q, want %q", rec.Target, "chat.example.com.")
	}

	var alpn []string
	var port uint16
	var cap string
	for _, kv := range rec.Value {
		switch v := kv.(type) {
		case *dns.SVCBAlpn:
			alpn = v.Alpn
		case *dns.SVCBPort:
			port = v.Port
		case *dns.SVCBLocal:
			if v.KeyCode == 65400 {
				cap = string(v.Data)
			}
		}
	}
	if len(alpn) != 1 || alpn[0] != "mcp" {
		t.Errorf("alpn = %q, want [mcp]", alpn)
	}
	if port != 443 {
		t.Errorf("port = %d, want 443", port)
	}
	if cap != "https://example.com/cap.json" {
		t.Errorf("key65400 = %q, want cap URI", cap)
	}
}

func TestClientPropagatesADFlag(t *testing.T) {
	c := newTestClient(t, resolvertest.WithAD())

	txt, err := c.LookupTXT(context.Background(), "_index._agents.example.com")
	if err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}
	if !txt.AD {
		t.Error("TXTResponse.AD = false, want true")
	}

	svcb, err := c.QuerySVCB(context.Background(), "chat.example.com")
	if err != nil {
		t.Fatalf("QuerySVCB: %v", err)
	}
	if !svcb.AD {
		t.Error("SVCBResponse.AD = false, want true")
	}
}

func TestClientADFlagFalseWithoutValidation(t *testing.T) {
	c := newTestClient(t)

	txt, err := c.LookupTXT(context.Background(), "_index._agents.example.com")
	if err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}
	if txt.AD {
		t.Error("TXTResponse.AD = true, want false")
	}
}

// blackholeServer listens on UDP and drops every query.
func blackholeServer(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().String()
}

func TestClientTimeout(t *testing.T) {
	c, err := resolver.NewClient(resolver.Config{
		Server:  blackholeServer(t),
		Timeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	start := time.Now()
	_, err = c.LookupTXT(context.Background(), "example.com")
	if err == nil {
		t.Fatal("LookupTXT succeeded, want timeout error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("LookupTXT took %v, want ~100ms", elapsed)
	}
}

func TestClientContextDeadline(t *testing.T) {
	c, err := resolver.NewClient(resolver.Config{Server: blackholeServer(t)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = c.LookupTXT(ctx, "example.com")
	if err == nil {
		t.Fatal("LookupTXT succeeded, want deadline error")
	}
	// The context deadline must win over the 5s default timeout.
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("LookupTXT took %v, want ~100ms", elapsed)
	}
}

func TestClientCanceledContext(t *testing.T) {
	c := newTestClient(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := c.LookupTXT(ctx, "_index._agents.example.com"); err == nil {
		t.Error("LookupTXT succeeded, want error for canceled context")
	}
}

// servfailServer answers every query with SERVFAIL.
func servfailServer(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeServerFailure)
			w.WriteMsg(m) //nolint:errcheck
		}),
	}
	go srv.ActivateAndServe() //nolint:errcheck
	t.Cleanup(func() { srv.Shutdown() }) //nolint:errcheck
	return pc.LocalAddr().String()
}

func TestClientServerFailure(t *testing.T) {
	c, err := resolver.NewClient(resolver.Config{Server: servfailServer(t)})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = c.LookupTXT(context.Background(), "example.com")
	if err == nil {
		t.Fatal("LookupTXT succeeded, want SERVFAIL error")
	}
	// SERVFAIL is a transport/server problem, not proof of absence.
	if errors.Is(err, resolver.ErrNotFound) {
		t.Errorf("err = %v, must not be ErrNotFound", err)
	}
}

func TestClientRetriesTruncatedOverTCP(t *testing.T) {
	// One RRset larger than the 4096-octet EDNS0 UDP size forces TC=1.
	var zone strings.Builder
	zone.WriteString("$ORIGIN example.com.\n$TTL 300\n")
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&zone, "big TXT \"%03d-%s\"\n", i, strings.Repeat("x", 180))
	}

	srv, err := resolvertest.New(zone.String())
	if err != nil {
		t.Fatalf("resolvertest.New: %v", err)
	}
	defer srv.Close() //nolint:errcheck

	c, err := resolver.NewClient(resolver.Config{Server: srv.Addr})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	resp, err := c.LookupTXT(context.Background(), "big.example.com")
	if err != nil {
		t.Fatalf("LookupTXT: %v", err)
	}
	if len(resp.Records) != 40 {
		t.Errorf("len(Records) = %d, want 40 (full RRset via TCP)", len(resp.Records))
	}
}
