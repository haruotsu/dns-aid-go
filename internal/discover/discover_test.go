package discover_test

import (
	"context"
	"slices"
	"testing"

	"github.com/haruotsu/dns-aid-go/internal/discover"
	"github.com/haruotsu/dns-aid-go/internal/fixture"
	"github.com/haruotsu/dns-aid-go/internal/resolver"
	"github.com/haruotsu/dns-aid-go/internal/resolver/resolvertest"
)

// newFixtureResolver serves the named testdata zone fixture from an
// in-process DNS server and returns a resolver querying it (N-7).
func newFixtureResolver(t *testing.T, zoneName string, opts ...resolvertest.Option) resolver.Resolver {
	t.Helper()
	zone, err := fixture.Zone(zoneName)
	if err != nil {
		t.Fatalf("fixture.Zone(%q): %v", zoneName, err)
	}
	return newZoneResolver(t, zone, opts...)
}

// newZoneResolver serves an inline zone from an in-process DNS server and
// returns a resolver querying it.
func newZoneResolver(t *testing.T, zone string, opts ...resolvertest.Option) resolver.Resolver {
	t.Helper()
	srv, err := resolvertest.New(zone, opts...)
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

// agentByName returns the agent with the given name, failing the test when
// it is absent.
func agentByName(t *testing.T, agents []discover.AgentRecord, name string) discover.AgentRecord {
	t.Helper()
	for _, a := range agents {
		if a.Name == name {
			return a
		}
	}
	t.Fatalf("agent %q not found in %d agents", name, len(agents))
	return discover.AgentRecord{}
}

func TestDiscoverZoneFullConnectionFields(t *testing.T) {
	r := newFixtureResolver(t, "zone_full")

	res, err := discover.Discover(context.Background(), r, "example.com", discover.Options{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if len(res.Agents) != 3 {
		t.Fatalf("len(Agents) = %d, want 3", len(res.Agents))
	}
	if len(res.Errors) != 0 {
		t.Fatalf("len(Errors) = %d, want 0: %v", len(res.Errors), res.Errors)
	}

	chat := agentByName(t, res.Agents, "chat")
	if chat.Domain != "example.com" {
		t.Errorf("chat.Domain = %q, want %q", chat.Domain, "example.com")
	}
	if chat.FQDN != "chat.example.com" {
		t.Errorf("chat.FQDN = %q, want %q", chat.FQDN, "chat.example.com")
	}
	if chat.Protocol != "mcp" {
		t.Errorf("chat.Protocol = %q, want %q", chat.Protocol, "mcp")
	}
	if chat.Endpoint != "chat.example.com" {
		t.Errorf("chat.Endpoint = %q, want %q", chat.Endpoint, "chat.example.com")
	}
	if chat.Port != 443 {
		t.Errorf("chat.Port = %d, want 443", chat.Port)
	}
	if !slices.Equal(chat.ALPN, []string{"mcp"}) {
		t.Errorf("chat.ALPN = %v, want [mcp]", chat.ALPN)
	}
	if chat.EndpointSource != discover.EndpointSourceDNSSVCB {
		t.Errorf("chat.EndpointSource = %q, want %q", chat.EndpointSource, discover.EndpointSourceDNSSVCB)
	}

	support := agentByName(t, res.Agents, "support")
	if support.Port != 8443 {
		t.Errorf("support.Port = %d, want 8443", support.Port)
	}
	// Protocol is derived from the first ALPN (OSS-03 §3.1), which may
	// differ from the protocol advertised in the index.
	if support.Protocol != "h2" {
		t.Errorf("support.Protocol = %q, want %q", support.Protocol, "h2")
	}
}

func TestDiscoverCustomSVCBParams(t *testing.T) {
	r := newFixtureResolver(t, "zone_custom_params")

	res, err := discover.Discover(context.Background(), r, "example.com", discover.Options{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	booking := agentByName(t, res.Agents, "booking")
	want := discover.AgentRecord{
		CapURI:    "https://mcp.example.com/.well-known/agent-cap.json",
		CapSHA256: "U0_t8vmbVaTHEXJ3PlnaJNSNvNnfhwOcTZ3WUfJOkbg",
		BAP:       "mcp/1,a2a/1",
		Policy:    "https://example.com/agent-policy",
		Realm:     "production",
		Sig:       "c2lnLXBsYWNlaG9sZGVy",
	}
	for _, f := range []struct{ name, got, want string }{
		{"CapURI", booking.CapURI, want.CapURI},
		{"CapSHA256", booking.CapSHA256, want.CapSHA256},
		{"BAP", booking.BAP, want.BAP},
		{"Policy", booking.Policy, want.Policy},
		{"Realm", booking.Realm, want.Realm},
		{"Sig", booking.Sig, want.Sig},
	} {
		if f.got != f.want {
			t.Errorf("booking.%s = %q, want %q", f.name, f.got, f.want)
		}
	}
	if booking.Endpoint != "mcp.example.com" {
		t.Errorf("booking.Endpoint = %q, want %q", booking.Endpoint, "mcp.example.com")
	}
}

func TestDiscoverTargetNameDotMeansOwner(t *testing.T) {
	r := newZoneResolver(t, `
$ORIGIN example.com.
$TTL 300
_index._agents TXT "agents=chat:mcp"
chat           SVCB 1 . alpn="mcp" port=443
`)

	res, err := discover.Discover(context.Background(), r, "example.com", discover.Options{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	chat := agentByName(t, res.Agents, "chat")
	// In ServiceMode a TargetName of "." denotes the owner name itself
	// (RFC 9460 §2.5).
	if chat.Endpoint != "chat.example.com" {
		t.Errorf("chat.Endpoint = %q, want %q", chat.Endpoint, "chat.example.com")
	}
}

func TestDiscoverPicksLowestSVCBPriority(t *testing.T) {
	r := newZoneResolver(t, `
$ORIGIN example.com.
$TTL 300
_index._agents TXT "agents=chat:mcp"
chat           SVCB 0 alias.example.com.
chat           SVCB 2 backup.example.com. alpn="mcp" port=8443
chat           SVCB 1 primary.example.com. alpn="mcp" port=443
`)

	res, err := discover.Discover(context.Background(), r, "example.com", discover.Options{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	chat := agentByName(t, res.Agents, "chat")
	// The lowest SvcPriority among ServiceMode records wins; AliasMode
	// (priority 0) records are not followed (RFC 9460 §2.4.1).
	if chat.Endpoint != "primary.example.com" {
		t.Errorf("chat.Endpoint = %q, want %q", chat.Endpoint, "primary.example.com")
	}
}

func TestDiscoverAliasModeOnlyIsError(t *testing.T) {
	r := newZoneResolver(t, `
$ORIGIN example.com.
$TTL 300
_index._agents TXT "agents=chat:mcp"
chat           SVCB 0 alias.example.com.
`)

	res, err := discover.Discover(context.Background(), r, "example.com", discover.Options{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if len(res.Agents) != 0 {
		t.Errorf("len(Agents) = %d, want 0", len(res.Agents))
	}
	if len(res.Errors) != 1 {
		t.Fatalf("len(Errors) = %d, want 1: %v", len(res.Errors), res.Errors)
	}
}
