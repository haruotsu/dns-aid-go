package dnsaid_test

import (
	"context"
	"slices"
	"testing"

	"github.com/haruotsu/dns-aid-go/internal/fixture"
	"github.com/haruotsu/dns-aid-go/internal/resolver/resolvertest"
	"github.com/haruotsu/dns-aid-go/pkg/dnsaid"
)

// newFixtureServer serves the named testdata zone fixture from an in-process
// DNS server and returns its address for Options.Resolver (N-7).
func newFixtureServer(t *testing.T, zoneName string, opts ...resolvertest.Option) string {
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
	return srv.Addr
}

// agentByName returns the agent with the given name, failing the test when
// it is absent.
func agentByName(t *testing.T, agents []dnsaid.AgentRecord, name string) dnsaid.AgentRecord {
	t.Helper()
	for _, a := range agents {
		if a.Name == name {
			return a
		}
	}
	t.Fatalf("agent %q not found in %d agents", name, len(agents))
	return dnsaid.AgentRecord{}
}

func TestDiscoverZoneFull(t *testing.T) {
	addr := newFixtureServer(t, "zone_full")

	res, err := dnsaid.Discover(context.Background(), "example.com", dnsaid.Options{Resolver: addr})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if len(res.Agents) != 3 {
		t.Fatalf("len(Agents) = %d, want 3", len(res.Agents))
	}
	if len(res.Errors) != 0 {
		t.Fatalf("len(Errors) = %d, want 0: %v", len(res.Errors), res.Errors)
	}

	wantIndex := []dnsaid.IndexEntry{
		{Name: "chat", Protocol: "mcp"},
		{Name: "billing", Protocol: "a2a"},
		{Name: "support", Protocol: "https"},
	}
	if !slices.Equal(res.Index, wantIndex) {
		t.Errorf("Index = %v, want %v", res.Index, wantIndex)
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
	if chat.CapURI != "https://chat.example.com/.well-known/agent-cap.json" {
		t.Errorf("chat.CapURI = %q", chat.CapURI)
	}
	if chat.EndpointSource != dnsaid.EndpointSourceDNSSVCB {
		t.Errorf("chat.EndpointSource = %q, want %q", chat.EndpointSource, dnsaid.EndpointSourceDNSSVCB)
	}
}

func TestDiscoverCapabilityTXTFallback(t *testing.T) {
	addr := newFixtureServer(t, "zone_full")

	res, err := dnsaid.Discover(context.Background(), "example.com", dnsaid.Options{Resolver: addr})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	billing := agentByName(t, res.Agents, "billing")
	if !slices.Equal(billing.Capabilities, []string{"billing", "invoicing"}) {
		t.Errorf("billing.Capabilities = %v, want [billing invoicing]", billing.Capabilities)
	}
	if billing.Version != "2.1.0" {
		t.Errorf("billing.Version = %q, want %q", billing.Version, "2.1.0")
	}
	if billing.CapabilitySource != dnsaid.CapabilitySourceTXTFallback {
		t.Errorf("billing.CapabilitySource = %q, want %q",
			billing.CapabilitySource, dnsaid.CapabilitySourceTXTFallback)
	}
}
