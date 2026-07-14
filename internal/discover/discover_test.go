package discover_test

import (
	"context"
	"errors"
	"slices"
	"strings"
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

func TestDiscoverCapabilitiesFromTXTFallback(t *testing.T) {
	r := newFixtureResolver(t, "zone_full")

	res, err := discover.Discover(context.Background(), r, "example.com", discover.Options{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	// chat carries a cap URI, but fetching it is stubbed until PR-11: the
	// TXT fallback must fill the capabilities for every agent (R-DISC-4).
	for _, tc := range []struct {
		name         string
		capabilities []string
		version      string
	}{
		{"chat", []string{"chat", "assistant"}, "1.0.0"},
		{"billing", []string{"billing", "invoicing"}, "2.1.0"},
		{"support", []string{"support"}, "0.9.0"},
	} {
		a := agentByName(t, res.Agents, tc.name)
		if !slices.Equal(a.Capabilities, tc.capabilities) {
			t.Errorf("%s.Capabilities = %v, want %v", tc.name, a.Capabilities, tc.capabilities)
		}
		if a.Version != tc.version {
			t.Errorf("%s.Version = %q, want %q", tc.name, a.Version, tc.version)
		}
		if a.CapabilitySource != discover.CapabilitySourceTXTFallback {
			t.Errorf("%s.CapabilitySource = %q, want %q", tc.name, a.CapabilitySource, discover.CapabilitySourceTXTFallback)
		}
	}
}

func TestDiscoverNoCapabilityTXT(t *testing.T) {
	r := newZoneResolver(t, `
$ORIGIN example.com.
$TTL 300
_index._agents TXT "agents=chat:mcp"
chat           SVCB 1 chat.example.com. alpn="mcp" port=443
`)

	res, err := discover.Discover(context.Background(), r, "example.com", discover.Options{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	chat := agentByName(t, res.Agents, "chat")
	if len(chat.Capabilities) != 0 {
		t.Errorf("chat.Capabilities = %v, want empty", chat.Capabilities)
	}
	if chat.CapabilitySource != discover.CapabilitySourceNone {
		t.Errorf("chat.CapabilitySource = %q, want %q", chat.CapabilitySource, discover.CapabilitySourceNone)
	}
	// The missing capability TXT is not a failure: no error is recorded.
	if len(res.Errors) != 0 {
		t.Errorf("len(Errors) = %d, want 0: %v", len(res.Errors), res.Errors)
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

func TestDiscoverIndexOnlyZone(t *testing.T) {
	r := newFixtureResolver(t, "zone_index_only")

	res, err := discover.Discover(context.Background(), r, "example.com", discover.Options{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	// One index entry, zero agents: a name without an SVCB record is not
	// an agent (R-DISC-3) and is reported as a warning, not a failure.
	if len(res.Index) != 1 {
		t.Errorf("len(Index) = %d, want 1", len(res.Index))
	}
	if len(res.Agents) != 0 {
		t.Errorf("len(Agents) = %d, want 0", len(res.Agents))
	}
	if len(res.Errors) != 1 {
		t.Fatalf("len(Errors) = %d, want 1: %v", len(res.Errors), res.Errors)
	}
	if !errors.Is(res.Errors[0], resolver.ErrNotFound) {
		t.Errorf("Errors[0] = %v, want resolver.ErrNotFound", res.Errors[0])
	}
}

func TestDiscoverPartialSuccess(t *testing.T) {
	r := newFixtureResolver(t, "zone_partial")

	res, err := discover.Discover(context.Background(), r, "example.com", discover.Options{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	// chat resolves; legacy (TXT only, NODATA) and ghost (NXDOMAIN) fail
	// without failing the whole call (R-DISC-5).
	if len(res.Agents) != 1 {
		t.Fatalf("len(Agents) = %d, want 1", len(res.Agents))
	}
	agentByName(t, res.Agents, "chat")
	if len(res.Errors) != 2 {
		t.Fatalf("len(Errors) = %d, want 2: %v", len(res.Errors), res.Errors)
	}
	for i, e := range res.Errors {
		if !errors.Is(e, resolver.ErrNotFound) {
			t.Errorf("Errors[%d] = %v, want resolver.ErrNotFound", i, e)
		}
	}
	// The error message must name the failing agent so the CLI warning
	// (OSS-03 §6.1) can point at it.
	if !strings.Contains(res.Errors[0].Error(), "legacy.example.com") {
		t.Errorf("Errors[0] = %v, want mention of legacy.example.com", res.Errors[0])
	}
}

func TestDiscoverIndexMissing(t *testing.T) {
	r := newZoneResolver(t, `
$ORIGIN example.com.
$TTL 300
unrelated TXT "not an index"
`)

	_, err := discover.Discover(context.Background(), r, "example.com", discover.Options{})
	if !errors.Is(err, discover.ErrIndexNotFound) {
		t.Fatalf("Discover error = %v, want ErrIndexNotFound", err)
	}
}

func TestDiscoverIndexMalformed(t *testing.T) {
	r := newZoneResolver(t, `
$ORIGIN example.com.
$TTL 300
_index._agents TXT "agents=chat"
`)

	_, err := discover.Discover(context.Background(), r, "example.com", discover.Options{})
	if !errors.Is(err, discover.ErrIndexNotFound) {
		t.Fatalf("Discover error = %v, want ErrIndexNotFound", err)
	}
}

func TestDiscoverTrailingDotDomain(t *testing.T) {
	r := newFixtureResolver(t, "zone_index_only")

	res, err := discover.Discover(context.Background(), r, "example.com.", discover.Options{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(res.Index) != 1 {
		t.Errorf("len(Index) = %d, want 1", len(res.Index))
	}
}

func TestDiscoverDNSSECValidated(t *testing.T) {
	ctx := context.Background()

	r := newFixtureResolver(t, "zone_full", resolvertest.WithAD())
	res, err := discover.Discover(ctx, r, "example.com", discover.Options{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if chat := agentByName(t, res.Agents, "chat"); !chat.DNSSECValidated {
		t.Errorf("chat.DNSSECValidated = false, want true with a validating resolver")
	}

	r = newFixtureResolver(t, "zone_full")
	res, err = discover.Discover(ctx, r, "example.com", discover.Options{})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if chat := agentByName(t, res.Agents, "chat"); chat.DNSSECValidated {
		t.Errorf("chat.DNSSECValidated = true, want false without validation")
	}
}

func TestDiscoverFilterByName(t *testing.T) {
	r := newFixtureResolver(t, "zone_full")

	res, err := discover.Discover(context.Background(), r, "example.com", discover.Options{Name: "billing"})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if len(res.Agents) != 1 {
		t.Fatalf("len(Agents) = %d, want 1", len(res.Agents))
	}
	agentByName(t, res.Agents, "billing")
	if len(res.Errors) != 0 {
		t.Errorf("len(Errors) = %d, want 0: %v", len(res.Errors), res.Errors)
	}
}

func TestDiscoverFilterByNameNotInIndex(t *testing.T) {
	r := newFixtureResolver(t, "zone_full")

	_, err := discover.Discover(context.Background(), r, "example.com", discover.Options{Name: "nonexistent"})
	if !errors.Is(err, discover.ErrAgentNotFound) {
		t.Fatalf("Discover error = %v, want ErrAgentNotFound", err)
	}
}

func TestDiscoverFilterByNameWithoutSVCB(t *testing.T) {
	r := newFixtureResolver(t, "zone_partial")

	// legacy is listed in the index but has no SVCB record: a lookup
	// naming it must fail with ErrAgentNotFound (OSS-03 §6.2).
	res, err := discover.Discover(context.Background(), r, "example.com", discover.Options{Name: "legacy"})
	if !errors.Is(err, discover.ErrAgentNotFound) {
		t.Fatalf("Discover error = %v, want ErrAgentNotFound", err)
	}
	if len(res.Errors) != 1 {
		t.Errorf("len(Errors) = %d, want 1: %v", len(res.Errors), res.Errors)
	}
}

func TestDiscoverFilterByProtocol(t *testing.T) {
	r := newFixtureResolver(t, "zone_full")

	// The protocol filter matches the index entry's advertised protocol,
	// so support (indexed as https) is selected even though its record's
	// first ALPN is h2.
	res, err := discover.Discover(context.Background(), r, "example.com", discover.Options{Protocol: "https"})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if len(res.Agents) != 1 {
		t.Fatalf("len(Agents) = %d, want 1", len(res.Agents))
	}
	agentByName(t, res.Agents, "support")
}

func TestDiscoverFilterByProtocolNoMatch(t *testing.T) {
	r := newFixtureResolver(t, "zone_full")

	res, err := discover.Discover(context.Background(), r, "example.com", discover.Options{Protocol: "smtp"})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(res.Agents) != 0 {
		t.Errorf("len(Agents) = %d, want 0", len(res.Agents))
	}
}

func TestDiscoverRequireDNSSEC(t *testing.T) {
	ctx := context.Background()
	opts := discover.Options{RequireDNSSEC: true}

	// A validating resolver satisfies the requirement.
	r := newFixtureResolver(t, "zone_full", resolvertest.WithAD())
	res, err := discover.Discover(ctx, r, "example.com", opts)
	if err != nil {
		t.Fatalf("Discover with AD: %v", err)
	}
	if len(res.Agents) != 3 {
		t.Errorf("len(Agents) = %d, want 3", len(res.Agents))
	}

	// Without the AD flag the whole call fails: the unvalidated index
	// cannot be trusted (OSS-03 §6.2).
	r = newFixtureResolver(t, "zone_full")
	_, err = discover.Discover(ctx, r, "example.com", opts)
	if !errors.Is(err, discover.ErrDNSSECRequired) {
		t.Fatalf("Discover without AD: error = %v, want ErrDNSSECRequired", err)
	}
}

// adStrippingResolver removes the AD flag from SVCB responses for one FQDN,
// simulating a zone where a single record fails validation.
type adStrippingResolver struct {
	resolver.Resolver
	fqdn string
}

func (r adStrippingResolver) QuerySVCB(ctx context.Context, fqdn string) (resolver.SVCBResponse, error) {
	resp, err := r.Resolver.QuerySVCB(ctx, fqdn)
	if fqdn == r.fqdn {
		resp.AD = false
	}
	return resp, err
}

func TestDiscoverRequireDNSSECDropsUnvalidatedAgent(t *testing.T) {
	r := adStrippingResolver{
		Resolver: newFixtureResolver(t, "zone_full", resolvertest.WithAD()),
		fqdn:     "chat.example.com",
	}

	res, err := discover.Discover(context.Background(), r, "example.com", discover.Options{RequireDNSSEC: true})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	// Only the unvalidated agent is dropped; the rest still resolve
	// (partial success, R-DISC-5).
	if len(res.Agents) != 2 {
		t.Fatalf("len(Agents) = %d, want 2", len(res.Agents))
	}
	if len(res.Errors) != 1 {
		t.Fatalf("len(Errors) = %d, want 1: %v", len(res.Errors), res.Errors)
	}
	if !errors.Is(res.Errors[0], discover.ErrDNSSECRequired) {
		t.Errorf("Errors[0] = %v, want ErrDNSSECRequired", res.Errors[0])
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
