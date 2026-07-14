package interop

import (
	"reflect"
	"strings"
	"testing"
)

// goSample is a discover --json document of this implementation (agents
// deliberately unsorted to exercise normalization ordering).
const goSample = `{
  "domain": "example.com",
  "index": [
    {"name": "chat", "protocol": "mcp"},
    {"name": "billing", "protocol": "a2a"}
  ],
  "agents": [
    {
      "name": "chat",
      "domain": "example.com",
      "fqdn": "chat.example.com",
      "protocol": "mcp",
      "endpoint": "chat.example.com",
      "port": 443,
      "alpn": ["mcp"],
      "capabilities": ["chat", "assistant"],
      "version": "1.0.0",
      "cap_uri": "https://chat.example.com/.well-known/agent-cap.json",
      "cap_sha256": "U0_t8vmbVaTHEXJ3PlnaJNSNvNnfhwOcTZ3WUfJOkbg",
      "endpoint_source": "dns_svcb",
      "capability_source": "txt_fallback",
      "dnssec_validated": false
    },
    {
      "name": "billing",
      "domain": "example.com",
      "fqdn": "billing.example.com",
      "protocol": "a2a",
      "endpoint": "billing.example.com",
      "port": 443,
      "alpn": ["a2a"],
      "endpoint_source": "dns_svcb",
      "capability_source": "none",
      "dnssec_validated": false
    }
  ],
  "errors": ["agent ghost.example.com: no matching DNS records"]
}`

// refSample is the same discovery as reported by the reference
// implementation CLI, including the structured-log lines it prints on
// stdout before the JSON document.
const refSample = `2026-07-14 19:23:53 [info     ] Discovering agents via DNS     domain=example.com query=_index._agents.example.com
2026-07-14 19:23:53 [warning  ] Agent Card URL blocked by SSRF protection error="Cannot resolve hostname 'chat.example.com': [Errno 8] nodename nor servname provided, or not known" url=https://chat.example.com/.well-known/agent-card.json
{
  "domain": "example.com",
  "query": "_index._agents.example.com",
  "discovery_method": "dns",
  "agents": [
    {
      "name": "chat",
      "protocol": "mcp",
      "endpoint": "https://chat.example.com:443",
      "endpoint_source": "dns_svcb",
      "capabilities": ["chat", "assistant"],
      "capability_source": "txt_fallback",
      "cap_uri": "https://chat.example.com/.well-known/agent-cap.json",
      "cap_sha256": "U0_t8vmbVaTHEXJ3PlnaJNSNvNnfhwOcTZ3WUfJOkbg",
      "well_known_path": null,
      "bap": null,
      "policy_uri": null,
      "realm": null,
      "description": null
    },
    {
      "name": "billing",
      "protocol": "a2a",
      "endpoint": "https://billing.example.com:443",
      "endpoint_source": "dns_svcb",
      "capabilities": [],
      "capability_source": null,
      "cap_uri": null,
      "cap_sha256": null,
      "well_known_path": null,
      "bap": null,
      "policy_uri": null,
      "realm": null,
      "description": null
    }
  ],
  "count": 2,
  "query_time_ms": 16.5
}`

// wantDoc is the canonical form both samples above must normalize to:
// agents sorted by name, endpoint split into host and port, null and
// missing optional fields both empty, absent capability source "none".
var wantDoc = Doc{
	Domain: "example.com",
	Agents: []Agent{
		{
			Name:             "billing",
			Protocol:         "a2a",
			Endpoint:         "billing.example.com",
			Port:             443,
			Capabilities:     []string{},
			EndpointSource:   "dns_svcb",
			CapabilitySource: "none",
		},
		{
			Name:             "chat",
			Protocol:         "mcp",
			Endpoint:         "chat.example.com",
			Port:             443,
			Capabilities:     []string{"chat", "assistant"},
			CapURI:           "https://chat.example.com/.well-known/agent-cap.json",
			CapSHA256:        "U0_t8vmbVaTHEXJ3PlnaJNSNvNnfhwOcTZ3WUfJOkbg",
			EndpointSource:   "dns_svcb",
			CapabilitySource: "txt_fallback",
		},
	},
}

func TestNormalizeGo(t *testing.T) {
	got, err := NormalizeGo([]byte(goSample))
	if err != nil {
		t.Fatalf("NormalizeGo: %v", err)
	}
	if !reflect.DeepEqual(got, wantDoc) {
		t.Errorf("NormalizeGo:\n got %+v\nwant %+v", got, wantDoc)
	}
}

func TestNormalizeRefStripsLogLinesAndNulls(t *testing.T) {
	got, err := NormalizeRef([]byte(refSample))
	if err != nil {
		t.Fatalf("NormalizeRef: %v", err)
	}
	if !reflect.DeepEqual(got, wantDoc) {
		t.Errorf("NormalizeRef:\n got %+v\nwant %+v", got, wantDoc)
	}
}

func TestNormalizeRefCustomParams(t *testing.T) {
	doc := `{
  "domain": "example.com",
  "agents": [{
    "name": "booking",
    "protocol": "mcp",
    "endpoint": "https://mcp.example.com",
    "endpoint_source": "dns_svcb",
    "capabilities": ["booking"],
    "capability_source": "txt_fallback",
    "cap_uri": null,
    "cap_sha256": null,
    "bap": "mcp=1.0",
    "policy_uri": "https://example.com/agent-policy",
    "realm": "production"
  }],
  "count": 1
}`
	got, err := NormalizeRef([]byte(doc))
	if err != nil {
		t.Fatalf("NormalizeRef: %v", err)
	}
	if len(got.Agents) != 1 {
		t.Fatalf("len(Agents) = %d, want 1", len(got.Agents))
	}
	a := got.Agents[0]
	if a.BAP != "mcp=1.0" {
		t.Errorf("BAP = %q, want %q", a.BAP, "mcp=1.0")
	}
	if a.Policy != "https://example.com/agent-policy" {
		t.Errorf("Policy = %q, want the policy_uri value", a.Policy)
	}
	if a.Realm != "production" {
		t.Errorf("Realm = %q, want %q", a.Realm, "production")
	}
	// An endpoint URL without an explicit port means the DNS-AID default.
	if a.Endpoint != "mcp.example.com" || a.Port != 443 {
		t.Errorf("endpoint = %q:%d, want mcp.example.com:443", a.Endpoint, a.Port)
	}
}

func TestNormalizeRefRejectsNonJSON(t *testing.T) {
	if _, err := NormalizeRef([]byte("log line only, no document\n")); err == nil {
		t.Error("NormalizeRef on log-only output: got nil error, want error")
	}
}

func TestNormalizeRejectsBrokenJSON(t *testing.T) {
	broken := []byte(`{"agents": [`)
	if _, err := NormalizeGo(broken); err == nil {
		t.Error("NormalizeGo on truncated JSON: got nil error, want error")
	}
	if _, err := NormalizeRef(broken); err == nil {
		t.Error("NormalizeRef on truncated JSON: got nil error, want error")
	}
}

func TestNormalizeRefRejectsBadEndpoints(t *testing.T) {
	cases := []struct {
		name     string
		endpoint string
	}{
		// A schemeless host:port parses as scheme "chat.example.com"
		// with no host, so it must be rejected, not silently emptied.
		{"schemeless host", "chat.example.com:443"},
		{"empty", ""},
		{"port out of range", "https://chat.example.com:99999"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := `{"domain": "example.com", "agents": [{"name": "chat", "protocol": "mcp", "endpoint": "` + tc.endpoint + `", "endpoint_source": "dns_svcb"}]}`
			_, err := NormalizeRef([]byte(doc))
			if err == nil {
				t.Errorf("NormalizeRef with endpoint %q: got nil error, want error", tc.endpoint)
			}
		})
	}
}

func TestDiffReportsDomainMismatch(t *testing.T) {
	a := Doc{Domain: "example.com"}
	b := Doc{Domain: "example.org"}
	d := Diff(a, b)
	if len(d) == 0 || !strings.Contains(d[0], "domain") {
		t.Errorf("Diff = %v, want a domain mismatch report", d)
	}
}

func TestDiffEqual(t *testing.T) {
	goDoc, err := NormalizeGo([]byte(goSample))
	if err != nil {
		t.Fatalf("NormalizeGo: %v", err)
	}
	refDoc, err := NormalizeRef([]byte(refSample))
	if err != nil {
		t.Fatalf("NormalizeRef: %v", err)
	}
	if d := Diff(goDoc, refDoc); len(d) != 0 {
		t.Errorf("Diff of equal docs = %v, want none", d)
	}
}

func TestDiffReportsFieldMismatch(t *testing.T) {
	a := wantDoc
	b := Doc{Domain: a.Domain, Agents: append([]Agent(nil), a.Agents...)}
	b.Agents[1].Protocol = "h2"

	d := Diff(a, b)
	if len(d) == 0 {
		t.Fatal("Diff = none, want a protocol mismatch")
	}
	joined := strings.Join(d, "\n")
	if !strings.Contains(joined, "protocol") || !strings.Contains(joined, "chat") {
		t.Errorf("Diff = %q, want it to name the agent and the protocol field", joined)
	}
}

func TestDiffReportsMissingAgent(t *testing.T) {
	a := wantDoc
	b := Doc{Domain: a.Domain, Agents: a.Agents[:1]} // billing only

	d := Diff(a, b)
	if len(d) == 0 {
		t.Fatal("Diff = none, want a missing-agent report")
	}
	if !strings.Contains(strings.Join(d, "\n"), "chat") {
		t.Errorf("Diff = %q, want it to name the missing agent", d)
	}
}
