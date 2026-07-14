// Package interop normalizes the discover CLI output of this implementation
// and of the Python reference implementation into one canonical form and
// reports the differences, proving interoperability in CI (R-CORE-2, N-1).
//
// Only fields both CLIs expose are compared. Notably absent: version, sig,
// and per-agent dnssec_validated (this implementation only), and
// description and well_known_path (reference only).
package interop

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// Doc is the canonical discover result compared across implementations.
type Doc struct {
	Domain string  `json:"domain"`
	Agents []Agent `json:"agents"`
}

// Agent is the canonical form of one discovered agent.
type Agent struct {
	Name         string   `json:"name"`
	Protocol     string   `json:"protocol"`
	Endpoint     string   `json:"endpoint"` // host without scheme or port
	Port         uint16   `json:"port"`
	Capabilities []string `json:"capabilities"`

	CapURI    string `json:"cap_uri,omitempty"`
	CapSHA256 string `json:"cap_sha256,omitempty"`
	BAP       string `json:"bap,omitempty"`
	Policy    string `json:"policy,omitempty"`
	Realm     string `json:"realm,omitempty"`

	EndpointSource   string `json:"endpoint_source"`
	CapabilitySource string `json:"capability_source"`
}

// defaultPort applies when an endpoint does not name one (RFC 9460 leaves
// the port to the scheme; the draft's deployments use HTTPS).
const defaultPort = 443

// goDoc mirrors the JSON of this implementation's `dnsaid discover --json`.
type goDoc struct {
	Domain string `json:"domain"`
	Agents []struct {
		Name             string   `json:"name"`
		Protocol         string   `json:"protocol"`
		Endpoint         string   `json:"endpoint"`
		Port             uint16   `json:"port"`
		Capabilities     []string `json:"capabilities"`
		CapURI           string   `json:"cap_uri"`
		CapSHA256        string   `json:"cap_sha256"`
		BAP              string   `json:"bap"`
		Policy           string   `json:"policy"`
		Realm            string   `json:"realm"`
		EndpointSource   string   `json:"endpoint_source"`
		CapabilitySource string   `json:"capability_source"`
	} `json:"agents"`
}

// NormalizeGo canonicalizes the JSON output of `dnsaid discover --json`.
func NormalizeGo(data []byte) (Doc, error) {
	var in goDoc
	if err := json.Unmarshal(data, &in); err != nil {
		return Doc{}, fmt.Errorf("parse go output: %w", err)
	}
	doc := Doc{Domain: in.Domain, Agents: make([]Agent, 0, len(in.Agents))}
	for _, a := range in.Agents {
		doc.Agents = append(doc.Agents, Agent{
			Name:             a.Name,
			Protocol:         a.Protocol,
			Endpoint:         a.Endpoint,
			Port:             a.Port,
			Capabilities:     emptyIfNil(a.Capabilities),
			CapURI:           a.CapURI,
			CapSHA256:        a.CapSHA256,
			BAP:              a.BAP,
			Policy:           a.Policy,
			Realm:            a.Realm,
			EndpointSource:   a.EndpointSource,
			CapabilitySource: noneIfEmpty(a.CapabilitySource),
		})
	}
	sortAgents(doc.Agents)
	return doc, nil
}

// refDoc mirrors the JSON of the reference CLI's `dns-aid discover --json`.
// Optional fields are pointers because the reference emits explicit nulls.
type refDoc struct {
	Domain string `json:"domain"`
	Agents []struct {
		Name             string   `json:"name"`
		Protocol         string   `json:"protocol"`
		Endpoint         string   `json:"endpoint"`
		Capabilities     []string `json:"capabilities"`
		CapabilitySource *string  `json:"capability_source"`
		CapURI           *string  `json:"cap_uri"`
		CapSHA256        *string  `json:"cap_sha256"`
		BAP              *string  `json:"bap"`
		PolicyURI        *string  `json:"policy_uri"`
		Realm            *string  `json:"realm"`
		EndpointSource   string   `json:"endpoint_source"`
	} `json:"agents"`
}

// NormalizeRef canonicalizes the JSON output of the reference CLI. The
// reference prints structured-log lines on stdout before the document, so
// everything preceding the first line that starts the JSON object is
// discarded.
func NormalizeRef(data []byte) (Doc, error) {
	data, err := extractJSONDocument(data)
	if err != nil {
		return Doc{}, err
	}
	var in refDoc
	if err := json.Unmarshal(data, &in); err != nil {
		return Doc{}, fmt.Errorf("parse reference output: %w", err)
	}
	doc := Doc{Domain: in.Domain, Agents: make([]Agent, 0, len(in.Agents))}
	for _, a := range in.Agents {
		host, port, err := splitEndpointURL(a.Endpoint)
		if err != nil {
			return Doc{}, fmt.Errorf("agent %s: %w", a.Name, err)
		}
		doc.Agents = append(doc.Agents, Agent{
			Name:             a.Name,
			Protocol:         a.Protocol,
			Endpoint:         host,
			Port:             port,
			Capabilities:     emptyIfNil(a.Capabilities),
			CapURI:           deref(a.CapURI),
			CapSHA256:        deref(a.CapSHA256),
			BAP:              deref(a.BAP),
			Policy:           deref(a.PolicyURI),
			Realm:            deref(a.Realm),
			EndpointSource:   a.EndpointSource,
			CapabilitySource: noneIfEmpty(deref(a.CapabilitySource)),
		})
	}
	sortAgents(doc.Agents)
	return doc, nil
}

// Diff compares two canonical documents and describes every difference,
// one per line; an empty result means the implementations agree.
func Diff(a, b Doc) []string {
	var diffs []string
	if a.Domain != b.Domain {
		diffs = append(diffs, fmt.Sprintf("domain: %q vs %q", a.Domain, b.Domain))
	}

	byName := func(agents []Agent) map[string]Agent {
		m := make(map[string]Agent, len(agents))
		for _, ag := range agents {
			m[ag.Name] = ag
		}
		return m
	}
	am, bm := byName(a.Agents), byName(b.Agents)

	names := make([]string, 0, len(am)+len(bm))
	for n := range am {
		names = append(names, n)
	}
	for n := range bm {
		if _, ok := am[n]; !ok {
			names = append(names, n)
		}
	}
	slices.Sort(names)

	for _, n := range names {
		aa, aok := am[n]
		ba, bok := bm[n]
		switch {
		case !aok:
			diffs = append(diffs, fmt.Sprintf("agent %q: missing on the first side", n))
		case !bok:
			diffs = append(diffs, fmt.Sprintf("agent %q: missing on the second side", n))
		default:
			diffs = append(diffs, diffAgent(n, aa, ba)...)
		}
	}
	return diffs
}

func diffAgent(name string, a, b Agent) []string {
	var diffs []string
	report := func(field string, av, bv any) {
		if !equalValue(av, bv) {
			diffs = append(diffs, fmt.Sprintf("agent %q: %s: %v vs %v", name, field, av, bv))
		}
	}
	report("protocol", a.Protocol, b.Protocol)
	report("endpoint", a.Endpoint, b.Endpoint)
	report("port", a.Port, b.Port)
	report("capabilities", a.Capabilities, b.Capabilities)
	report("cap_uri", a.CapURI, b.CapURI)
	report("cap_sha256", a.CapSHA256, b.CapSHA256)
	report("bap", a.BAP, b.BAP)
	report("policy", a.Policy, b.Policy)
	report("realm", a.Realm, b.Realm)
	report("endpoint_source", a.EndpointSource, b.EndpointSource)
	report("capability_source", a.CapabilitySource, b.CapabilitySource)
	return diffs
}

func equalValue(a, b any) bool {
	if as, ok := a.([]string); ok {
		bs, ok := b.([]string)
		return ok && slices.Equal(as, bs)
	}
	return a == b
}

// extractJSONDocument returns data from the first line whose first byte is
// '{': the reference CLI logs to stdout line by line before printing the
// pretty-printed JSON document, whose opening brace starts its own line.
func extractJSONDocument(data []byte) ([]byte, error) {
	for off := 0; off < len(data); {
		line := data[off:]
		if i := bytes.IndexByte(line, '\n'); i >= 0 {
			line = line[:i]
		}
		if trimmed := bytes.TrimSpace(line); len(trimmed) > 0 && trimmed[0] == '{' {
			return data[off:], nil
		}
		off += len(line) + 1
	}
	return nil, fmt.Errorf("no JSON document found in output:\n%s", data)
}

// splitEndpointURL splits the reference CLI's endpoint URL
// (e.g. "https://chat.example.com:443") into host and port.
func splitEndpointURL(endpoint string) (string, uint16, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return "", 0, fmt.Errorf("endpoint %q is not a URL with a host: %v", endpoint, err)
	}
	if u.Port() == "" {
		return u.Hostname(), defaultPort, nil
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil {
		return "", 0, fmt.Errorf("endpoint %q: invalid port: %w", endpoint, err)
	}
	return u.Hostname(), uint16(port), nil
}

func sortAgents(agents []Agent) {
	slices.SortFunc(agents, func(a, b Agent) int { return strings.Compare(a.Name, b.Name) })
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func emptyIfNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func noneIfEmpty(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
