package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/haruotsu/dns-aid-go/pkg/dnsaid"
)

// indexSource labels where the agent index came from. v0.1 only implements
// the DNS TXT index (R-DISC-1); an HTTP index is a possible future source.
const indexSource = "dns_txt"

// writeHuman prints the discover result in the human format of OSS-03 §6.1.
func writeHuman(w io.Writer, domain string, res dnsaid.Result) {
	noun := "agents"
	if len(res.Agents) == 1 {
		noun = "agent"
	}
	fmt.Fprintf(w, "FOUND %d %s at %s  (index: %s)\n", len(res.Agents), noun, domain, indexSource)
	if len(res.Agents) == 0 {
		return
	}
	fmt.Fprintln(w)

	// Column widths of the FQDN / protocol / endpoint columns, so the
	// dnssec flags line up like the design example.
	var wFQDN, wProto, wEndpoint int
	for _, a := range res.Agents {
		wFQDN = max(wFQDN, len(a.FQDN))
		wProto = max(wProto, len(a.Protocol))
		wEndpoint = max(wEndpoint, len(endpoint(a)))
	}
	for _, a := range res.Agents {
		fmt.Fprintf(w, "  %-*s  %-*s  →  %-*s  [dnssec:%s]\n",
			wFQDN, a.FQDN, wProto, a.Protocol, wEndpoint, endpoint(a), dnssecStatus(a))
		if len(a.Capabilities) > 0 {
			fmt.Fprintf(w, "    capabilities: %s  (source: %s)\n",
				strings.Join(a.Capabilities, ", "), a.CapabilitySource)
		}
	}
}

func endpoint(a dnsaid.AgentRecord) string {
	return fmt.Sprintf("%s:%d", a.Endpoint, a.Port)
}

func dnssecStatus(a dnsaid.AgentRecord) string {
	if a.DNSSECValidated {
		return "ok"
	}
	return "unvalidated"
}

// jsonResult is the --json document: agents[] + errors[] (R-CLI-3). Arrays
// are always present (never null) so consumers can index them without
// null checks; this shape is also what the interop CI (PR-10) will compare.
type jsonResult struct {
	Domain string      `json:"domain"`
	Index  []jsonIndex `json:"index"`
	Agents []jsonAgent `json:"agents"`
	Errors []string    `json:"errors"`
}

type jsonIndex struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
}

type jsonAgent struct {
	Name     string   `json:"name"`
	Domain   string   `json:"domain"`
	FQDN     string   `json:"fqdn"`
	Protocol string   `json:"protocol"`
	Endpoint string   `json:"endpoint"`
	Port     uint16   `json:"port"`
	ALPN     []string `json:"alpn,omitempty"`

	Capabilities []string `json:"capabilities,omitempty"`
	Version      string   `json:"version,omitempty"`

	CapURI    string `json:"cap_uri,omitempty"`
	CapSHA256 string `json:"cap_sha256,omitempty"`
	BAP       string `json:"bap,omitempty"`
	Policy    string `json:"policy,omitempty"`
	Realm     string `json:"realm,omitempty"`
	Sig       string `json:"sig,omitempty"`

	EndpointSource   string `json:"endpoint_source"`
	CapabilitySource string `json:"capability_source"`
	DNSSECValidated  bool   `json:"dnssec_validated"`
}

func writeJSON(w io.Writer, domain string, res dnsaid.Result) error {
	doc := jsonResult{
		Domain: domain,
		Index:  make([]jsonIndex, 0, len(res.Index)),
		Agents: make([]jsonAgent, 0, len(res.Agents)),
		Errors: make([]string, 0, len(res.Errors)),
	}
	for _, e := range res.Index {
		doc.Index = append(doc.Index, jsonIndex{Name: e.Name, Protocol: e.Protocol})
	}
	for _, a := range res.Agents {
		doc.Agents = append(doc.Agents, jsonAgent{
			Name:             a.Name,
			Domain:           a.Domain,
			FQDN:             a.FQDN,
			Protocol:         a.Protocol,
			Endpoint:         a.Endpoint,
			Port:             a.Port,
			ALPN:             a.ALPN,
			Capabilities:     a.Capabilities,
			Version:          a.Version,
			CapURI:           a.CapURI,
			CapSHA256:        a.CapSHA256,
			BAP:              a.BAP,
			Policy:           a.Policy,
			Realm:            a.Realm,
			Sig:              a.Sig,
			EndpointSource:   a.EndpointSource,
			CapabilitySource: a.CapabilitySource,
			DNSSECValidated:  a.DNSSECValidated,
		})
	}
	for _, e := range res.Errors {
		doc.Errors = append(doc.Errors, e.Error())
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
