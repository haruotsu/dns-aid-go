// Package dnsaid is the public library API of dns-aid-go (R-CLI-4): the CLI
// and library consumers use the same entry points. It only exposes stable
// types and delegates all work to the internal packages, so the public
// surface stays small while the implementation evolves.
//
// The read side implements draft-mozleywilliams-dnsop-dnsaid discovery:
// Discover resolves the domain's agent index, queries each agent's SVCB
// record, and resolves capabilities.
package dnsaid

import (
	"context"
	"fmt"
	"time"

	"github.com/haruotsu/dns-aid-go/internal/discover"
	"github.com/haruotsu/dns-aid-go/internal/resolver"
)

// Sentinel errors of the discover flow (OSS-03 §6.2). Errors returned by
// Discover wrap these; test with errors.Is.
var (
	// ErrIndexNotFound reports that the domain's agent index TXT record
	// could not be resolved or parsed.
	ErrIndexNotFound = discover.ErrIndexNotFound

	// ErrAgentNotFound reports that the agent named in Options.Name is
	// not in the index or has no SVCB record.
	ErrAgentNotFound = discover.ErrAgentNotFound

	// ErrDNSSECRequired reports that Options.RequireDNSSEC is set but a
	// response came back without the AD flag.
	ErrDNSSECRequired = discover.ErrDNSSECRequired
)

// EndpointSource values report how an agent's endpoint was resolved
// (R-DISC-7).
const (
	EndpointSourceDNSSVCB = discover.EndpointSourceDNSSVCB
)

// CapabilitySource values report how an agent's capabilities were resolved
// (R-DISC-7).
const (
	CapabilitySourceCapURI      = discover.CapabilitySourceCapURI
	CapabilitySourceTXTFallback = discover.CapabilitySourceTXTFallback
	CapabilitySourceNone        = discover.CapabilitySourceNone
)

// AgentRecord is the normalized representation of one discovered agent
// (OSS-03 §3.1).
type AgentRecord struct {
	Name   string // agent label from the index (e.g. "chat")
	Domain string // queried domain (e.g. "example.com")
	FQDN   string // Name + "." + Domain

	// Connection (from SVCB)
	Protocol string // derived from the first ALPN
	Endpoint string // SVCB TargetName
	Port     uint16 // default 443
	ALPN     []string

	// Capabilities (from cap document or TXT)
	Capabilities []string
	Version      string

	// SVCB custom parameters (draft)
	CapURI, CapSHA256, BAP, Policy, Realm, Sig string

	// Resolution transparency (R-DISC-7)
	EndpointSource   string
	CapabilitySource string

	// Verification
	DNSSECValidated bool
}

// IndexEntry is one agent entry in the domain's agent index (R-DISC-1).
type IndexEntry struct {
	Name     string
	Protocol string
}

// Result is the outcome of one Discover call. Agents and Errors are
// independent: individual agent failures are collected in Errors while the
// remaining agents are still returned (partial success, R-DISC-5).
type Result struct {
	// Index holds the parsed domain index entries, including those that
	// did not yield an agent.
	Index []IndexEntry

	Agents []AgentRecord
	Errors []error
}

// Options configures one Discover call.
type Options struct {
	// Protocol keeps only the index entries advertising this protocol.
	// Empty means no filter. The comparison is case-insensitive.
	Protocol string

	// Name looks up a single agent by its index name. When it is not in
	// the index or has no SVCB record, Discover returns ErrAgentNotFound.
	// Empty means no filter. The comparison is case-insensitive
	// (RFC 4343).
	Name string

	// RequireDNSSEC rejects responses without the AD flag: an
	// unvalidated index fails the whole call with ErrDNSSECRequired, an
	// unvalidated agent record is dropped with the error recorded in
	// Result.Errors.
	RequireDNSSEC bool

	// Resolver is the "host:port" of the DNS server to query. Empty
	// selects the first nameserver from the system configuration.
	Resolver string

	// Timeout bounds one DNS query. Zero means the 5s default.
	Timeout time.Duration
}

// Discover resolves the agents advertised by domain (OSS-03 §4.1): the
// domain's agent index, each agent's SVCB record, and its capabilities.
// Individual agent failures do not fail the call; they are collected in
// Result.Errors (R-DISC-5).
func Discover(ctx context.Context, domain string, opts Options) (Result, error) {
	r, err := resolver.NewClient(resolver.Config{
		Server:  opts.Resolver,
		Timeout: opts.Timeout,
	})
	if err != nil {
		return Result{}, fmt.Errorf("configure resolver: %w", err)
	}

	res, err := discover.Discover(ctx, r, domain, discover.Options{
		Protocol:      opts.Protocol,
		Name:          opts.Name,
		RequireDNSSEC: opts.RequireDNSSEC,
	})
	if err != nil {
		return Result{}, err
	}
	return toResult(res), nil
}

// toResult converts the internal discover result into the public types, so
// no internal type leaks through the API (R-CLI-4).
func toResult(res discover.Result) Result {
	out := Result{Errors: res.Errors}
	for _, e := range res.Index {
		out.Index = append(out.Index, IndexEntry{Name: e.Name, Protocol: e.Protocol})
	}
	for _, a := range res.Agents {
		out.Agents = append(out.Agents, AgentRecord{
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
	return out
}
