// Package discover implements the read-side discovery flow of
// draft-mozleywilliams-dnsop-dnsaid (OSS-03 §4.1): resolve the domain index,
// query each agent's SVCB record, resolve capabilities, and assemble a
// partial-success Result (R-DISC-1..5, 7).
package discover

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/miekg/dns"

	"github.com/haruotsu/dns-aid-go/internal/record"
	"github.com/haruotsu/dns-aid-go/internal/resolver"
)

// Sentinel errors of the discover flow (OSS-03 §6.2).
var (
	// ErrIndexNotFound reports that the domain index TXT record could not
	// be resolved or parsed.
	ErrIndexNotFound = errors.New("agent index not found")

	// ErrAgentNotFound reports that the agent named in Options.Name is
	// not in the index or has no SVCB record.
	ErrAgentNotFound = errors.New("agent not found")

	// ErrDNSSECRequired reports that Options.RequireDNSSEC is set but a
	// response came back without the AD flag.
	ErrDNSSECRequired = errors.New("DNSSEC validation required but response is not authenticated")
)

// indexLabel is the owner-name prefix of the domain index TXT record
// (R-DISC-1).
const indexLabel = "_index._agents."

// maxIndexEntries bounds how many filter-matching index entries one Discover
// call resolves. Each entry costs two queries (SVCB + capability TXT), so an
// unbounded index in a hostile or broken zone (a TXT RRset can reach ~64KB
// over TCP) would amplify one lookup into tens of thousands of queries. 256
// agents per domain is generous versus any realistic deployment; matching
// entries beyond the bound are skipped with one error recorded, not a
// failure (R-DISC-5). Filtering happens before the bound is applied, so an
// agent named via Options.Name is found regardless of its index position.
const maxIndexEntries = 256

// EndpointSource values report how an agent's endpoint was resolved
// (R-DISC-7).
const (
	EndpointSourceDNSSVCB = "dns_svcb"
)

// CapabilitySource values report how an agent's capabilities were resolved
// (R-DISC-7). CapabilitySourceCapURI is produced once cap-document fetching
// lands (PR-11); until then the TXT fallback covers every agent.
const (
	CapabilitySourceCapURI      = "cap_uri"
	CapabilitySourceTXTFallback = "txt_fallback"
	CapabilitySourceNone        = "none"
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

// Result is the outcome of one Discover call. Agents and Errors are
// independent: individual agent failures are collected in Errors while the
// remaining agents are still returned (partial success, R-DISC-5).
type Result struct {
	// Index holds the parsed domain index entries, including those that
	// did not yield an agent.
	Index []record.IndexEntry

	Agents []AgentRecord
	Errors []error
}

// Options filters and hardens a Discover call (R-DISC-6).
type Options struct {
	// Protocol keeps only the index entries advertising this protocol.
	// It matches the protocol named in the domain index entry, not the
	// ALPN-derived AgentRecord.Protocol, which may differ (e.g. "https"
	// in the index vs "h2" from the record's ALPN). Alignment with the
	// reference implementation will be revisited in interop testing
	// (PR-10, R-CORE-2). Empty means no filter. The comparison is
	// case-insensitive.
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
}

// Discover resolves the agents advertised by domain (OSS-03 §4.1).
func Discover(ctx context.Context, r resolver.Resolver, domain string, opts Options) (Result, error) {
	domain = strings.TrimSuffix(domain, ".")

	entries, err := lookupIndex(ctx, r, domain, opts)
	if err != nil {
		return Result{}, err
	}

	res := Result{Index: entries}
	// The bound applies to the entries that pass the filters, not to the
	// index position: an agent named via Options.Name is found no matter
	// how deep in the index it is listed.
	processed, skipped := 0, 0
	for _, e := range entries {
		if !matchesFilters(e, opts) {
			continue
		}
		if processed >= maxIndexEntries {
			skipped++
			continue
		}
		processed++
		fqdn := e.Name + "." + domain
		rec, err := queryAgent(ctx, r, e, fqdn, opts)
		if err != nil {
			res.Errors = append(res.Errors, err)
			continue
		}
		rec.Domain = domain
		if err := fillCapabilities(ctx, r, &rec, opts); err != nil {
			res.Errors = append(res.Errors, err)
		}
		res.Agents = append(res.Agents, rec)
	}
	if skipped > 0 {
		res.Errors = append(res.Errors, fmt.Errorf(
			"index at %s%s lists %d matching agents, only the first %d processed (%d skipped)",
			indexLabel, domain, processed+skipped, maxIndexEntries, skipped))
	}

	// A lookup naming one agent must yield it (OSS-03 §6.2).
	if opts.Name != "" && len(res.Agents) == 0 {
		return res, fmt.Errorf("%w: %s.%s", ErrAgentNotFound, opts.Name, domain)
	}
	return res, nil
}

// matchesFilters reports whether an index entry passes the Name and
// Protocol filters (R-DISC-6).
func matchesFilters(e record.IndexEntry, opts Options) bool {
	if opts.Name != "" && !strings.EqualFold(e.Name, opts.Name) {
		return false
	}
	if opts.Protocol != "" && !strings.EqualFold(e.Protocol, opts.Protocol) {
		return false
	}
	return true
}

// lookupIndex resolves and parses the domain index TXT record (R-DISC-1).
// Any failure maps to ErrIndexNotFound (OSS-03 §6.2).
func lookupIndex(ctx context.Context, r resolver.Resolver, domain string, opts Options) ([]record.IndexEntry, error) {
	resp, err := r.LookupTXT(ctx, indexLabel+domain)
	if err != nil {
		return nil, fmt.Errorf("%w at %s%s: %w", ErrIndexNotFound, indexLabel, domain, err)
	}
	if opts.RequireDNSSEC && !resp.AD {
		return nil, fmt.Errorf("%w: index %s%s", ErrDNSSECRequired, indexLabel, domain)
	}

	// The index is one TXT record, but unrelated TXT records may share the
	// name: parse each record (character-strings concatenated, RFC 1035)
	// and use the first that is a well-formed index.
	var lastErr error
	for _, txt := range resp.Records {
		entries, err := record.ParseIndexTXT(txt...)
		if err != nil {
			lastErr = err
			continue
		}
		return entries, nil
	}
	return nil, fmt.Errorf("%w at %s%s: %w", ErrIndexNotFound, indexLabel, domain, lastErr)
}

// queryAgent resolves one index entry into an AgentRecord via its SVCB
// record (R-DISC-2).
func queryAgent(ctx context.Context, r resolver.Resolver, e record.IndexEntry, fqdn string, opts Options) (AgentRecord, error) {
	resp, err := r.QuerySVCB(ctx, fqdn)
	if err != nil {
		return AgentRecord{}, fmt.Errorf("agent %s: %w", fqdn, err)
	}
	if opts.RequireDNSSEC && !resp.AD {
		return AgentRecord{}, fmt.Errorf("%w: agent %s", ErrDNSSECRequired, fqdn)
	}

	svcb, err := selectSVCB(resp.Records)
	if err != nil {
		return AgentRecord{}, fmt.Errorf("agent %s: %w", fqdn, err)
	}

	rec := AgentRecord{
		Name:            e.Name,
		FQDN:            fqdn,
		Protocol:        e.Protocol,
		Endpoint:        strings.TrimSuffix(svcb.Target, "."),
		Port:            443,
		EndpointSource:  EndpointSourceDNSSVCB,
		DNSSECValidated: resp.AD,
	}
	// A TargetName of "." in ServiceMode means the owner name itself
	// (RFC 9460 §2.5).
	if rec.Endpoint == "" {
		rec.Endpoint = fqdn
	}

	for _, kv := range svcb.Value {
		switch v := kv.(type) {
		case *dns.SVCBAlpn:
			// Copy so the returned record does not alias the DNS
			// record's internal slice.
			rec.ALPN = slices.Clone(v.Alpn)
		case *dns.SVCBPort:
			rec.Port = v.Port
		}
	}
	// ALPN values come straight from DNS and override the agent's
	// Protocol; a control character here could inject terminal escapes
	// into CLI output, and an empty or non-printable value makes the
	// endpoint identity suspect, so the agent is rejected.
	for _, alpn := range rec.ALPN {
		if !isVisibleASCII(alpn) {
			return AgentRecord{}, fmt.Errorf("agent %s: SVCB alpn value %q is not printable ASCII", fqdn, alpn)
		}
	}
	// Protocol is derived from the first ALPN (OSS-03 §3.1); the index
	// protocol is only a fallback when the record has no ALPN.
	if len(rec.ALPN) > 0 {
		rec.Protocol = rec.ALPN[0]
	}

	params, err := record.ParseSVCBParams(svcb.Value)
	if err != nil {
		return AgentRecord{}, fmt.Errorf("agent %s: %w", fqdn, err)
	}
	rec.CapURI = params.Cap
	rec.CapSHA256 = params.CapSHA256
	rec.BAP = params.BAP
	rec.Policy = params.Policy
	rec.Realm = params.Realm
	rec.Sig = params.Sig
	// Custom parameter values come straight from raw wire bytes and flow
	// into CLI output; legitimate values are URIs, base64url, or tokens,
	// so anything outside visible ASCII risks terminal escape injection
	// and rejects the agent (same policy as ALPN above).
	for _, p := range []struct{ name, value string }{
		{"cap", rec.CapURI},
		{"cap-sha256", rec.CapSHA256},
		{"bap", rec.BAP},
		{"policy", rec.Policy},
		{"realm", rec.Realm},
		{"sig", rec.Sig},
	} {
		if p.value != "" && !isVisibleASCII(p.value) {
			return AgentRecord{}, fmt.Errorf("agent %s: SVCB %s value %q is not printable ASCII", fqdn, p.name, p.value)
		}
	}

	return rec, nil
}

// capabilityTXT keys of the simple capability TXT record (OSS-03 §3.2),
// e.g. "capabilities=chat,assistant" "version=1.0.0".
const (
	capabilitiesKey = "capabilities="
	versionKey      = "version="
)

// fillCapabilities resolves rec's capabilities (R-DISC-4). Fetching the cap
// document (rec.CapURI) is stubbed until PR-11, so the priority order
// degenerates to the TXT fallback: the first "capabilities=" and "version="
// key found in the agent's TXT records win. A missing TXT record is normal,
// not an error; any other failure is returned so the caller can record it,
// with the agent kept at CapabilitySource "none" (partial success, R-DISC-5).
func fillCapabilities(ctx context.Context, r resolver.Resolver, rec *AgentRecord, opts Options) error {
	rec.CapabilitySource = CapabilitySourceNone

	resp, err := r.LookupTXT(ctx, rec.FQDN)
	if err != nil {
		// A missing record is the normal "no capabilities advertised"
		// case; any other failure (timeout, SERVFAIL) is reported.
		if errors.Is(err, resolver.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("capability TXT %s: %w", rec.FQDN, err)
	}
	// An unvalidated capability TXT record must not be trusted when DNSSEC
	// is required (OSS-03 §6.2); the agent itself was already validated via
	// its SVCB response.
	if opts.RequireDNSSEC && !resp.AD {
		return fmt.Errorf("%w: capability TXT %s", ErrDNSSECRequired, rec.FQDN)
	}
	// A capabilities or version value containing non-printable characters
	// is ignored (treated as not present): these strings flow into CLI
	// output, so control characters risk terminal escape injection.
	tainted := false
	for _, txt := range resp.Records {
		for _, s := range txt {
			if v, ok := strings.CutPrefix(s, capabilitiesKey); ok && rec.Capabilities == nil {
				if caps := splitCapabilities(v); capabilitiesVisibleASCII(caps) {
					rec.Capabilities = caps
					rec.CapabilitySource = CapabilitySourceTXTFallback
				} else {
					tainted = true
				}
			}
			if v, ok := strings.CutPrefix(s, versionKey); ok && rec.Version == "" && v != "" {
				if isVisibleASCII(v) {
					rec.Version = v
				} else {
					tainted = true
				}
			}
		}
	}
	if tainted {
		return fmt.Errorf("capability TXT %s: value with non-printable characters ignored", rec.FQDN)
	}
	return nil
}

// isVisibleASCII reports whether s is non-empty and every byte is visible
// ASCII (0x21..0x7E). DNS-sourced strings destined for CLI output (ALPN,
// capability tokens, version) are restricted to this set to prevent terminal
// escape injection. Capability and version tokens are whitespace-trimmed
// before this check, so no spaces are expected inside a token.
func isVisibleASCII(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// capabilitiesVisibleASCII reports whether every capability token is visible
// ASCII (see isVisibleASCII).
func capabilitiesVisibleASCII(caps []string) bool {
	for _, c := range caps {
		if !isVisibleASCII(c) {
			return false
		}
	}
	return true
}

// splitCapabilities splits a "capabilities=" value on commas, trimming
// whitespace and dropping empty items.
func splitCapabilities(value string) []string {
	var caps []string
	for _, c := range strings.Split(value, ",") {
		if c = strings.TrimSpace(c); c != "" {
			caps = append(caps, c)
		}
	}
	return caps
}

// checkMandatory enforces the SVCB mandatory parameter (RFC 9460 §8): a
// client MUST ignore a record whose mandatory SvcParam lists a key it does
// not implement. This client implements alpn, port, and the draft's
// private-use keys (record.KeyCap..record.KeySig); any other mandatory key
// rejects the record.
func checkMandatory(svcb *dns.SVCB) error {
	for _, kv := range svcb.Value {
		m, ok := kv.(*dns.SVCBMandatory)
		if !ok {
			continue
		}
		for _, key := range m.Code {
			if !supportedSVCBKey(key) {
				return fmt.Errorf("SVCB mandatory parameter requires unsupported key %q (RFC 9460 §8)", key.String())
			}
		}
	}
	return nil
}

// supportedSVCBKey reports whether this client implements the SvcParamKey
// for the purposes of the mandatory check (RFC 9460 §8).
func supportedSVCBKey(key dns.SVCBKey) bool {
	switch key {
	case dns.SVCB_ALPN, dns.SVCB_PORT:
		return true
	}
	return key >= record.KeyCap && key <= record.KeySig
}

// selectSVCB picks the preferred record from an SVCB RRset: the lowest
// SvcPriority among the usable ServiceMode records (RFC 9460 §2.4.1).
// AliasMode records (SvcPriority 0) are not followed, and a record failing
// the mandatory check (RFC 9460 §8) is ignored so selection falls back to
// the next-lowest-priority record.
func selectSVCB(records []*dns.SVCB) (*dns.SVCB, error) {
	var best *dns.SVCB
	var mandatoryErr error
	for _, svcb := range records {
		if svcb.Priority == 0 {
			continue
		}
		if err := checkMandatory(svcb); err != nil {
			mandatoryErr = err
			continue
		}
		if best == nil || svcb.Priority < best.Priority {
			best = svcb
		}
	}
	if best == nil {
		if mandatoryErr != nil {
			return nil, fmt.Errorf("no usable ServiceMode SVCB record: %w", mandatoryErr)
		}
		return nil, fmt.Errorf("no ServiceMode SVCB record (AliasMode is not supported)")
	}
	return best, nil
}
