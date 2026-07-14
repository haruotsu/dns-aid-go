// Package resolver abstracts the read-side DNS queries used by discover and
// verify. The Resolver interface has a real implementation backed by
// miekg/dns (Client) and can be served in tests by the in-process DNS server
// in the resolvertest subpackage, so tests never depend on real domains
// (N-7).
package resolver

import (
	"context"
	"errors"

	"github.com/miekg/dns"
)

// ErrNotFound reports that the queried name does not exist (NXDOMAIN) or
// exists without records of the queried type (NODATA). Discover treats both
// the same way: the agent has no such record (R-DISC-3).
var ErrNotFound = errors.New("no matching DNS records")

// TXTResponse is the answer to a TXT lookup.
type TXTResponse struct {
	// Records holds the character-strings of each TXT record, one inner
	// slice per record. A record's character-strings are kept separate so
	// callers can concatenate them per record (RFC 1035).
	Records [][]string

	// AD reports whether the resolver set the Authenticated Data flag,
	// i.e. the response was DNSSEC-validated (RFC 6840 §5.8).
	AD bool
}

// SVCBResponse is the answer to an SVCB query.
type SVCBResponse struct {
	// Records holds the SVCB records in answer order.
	Records []*dns.SVCB

	// AD reports whether the resolver set the Authenticated Data flag.
	AD bool
}

// Resolver is the read-side DNS abstraction. Both queries return ErrNotFound
// (possibly wrapped) when the name yields no records of the requested type.
type Resolver interface {
	LookupTXT(ctx context.Context, fqdn string) (TXTResponse, error)
	QuerySVCB(ctx context.Context, fqdn string) (SVCBResponse, error)
}
