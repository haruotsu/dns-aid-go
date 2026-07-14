package resolver

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// defaultTimeout bounds one DNS query when Config.Timeout is zero
// (OSS-03 §6.3).
const defaultTimeout = 5 * time.Second

// ednsUDPSize is the maximum UDP response size advertised via EDNS0.
const ednsUDPSize = 4096

// resolvConfPath is the standard system resolver configuration. It is a
// variable so tests can point NewClient at a fixture file.
var resolvConfPath = "/etc/resolv.conf"

// Config configures a Client.
type Config struct {
	// Server is the "host:port" of the DNS server to query. Empty selects
	// the first nameserver from the system configuration.
	Server string

	// Timeout bounds one query including a TCP retry after truncation.
	// Zero means the 5s default.
	Timeout time.Duration
}

// Client implements Resolver with miekg/dns. Queries are sent with EDNS0
// DO=1 so a validating resolver returns the AD flag (R-DISC-2), first over
// UDP and again over TCP when the response is truncated.
type Client struct {
	server  string
	timeout time.Duration
	udp     *dns.Client
	tcp     *dns.Client
}

var _ Resolver = (*Client)(nil)

// NewClient builds a Client from cfg, resolving defaults for unset fields.
func NewClient(cfg Config) (*Client, error) {
	server := cfg.Server
	if server == "" {
		conf, err := dns.ClientConfigFromFile(resolvConfPath)
		if err != nil {
			return nil, fmt.Errorf("load system resolver config: %w", err)
		}
		if len(conf.Servers) == 0 {
			return nil, fmt.Errorf("no nameservers in %s", resolvConfPath)
		}
		server = net.JoinHostPort(conf.Servers[0], conf.Port)
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}

	return &Client{
		server:  server,
		timeout: timeout,
		udp:     &dns.Client{Timeout: timeout},
		tcp:     &dns.Client{Net: "tcp", Timeout: timeout},
	}, nil
}

// LookupTXT implements Resolver.
func (c *Client) LookupTXT(ctx context.Context, fqdn string) (TXTResponse, error) {
	msg, err := c.query(ctx, fqdn, dns.TypeTXT)
	if err != nil {
		return TXTResponse{}, err
	}

	resp := TXTResponse{AD: msg.AuthenticatedData}
	for _, rr := range msg.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			resp.Records = append(resp.Records, txt.Txt)
		}
	}
	if len(resp.Records) == 0 {
		return TXTResponse{}, fmt.Errorf("%w: TXT %s", ErrNotFound, fqdn)
	}
	return resp, nil
}

// QuerySVCB implements Resolver.
func (c *Client) QuerySVCB(ctx context.Context, fqdn string) (SVCBResponse, error) {
	msg, err := c.query(ctx, fqdn, dns.TypeSVCB)
	if err != nil {
		return SVCBResponse{}, err
	}

	resp := SVCBResponse{AD: msg.AuthenticatedData}
	for _, rr := range msg.Answer {
		if svcb, ok := rr.(*dns.SVCB); ok {
			resp.Records = append(resp.Records, svcb)
		}
	}
	if len(resp.Records) == 0 {
		return SVCBResponse{}, fmt.Errorf("%w: SVCB %s", ErrNotFound, fqdn)
	}
	return resp, nil
}

// query sends one qtype question for fqdn and returns the validated
// response message. It retries over TCP when the UDP response is truncated;
// one deadline of c.timeout covers both exchanges.
func (c *Client) query(ctx context.Context, fqdn string, qtype uint16) (*dns.Msg, error) {
	// An earlier deadline on ctx wins (context.WithTimeout keeps it).
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), qtype)
	m.SetEdns0(ednsUDPSize, true) // DO=1: request DNSSEC validation info

	r, _, err := c.udp.ExchangeContext(ctx, m, c.server)
	if err == nil && r.Truncated {
		r, _, err = c.tcp.ExchangeContext(ctx, m, c.server)
	}
	if err != nil {
		return nil, fmt.Errorf("query %s %s: %w", dns.TypeToString[qtype], fqdn, err)
	}

	switch r.Rcode {
	case dns.RcodeSuccess:
		return r, nil
	case dns.RcodeNameError:
		return nil, fmt.Errorf("%w: %s %s: NXDOMAIN", ErrNotFound, dns.TypeToString[qtype], fqdn)
	default:
		return nil, fmt.Errorf("query %s %s: server returned %s",
			dns.TypeToString[qtype], fqdn, dns.RcodeToString[r.Rcode])
	}
}
