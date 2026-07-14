// Package resolvertest provides an in-process DNS server that serves a
// fixed zone for tests. It lets resolver and discover tests run without any
// network access to real domains (N-7).
package resolvertest

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// Server is an in-process DNS server answering from a static zone.
type Server struct {
	// Addr is the "host:port" the server listens on, for both UDP and TCP.
	Addr string

	udp *dns.Server
	tcp *dns.Server

	records map[rrKey][]dns.RR
	names   map[string]bool
	ad      bool
}

// Option configures a Server.
type Option func(*Server)

// WithAD makes the server behave like a validating resolver that has
// authenticated the zone: responses to security-aware queries (DO or AD bit
// set) carry the AD flag (RFC 6840 §5.8).
func WithAD() Option {
	return func(s *Server) { s.ad = true }
}

// rrKey identifies one RRset in the zone.
type rrKey struct {
	name  string // fully-qualified, lowercase
	qtype uint16
}

// New parses zone (RFC 1035 master file syntax; use $ORIGIN for relative
// names) and starts a DNS server for it on a random loopback port, listening
// on both UDP and TCP.
func New(zone string, opts ...Option) (*Server, error) {
	s := &Server{
		records: make(map[rrKey][]dns.RR),
		names:   make(map[string]bool),
	}
	for _, opt := range opts {
		opt(s)
	}
	if err := s.loadZone(zone); err != nil {
		return nil, err
	}
	if err := s.listen(); err != nil {
		return nil, err
	}
	return s, nil
}

// Close shuts the server down.
func (s *Server) Close() error {
	uerr := s.udp.Shutdown()
	terr := s.tcp.Shutdown()
	if uerr != nil {
		return uerr
	}
	return terr
}

func (s *Server) loadZone(zone string) error {
	zp := dns.NewZoneParser(strings.NewReader(zone), "", "")
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		name := strings.ToLower(rr.Header().Name)
		k := rrKey{name: name, qtype: rr.Header().Rrtype}
		s.records[k] = append(s.records[k], rr)
		s.names[name] = true
	}
	if err := zp.Err(); err != nil {
		return fmt.Errorf("parse zone: %w", err)
	}
	if len(s.records) == 0 {
		return fmt.Errorf("zone has no records")
	}
	return nil
}

// listen binds UDP and TCP on the same loopback port so a client can retry a
// truncated UDP response over TCP against the same address.
func (s *Server) listen() error {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen udp: %w", err)
	}
	addr := pc.LocalAddr().String()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		_ = pc.Close()
		return fmt.Errorf("listen tcp on %s: %w", addr, err)
	}

	handler := dns.HandlerFunc(s.handle)
	s.udp = &dns.Server{PacketConn: pc, Handler: handler}
	s.tcp = &dns.Server{Listener: ln, Handler: handler}
	go s.udp.ActivateAndServe() //nolint:errcheck // serve loop ends on Shutdown
	go s.tcp.ActivateAndServe() //nolint:errcheck // serve loop ends on Shutdown
	s.Addr = addr
	return nil
}

func (s *Server) handle(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	m.AuthenticatedData = s.ad && securityAware(req)

	if len(req.Question) == 1 {
		q := req.Question[0]
		name := strings.ToLower(q.Name)
		switch {
		case len(s.records[rrKey{name, q.Qtype}]) > 0:
			m.Answer = s.records[rrKey{name, q.Qtype}]
		case s.names[name]:
			// NODATA: the name exists with other types only.
		default:
			m.Rcode = dns.RcodeNameError
		}
	} else {
		m.Rcode = dns.RcodeFormatError
	}

	// A response that does not fit in the client's UDP buffer must be
	// truncated with the TC bit set so the client retries over TCP
	// (RFC 1035 §4.2.1); Truncate does both.
	if w.RemoteAddr().Network() == "udp" {
		m.Truncate(udpSize(req))
	}

	w.WriteMsg(m) //nolint:errcheck // nothing to do on a failed reply in tests
}

// udpSize returns the maximum UDP response size the client advertised via
// EDNS0, or the 512-octet DNS minimum without EDNS0.
func udpSize(req *dns.Msg) int {
	if opt := req.IsEdns0(); opt != nil && int(opt.UDPSize()) > dns.MinMsgSize {
		return int(opt.UDPSize())
	}
	return dns.MinMsgSize
}

// securityAware reports whether the query indicates the client understands
// DNSSEC, i.e. it set the DO bit (RFC 4035 §3.2.1) or the AD bit
// (RFC 6840 §5.7).
func securityAware(req *dns.Msg) bool {
	if req.AuthenticatedData {
		return true
	}
	opt := req.IsEdns0()
	return opt != nil && opt.Do()
}
