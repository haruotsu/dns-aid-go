"""Point dnspython's resolvers at the interop fixture DNS server.

Injected via PYTHONPATH when the interop harness runs the reference
implementation's CLI (Python imports sitecustomize automatically at
startup). The reference creates dns.asyncresolver.Resolver() internally
with no injection point, so the shared BaseResolver initializer is patched
to send every query to the server named by INTEROP_DNS_HOST /
INTEROP_DNS_PORT. Without INTEROP_DNS_HOST this module does nothing.

The reference's HTTP fetches (cap documents, agent cards) and their SSRF
checks resolve hostnames through the system resolver, not dnspython, so
socket.getaddrinfo is also patched: lookups of anything but an address
literal or localhost fail deterministically. Otherwise the comparison
would query real DNS for the fixture's example.com hosts and depend on it
answering NXDOMAIN — a resolver that hijacks NXDOMAIN would make the
reference attempt live HTTPS connections.
"""

import ipaddress
import os
import socket

_host = os.environ.get("INTEROP_DNS_HOST")
if _host:
    import dns.resolver

    _port = int(os.environ.get("INTEROP_DNS_PORT", "53"))
    _orig_init = dns.resolver.BaseResolver.__init__

    def _patched_init(self, *args, **kwargs):
        try:
            _orig_init(self, *args, **kwargs)
        except Exception:
            # No usable system resolv.conf: start unconfigured instead.
            _orig_init(self, configure=False)
        self.nameservers = [_host]
        self.port = _port

    dns.resolver.BaseResolver.__init__ = _patched_init

    _orig_getaddrinfo = socket.getaddrinfo

    def _is_literal_or_local(host):
        if host is None or host == "" or host == "localhost":
            return True
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _patched_getaddrinfo(host, *args, **kwargs):
        if _is_literal_or_local(host if not isinstance(host, bytes) else host.decode()):
            return _orig_getaddrinfo(host, *args, **kwargs)
        raise socket.gaierror(
            socket.EAI_NONAME,
            f"interop harness blocks system DNS resolution of {host!r}",
        )

    socket.getaddrinfo = _patched_getaddrinfo
