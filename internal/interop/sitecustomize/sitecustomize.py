"""Point dnspython's resolvers at the interop fixture DNS server.

Injected via PYTHONPATH when the interop harness runs the reference
implementation's CLI (Python imports sitecustomize automatically at
startup). The reference creates dns.asyncresolver.Resolver() internally
with no injection point, so the shared BaseResolver initializer is patched
to send every query to the server named by INTEROP_DNS_HOST /
INTEROP_DNS_PORT. Without INTEROP_DNS_HOST this module does nothing.
"""

import os

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
