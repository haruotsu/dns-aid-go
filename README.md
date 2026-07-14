# dns-aid-go

> An independent Go implementation of DNS-AID (`draft-mozleywilliams-dnsop-dnsaid`).

**dns-aid-go** is a Go implementation (CLI + library) of DNS-AID, a protocol
for discovering AI agents through DNS. It relies only on existing DNS record
types (SVCB / TXT / TLSA) and DNSSEC — it introduces no new record types, no
central registry, and no separate network.

It aims to be the **second, independent implementation** of the protocol
alongside the Python reference implementation. In the IETF standardization
process, multiple interoperable implementations are evidence of a maturing
draft, and implementing from the specification (rather than porting the
reference code) helps surface ambiguities to feed back to the IETF.

## Installation

### Pre-built binaries

Download the binary for your platform from the
[releases page](https://github.com/haruotsu/dns-aid-go/releases).

### go install

```sh
go install github.com/haruotsu/dns-aid-go/cmd/dnsaid@latest
```

### Container image

Multi-arch (amd64/arm64) images are published to GitHub Container Registry:

```sh
docker run --rm ghcr.io/haruotsu/dns-aid-go:latest discover example.com
```

### Library

```sh
go get github.com/haruotsu/dns-aid-go
```

## Usage

### CLI

Discover the agents a domain advertises:

```sh
dnsaid discover example.com
```

```
FOUND 3 agents at example.com  (index: dns_txt)

  chat.example.com     mcp  →  chat.example.com:443      [dnssec:ok]
    capabilities: chat, assistant     (source: txt_fallback)
  billing.example.com  a2a  →  billing.example.com:443   [dnssec:ok]
    capabilities: billing, invoicing  (source: txt_fallback)
  support.example.com  h2   →  support.example.com:8443  [dnssec:ok]
    capabilities: support             (source: txt_fallback)
```

Useful flags and environment variables:

```sh
dnsaid discover example.com --json               # machine-readable output (agents[] + errors[])
dnsaid discover example.com --protocol mcp       # only agents advertising this protocol
dnsaid discover example.com --name chat          # look up a single agent by index name
dnsaid discover example.com --require-dnssec     # reject responses without the AD flag
dnsaid version                                   # version + conformant draft

DNSAID_RESOLVER=127.0.0.1:5353 dnsaid discover example.com   # query a specific DNS server
DNSAID_TIMEOUT=10s dnsaid discover example.com               # per-query timeout (default 5s)
```

Exit codes: `0` success (including partial success with at least one agent),
`1` generic error, `2` agent index not found, `3` agent not found,
`4` DNSSEC validation required but unavailable.

### Library

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/haruotsu/dns-aid-go/pkg/dnsaid"
)

func main() {
	res, err := dnsaid.Discover(context.Background(), "example.com", dnsaid.Options{
		Protocol: "mcp", // empty = no filter
	})
	if err != nil {
		log.Fatal(err)
	}
	for _, a := range res.Agents {
		fmt.Printf("%s: %s://%s:%d capabilities=%v\n",
			a.Name, a.Protocol, a.Endpoint, a.Port, a.Capabilities)
	}
}
```

See the [package documentation](https://pkg.go.dev/github.com/haruotsu/dns-aid-go/pkg/dnsaid)
for the full API.

## Conformance

This implementation conforms to revision `-02` of the IETF draft
[`draft-mozleywilliams-dnsop-dnsaid`](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid/).

The specification is the source of truth; the Python reference implementation is
used only to confirm interoperable behavior. Because the draft is still evolving,
conformance may change between releases — every draft revision is recorded in the
release notes. Run `dnsaid version` to see which draft a binary conforms to.

Interoperability with the reference implementation is verified continuously:
the [interop workflow](.github/workflows/interop.yml) serves the fixture zones
from an in-process DNS server, runs `dnsaid discover` and the reference CLI
against them, and requires the normalized JSON results to match. A weekly
scheduled run repeats the check against the latest reference release to catch
drift early. To reproduce it locally or in a fork:

```sh
pip install -r internal/interop/requirements.txt
go test -tags interop ./internal/interop/
```

## Status and limitations

The current release is **read-only**: it only queries DNS and never writes to it.

| Milestone | Scope |
|-----------|-------|
| `v0.1` | `discover` (read-only) — **current** |
| `v0.2` | `verify` + interoperability proof with the reference implementation |
| `v0.3` | `publish` / `delete` (write) |

Not yet available:

- `verify` — record completeness / DNSSEC scoring (planned for v0.2)
- `publish` / `delete` — writing records to a DNS backend (planned for v0.3)
- Capability document fetching over HTTPS (`cap` / `cap-sha256` are parsed and
  exposed, but the document itself is not fetched yet)

As long as the underlying IETF draft is evolving, this project stays on `0.x`
versions: the public API, CLI flags, and output formats may still change
between minor releases.

## Versioning and releases

Releases follow [SemVer](https://semver.org/) and are fully automated with
[tagpr](https://github.com/Songmu/tagpr): merging the auto-generated release PR
creates the tag, the changelog, and the GitHub Release with pre-built binaries.
Manual tags are never pushed.

## License

Licensed under the [Apache License 2.0](LICENSE).

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.
