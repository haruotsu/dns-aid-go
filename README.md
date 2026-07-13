# dns-aid-go

> An independent Go implementation of DNS-AID (`draft-mozleywilliams-dnsop-dnsaid`).

**Status: WIP** — this project is under active development toward its first
release (`v0.1`). The public API, CLI flags, and output formats are not yet
stable and may change without notice.

## Overview

**dns-aid-go** is a Go implementation (CLI + library) of DNS-AID, a protocol
for discovering AI agents through DNS. It relies only on existing DNS record
types (SVCB / TXT / TLSA) and DNSSEC — it introduces no new record types, no
central registry, and no separate network.

It aims to be the **second, independent implementation** of the protocol
alongside the Python reference implementation. In the IETF standardization
process, multiple interoperable implementations are evidence of a maturing
draft, and implementing from the specification (rather than porting the
reference code) helps surface ambiguities to feed back to the IETF.

### Goals

- **Discover** agents published under a domain via the DNS index and SVCB records.
- **Verify** that an agent's records are present, complete, and DNSSEC-protected.
- **Publish** agent records to a DNS backend (planned for a later release).
- Provide the same capabilities as both a CLI (`dnsaid`) and a Go library
  (`pkg/dnsaid`).

## Conformance

This implementation conforms to the IETF draft
[`draft-mozleywilliams-dnsop-dnsaid`](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid/).

The specification is the source of truth; the Python reference implementation is
used only to confirm interoperable behavior. Because the draft is still evolving,
conformance may change between releases — every draft revision is recorded in the
release notes.

## Status and limitations

The initial release milestones are read-only:

| Milestone | Scope |
|-----------|-------|
| `v0.1` | `discover` (read-only) |
| `v0.2` | `verify` + interoperability proof |
| `v0.3` | `publish` / `delete` (write) |

Write operations (`publish` / `delete`) are intentionally **not** available in
the early read-only releases (see requirement N-2).

## License

Licensed under the [Apache License 2.0](LICENSE).

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.
