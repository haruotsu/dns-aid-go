# Contributing to dns-aid-go

Thanks for your interest in contributing! This project is an independent Go
implementation of DNS-AID (`draft-mozleywilliams-dnsop-dnsaid`), and
contributions of all kinds — bug reports, tests, documentation, and code — are
welcome.

## Ground rules

- **Language**: All code comments, documentation, and error messages must be in
  English (requirement N-5).
- **License**: By contributing, you agree that your contributions are licensed
  under the [Apache License 2.0](LICENSE).
- **Vendor neutral**: Do not introduce dependencies on, or references to, any
  specific DNS provider. Standard protocol names and generic managed-DNS
  backends (e.g. Cloudflare) are the only exceptions (requirement N-8).
- **No real-world domains in tests**: Test fixtures must be self-contained
  (in-repo zone data / mock DNS) and must not query real external domains. Use
  `example.com`-style names only (requirement N-7).

## Development

Requirements:

- Go (see `go.mod` for the minimum version).

Common commands:

```sh
go build ./...   # build everything
go vet ./...     # static checks
go test ./...    # run the test suite
```

Continuous integration runs `go vet`, `golangci-lint`, and `go test` on every
push and pull request. Please make sure these pass locally before opening a PR.

## Test-driven development

This project follows a test-driven workflow: add or adjust tests that describe
the desired behavior, watch them fail, then write the minimum code to make them
pass, and refactor. Core logic (`record` / `discover`) is expected to keep at
least 80% test coverage (requirement N-7).

## Pull requests

Keep each PR focused on a single concern. A good PR description covers:

- **Purpose** and the requirement ID(s) it addresses.
- **Changes** made.
- **Tests** added or updated.
- Whether it introduces any **breaking changes**.

## Releases

Releases are automated with [tagpr](https://github.com/Songmu/tagpr). Do **not**
create tags manually. Merging a feature PR into `main` updates a release PR;
merging that release PR cuts the release. The version constant in
`internal/version/version.go` is the single source of truth and is managed by
tagpr — do not edit it by hand.
