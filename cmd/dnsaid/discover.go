package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/haruotsu/dns-aid-go/pkg/dnsaid"
)

func newDiscoverCmd() *cobra.Command {
	var (
		protocol      string
		name          string
		requireDNSSEC bool
		jsonOut       bool
	)
	cmd := &cobra.Command{
		Use:   "discover <domain>",
		Short: "Discover the AI agents advertised by a domain",
		Long: `Discover resolves the domain's agent index and each agent's SVCB record.

Individual agent failures do not fail the command: they are reported as
WARN lines on stderr (and in errors[] with --json), and the exit code is 0
as long as at least one agent was discovered.

Environment variables:
  DNSAID_RESOLVER   DNS server to query as "host:port" (default: system configuration)
  DNSAID_TIMEOUT    per-query timeout as a Go duration, e.g. "5s" (default: 5s)`,
		Args: exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := dnsaid.Options{
				Protocol:      protocol,
				Name:          name,
				RequireDNSSEC: requireDNSSEC,
				Resolver:      os.Getenv("DNSAID_RESOLVER"),
			}
			if v := os.Getenv("DNSAID_TIMEOUT"); v != "" {
				d, err := time.ParseDuration(v)
				if err != nil {
					return fmt.Errorf("invalid DNSAID_TIMEOUT %q: %w", v, err)
				}
				// A non-positive timeout would expire every query
				// immediately and misdiagnose as a missing index.
				if d <= 0 {
					return fmt.Errorf("invalid DNSAID_TIMEOUT %q: must be positive", v)
				}
				opts.Timeout = d
			}

			domain := args[0]
			res, err := dnsaid.Discover(cmd.Context(), domain, opts)
			if err != nil {
				return err
			}

			// Partial failures go to stderr so stdout stays parseable
			// (OSS-03 §6.2).
			for _, e := range res.Errors {
				fmt.Fprintf(cmd.ErrOrStderr(), "WARN %v\n", e) //nolint:errcheck // best-effort diagnostics; nothing to do when stderr is gone
			}
			write := writeHuman
			if jsonOut {
				write = writeJSON
			}
			if err := write(cmd.OutOrStdout(), domain, res); err != nil {
				return err
			}

			// Exit code 0 requires at least one discovered agent
			// (OSS-03 §6.2); an empty index with no failures is a
			// valid "nothing advertised" answer.
			if len(res.Agents) == 0 && len(res.Errors) > 0 {
				return fmt.Errorf("no agents discovered at %s", domain)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&protocol, "protocol", "", "only list agents advertising this protocol in the index")
	cmd.Flags().StringVar(&name, "name", "", "look up a single agent by its index name")
	cmd.Flags().BoolVar(&requireDNSSEC, "require-dnssec", false, "reject DNS responses without the AD flag")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "print the result as JSON")
	return cmd
}
