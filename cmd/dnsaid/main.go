// Command dnsaid is the CLI of dns-aid-go (R-CLI-1..3): DNS-based AI agent
// discovery per draft-mozleywilliams-dnsop-dnsaid.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/haruotsu/dns-aid-go/pkg/dnsaid"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the CLI and returns its exit code. It is the in-process entry
// point shared by main and the integration tests.
func run(args []string, stdout, stderr io.Writer) int {
	root := newRootCmd()
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err) //nolint:errcheck // best-effort diagnostics; nothing to do when stderr is gone
		if uerr, ok := errors.AsType[*usageError](err); ok {
			fmt.Fprintf(stderr, "\n%s", uerr.cmd.UsageString()) //nolint:errcheck // best-effort diagnostics
		}
		return exitCode(err)
	}
	return 0
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "dnsaid",
		Short: "DNS-based AI agent discovery (draft-mozleywilliams-dnsop-dnsaid)",
		// run prints errors and usage itself: cobra would print usage
		// on the output writer (stdout), where it would corrupt
		// machine-readable output.
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return &usageError{cmd: cmd, err: err}
	})
	root.AddCommand(newDiscoverCmd())
	return root
}

// usageError marks an error as a command-line usage mistake, so run appends
// the offending command's usage text to the error message.
type usageError struct {
	cmd *cobra.Command
	err error
}

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

// exactArgs is cobra.ExactArgs returning a usageError, so argument-count
// mistakes print usage while runtime failures do not.
func exactArgs(n int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(n)(cmd, args); err != nil {
			return &usageError{cmd: cmd, err: err}
		}
		return nil
	}
}

// exitCode maps an error to the CLI exit code (OSS-03 §6.2).
func exitCode(err error) int {
	switch {
	case errors.Is(err, dnsaid.ErrIndexNotFound):
		return 2
	case errors.Is(err, dnsaid.ErrAgentNotFound):
		return 3
	case errors.Is(err, dnsaid.ErrDNSSECRequired):
		return 4
	default:
		return 1
	}
}
