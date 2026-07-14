package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/haruotsu/dns-aid-go/internal/version"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the dnsaid version and the conformant DNS-AID draft",
		Args:  exactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "dnsaid version %s\n", version.String())
			return err
		},
	}
}
