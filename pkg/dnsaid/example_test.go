package dnsaid_test

import (
	"context"
	"fmt"
	"log"

	"github.com/haruotsu/dns-aid-go/pkg/dnsaid"
)

// ExampleDiscover lists the agents advertised by a domain. Leaving
// Options.Resolver empty uses the system resolver; the Protocol filter keeps
// only agents advertising the given protocol. There is no Output comment so
// the example is compiled but not executed, keeping tests offline (N-7).
func ExampleDiscover() {
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
