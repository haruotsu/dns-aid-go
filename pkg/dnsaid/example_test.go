package dnsaid_test

import (
	"context"
	"fmt"
	"log"

	"github.com/haruotsu/dns-aid-go/internal/resolver/resolvertest"
	"github.com/haruotsu/dns-aid-go/pkg/dnsaid"
)

// ExampleDiscover resolves the agents advertised by a domain. The in-process
// DNS server only makes the example runnable without network access (N-7);
// a real caller leaves Options.Resolver empty to use the system resolver.
func ExampleDiscover() {
	srv, err := resolvertest.New(`
$ORIGIN example.com.
$TTL 300
_index._agents TXT "agents=chat:mcp,billing:a2a"
chat    SVCB 1 chat.example.com. alpn="mcp" port=443
chat    TXT  "capabilities=chat,assistant" "version=1.0.0"
billing SVCB 1 billing.example.com. alpn="a2a" port=443
`)
	if err != nil {
		log.Fatal(err)
	}
	defer srv.Close() //nolint:errcheck // example teardown

	res, err := dnsaid.Discover(context.Background(), "example.com", dnsaid.Options{
		Resolver: srv.Addr, // empty = system resolver
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, a := range res.Agents {
		fmt.Printf("%s: %s://%s:%d capabilities=%v\n",
			a.Name, a.Protocol, a.Endpoint, a.Port, a.Capabilities)
	}
	// Output:
	// chat: mcp://chat.example.com:443 capabilities=[chat assistant]
	// billing: a2a://billing.example.com:443 capabilities=[]
}
