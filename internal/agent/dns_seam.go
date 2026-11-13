package agent

import (
	"context"
	"errors"

	"github.com/go-acme/lego/v4/challenge"
)

// dnsProvider is what a dns-01 deployment needs from a DNS provider: lego's
// Present and CleanUp, plus Timeout (propagation timeout and polling
// interval), which lego's resolver asks for.
type dnsProvider interface {
	challenge.Provider
	challenge.ProviderTimeout
}

// dnsProviderFactory builds the provider of one issuance: name is the key
// under dns_providers, cfg its (validated) entry and d the deployment that
// asks. Tests replace Agent.newDNSProvider with a fake; the default fails
// until the real providers exist (docs/PHASE3.md step 40).
type dnsProviderFactory func(ctx context.Context, name string, cfg DNSProvider, d Deployment) (dnsProvider, error)

// errDNSNotBuilt is what the default factory answers.
var errDNSNotBuilt = errors.New("dns-01 is not built into this agent yet")

// errDNSNotWired: a provider exists but is not connected to lego yet.
var errDNSNotWired = errors.New("dns-01 is not connected to the ACME client yet")

func notBuiltDNSProvider(context.Context, string, DNSProvider, Deployment) (dnsProvider, error) {
	return nil, errDNSNotBuilt
}

// dnsProviderFor returns the provider of a dns-01 deployment. It never
// touches the network and never loads a credentials file by itself.
func (a *Agent) dnsProviderFor(ctx context.Context, d Deployment) (dnsProvider, error) {
	cfg, ok := a.cfg.DNSProviders[d.DNSProvider]
	if !ok {
		return nil, errors.New("dns-01: dns_provider is not under dns_providers")
	}
	factory := a.newDNSProvider
	if factory == nil {
		factory = notBuiltDNSProvider
	}
	return factory(ctx, d.DNSProvider, cfg, d)
}
