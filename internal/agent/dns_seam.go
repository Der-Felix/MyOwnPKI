package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
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
// asks. Tests replace Agent.newDNSProvider with a fake; the default
// (buildDNSProvider) reads the credentials file and builds the real provider.
// Whatever the factory returns runs inside a dnsGuard.
type dnsProviderFactory func(ctx context.Context, name string, cfg DNSProvider, d Deployment) (dnsProvider, error)

// dnsTuning holds what tests change in the dns-01 path; the zero value is
// production. None of it is configuration.
type dnsTuning struct {
	// poll is the interval of the propagation check (default 2 s).
	poll time.Duration
	// cleanup bounds one CleanUp (default 30 s).
	cleanup time.Duration
	// resolvConf is read for the resolver when dns_providers has none
	// (default /etc/resolv.conf).
	resolvConf string
	// cloudflare points the Cloudflare provider at a stub.
	cloudflare *cloudflareTest
}

func (a *Agent) pollInterval() time.Duration {
	if a.dns.poll > 0 {
		return a.dns.poll
	}
	return dns01.DefaultPollingInterval
}

// buildDNSProvider is the default factory: it loads the credentials file at
// the start of the issuance (so a rotated file works at the next renewal) and
// builds the provider of cfg.Type. The credentials are wiped when the guard
// closes. Every error is free of secrets.
func (a *Agent) buildDNSProvider(_ context.Context, name string, cfg DNSProvider, _ Deployment) (dnsProvider, error) {
	creds, err := loadDNSCredentials(cfg.CredentialsFile, cfg.Type)
	if err != nil {
		return nil, fmt.Errorf("dns provider %q: %w", name, err)
	}
	var p dnsProvider
	switch cfg.Type {
	case DNSTypeRFC2136:
		var rp *rfc2136Provider
		if rp, err = newRFC2136Provider(cfg, creds, a.Now); err == nil {
			p = rp
		}
	case DNSTypeCloudflare:
		var cp *cloudflareProvider
		if cp, err = newCloudflareProvider(cfg, creds, a.cfg.Proxy, a.dns.cloudflare); err == nil {
			p = cp
		}
	default:
		err = errors.New("unknown provider type")
	}
	if err != nil {
		creds.wipe()
		return nil, fmt.Errorf("dns provider %q: %w", name, creds.redact(err))
	}
	return p, nil
}

// dnsProviderFor returns the guarded provider of a dns-01 deployment. It
// never touches the network. The caller runs finish and close.
func (a *Agent) dnsProviderFor(ctx context.Context, d Deployment) (*dnsGuard, error) {
	cfg, ok := a.cfg.DNSProviders[d.DNSProvider]
	if !ok {
		return nil, errors.New("dns-01: dns_provider is not under dns_providers")
	}
	factory := a.newDNSProvider
	if factory == nil {
		factory = a.buildDNSProvider
	}
	inner, err := factory(ctx, d.DNSProvider, cfg, d)
	if err != nil {
		return nil, err
	}
	g := newDNSGuard(ctx, inner, d.DNSProvider, cfg, d, a.pollInterval(), a.log)
	if a.dns.cleanup > 0 {
		g.cleanupTimeout = a.dns.cleanup
	}
	return g, nil
}
