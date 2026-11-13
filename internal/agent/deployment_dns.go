package agent

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// The dns-01 part of "deployment add" (docs/PHASE3.md §13.1, step 42): the
// flags --dns-provider, --dns-type, --dns-credentials, --dns-nameserver,
// --dns-zone, --dns-resolver and --check-name.
//
// A deployment only names a provider; the settings live in the top-level map
// dns_providers so that several deployments share them. The DNS flags define
// that entry when its name is new and must agree with it when it exists: a
// second deployment of the same host repeats the flags (a Salt run does) and
// changes nothing, while a different definition is refused, because the
// editor never rewrites an entry that somebody may have tuned by hand
// (ttl, propagation).

// dnsFlagsGiven are the spelled flags of the spec, for a message.
func dnsFlagsGiven(spec *DeploymentSpec) []string {
	var out []string
	for _, f := range []struct{ flag, value string }{
		{"--dns-provider", spec.DNSProvider}, {"--dns-type", spec.DNSType}, {"--dns-credentials", spec.DNSCredentials},
		{"--dns-nameserver", spec.DNSNameserver}, {"--dns-zone", spec.DNSZone}, {"--dns-resolver", spec.DNSResolver},
	} {
		if f.value != "" {
			out = append(out, f.flag)
		}
	}
	return out
}

// lowerName is a DNS name as agent.yaml keeps it: lower case, no trailing dot.
func lowerName(z string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(z)), ".")
}

// completeDNS checks the dns-01 flags against each other and against the
// dns_providers of agent.yaml, and fills Deployment.DNSProvider and CheckName.
// d.Challenge, d.Names and d.Check are already set.
func (s *editSession) completeDNS(spec *DeploymentSpec, d *Deployment) error {
	d.CheckName = lowerName(spec.CheckName)
	if d.CheckName != "" && d.Check == "" {
		return errors.New("--check-name goes with a TLS check: pass --check HOST:PORT (or use a recipe that has one)")
	}
	given := dnsFlagsGiven(spec)
	if d.Challenge != ChallengeDNS01 {
		switch {
		case len(given) > 0:
			return fmt.Errorf("%s belong to --challenge dns-01 (this deployment uses %s)", strings.Join(given, ", "), d.Challenge)
		case slices.ContainsFunc(d.Names, func(n string) bool { return strings.HasPrefix(n, "*.") }):
			return errors.New("a wildcard name can only be proven with dns-01 (RFC 8555 §7.1.3): pass --challenge dns-01 and --dns-provider NAME")
		}
		return nil
	}
	if d.Check != "" && serverName(*d) == "" {
		return errors.New("every name is a wildcard, so the TLS check needs a concrete server name: pass --check-name www.homelab.lan")
	}
	d.DNSProvider = strings.TrimSpace(spec.DNSProvider)
	if d.DNSProvider == "" {
		return errors.New("--challenge dns-01 needs --dns-provider NAME, the entry of dns_providers (e.g. homelab-dns)")
	}
	if !nameRE.MatchString(d.DNSProvider) {
		return fmt.Errorf("--dns-provider %q: lower case letters, digits and '-', e.g. homelab-dns", d.DNSProvider)
	}
	if existing, ok := s.cfg.DNSProviders[d.DNSProvider]; ok {
		return dnsConflict(d.DNSProvider, existing, spec)
	}
	return newDNSProviderProblem(d.DNSProvider, spec)
}

// dnsConflict refuses a flag that contradicts the entry agent.yaml has. A flag
// that is left out takes the entry as it is.
func dnsConflict(name string, have DNSProvider, spec *DeploymentSpec) error {
	var diff []string
	check := func(flag, given, current string) {
		if given != "" && given != current {
			diff = append(diff, fmt.Sprintf("%s %s (agent.yaml has %s)", flag, given, orDash(current)))
		}
	}
	check("--dns-type", spec.DNSType, have.Type)
	if spec.DNSCredentials != "" && filepath.Clean(spec.DNSCredentials) != filepath.Clean(have.CredentialsFile) {
		check("--dns-credentials", spec.DNSCredentials, have.CredentialsFile)
	}
	check("--dns-nameserver", spec.DNSNameserver, have.Nameserver)
	if spec.DNSZone != "" {
		check("--dns-zone", lowerName(spec.DNSZone), have.Zone)
	}
	check("--dns-resolver", spec.DNSResolver, have.Resolver)
	if len(diff) == 0 {
		return nil
	}
	return fmt.Errorf("dns provider %q exists with another definition: %s – edit agent.yaml by hand, or pass a new --dns-provider name; the existing entry was not changed",
		name, strings.Join(diff, "; "))
}

// newDNSProviderProblem checks the flags that define a new provider entry.
// Their values are judged again by ParseConfig (the path rules of
// credentials_file, the form of nameserver and zone) before a byte is written.
func newDNSProviderProblem(name string, spec *DeploymentSpec) error {
	if spec.DNSType == "" {
		return fmt.Errorf("dns provider %q is not in agent.yaml: pass --dns-type %s or %s with --dns-credentials (and --dns-nameserver for rfc2136) to define it, or add it to dns_providers by hand",
			name, DNSTypeRFC2136, DNSTypeCloudflare)
	}
	switch spec.DNSType {
	case DNSTypeRFC2136:
		if spec.DNSNameserver == "" {
			return errors.New("--dns-type rfc2136 needs --dns-nameserver HOST[:PORT], the DNS server that accepts the update (e.g. 192.0.2.53)")
		}
	case DNSTypeCloudflare:
		if spec.DNSNameserver != "" || spec.DNSZone != "" {
			return errors.New("--dns-nameserver and --dns-zone are for --dns-type rfc2136 (Cloudflare is reached by its API and finds the zone itself)")
		}
	default:
		return fmt.Errorf("--dns-type: %s or %s", DNSTypeRFC2136, DNSTypeCloudflare)
	}
	if spec.DNSCredentials == "" {
		return errors.New("--dns-credentials FILE is required: the absolute path of the root-only file with the TSIG key or API token (e.g. /etc/myownpki-agent/dns/homelab.yaml)")
	}
	return nil
}

// newDNSProvider is the entry to write: set only when the name is not in
// agent.yaml yet and --dns-type defines it.
func (s *editSession) newDNSProvider(d Deployment, spec DeploymentSpec) (DNSProvider, bool) {
	if d.Challenge != ChallengeDNS01 {
		return DNSProvider{}, false
	}
	if _, ok := s.cfg.DNSProviders[d.DNSProvider]; ok {
		return DNSProvider{}, false
	}
	return DNSProvider{Type: spec.DNSType, CredentialsFile: spec.DNSCredentials, Nameserver: spec.DNSNameserver,
		Zone: lowerName(spec.DNSZone), Resolver: spec.DNSResolver}, true
}

// warnCredentials tells what is wrong with the credentials file of the
// deployment's provider. It is a warning and never an error: a configuration
// management run writes agent.yaml before it places the secret, and the file
// is only read when an issuance starts. It prints the state and the path,
// never a value.
func (s *editSession) warnCredentials(d Deployment, spec DeploymentSpec) {
	if d.Challenge != ChallengeDNS01 {
		return
	}
	p, ok := s.cfg.DNSProviders[d.DNSProvider]
	if !ok {
		p = DNSProvider{Type: spec.DNSType, CredentialsFile: spec.DNSCredentials}
	}
	creds, err := loadDNSCredentials(p.CredentialsFile, p.Type)
	if err == nil {
		creds.wipe()
		return
	}
	text := "cannot be read"
	var ce *credentialsError
	if errors.As(err, &ce) {
		text = ce.State
		if ce.Detail != "" {
			text += ": " + ce.Detail
		}
	}
	_, _ = fmt.Fprintf(s.opts.Stderr, "warning: DNS credentials file %s: %s – deployment %s fails to renew until it is fixed (root-owned, mode 0600); \"myownpki-agent config check\" shows its state.\n",
		p.CredentialsFile, text, d.Name)
}
