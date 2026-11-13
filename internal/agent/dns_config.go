package agent

import (
	"errors"
	"fmt"
	"maps"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// DNS provider types and propagation modes of docs/PHASE3.md §13.2.
const (
	DNSTypeRFC2136    = "rfc2136"
	DNSTypeCloudflare = "cloudflare"

	PropagationAuthoritative = "authoritative"
	PropagationResolver      = "resolver"
	PropagationWait          = "wait"
)

// Bounds and defaults of a dns_providers entry (docs/PHASE3.md §13.2).
const (
	maxDNSProviders = 20

	defaultDNSTTL             = 120
	maxDNSTTL                 = 3600
	minTTLCloudflare          = 120
	minTTLRFC2136             = 30
	maxPropagationWait        = 300 // seconds
	defaultPropagationTimeout = 120 // seconds
	maxPropagationTimeout     = 600 // seconds
)

// DNSProvider is one entry of dns_providers: how and where the agent writes
// the TXT record of a dns-01 challenge. It holds no secret; CredentialsFile
// names the root-only file with the TSIG key or the API token (see
// dns_creds.go).
type DNSProvider struct {
	// Type is rfc2136 or cloudflare.
	Type string `yaml:"type"`
	// CredentialsFile is an absolute path, read at the start of every issuance.
	CredentialsFile string `yaml:"credentials_file"`
	// Nameserver is host or host:port (default port 53); rfc2136 only.
	Nameserver string `yaml:"nameserver"`
	// Zone is the zone to update; rfc2136 only, "" = found by an SOA lookup.
	Zone string `yaml:"zone"`
	// TTL of the TXT record in seconds (default 120).
	TTL int `yaml:"ttl"`
	// Resolver is IP or IP:port used for SOA, CNAME and propagation queries.
	Resolver string `yaml:"resolver"`
	// Propagation is authoritative (default), resolver or wait.
	Propagation string `yaml:"propagation"`
	// PropagationWait is a pause in seconds before the first check (default 0).
	PropagationWait int `yaml:"propagation_wait"`
	// PropagationTimeout is how long the agent polls, in seconds (default 120).
	PropagationTimeout int `yaml:"propagation_timeout"`
}

// forbiddenCredentialsDirs are hidden from the agent by ProtectHome=yes of
// its systemd unit (docs/PHASE3.md §13.2, decision 2).
var forbiddenCredentialsDirs = []string{"/home", "/root", "/run/user"}

// serverName is the SNI of the local TLS check: check_name, else the first
// name that is not a wildcard. "" means there is none (Validate refuses a
// deployment with a check and no such name).
func serverName(d Deployment) string {
	if d.CheckName != "" {
		return d.CheckName
	}
	for _, n := range d.Names {
		if !strings.HasPrefix(n, "*.") {
			return n
		}
	}
	return ""
}

// validateDNSProviders checks every dns_providers entry, fills the defaults
// (ttl, propagation, propagation_timeout, a normalized zone) and reports all
// problems through add. It runs after the deployments are known, because the
// credentials file may not lie where the agent writes.
func (c *Config) validateDNSProviders(add func(format string, args ...any)) {
	if len(c.DNSProviders) > maxDNSProviders {
		add("dns_providers: at most %d", maxDNSProviders)
	}
	for _, name := range slices.Sorted(maps.Keys(c.DNSProviders)) {
		p := c.DNSProviders[name]
		if !nameRE.MatchString(name) {
			add("dns_providers: %q: a name of lower case letters, digits and '-', e.g. homelab-dns", name)
			continue
		}
		where := "dns_providers." + name
		switch p.Type {
		case DNSTypeRFC2136, DNSTypeCloudflare:
		default:
			add("%s: type: %s or %s", where, DNSTypeRFC2136, DNSTypeCloudflare)
		}
		if problem := c.credentialsPathProblem(p.CredentialsFile); problem != "" {
			add("%s: credentials_file: %s", where, problem)
		}
		switch p.Type {
		case DNSTypeRFC2136:
			if p.Nameserver == "" {
				add("%s: nameserver: required for rfc2136, host or host:port of the DNS server that accepts the update, e.g. 192.0.2.53", where)
			} else if err := checkEndpoint(p.Nameserver, true); err != nil {
				add("%s: nameserver: %q: %v", where, p.Nameserver, err)
			}
			if p.Zone != "" {
				p.Zone = strings.TrimSuffix(strings.ToLower(p.Zone), ".")
				if err := checkZone(p.Zone); err != nil {
					add("%s: zone: %q: %v", where, p.Zone, err)
				}
			}
		case DNSTypeCloudflare:
			if p.Nameserver != "" {
				add("%s: nameserver: only for rfc2136 (Cloudflare is reached by its API)", where)
			}
			if p.Zone != "" {
				add("%s: zone: only for rfc2136 (Cloudflare finds the zone itself)", where)
			}
		}
		if p.TTL == 0 {
			p.TTL = defaultDNSTTL
		}
		low := minTTLRFC2136
		if p.Type == DNSTypeCloudflare {
			low = minTTLCloudflare
		}
		if p.TTL < low || p.TTL > maxDNSTTL {
			add("%s: ttl: %d to %d seconds for %s (default %d)", where, low, maxDNSTTL, p.Type, defaultDNSTTL)
		}
		if p.Resolver != "" {
			if err := checkEndpoint(p.Resolver, false); err != nil {
				add("%s: resolver: %q: %v", where, p.Resolver, err)
			}
		}
		switch p.Propagation {
		case "":
			p.Propagation = PropagationAuthoritative
		case PropagationAuthoritative, PropagationResolver, PropagationWait:
		default:
			add("%s: propagation: %s, %s or %s", where, PropagationAuthoritative, PropagationResolver, PropagationWait)
		}
		if p.PropagationWait < 0 || p.PropagationWait > maxPropagationWait {
			add("%s: propagation_wait: 0 to %d seconds", where, maxPropagationWait)
		}
		if p.PropagationTimeout == 0 {
			p.PropagationTimeout = defaultPropagationTimeout
		}
		if p.PropagationTimeout < 1 || p.PropagationTimeout > maxPropagationTimeout {
			add("%s: propagation_timeout: 1 to %d seconds (default %d)", where, maxPropagationTimeout, defaultPropagationTimeout)
		}
		c.DNSProviders[name] = p
	}
}

// credentialsPathProblem returns what is wrong with a credentials_file path
// ("" = nothing). Only the path is judged; the file itself is checked by
// loadDNSCredentials when an issuance starts.
func (c *Config) credentialsPathProblem(p string) string {
	if p == "" {
		return "required, the absolute path of the credentials file, e.g. /etc/myownpki-agent/dns/homelab.yaml"
	}
	slash := filepath.ToSlash(filepath.Clean(p))
	for _, dir := range forbiddenCredentialsDirs {
		if slash == dir || strings.HasPrefix(slash, dir+"/") {
			return fmt.Sprintf("%q is under %s, which the agent's systemd unit hides (ProtectHome=yes); use /etc/myownpki-agent/dns/", p, dir)
		}
	}
	switch {
	case !filepath.IsAbs(p):
		return fmt.Sprintf("%q: an absolute path", p)
	case slices.Contains(strings.Split(filepath.ToSlash(p), "/"), ".."):
		return fmt.Sprintf("%q: no .. path segments", p)
	case Under([]string{c.StateDir}, p):
		return fmt.Sprintf("%q is under state_dir; the agent writes there, a secret file must not", p)
	case Under(c.Paths, p):
		return fmt.Sprintf("%q is under one of paths; the agent writes there, a secret file must not", p)
	}
	for _, d := range c.Deployments {
		targets := []string{d.Files.Certificate, d.Files.Chain, d.Files.Fullchain, d.Files.Key}
		if d.Profile == ProfileNginx {
			targets = []string{d.Dir}
		}
		for _, t := range targets {
			if t != "" && Under([]string{t}, p) {
				return fmt.Sprintf("%q is a deployment target of %s; the agent writes there, a secret file must not", p, d.Name)
			}
		}
	}
	return ""
}

// checkEndpoint accepts an IP, "host", "host:port" and "[v6]:port". A host
// name is allowed for a nameserver; a resolver must be an IP.
func checkEndpoint(s string, nameAllowed bool) error {
	host, port := s, ""
	if net.ParseIP(s) == nil {
		if h, p, err := net.SplitHostPort(s); err == nil {
			host, port = h, p
		} else if strings.ContainsAny(s, ":[]") {
			return errors.New("want host or host:port, e.g. 192.0.2.53 or ns1.homelab.lan:53")
		}
	}
	if port != "" {
		if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
			return errors.New("port: 1 to 65535")
		}
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	if !nameAllowed {
		return errors.New("want an IP address; a resolver is not itself looked up")
	}
	return checkLabels(host)
}

// checkZone: a DNS name of at least one label ("lan" is a zone too).
func checkZone(z string) error { return checkLabels(z) }

func checkLabels(h string) error {
	if len(h) == 0 || len(h) > 253 {
		return errors.New("1 to 253 characters")
	}
	for _, l := range strings.Split(h, ".") {
		if !nameRE.MatchString(l) {
			return fmt.Errorf("label %q: lower case letters, digits and '-'", l)
		}
	}
	return nil
}

// unusedDNSProviders are dns_providers no deployment refers to (a warning,
// not an error: the entry may be prepared before its deployment).
func (c *Config) unusedDNSProviders() []string {
	used := map[string]bool{}
	for _, d := range c.Deployments {
		if d.Challenge == ChallengeDNS01 {
			used[d.DNSProvider] = true
		}
	}
	var out []string
	for _, name := range slices.Sorted(maps.Keys(c.DNSProviders)) {
		if !used[name] {
			out = append(out, name)
		}
	}
	return out
}
