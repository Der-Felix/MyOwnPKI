package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"go.yaml.in/yaml/v3"
)

// dnsTestConfig is a valid configuration with one wildcard deployment that
// uses an rfc2136 provider; each case changes one thing.
func dnsTestConfig(dir string) *Config {
	return &Config{
		Server: "https://pki.homelab.lan:8444", CABundle: filepath.Join(dir, "root.pem"), Hostname: "proxy1.homelab.lan",
		StateDir: filepath.Join(dir, "state"), LogLevel: "info", ACMEDirectory: "https://pki.homelab.lan/acme/directory",
		Enrollment: Enrollment{Challenge: ChallengeStandalone}, Paths: []string{filepath.Join(dir, "ssl")},
		DNSProviders: map[string]DNSProvider{"homelab-dns": {
			Type: DNSTypeRFC2136, CredentialsFile: filepath.Join(dir, "dns", "homelab.yaml"), Nameserver: "192.0.2.53",
		}},
		Deployments: []Deployment{{
			Name: "wild", Profile: ProfileFile, Names: []string{"*.homelab.lan", "homelab.lan"}, Challenge: ChallengeDNS01, DNSProvider: "homelab-dns",
			Files: Files{Fullchain: filepath.Join(dir, "ssl", "fullchain.pem"), Key: filepath.Join(dir, "ssl", "key.pem")},
		}},
	}
}

func TestDNSConfigRules(t *testing.T) {
	t.Parallel()
	cloudflare := func(c *Config) {
		p := c.DNSProviders["homelab-dns"]
		p.Type, p.Nameserver = DNSTypeCloudflare, ""
		c.DNSProviders["homelab-dns"] = p
	}
	provider := func(change func(*DNSProvider)) func(*Config) {
		return func(c *Config) {
			p := c.DNSProviders["homelab-dns"]
			change(&p)
			c.DNSProviders["homelab-dns"] = p
		}
	}
	deployment := func(change func(*Deployment)) func(*Config) {
		return func(c *Config) { change(&c.Deployments[0]) }
	}
	tests := []struct {
		name   string
		change func(*Config)
		want   string // "" = valid; otherwise a substring of the error
	}{
		{name: "rfc2136 wildcard and apex"},
		{name: "cloudflare", change: cloudflare},
		{name: "cloudflare with the minimum ttl", change: func(c *Config) { cloudflare(c); provider(func(p *DNSProvider) { p.TTL = 120 })(c) }},
		{name: "wildcard needs dns-01", change: deployment(func(d *Deployment) { d.Challenge, d.DNSProvider = ChallengeStandalone, "" }), want: "a wildcard needs challenge: dns-01"},
		{name: "wildcard without a domain", change: deployment(func(d *Deployment) { d.Names = []string{"*.lan"} }), want: "not fully qualified"},
		{name: "double wildcard", change: deployment(func(d *Deployment) { d.Names = []string{"*.*.homelab.lan"} }), want: "after \"*.\""},
		{name: "star inside a label", change: deployment(func(d *Deployment) { d.Names = []string{"w*.homelab.lan"} }), want: "label"},
		{name: "bare wildcard", change: deployment(func(d *Deployment) { d.Names = []string{"*"} }), want: "not fully qualified"},
		{name: "dns-01 without provider", change: deployment(func(d *Deployment) { d.DNSProvider = "" }), want: "dns_provider: challenge: dns-01 needs"},
		{name: "unknown provider", change: deployment(func(d *Deployment) { d.DNSProvider = "other" }), want: `"other" is not under dns_providers`},
		{name: "provider with http-01", change: deployment(func(d *Deployment) { d.Names, d.Challenge = []string{"proxy1.homelab.lan"}, ChallengeStandalone }), want: "only with challenge: dns-01"},
		{name: "webroot with dns-01", change: deployment(func(d *Deployment) { d.Webroot = "/var/www/html" }), want: "webroot: not with challenge: dns-01"},
		{name: "unknown challenge", change: deployment(func(d *Deployment) { d.Challenge = "tls-alpn-01" }), want: "standalone, webroot or dns-01"},
		{name: "enrollment stays http-01", change: func(c *Config) { c.Enrollment.Challenge = ChallengeDNS01 }, want: "enrollment.challenge: standalone or webroot"},

		{name: "no type", change: provider(func(p *DNSProvider) { p.Type = "" }), want: "type: rfc2136 or cloudflare"},
		{name: "unknown type", change: provider(func(p *DNSProvider) { p.Type = "route53" }), want: "type: rfc2136 or cloudflare"},
		{name: "bad provider name", change: func(c *Config) { c.DNSProviders["Bad_Name"] = c.DNSProviders["homelab-dns"] }, want: `"Bad_Name": a name of lower case`},

		{name: "credentials missing", change: provider(func(p *DNSProvider) { p.CredentialsFile = "" }), want: "credentials_file: required"},
		{name: "credentials relative", change: provider(func(p *DNSProvider) { p.CredentialsFile = "dns/homelab.yaml" }), want: "an absolute path"},
		{name: "credentials dotdot", change: func(c *Config) {
			p := c.DNSProviders["homelab-dns"]
			p.CredentialsFile = filepath.Dir(p.CredentialsFile) + string(filepath.Separator) + ".." + string(filepath.Separator) + "dns.yaml"
			c.DNSProviders["homelab-dns"] = p
		}, want: "no .. path segments"},
		{name: "credentials in /home", change: provider(func(p *DNSProvider) { p.CredentialsFile = "/home/felix/dns.yaml" }), want: "under /home"},
		{name: "credentials in /root", change: provider(func(p *DNSProvider) { p.CredentialsFile = "/root/dns.yaml" }), want: "under /root"},
		{name: "credentials in /run/user", change: provider(func(p *DNSProvider) { p.CredentialsFile = "/run/user/1000/dns.yaml" }), want: "under /run/user"},
		{name: "credentials in state_dir", change: func(c *Config) {
			p := c.DNSProviders["homelab-dns"]
			p.CredentialsFile = filepath.Join(c.StateDir, "dns.yaml")
			c.DNSProviders["homelab-dns"] = p
		}, want: "under state_dir"},
		{name: "credentials in paths", change: func(c *Config) {
			p := c.DNSProviders["homelab-dns"]
			p.CredentialsFile = filepath.Join(c.Paths[0], "dns.yaml")
			c.DNSProviders["homelab-dns"] = p
		}, want: "under one of paths"},
		{name: "credentials are a deployment key", change: func(c *Config) {
			p := c.DNSProviders["homelab-dns"]
			p.CredentialsFile = c.Deployments[0].Files.Key
			c.DNSProviders["homelab-dns"] = p
		}, want: "the agent writes there"},
		{name: "credentials in an nginx directory", change: func(c *Config) {
			dir := filepath.Join(filepath.Dir(c.StateDir), "nginx-certs")
			c.Paths = append(c.Paths, dir)
			c.Deployments[0].Profile, c.Deployments[0].Dir, c.Deployments[0].Files = ProfileNginx, dir, Files{}
			p := c.DNSProviders["homelab-dns"]
			p.CredentialsFile = filepath.Join(dir, "dns.yaml")
			c.DNSProviders["homelab-dns"] = p
		}, want: "under one of paths"},

		{name: "rfc2136 without nameserver", change: provider(func(p *DNSProvider) { p.Nameserver = "" }), want: "nameserver: required for rfc2136"},
		{name: "nameserver with port", change: provider(func(p *DNSProvider) { p.Nameserver = "192.0.2.53:5353" })},
		{name: "nameserver as name", change: provider(func(p *DNSProvider) { p.Nameserver = "ns1.homelab.lan" })},
		{name: "nameserver name and port", change: provider(func(p *DNSProvider) { p.Nameserver = "ns1.homelab.lan:53" })},
		{name: "nameserver single label", change: provider(func(p *DNSProvider) { p.Nameserver = "ns1" })},
		{name: "nameserver IPv6", change: provider(func(p *DNSProvider) { p.Nameserver = "2001:db8::53" })},
		{name: "nameserver IPv6 with port", change: provider(func(p *DNSProvider) { p.Nameserver = "[2001:db8::53]:53" })},
		{name: "nameserver port zero", change: provider(func(p *DNSProvider) { p.Nameserver = "ns1:0" }), want: "port: 1 to 65535"},
		{name: "nameserver port text", change: provider(func(p *DNSProvider) { p.Nameserver = "ns1:dns" }), want: "port: 1 to 65535"},
		{name: "nameserver port too large", change: provider(func(p *DNSProvider) { p.Nameserver = "ns1:65536" }), want: "port: 1 to 65535"},
		{name: "nameserver broken bracket", change: provider(func(p *DNSProvider) { p.Nameserver = "[::1" }), want: "want host or host:port"},
		{name: "nameserver upper case", change: provider(func(p *DNSProvider) { p.Nameserver = "NS1.homelab.lan" }), want: "lower case"},
		{name: "nameserver URL", change: provider(func(p *DNSProvider) { p.Nameserver = "tcp://ns1.homelab.lan" }), want: "port: 1 to 65535"},
		{name: "cloudflare with nameserver", change: func(c *Config) { cloudflare(c); provider(func(p *DNSProvider) { p.Nameserver = "192.0.2.53" })(c) }, want: "nameserver: only for rfc2136"},
		{name: "cloudflare with zone", change: func(c *Config) { cloudflare(c); provider(func(p *DNSProvider) { p.Zone = "homelab.lan" })(c) }, want: "zone: only for rfc2136"},
		{name: "zone", change: provider(func(p *DNSProvider) { p.Zone = "Homelab.Lan." })},
		{name: "zone single label", change: provider(func(p *DNSProvider) { p.Zone = "lan" })},
		{name: "zone with a space", change: provider(func(p *DNSProvider) { p.Zone = "home lab.lan" }), want: "zone"},

		{name: "ttl 30 for rfc2136", change: provider(func(p *DNSProvider) { p.TTL = 30 })},
		{name: "ttl 29 for rfc2136", change: provider(func(p *DNSProvider) { p.TTL = 29 }), want: "ttl: 30 to 3600 seconds for rfc2136"},
		{name: "ttl 3600", change: provider(func(p *DNSProvider) { p.TTL = 3600 })},
		{name: "ttl 3601", change: provider(func(p *DNSProvider) { p.TTL = 3601 }), want: "ttl: 30 to 3600"},
		{name: "ttl negative", change: provider(func(p *DNSProvider) { p.TTL = -1 }), want: "ttl: 30 to 3600"},
		{name: "ttl 119 for cloudflare", change: func(c *Config) { cloudflare(c); provider(func(p *DNSProvider) { p.TTL = 119 })(c) }, want: "ttl: 120 to 3600 seconds for cloudflare"},

		{name: "resolver IP", change: provider(func(p *DNSProvider) { p.Resolver = "192.0.2.1" })},
		{name: "resolver IP and port", change: provider(func(p *DNSProvider) { p.Resolver = "192.0.2.1:5353" })},
		{name: "resolver IPv6 and port", change: provider(func(p *DNSProvider) { p.Resolver = "[2001:db8::1]:53" })},
		{name: "resolver name", change: provider(func(p *DNSProvider) { p.Resolver = "dns.homelab.lan" }), want: "want an IP address"},
		{name: "resolver port zero", change: provider(func(p *DNSProvider) { p.Resolver = "192.0.2.1:0" }), want: "port: 1 to 65535"},

		{name: "propagation resolver", change: provider(func(p *DNSProvider) { p.Propagation = PropagationResolver })},
		{name: "propagation wait", change: provider(func(p *DNSProvider) { p.Propagation, p.PropagationWait = PropagationWait, 300 })},
		{name: "propagation unknown", change: provider(func(p *DNSProvider) { p.Propagation = "fast" }), want: "propagation: authoritative, resolver or wait"},
		{name: "propagation_wait too long", change: provider(func(p *DNSProvider) { p.PropagationWait = 301 }), want: "propagation_wait: 0 to 300"},
		{name: "propagation_wait negative", change: provider(func(p *DNSProvider) { p.PropagationWait = -1 }), want: "propagation_wait: 0 to 300"},
		{name: "propagation_timeout 600", change: provider(func(p *DNSProvider) { p.PropagationTimeout = 600 })},
		{name: "propagation_timeout too long", change: provider(func(p *DNSProvider) { p.PropagationTimeout = 601 }), want: "propagation_timeout: 1 to 600"},
		{name: "propagation_timeout negative", change: provider(func(p *DNSProvider) { p.PropagationTimeout = -5 }), want: "propagation_timeout: 1 to 600"},

		{name: "twenty one providers", change: func(c *Config) {
			for i := range 20 {
				c.DNSProviders[fmt.Sprintf("p%02d", i)] = c.DNSProviders["homelab-dns"]
			}
		}, want: "dns_providers: at most 20"},

		{name: "check_name", change: deployment(func(d *Deployment) { d.Check, d.CheckName = "127.0.0.1:443", "www.homelab.lan" })},
		{name: "check without check_name uses the apex", change: deployment(func(d *Deployment) { d.Check = "127.0.0.1:443" })},
		{name: "check with wildcards only", change: deployment(func(d *Deployment) { d.Names, d.Check = []string{"*.homelab.lan"}, "127.0.0.1:443" }), want: "every name is a wildcard"},
		{name: "wildcards only with check_name", change: deployment(func(d *Deployment) {
			d.Names, d.Check, d.CheckName = []string{"*.homelab.lan"}, "127.0.0.1:443", "www.homelab.lan"
		})},
		{name: "wildcards only without check", change: deployment(func(d *Deployment) { d.Names = []string{"*.homelab.lan"} })},
		{name: "check_name without check", change: deployment(func(d *Deployment) { d.CheckName = "www.homelab.lan" }), want: "check_name: only together with check"},
		{name: "check_name is a wildcard", change: deployment(func(d *Deployment) { d.Check, d.CheckName = "127.0.0.1:443", "*.homelab.lan" }), want: "check_name"},
		{name: "check_name is an IP", change: deployment(func(d *Deployment) { d.Check, d.CheckName = "127.0.0.1:443", "192.0.2.10" }), want: "IP identifiers"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := dnsTestConfig(t.TempDir())
			if tt.change != nil {
				tt.change(c)
			}
			err := c.Validate()
			switch {
			case tt.want == "" && err != nil:
				t.Fatalf("valid configuration refused: %v", err)
			case tt.want != "" && err == nil:
				t.Fatalf("accepted, want an error with %q", tt.want)
			case tt.want != "" && !errors.Is(err, ErrInvalid):
				t.Fatalf("error does not wrap ErrInvalid: %v", err)
			case tt.want != "" && !strings.Contains(err.Error(), tt.want):
				t.Fatalf("error %q lacks %q", err, tt.want)
			}
		})
	}
}

func TestDNSConfigDefaultsAndNormalization(t *testing.T) {
	t.Parallel()
	c := dnsTestConfig(t.TempDir())
	p := c.DNSProviders["homelab-dns"]
	p.Zone = "Homelab.LAN."
	c.DNSProviders["homelab-dns"] = p
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	got := c.DNSProviders["homelab-dns"]
	if got.TTL != 120 || got.Propagation != PropagationAuthoritative || got.PropagationWait != 0 || got.PropagationTimeout != 120 || got.Zone != "homelab.lan" {
		t.Fatalf("defaults: %+v", got)
	}
}

func TestDNSConfigReportsEveryProblemAtOnce(t *testing.T) {
	t.Parallel()
	c := dnsTestConfig(t.TempDir())
	c.DNSProviders["homelab-dns"] = DNSProvider{Type: "x", CredentialsFile: "/root/a", TTL: 1, Propagation: "y", PropagationWait: 999, PropagationTimeout: 999}
	c.Deployments[0].Webroot = "/w"
	err := c.Validate()
	if err == nil {
		t.Fatal("accepted")
	}
	for _, want := range []string{"type:", "credentials_file:", "ttl:", "propagation:", "propagation_wait:", "propagation_timeout:", "webroot:"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}
}

func TestCredentialsPathProblemOnSlashPaths(t *testing.T) {
	t.Parallel()
	// Independent of the host's path syntax: the forbidden directories are
	// matched on the slash form, so this also holds on Windows.
	c := &Config{StateDir: "/var/lib/myownpki-agent", Paths: []string{"/etc/ssl/homelab"}}
	for p, want := range map[string]string{
		"/home/a/dns.yaml":                 "/home",
		"/home":                            "/home",
		"/root/dns.yaml":                   "/root",
		"/run/user/0/dns.yaml":             "/run/user",
		"/homey/dns.yaml":                  "", // a sibling, not /home
		"/rootless/dns.yaml":               "",
		"/run/users/dns.yaml":              "",
		"/etc/myownpki-agent/dns/a.yaml":   "",
		"/var/lib/myownpki-agent/dns.yaml": "state_dir",
		"/etc/ssl/homelab/dns.yaml":        "paths",
		"/etc/ssl/homelab/../../../home/x": "/home", // Clean first
	} {
		if runtime.GOOS == "windows" && want != "/home" && want != "/root" && want != "/run/user" {
			continue // not absolute on Windows; the generic rules are covered above
		}
		got := c.credentialsPathProblem(p)
		if (want == "") != (got == "") || !strings.Contains(got, want) {
			t.Errorf("%s: %q, want %q", p, got, want)
		}
	}
}

func TestDNSConfigStrictKeys(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	base := fmt.Sprintf(`server: https://pki.homelab.lan:8444
ca_bundle: '%s'
hostname: proxy1.homelab.lan
state_dir: '%s'
acme_directory: https://pki.homelab.lan/acme/directory
paths: ['%s']
dns_providers:
  homelab-dns:
    type: rfc2136
    credentials_file: '%s'
    nameserver: 192.0.2.53
%%s
deployments:
  - name: wild
    profile: file
    names: ['*.homelab.lan', homelab.lan]
    challenge: dns-01
    dns_provider: homelab-dns
%%s
    files: {fullchain: '%s', key: '%s'}
`, filepath.Join(dir, "root.pem"), filepath.Join(dir, "state"), filepath.Join(dir, "ssl"), filepath.Join(dir, "dns", "a.yaml"),
		filepath.Join(dir, "ssl", "fullchain.pem"), filepath.Join(dir, "ssl", "key.pem"))
	parse := func(provider, deployment string) error {
		_, err := ParseConfig("agent.yaml", fmt.Appendf(nil, base, provider, deployment))
		return err
	}
	if err := parse("", ""); err != nil {
		t.Fatalf("valid: %v", err)
	}
	if err := parse("    ttl: 300\n    propagation: resolver\n    resolver: 192.0.2.1\n    propagation_wait: 5\n    propagation_timeout: 60\n    zone: homelab.lan", "    check: 127.0.0.1:443\n    check_name: www.homelab.lan"); err != nil {
		t.Fatalf("every key: %v", err)
	}
	for name, tt := range map[string][2]string{
		"unknown provider key":    {"    base_url: https://evil.example", ""},
		"api_token in agent.yaml": {"    api_token: secret", ""},
		"misspelled key":          {"    credentials: x", ""},
		"unknown deployment key":  {"", "    dns_provider_name: x"},
		"duplicate key":           {"    ttl: 60\n    ttl: 90", ""},
	} {
		err := parse(tt[0], tt[1])
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: accepted or wrong error: %v", name, err)
		}
	}

	out, err := yaml.Marshal(&DNSProvider{})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"api_token", "tsig_secret", "base_url"} {
		if strings.Contains(string(out), key) {
			t.Errorf("DNSProvider has a %q key", key)
		}
	}
}

// An agent.yaml written for 0.3.6 or older must parse to exactly what it
// parsed to before: the new keys are empty, the map is nil.
func TestDNSConfigOldFileUnchanged(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	data := fmt.Appendf(nil, `server: https://pki.homelab.lan:8444
ca_bundle: '%s'
hostname: proxy1.homelab.lan
state_dir: '%s'
acme_directory: https://pki.homelab.lan/acme/directory
paths: ['%s']
deployments:
  - name: proxy
    profile: file
    names: [proxy1.homelab.lan]
    challenge: standalone
    check: 127.0.0.1:443
    files: {fullchain: '%s', key: '%s'}
`, filepath.Join(dir, "root.pem"), filepath.Join(dir, "state"), filepath.Join(dir, "ssl"), filepath.Join(dir, "ssl", "fullchain.pem"), filepath.Join(dir, "ssl", "key.pem"))
	c, err := ParseConfig("agent.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	want := &Config{
		Server: "https://pki.homelab.lan:8444", CABundle: filepath.Join(dir, "root.pem"), Hostname: "proxy1.homelab.lan", StateDir: filepath.Join(dir, "state"),
		ACMEDirectory: "https://pki.homelab.lan/acme/directory", LogLevel: "info", Enrollment: Enrollment{Challenge: ChallengeStandalone},
		Sandbox: Sandbox{Write: []string{}}, Paths: []string{filepath.Join(dir, "ssl")},
		Deployments: []Deployment{{Name: "proxy", Profile: ProfileFile, Names: []string{"proxy1.homelab.lan"}, Challenge: ChallengeStandalone, Check: "127.0.0.1:443",
			Files: Files{Fullchain: filepath.Join(dir, "ssl", "fullchain.pem"), Key: filepath.Join(dir, "ssl", "key.pem")}}},
	}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("parsed\n%+v\nwant\n%+v", c, want)
	}
	if len(c.Warnings()) != 0 {
		t.Fatalf("warnings for an old file: %v", c.Warnings())
	}
}

func TestDNSUnusedProviderWarning(t *testing.T) {
	t.Parallel()
	c := dnsTestConfig(t.TempDir())
	c.DNSProviders["spare"] = c.DNSProviders["homelab-dns"]
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	warnings := c.Warnings()
	if len(warnings) != 1 || !strings.Contains(warnings[0], "dns_providers.spare: no deployment uses it") {
		t.Fatalf("warnings: %q", warnings)
	}
	c.Deployments = nil
	if got := c.Warnings(); len(got) != 2 {
		t.Fatalf("both providers are unused: %q", got)
	}
}

func TestServerName(t *testing.T) {
	t.Parallel()
	for name, tt := range map[string]struct {
		d    Deployment
		want string
	}{
		"first name":            {Deployment{Names: []string{"a.homelab.lan", "b.homelab.lan"}}, "a.homelab.lan"},
		"skips the wildcard":    {Deployment{Names: []string{"*.homelab.lan", "homelab.lan"}}, "homelab.lan"},
		"check_name wins":       {Deployment{Names: []string{"a.homelab.lan"}, CheckName: "www.homelab.lan"}, "www.homelab.lan"},
		"wildcards only":        {Deployment{Names: []string{"*.homelab.lan"}}, ""},
		"wildcards and a check": {Deployment{Names: []string{"*.homelab.lan"}, CheckName: "www.homelab.lan"}, "www.homelab.lan"},
	} {
		if got := serverName(tt.d); got != tt.want {
			t.Errorf("%s: %q, want %q", name, got, tt.want)
		}
	}
}

// The TLS check asks the local service for a concrete name, never "*.x".
func TestCheckServedUsesConcreteServerName(t *testing.T) {
	t.Parallel()
	m := testMaterial(t, "homelab.lan", 7)
	pair, err := tls.X509KeyPair(m.Certificate, m.Key)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var seen []string
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12,
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			mu.Lock()
			seen = append(seen, h.ServerName)
			mu.Unlock()
			return &pair, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.HandshakeContext(t.Context())
				}
			}()
		}
	}()
	a := &Agent{Sleep: sleep}
	want := fingerprint(m.Leaf.Raw)
	check := func(d Deployment) {
		t.Helper()
		d.Name, d.Check = "wild", ln.Addr().String()
		if _, cerr := a.checkServed(t.Context(), d, want); cerr != nil {
			t.Fatalf("check: %v", cerr)
		}
	}
	check(Deployment{Names: []string{"*.homelab.lan", "homelab.lan"}})
	check(Deployment{Names: []string{"*.homelab.lan", "homelab.lan"}, CheckName: "www.homelab.lan"})
	check(Deployment{Names: []string{"proxy1.homelab.lan"}})
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(seen, []string{"homelab.lan", "www.homelab.lan", "proxy1.homelab.lan"}) {
		t.Fatalf("server names sent: %q", seen)
	}
	if _, err := a.checkServed(t.Context(), Deployment{Name: "wild", Names: []string{"*.homelab.lan"}, Check: ln.Addr().String()}, want); err == nil || !strings.Contains(err.Error(), "check_name") {
		t.Fatalf("a wildcard-only deployment without check_name: %v", err)
	}
	if len(seen) != 3 {
		t.Fatalf("the refused check still connected: %q", seen)
	}
}

type fakeDNSProvider struct {
	presented, cleaned []string
}

func (f *fakeDNSProvider) Present(domain, _, _ string) error {
	f.presented = append(f.presented, domain)
	return nil
}

func (f *fakeDNSProvider) CleanUp(domain, _, _ string) error {
	f.cleaned = append(f.cleaned, domain)
	return nil
}

func (*fakeDNSProvider) Timeout() (time.Duration, time.Duration) { return time.Minute, time.Second }

// The default factory reads the credentials file at the start of the
// issuance: a missing file stops it before the account and the network, with
// a message that names the provider and the file.
func TestDNS01DefaultFactoryNeedsTheCredentialsFile(t *testing.T) {
	t.Parallel()
	c := dnsTestConfig(t.TempDir())
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	d := c.Deployments[0]
	// A nil factory and a field set to the default behave the same. The agent
	// has no state or channel: reaching the account would panic.
	for name, a := range map[string]*Agent{
		"nil factory":     {cfg: c},
		"default factory": {cfg: c},
	} {
		a.newDNSProvider = nil
		_, err := a.obtain(t.Context(), d)
		var ce *credentialsError
		if !errors.As(err, &ce) || ce.State != credMissing || !strings.Contains(err.Error(), `deployment "wild"`) || !strings.Contains(err.Error(), `dns provider "homelab-dns"`) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDNS01SeamPassesTheEntryAndRunsTheProviderInTheGuard(t *testing.T) {
	t.Parallel()
	c := dnsTestConfig(t.TempDir())
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	d := c.Deployments[0]
	fake := &fakeDNSProvider{}
	var gotName string
	var gotCfg DNSProvider
	var gotDeployment Deployment
	a := &Agent{cfg: c, newDNSProvider: func(_ context.Context, name string, cfg DNSProvider, d Deployment) (dnsProvider, error) {
		gotName, gotCfg, gotDeployment = name, cfg, d
		return fake, nil
	}}
	g, err := a.dnsProviderFor(t.Context(), d)
	if err != nil || g.inner != dnsProvider(fake) {
		t.Fatalf("provider %v, %v", g, err)
	}
	if gotName != "homelab-dns" || gotCfg != c.DNSProviders["homelab-dns"] || !reflect.DeepEqual(gotDeployment, d) {
		t.Fatalf("factory got %q %+v %+v", gotName, gotCfg, gotDeployment)
	}
	// Nothing is presented by building the provider.
	if len(fake.presented)+len(fake.cleaned) != 0 {
		t.Fatalf("provider used: %+v", fake)
	}
	// lego needs a provider, and a resolver of the agent's own.
	set := func(challenge.Provider, ...dns01.ChallengeOption) error { return nil }
	if err := a.connectDNS01(t.Context(), set, nil, c.DNSProviders["homelab-dns"]); err == nil {
		t.Fatal("dns-01 without a provider connected")
	}
}

func TestDNS01SeamFactoryErrorStopsBeforeTheAccount(t *testing.T) {
	t.Parallel()
	c := dnsTestConfig(t.TempDir())
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("credentials file is missing")
	a := &Agent{cfg: c, newDNSProvider: func(context.Context, string, DNSProvider, Deployment) (dnsProvider, error) { return nil, boom }}
	// a has no state or channel: reaching the account would panic.
	if _, err := a.obtain(t.Context(), c.Deployments[0]); !errors.Is(err, boom) {
		t.Fatalf("obtain: %v", err)
	}
	d := c.Deployments[0]
	d.DNSProvider = "missing"
	if _, err := a.dnsProviderFor(t.Context(), d); err == nil {
		t.Fatal("unknown provider accepted")
	}
}

// dns-01 binds no port, so it asks for no low-ports drop-in.
func TestDNS01NeedsNoLowPorts(t *testing.T) {
	t.Parallel()
	c := dnsTestConfig(t.TempDir())
	c.Enrollment.Challenge = ChallengeWebroot
	c.Enrollment.Webroot = filepath.Join(filepath.Dir(c.StateDir), "ssl", "www")
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := lowPortsWanted(c, false); got != lowPortsDontCare {
		t.Fatalf("low ports wish %v with only webroot and dns-01", got)
	}
}

func TestDNSProviderEntryInYAMLEditorOrder(t *testing.T) {
	t.Parallel()
	e, err := openYAMLEditor([]byte("server: x\nenrollment:\n  challenge: standalone\nhooks: {}\npaths: []\ndeployments: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.ensure(e.root, "dns_providers", yaml.MappingNode); err != nil {
		t.Fatal(err)
	}
	out, err := e.bytes()
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for line := range strings.SplitSeq(string(out), "\n") {
		if m := topLevelLine.FindStringSubmatch(line); m != nil {
			keys = append(keys, m[1])
		}
	}
	if want := []string{"server", "enrollment", "dns_providers", "hooks", "paths", "deployments"}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("order %v, want %v\n%s", keys, want, out)
	}
}

// Deployment targets are already confined to paths by Validate; the rule
// stays as a second line of defense, so it is tested without paths.
func TestCredentialsPathIsNoDeploymentTarget(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	c := &Config{StateDir: filepath.Join(dir, "state"), Deployments: []Deployment{
		{Name: "files", Profile: ProfileFile, Files: Files{Fullchain: filepath.Join(dir, "ssl", "fullchain.pem"), Key: filepath.Join(dir, "ssl", "key.pem")}},
		{Name: "nginx", Profile: ProfileNginx, Dir: filepath.Join(dir, "nginx")},
	}}
	for p, want := range map[string]string{
		filepath.Join(dir, "ssl", "key.pem"):          "deployment target of files",
		filepath.Join(dir, "nginx", "dns.yaml"):       "deployment target of nginx",
		filepath.Join(dir, "nginx", "sub", "dns.yml"): "deployment target of nginx",
		filepath.Join(dir, "ssl", "dns.yaml"):         "", // next to a target file, not a target
		filepath.Join(dir, "etc", "dns.yaml"):         "",
	} {
		got := c.credentialsPathProblem(p)
		if (want == "") != (got == "") || !strings.Contains(got, want) {
			t.Errorf("%s: %q, want %q", p, got, want)
		}
	}
}
