package server

import (
	"crypto/x509"
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agent"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/testutil/dnsserver"
)

// docs/PHASE3.md step 41: the real agent, the real ACME server and an
// in-process DNS server. The server reads _acme-challenge through
// acme.resolver (the dnsserver); the agent writes the record through RFC 2136
// or through the Cloudflare stub, whose handler writes into the same zone
// store. Nothing here runs in parallel: lego keeps its resolver list in
// package variables.

var (
	dns01Secret      = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	dns01WrongSecret = base64.StdEncoding.EncodeToString([]byte("fedcba9876543210fedcba9876543210"))
)

const dns01Token = "cf-sentinel-token-7f3a"

// dns01Names is what a wildcard deployment asks for: two authorizations that
// share one TXT name.
var dns01Names = []string{"*.homelab.lan", "homelab.lan"}

type dns01Opts struct {
	provider  string   // agent.DNSTypeRFC2136 or agent.DNSTypeCloudflare
	wildcards bool     // the domain homelab.lan allows wildcards
	granted   []string // names the admin adds to the agent (beyond its host name)
	secret    string   // the TSIG secret in the agent's credentials file
	timeout   int      // propagation_timeout in seconds
}

type dns01Env struct {
	*agentEnv
	store *dnsserver.Store
	dns   *dnsserver.Server
	cf    *dnsserver.CloudflareStub
	agent *agent.Agent
}

func newDNS01Env(t *testing.T, o dns01Opts) *dns01Env {
	t.Helper()
	ctx := t.Context()
	store := dnsserver.NewStore("homelab.lan")
	srv := dnsserver.Start(t, store, dnsserver.Key{Name: "acme-agent", Secret: dns01Secret})
	cf := dnsserver.StartCloudflare(t, store, dnsserver.CloudflareOptions{Token: dns01Token})
	e := newAgentEnv(t, func(opt *Options) { opt.Config.ACME.Resolver = srv.Addr() })
	if o.wildcards {
		d, err := e.srv.engine.DomainFor(ctx, "dns", "homelab.lan")
		if err != nil || d == nil {
			t.Fatalf("domain: %v", err)
		}
		if _, err = e.srv.engine.UpdateDomain(ctx, d.ID, ca.DomainSettings{Wildcards: ptrTo(true)}, console); err != nil {
			t.Fatal(err)
		}
	}

	// The credentials file lives beside the agent's directories, never below
	// them, in a directory only the test user can write.
	credDir := filepath.Join(t.TempDir(), "dns")
	if err := os.Mkdir(credDir, 0o700); err != nil {
		t.Fatal(err)
	}
	creds := filepath.Join(credDir, "homelab.yaml")
	entry := agent.DNSProvider{
		Type: o.provider, CredentialsFile: creds, Resolver: srv.Addr(),
		Propagation: agent.PropagationResolver, PropagationTimeout: o.timeout,
	}
	content := "api_token: " + dns01Token + "\n"
	if o.provider == agent.DNSTypeRFC2136 {
		entry.Nameserver = srv.Addr()
		content = "tsig_key_name: acme-agent\ntsig_algorithm: hmac-sha256\ntsig_secret: " + o.secret + "\n"
	}
	if err := os.WriteFile(creds, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	a, _ := e.newTestAgent(t, func(cfg *agent.Config) {
		cfg.DNSProviders = map[string]agent.DNSProvider{"homelab-dns": entry}
	})
	a.SetDNSTest(agent.DNSTest{CloudflareURL: cf.URL, CloudflareRoots: cf.Roots, Poll: 50 * time.Millisecond})

	token, _, err := e.srv.Agents().CreateJoinToken(ctx, console, "proxy", []string{"proxy1.homelab.lan"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.Enroll(ctx, token)
	if err != nil || !res.Admitted() {
		t.Fatalf("enroll: %v", err)
	}
	// Enrollment grants the host name only; a wildcard needs the identical
	// pattern in the agent's names (agents.Matches).
	for _, name := range o.granted {
		if err = e.srv.Agents().AddName(ctx, console, res.AgentID, name); err != nil {
			t.Fatal(err)
		}
	}
	return &dns01Env{agentEnv: e, store: store, dns: srv, cf: cf, agent: a}
}

func (e *dns01Env) deployment() agent.Deployment {
	return agent.Deployment{Name: "wild", Names: dns01Names, Challenge: agent.ChallengeDNS01, DNSProvider: "homelab-dns"}
}

// wantNoChallengeRecords is the check after every case: whatever happened,
// the zone holds no _acme-challenge record.
func (e *dns01Env) wantNoChallengeRecords(t *testing.T) {
	t.Helper()
	if recs := e.store.ChallengeRecords(); len(recs) != 0 {
		t.Fatalf("the zone still holds challenge records: %v", recs)
	}
}

// wantNoSecret fails when an error text carries a secret of the test.
func wantNoSecret(t *testing.T, err error) {
	t.Helper()
	for _, s := range []string{dns01Secret, dns01WrongSecret, dns01Token} {
		if strings.Contains(err.Error(), s) {
			t.Fatalf("the error contains a secret: %v", err)
		}
	}
}

func TestAgentDNS01EndToEnd(t *testing.T) {
	for _, provider := range []string{agent.DNSTypeRFC2136, agent.DNSTypeCloudflare} {
		t.Run(provider, func(t *testing.T) {
			e := newDNS01Env(t, dns01Opts{provider: provider, wildcards: true, granted: dns01Names, secret: dns01Secret, timeout: 30})
			mat, err := e.agent.Obtain(t.Context(), e.deployment())
			if err != nil {
				t.Fatal(err)
			}
			wantWildcardMaterial(t, e.agentEnv, mat)
			// The server read the record through acme.resolver.
			if len(e.dns.Queries("_acme-challenge.homelab.lan", "TXT")) == 0 {
				t.Error("the ACME server never asked the resolver for the challenge record")
			}
			switch provider {
			case agent.DNSTypeRFC2136:
				// Two records on one name: two applied UPDATEs to add, two to remove, all signed.
				if n := e.dns.Updates(); n < 4 {
					t.Errorf("applied updates: %d, want at least 4", n)
				}
				for _, m := range e.dns.Messages() {
					if m.Opcode == "UPDATE" && !m.TSIGOK {
						t.Errorf("an update without a valid signature: %+v", m)
					}
				}
			case agent.DNSTypeCloudflare:
				methods := map[string]int{}
				for _, r := range e.cf.Requests() {
					if r.Authorization != "Bearer "+dns01Token {
						t.Errorf("a request without the token: %s %s", r.Method, r.Path)
					}
					if strings.HasSuffix(r.Path, "/dns_records") || strings.Contains(r.Path, "/dns_records/") {
						methods[r.Method]++
					}
				}
				if methods["POST"] != 2 || methods["DELETE"] != 2 {
					t.Errorf("record calls: %v, want 2 creates and 2 deletes", methods)
				}
			}
			e.wantNoChallengeRecords(t)
		})
	}
}

func TestAgentDNS01Refusals(t *testing.T) {
	t.Run("a name missing in the agent's names", func(t *testing.T) {
		// The host name and homelab.lan, but not *.homelab.lan.
		e := newDNS01Env(t, dns01Opts{provider: agent.DNSTypeRFC2136, wildcards: true, granted: []string{"homelab.lan"}, secret: dns01Secret, timeout: 30})
		_, err := e.agent.Obtain(t.Context(), e.deployment())
		if err == nil || !strings.Contains(err.Error(), "allowed names") {
			t.Fatalf("want the server's rejectedIdentifier, got: %v", err)
		}
		t.Logf("error: %v", err)
		if n := e.dns.Updates(); n != 0 {
			t.Errorf("the refused order still reached the DNS server: %d updates", n)
		}
		e.wantNoChallengeRecords(t)
	})

	t.Run("a domain without wildcards", func(t *testing.T) {
		e := newDNS01Env(t, dns01Opts{provider: agent.DNSTypeRFC2136, wildcards: false, granted: dns01Names, secret: dns01Secret, timeout: 30})
		_, err := e.agent.Obtain(t.Context(), e.deployment())
		if err == nil || !strings.Contains(err.Error(), "no domain covers") {
			t.Fatalf("want the server's rejectedIdentifier, got: %v", err)
		}
		t.Logf("error: %v", err)
		if n := e.dns.Updates(); n != 0 {
			t.Errorf("the refused order still reached the DNS server: %d updates", n)
		}
		e.wantNoChallengeRecords(t)
	})

	t.Run("the record never appears", func(t *testing.T) {
		e := newDNS01Env(t, dns01Opts{provider: agent.DNSTypeRFC2136, wildcards: true, granted: dns01Names, secret: dns01Secret, timeout: 1})
		// The UPDATE is applied, but no query ever sees the record.
		e.dns.HideTXT(func(string, string) bool { return true })
		start := time.Now()
		_, err := e.agent.Obtain(t.Context(), e.deployment())
		if err == nil || !strings.Contains(err.Error(), "propagation") {
			t.Fatalf("want a propagation timeout, got: %v", err)
		}
		if time.Since(start) > 30*time.Second {
			t.Errorf("the timeout of 1 s took %s", time.Since(start))
		}
		wantNoSecret(t, err)
		t.Logf("error: %v", err)
		// The record was written, and the agent removed it again.
		if n := e.dns.Updates(); n < 2 {
			t.Errorf("applied updates: %d: the record was never written, so the case proves nothing", n)
		}
		e.wantNoChallengeRecords(t)
	})

	t.Run("a wrong TSIG key", func(t *testing.T) {
		e := newDNS01Env(t, dns01Opts{provider: agent.DNSTypeRFC2136, wildcards: true, granted: dns01Names, secret: dns01WrongSecret, timeout: 30})
		_, err := e.agent.Obtain(t.Context(), e.deployment())
		if err == nil || !strings.Contains(err.Error(), "homelab-dns") || !strings.Contains(err.Error(), "NOTAUTH") {
			t.Fatalf("want a failure that names the provider and the refusal, got: %v", err)
		}
		wantNoSecret(t, err)
		t.Logf("error: %v", err)
		if n := e.dns.Updates(); n != 0 {
			t.Errorf("the DNS server applied %d updates signed with a wrong key", n)
		}
		e.wantNoChallengeRecords(t)
	})
}

// A zone that delegates _acme-challenge by CNAME (the usual split-DNS setup):
// the agent writes at the target, the ACME server reads through the alias.
func TestAgentDNS01DelegatedByCNAME(t *testing.T) {
	e := newDNS01Env(t, dns01Opts{provider: agent.DNSTypeRFC2136, wildcards: true, granted: dns01Names, secret: dns01Secret, timeout: 30})
	e.store.SetCNAME("_acme-challenge.homelab.lan", "_acme-challenge.acme.homelab.lan")
	mat, err := e.agent.Obtain(t.Context(), e.deployment())
	if err != nil {
		t.Fatal(err)
	}
	if len(mat.Leaf.DNSNames) != 2 {
		t.Fatalf("SANs of the certificate: %v", mat.Leaf.DNSNames)
	}
	if n := e.dns.Updates(); n < 4 {
		t.Errorf("applied updates: %d, want at least 4", n)
	}
	if len(e.dns.Queries("_acme-challenge.homelab.lan", "CNAME")) == 0 {
		t.Error("the agent never looked for the alias, so it did not write at the target")
	}
	e.wantNoChallengeRecords(t)
	if target, ok := e.store.CNAME("_acme-challenge.homelab.lan"); !ok || target == "" {
		t.Error("the alias was removed")
	}
}

// wantWildcardMaterial checks what a wildcard deployment gets: exactly the
// two names, a chain that verifies against the root, for a name below the
// wildcard and for the bare name.
func wantWildcardMaterial(t *testing.T, e *agentEnv, mat *agent.Material) {
	t.Helper()
	if got, want := slices.Sorted(slices.Values(mat.Leaf.DNSNames)), slices.Sorted(slices.Values(dns01Names)); !slices.Equal(got, want) {
		t.Fatalf("SANs of the certificate: %v, want %v", got, want)
	}
	inter := x509.NewCertPool()
	inter.AppendCertsFromPEM(mat.Chain)
	for _, host := range []string{"x.homelab.lan", "homelab.lan"} {
		if _, err := mat.Leaf.Verify(x509.VerifyOptions{Roots: e.root, Intermediates: inter, DNSName: host}); err != nil {
			t.Errorf("verify for %s: %v", host, err)
		}
	}
}
