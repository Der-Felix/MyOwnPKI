//go:build conformance

package server

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agent"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
)

// TestConformanceAgentDNS01 (v0.3.7, docs/PHASE3.md step 41): the agent's own
// RFC 2136 provider against the BIND of test/conformance, which the ACME
// server reads as its resolver. The agent's names are *.homelab.lan and
// homelab.lan, so one issuance writes two TXT values at one name and removes
// them again. The TSIG key comes from run.sh (CONF_TSIG_NAME and
// CONF_TSIG_SECRET) and reaches the agent only through a 0600 credentials
// file, as in production; the secret is in no log line and no failure text.
// It runs in the conformance CI job after the tests of internal/acme, which
// start BIND. The checks are those of the in-process tests of
// agent_dns01_test.go; the point is the real name server.
func TestConformanceAgentDNS01(t *testing.T) {
	env := map[string]string{}
	for _, name := range []string{"CONF_DNS", "CONF_TSIG_NAME", "CONF_TSIG_SECRET"} {
		if env[name] = os.Getenv(name); env[name] == "" {
			t.Fatalf("%s is not set – run test/conformance/run.sh", name)
		}
	}
	bind := env["CONF_DNS"]
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, bind)
	}}
	// txt reads the challenge name from BIND itself, never from a cache.
	txt := func(t *testing.T) []string {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		values, err := resolver.LookupTXT(ctx, "_acme-challenge.homelab.lan")
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil
		}
		if err != nil {
			t.Fatalf("BIND at %s: %v", bind, err)
		}
		return values
	}

	e := newAgentEnv(t, func(opt *Options) { opt.Config.ACME.Resolver = bind })
	ctx := t.Context()
	d, err := e.srv.engine.DomainFor(ctx, "dns", "homelab.lan")
	if err != nil || d == nil {
		t.Fatalf("domain: %v", err)
	}
	if _, err = e.srv.engine.UpdateDomain(ctx, d.ID, ca.DomainSettings{Wildcards: ptrTo(true)}, console); err != nil {
		t.Fatal(err)
	}

	credDir := filepath.Join(t.TempDir(), "dns")
	if err = os.Mkdir(credDir, 0o700); err != nil {
		t.Fatal(err)
	}
	creds := filepath.Join(credDir, "homelab.yaml")
	writeCreds := func(secret string) {
		t.Helper()
		content := "tsig_key_name: " + env["CONF_TSIG_NAME"] + "\ntsig_algorithm: hmac-sha256\ntsig_secret: " + secret + "\n"
		if werr := os.WriteFile(creds, []byte(content), 0o600); werr != nil {
			t.Fatal(werr)
		}
	}
	writeCreds(dns01WrongSecret)
	a, _ := e.newTestAgent(t, func(cfg *agent.Config) {
		cfg.DNSProviders = map[string]agent.DNSProvider{"homelab-dns": {
			Type: agent.DNSTypeRFC2136, CredentialsFile: creds, Nameserver: bind, Resolver: bind,
			Propagation: agent.PropagationResolver, PropagationTimeout: 60,
		}}
	})
	token, _, err := e.srv.Agents().CreateJoinToken(ctx, console, "proxy", []string{"proxy1.homelab.lan"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.Enroll(ctx, token)
	if err != nil || !res.Admitted() {
		t.Fatalf("enroll: %v", err)
	}
	for _, name := range dns01Names {
		if err = e.srv.Agents().AddName(ctx, console, res.AgentID, name); err != nil {
			t.Fatal(err)
		}
	}
	dep := agent.Deployment{Name: "wild", Names: dns01Names, Challenge: agent.ChallengeDNS01, DNSProvider: "homelab-dns"}

	// A wrong secret must fail without a secret in the text and without a
	// record left in the zone. It runs first: a valid authorization of this
	// account would let the second issuance skip DNS altogether.
	t.Run("a wrong TSIG secret", func(t *testing.T) {
		_, oerr := a.Obtain(ctx, dep)
		if oerr == nil {
			t.Fatal("BIND accepted an update signed with a wrong secret")
		}
		for _, secret := range []string{dns01WrongSecret, env["CONF_TSIG_SECRET"]} {
			if strings.Contains(oerr.Error(), secret) {
				t.Fatalf("the error contains a secret: %v", oerr)
			}
		}
		if left := txt(t); len(left) != 0 {
			t.Fatalf("BIND holds %d challenge record(s) after a failed update", len(left))
		}
	})

	// The same agent after the file was corrected, without a restart: both
	// names through the real name server, then no record left.
	t.Run("both names through RFC 2136", func(t *testing.T) {
		writeCreds(env["CONF_TSIG_SECRET"])
		mat, oerr := a.Obtain(ctx, dep)
		if oerr != nil {
			t.Fatal(oerr)
		}
		wantWildcardMaterial(t, e, mat)
		if left := txt(t); len(left) != 0 {
			t.Fatalf("BIND holds %d challenge record(s) after the issuance", len(left))
		}
	})
}
