package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"

	"github.com/Der-Felix/MyOwnPKI/internal/testutil/dnsserver"
)

// These tests drive lego's dns-01 solver the way the agent does
// (dns01.NewChallenge is what ac.Challenge.SetDNS01Provider calls), against
// the in-process DNS server. lego keeps its resolver list in package
// variables, so none of them runs in parallel.

const (
	testZone      = "homelab.lan."
	testChallenge = "_acme-challenge.homelab.lan."
	// base64 of "SENTINEL-TSIG-SECRET-4f9a"
	testTSIGSecret = "U0VOVElORUwtVFNJRy1TRUNSRVQtNGY5YQ==" //nolint:gosec // a test sentinel
)

func tsigCreds(secret string) *dnsCredentials {
	return &dnsCredentials{Type: DNSTypeRFC2136, TSIGKeyName: "acme-agent", TSIGAlgorithm: "hmac-sha256", TSIGSecret: newSecret([]byte(secret))}
}

// dnsHarness is a DNS server with a zone store, and what a test needs to run
// issuance rounds against it.
type dnsHarness struct {
	t     *testing.T
	store *dnsserver.Store
	srv   *dnsserver.Server
	cfg   DNSProvider
	core  *api.Core
}

func newDNSHarness(t *testing.T, keys ...dnsserver.Key) *dnsHarness {
	t.Helper()
	store := dnsserver.NewStore(testZone)
	if keys == nil {
		keys = []dnsserver.Key{{Name: "acme-agent", Secret: testTSIGSecret}}
	}
	srv := dnsserver.Start(t, store, keys...)
	// A directory is all api.New needs; the key authorization is local.
	dir := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "https://" + r.Host
		_ = json.NewEncoder(w).Encode(map[string]string{"newNonce": base + "/nonce", "newAccount": base + "/acct", "newOrder": base + "/order"})
	}))
	t.Cleanup(dir.Close)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	core, err := api.New(dir.Client(), "test", dir.URL, "", key)
	if err != nil {
		t.Fatal(err)
	}
	h := &dnsHarness{t: t, store: store, srv: srv, core: core, cfg: DNSProvider{
		Type: DNSTypeRFC2136, Nameserver: srv.Addr(), TTL: 120, Resolver: srv.Addr(),
		Propagation: PropagationResolver, PropagationTimeout: 120,
	}}
	setLegoDNS([]string{srv.Addr()})
	dns01.ClearFqdnCache()
	return h
}

func (h *dnsHarness) provider(creds *dnsCredentials) *rfc2136Provider {
	h.t.Helper()
	p, err := newRFC2136Provider(h.cfg, creds, time.Now)
	if err != nil {
		h.t.Fatal(err)
	}
	p.timeout = 5 * time.Second
	return p
}

// guard wraps a provider for the deployment *.homelab.lan + homelab.lan with
// short waits.
func (h *dnsHarness) guard(ctx context.Context, p dnsProvider, d Deployment) *dnsGuard {
	g := newDNSGuard(ctx, p, "homelab-dns", h.cfg, d, 20*time.Millisecond, nil)
	g.timeout = 2 * time.Second
	return g
}

func (h *dnsHarness) authz(domain string, wildcard bool) acme.Authorization {
	token := "token-" + strings.TrimPrefix(domain, "*.")
	if wildcard {
		token += "-wild"
	}
	return acme.Authorization{
		Status: "pending", Identifier: acme.Identifier{Type: "dns", Value: domain}, Wildcard: wildcard,
		Challenges: []acme.Challenge{{Type: "dns-01", Token: token, URL: "http://acme.invalid/chall/" + token}},
	}
}

// value is the TXT value the ACME server expects for an authorization.
func (h *dnsHarness) value(a acme.Authorization) string {
	h.t.Helper()
	keyAuth, err := h.core.GetKeyAuthorization(a.Challenges[0].Token)
	if err != nil {
		h.t.Fatal(err)
	}
	return dns01.GetChallengeInfo(a.Identifier.Value, keyAuth).Value
}

// round is one issuance as lego's prober runs it: Present every
// authorization, solve every one (the propagation check, then the ACME
// server's own look at the record, which validate stands for), and clean up
// whatever the outcome.
func (h *dnsHarness) round(ctx context.Context, g *dnsGuard, authzs []acme.Authorization, validate func(a acme.Authorization) error) error {
	h.t.Helper()
	defer routeLegoLog(nil, g)() // lego logs to stderr otherwise
	ch := dns01.NewChallenge(h.core, func(_ *api.Core, domain string, chlng acme.Challenge) error {
		for _, a := range authzs {
			if challenge.GetTargetedDomain(a) == domain && a.Challenges[0].Token == chlng.Token {
				return validate(a)
			}
		}
		return errors.New("validate: unknown authorization")
	}, g, dnsChallengeOptions(ctx, h.cfg, []string{h.srv.Addr()})...)
	var errs []error
	failed := map[int]bool{}
	for i, a := range authzs {
		if err := ch.PreSolve(a); err != nil {
			errs = append(errs, err)
			failed[i] = true
		}
	}
	defer func() {
		for _, a := range authzs {
			_ = ch.CleanUp(a) // lego only logs this error; the guard records it
		}
		g.finish()
	}()
	for i, a := range authzs {
		if failed[i] {
			continue // lego does not solve what it could not present
		}
		if err := ch.Solve(a); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// visible reports whether the value is in the zone right now.
func (h *dnsHarness) visible(name, value string) bool {
	for _, v := range h.store.TXT(name) {
		if v == value {
			return true
		}
	}
	return false
}

func (h *dnsHarness) wantNoChallengeRecords() {
	h.t.Helper()
	if left := h.store.ChallengeRecords(); len(left) != 0 {
		h.t.Fatalf("records left in the zone: %+v", left)
	}
}

func wildcardPair(h *dnsHarness) []acme.Authorization {
	return []acme.Authorization{h.authz("homelab.lan", true), h.authz("homelab.lan", false)}
}

func TestDNS01WildcardAndBaseNameGiveTwoRecordsAndTwoRemovals(t *testing.T) {
	h := newDNSHarness(t)
	log, logs := captureLog()
	g := h.guard(t.Context(), h.provider(tsigCreds(testTSIGSecret)), wildcardDeployment())
	g.log = log
	authzs := wildcardPair(h)
	err := h.round(t.Context(), g, authzs, func(a acme.Authorization) error {
		// What the ACME server sees when it validates: this run's value.
		if !h.visible(testChallenge, h.value(a)) {
			t.Errorf("value of %v is not in the zone: %v", a.Wildcard, h.store.TXT(testChallenge))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(authzs) != 2 || h.value(authzs[0]) == h.value(authzs[1]) {
		t.Fatal("the two authorizations share a value")
	}
	h.wantNoChallengeRecords()
	if n := h.srv.Updates(); n != 4 {
		t.Fatalf("%d updates, want 2 adds and 2 removals", n)
	}
	for _, m := range h.srv.Messages() {
		if m.Opcode == "UPDATE" && (m.Network != "tcp" || !m.Signed || !m.TSIGOK) {
			t.Fatalf("an update that is not signed TCP: %+v", m)
		}
	}
	if w := g.Warnings(); len(w) != 0 {
		t.Fatalf("warnings %q", w)
	}
	if strings.Contains(logs.String(), testTSIGSecret) || strings.Contains(logs.String(), sentinelSecret) {
		t.Fatalf("log: %s", logs)
	}
}

func TestDNS01QueriesGoToTheAgentsResolverOnly(t *testing.T) {
	h := newDNSHarness(t)
	g := h.guard(t.Context(), h.provider(tsigCreds(testTSIGSecret)), Deployment{Name: "web", Names: []string{"homelab.lan"}})
	a := h.authz("homelab.lan", false)
	if err := h.round(t.Context(), g, []acme.Authorization{a}, func(acme.Authorization) error { return nil }); err != nil {
		t.Fatal(err)
	}
	// lego looked for the CNAME and polled the TXT record at the test server;
	// the names exist nowhere else, so a query to a public resolver (lego's
	// fallback) would have failed the round instead.
	if len(h.srv.Queries(testChallenge, "CNAME")) == 0 || len(h.srv.Queries(testChallenge, "TXT")) == 0 {
		t.Fatalf("no query reached the configured resolver: %+v", h.srv.Messages())
	}
	// The mode "resolver" asks only the resolver: no query for authoritative
	// name servers (NS) and no UDP to anything but the test server.
	if len(h.srv.Queries("", "NS")) != 0 {
		t.Fatalf("NS queries in resolver mode: %+v", h.srv.Queries("", "NS"))
	}
}

func TestDNS01CleansUpAfterAFailedValidation(t *testing.T) {
	h := newDNSHarness(t)
	g := h.guard(t.Context(), h.provider(tsigCreds(testTSIGSecret)), wildcardDeployment())
	err := h.round(t.Context(), g, wildcardPair(h), func(acme.Authorization) error { return errors.New("the ACME server did not find the record") })
	if err == nil || !strings.Contains(err.Error(), "did not find") {
		t.Fatalf("round: %v", err)
	}
	h.wantNoChallengeRecords()
}

func TestDNS01CleansUpAfterACancellationWhileWaiting(t *testing.T) {
	h := newDNSHarness(t)
	// The record exists but nobody can see it, so the check keeps polling.
	h.srv.HideTXT(func(string, string) bool { return true })
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	g := h.guard(ctx, h.provider(tsigCreds(testTSIGSecret)), wildcardDeployment())
	g.timeout = time.Minute
	go func() {
		for len(h.store.ChallengeRecords()) < 2 { // both records are written, the wait has begun
			time.Sleep(5 * time.Millisecond)
		}
		cancel()
	}()
	start := time.Now()
	err := h.round(ctx, g, wildcardPair(h), func(acme.Authorization) error { return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("round: %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("the wait did not stop at the cancellation: %v", time.Since(start))
	}
	h.wantNoChallengeRecords()
	if w := g.Warnings(); len(w) != 0 {
		t.Fatalf("warnings %q", w)
	}
}

func TestDNS01CleansUpAfterAPropagationTimeout(t *testing.T) {
	h := newDNSHarness(t)
	h.srv.HideTXT(func(string, string) bool { return true }) // the record never appears
	g := h.guard(t.Context(), h.provider(tsigCreds(testTSIGSecret)), Deployment{Name: "web", Names: []string{"homelab.lan"}})
	g.timeout = 300 * time.Millisecond
	err := h.round(t.Context(), g, []acme.Authorization{h.authz("homelab.lan", false)}, func(acme.Authorization) error {
		t.Error("the ACME server was asked although the record never appeared")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "time limit exceeded") {
		t.Fatalf("round: %v", err)
	}
	h.wantNoChallengeRecords()
}

func TestDNS01RefusesAForeignDomainFromTheACMEServer(t *testing.T) {
	h := newDNSHarness(t)
	h.store.AddZone("evil.example.")
	g := h.guard(t.Context(), h.provider(tsigCreds(testTSIGSecret)), Deployment{Name: "web", Names: []string{"homelab.lan"}})
	err := h.round(t.Context(), g, []acme.Authorization{h.authz("evil.example", false)}, func(acme.Authorization) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "not one of this deployment's names") {
		t.Fatalf("round: %v", err)
	}
	if n := h.srv.Updates(); n != 0 {
		t.Fatalf("%d updates for a refused name", n)
	}
	h.wantNoChallengeRecords()
	if len(g.Warnings()) != 0 {
		t.Fatalf("warnings %q", g.Warnings())
	}
}

func TestDNS01WrongTSIGKeyFailsWithoutLeakingTheSecret(t *testing.T) {
	h := newDNSHarness(t) // the server's key differs from the agent's
	wrong := base64.StdEncoding.EncodeToString([]byte("another-secret-entirely-0123456"))
	log, logs := captureLog()
	g := h.guard(t.Context(), h.provider(tsigCreds(wrong)), Deployment{Name: "web", Names: []string{"homelab.lan"}})
	g.log = log
	err := h.round(t.Context(), g, []acme.Authorization{h.authz("homelab.lan", false)}, func(acme.Authorization) error { return nil })
	if err == nil || !strings.Contains(err.Error(), `dns provider "homelab-dns"`) || !strings.Contains(err.Error(), "NOTAUTH") {
		t.Fatalf("round: %v", err)
	}
	h.wantNoChallengeRecords()
	for _, text := range []string{err.Error(), logs.String(), strings.Join(g.Warnings(), "\n")} {
		if strings.Contains(text, wrong) || strings.Contains(text, "another-secret") || strings.Contains(text, testTSIGSecret) {
			t.Fatalf("a secret in %q", text)
		}
	}
	for _, m := range h.srv.Messages() {
		if m.Opcode == "UPDATE" && m.Rcode == "NOERROR" {
			t.Fatalf("an update was applied with the wrong key: %+v", m)
		}
	}
}

func TestDNS01ForgedResponseMACIsNotAccepted(t *testing.T) {
	h := newDNSHarness(t)
	h.srv.ForgeResponseMAC(true)
	g := h.guard(t.Context(), h.provider(tsigCreds(testTSIGSecret)), Deployment{Name: "web", Names: []string{"homelab.lan"}})
	err := h.round(t.Context(), g, []acme.Authorization{h.authz("homelab.lan", false)}, func(acme.Authorization) error {
		t.Error("validated although the answer was forged")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "TSIG signature is wrong") {
		t.Fatalf("round: %v", err)
	}
	// The forged answer hid a success from the agent; the cleanup still
	// removes the record the server applied.
	h.wantNoChallengeRecords()
}

func TestDNS01StaleRecordsStayAndTheRunsOwnValueGoes(t *testing.T) {
	h := newDNSHarness(t)
	h.store.AddTXT(testChallenge, "stale-value-of-an-earlier-run")
	h.store.AddTXT("_acme-challenge.other.homelab.lan.", "unrelated")
	g := h.guard(t.Context(), h.provider(tsigCreds(testTSIGSecret)), Deployment{Name: "web", Names: []string{"homelab.lan"}})
	a := h.authz("homelab.lan", false)
	err := h.round(t.Context(), g, []acme.Authorization{a}, func(acme.Authorization) error {
		if got := h.store.TXT(testChallenge); len(got) != 2 {
			t.Errorf("values during validation: %v", got)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := h.store.TXT(testChallenge); len(got) != 1 || got[0] != "stale-value-of-an-earlier-run" {
		t.Fatalf("after the run: %v (only this run's value may go)", got)
	}
	if h.visible(testChallenge, h.value(a)) {
		t.Fatal("this run's value is still there")
	}
	if got := h.store.TXT("_acme-challenge.other.homelab.lan."); len(got) != 1 {
		t.Fatalf("an unrelated record changed: %v", got)
	}
}

func TestDNS01PresentIsIdempotent(t *testing.T) {
	h := newDNSHarness(t)
	p := h.provider(tsigCreds(testTSIGSecret))
	a := h.authz("homelab.lan", false)
	keyAuth, _ := h.core.GetKeyAuthorization(a.Challenges[0].Token)
	for range 2 {
		if err := p.Present("homelab.lan", "t", keyAuth); err != nil {
			t.Fatal(err)
		}
	}
	if got := h.store.TXT(testChallenge); len(got) != 1 {
		t.Fatalf("values after two Presents: %v", got)
	}
	for range 2 { // removing a value that is gone is fine
		if err := p.CleanUp("homelab.lan", "t", keyAuth); err != nil {
			t.Fatal(err)
		}
	}
	h.wantNoChallengeRecords()
}

func TestDNS01ProviderRefusedByThePolicyOfTheServer(t *testing.T) {
	h := newDNSHarness(t, dnsserver.Key{Name: "acme-agent", Secret: testTSIGSecret, Allow: func(name string) bool {
		return name == "_acme-challenge.elsewhere.lan."
	}})
	g := h.guard(t.Context(), h.provider(tsigCreds(testTSIGSecret)), Deployment{Name: "web", Names: []string{"homelab.lan"}})
	err := h.round(t.Context(), g, []acme.Authorization{h.authz("homelab.lan", false)}, func(acme.Authorization) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "REFUSED") || !strings.Contains(err.Error(), "update policy") {
		t.Fatalf("round: %v", err)
	}
	h.wantNoChallengeRecords()
}

func TestDNS01ConfiguredZoneMustContainTheName(t *testing.T) {
	h := newDNSHarness(t)
	h.cfg.Zone = "other.lan"
	g := h.guard(t.Context(), h.provider(tsigCreds(testTSIGSecret)), Deployment{Name: "web", Names: []string{"homelab.lan"}})
	err := h.round(t.Context(), g, []acme.Authorization{h.authz("homelab.lan", false)}, func(acme.Authorization) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "zone mismatch") {
		t.Fatalf("round: %v", err)
	}
	if n := h.srv.Updates(); n != 0 {
		t.Fatalf("%d updates outside the zone", n)
	}
	// A zone that is right needs no SOA lookup.
	h.cfg.Zone = "homelab.lan"
	g = h.guard(t.Context(), h.provider(tsigCreds(testTSIGSecret)), Deployment{Name: "web", Names: []string{"homelab.lan"}})
	if err := h.round(t.Context(), g, []acme.Authorization{h.authz("homelab.lan", false)}, func(acme.Authorization) error { return nil }); err != nil {
		t.Fatal(err)
	}
	h.wantNoChallengeRecords()
}

func TestDNS01NameserverThatIsNotAuthoritativeSaysSo(t *testing.T) {
	h := newDNSHarness(t)
	// The agent's resolver serves the zone, but the nameserver it updates does
	// not: its SOA lookups fail.
	other := dnsserver.Start(t, dnsserver.NewStore("elsewhere.lan."))
	h.cfg.Nameserver = other.Addr()
	g := h.guard(t.Context(), h.provider(tsigCreds(testTSIGSecret)), Deployment{Name: "web", Names: []string{"homelab.lan"}})
	err := h.round(t.Context(), g, []acme.Authorization{h.authz("homelab.lan", false)}, func(acme.Authorization) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "no SOA record") {
		t.Fatalf("round: %v", err)
	}
	h.wantNoChallengeRecords()
}

// A CNAME at _acme-challenge delegates the record to another zone: lego
// follows it, so the update goes to the zone of the target.
func TestDNS01CNAMEDelegationWritesTheTargetsZone(t *testing.T) {
	h := newDNSHarness(t)
	h.store.AddZone("acme.example.")
	h.store.SetCNAME(testChallenge, "_acme-challenge.homelab.acme.example.")
	g := h.guard(t.Context(), h.provider(tsigCreds(testTSIGSecret)), Deployment{Name: "web", Names: []string{"homelab.lan"}})
	a := h.authz("homelab.lan", false)
	target := "_acme-challenge.homelab.acme.example."
	err := h.round(t.Context(), g, []acme.Authorization{a}, func(acme.Authorization) error {
		if !h.visible(target, h.value(a)) || len(h.store.TXT(testChallenge)) != 0 {
			t.Errorf("target %v, alias %v", h.store.TXT(target), h.store.TXT(testChallenge))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	h.wantNoChallengeRecords()
	var zones []string
	for _, m := range h.srv.Messages() {
		if m.Opcode == "UPDATE" {
			zones = append(zones, m.Name)
		}
	}
	if len(zones) != 2 || zones[0] != "acme.example." || zones[1] != "acme.example." {
		t.Fatalf("updates went to %v", zones)
	}
}

func TestDNS01PropagationWaitModeNeverQueriesTheRecord(t *testing.T) {
	h := newDNSHarness(t)
	h.cfg.Propagation = PropagationWait
	h.srv.HideTXT(func(string, string) bool { return true }) // a check would never succeed
	g := h.guard(t.Context(), h.provider(tsigCreds(testTSIGSecret)), Deployment{Name: "web", Names: []string{"homelab.lan"}})
	err := h.round(t.Context(), g, []acme.Authorization{h.authz("homelab.lan", false)}, func(acme.Authorization) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	h.wantNoChallengeRecords()
}

func TestDNS01PropagationWaitPausesOnceAndStopsOnCancel(t *testing.T) {
	h := newDNSHarness(t)
	h.cfg.Propagation = PropagationWait
	h.cfg.PropagationWait = 300
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	g := h.guard(ctx, h.provider(tsigCreds(testTSIGSecret)), Deployment{Name: "web", Names: []string{"homelab.lan"}})
	g.timeout = time.Hour
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	err := h.round(ctx, g, []acme.Authorization{h.authz("homelab.lan", false)}, func(acme.Authorization) error { return nil })
	if !errors.Is(err, context.Canceled) || time.Since(start) > 10*time.Second {
		t.Fatalf("after %v: %v", time.Since(start), err)
	}
	h.wantNoChallengeRecords()
}

func TestDNSResolversNeverFallBackToPublicOnes(t *testing.T) {
	// The configured resolver wins; a bare IP gets port 53.
	got, err := dnsResolvers(DNSProvider{Resolver: "192.0.2.53"}, filepath.Join(t.TempDir(), "absent"))
	if err != nil || len(got) != 1 || got[0] != "192.0.2.53:53" {
		t.Fatalf("%v, %v", got, err)
	}
	got, err = dnsResolvers(DNSProvider{Resolver: "[2001:db8::53]:5353"}, "")
	if err != nil || got[0] != "[2001:db8::53]:5353" {
		t.Fatalf("%v, %v", got, err)
	}
	// Without one, resolv.conf is read; without that, the issuance is refused.
	conf := filepath.Join(t.TempDir(), "resolv.conf")
	if werr := os.WriteFile(conf, []byte("search homelab.lan\nnameserver 192.0.2.1\nnameserver 2001:db8::1\n"), 0o600); werr != nil {
		t.Fatal(werr)
	}
	if got, err = dnsResolvers(DNSProvider{}, conf); err != nil || len(got) != 2 || got[0] != "192.0.2.1:53" || got[1] != "[2001:db8::1]:53" {
		t.Fatalf("%v, %v", got, err)
	}
	for name, path := range map[string]string{"missing": filepath.Join(t.TempDir(), "absent"), "empty": func() string {
		p := filepath.Join(t.TempDir(), "empty")
		_ = os.WriteFile(p, []byte("# nothing\n"), 0o600)
		return p
	}()} {
		_, err := dnsResolvers(DNSProvider{}, path)
		if err == nil || !strings.Contains(err.Error(), "never falls back to public resolvers") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// With no resolver, connectDNS01 refuses before it touches lego's variables.
func TestDNS01IssuanceWithoutAResolverStopsBeforeLego(t *testing.T) {
	h := newDNSHarness(t)
	a := &Agent{cfg: &Config{}, dns: dnsTuning{resolvConf: filepath.Join(t.TempDir(), "absent")}}
	cfg := h.cfg
	cfg.Resolver = ""
	called := false
	set := func(challenge.Provider, ...dns01.ChallengeOption) error { called = true; return nil }
	g := h.guard(t.Context(), newRecordingProvider(), wildcardDeployment())
	err := a.connectDNS01(t.Context(), set, g, cfg)
	if err == nil || called {
		t.Fatalf("connected without a resolver: %v, called %v", err, called)
	}
	// The variables are still the harness's server: lego finds the zone there.
	zone, err := dns01.FindZoneByFqdn(testChallenge)
	if err != nil || zone != testZone {
		t.Fatalf("zone %q, %v", zone, err)
	}
	// With the resolver, the options reach lego.
	cfg.Resolver = h.srv.Addr()
	if err := a.connectDNS01(t.Context(), set, g, cfg); err != nil || !called {
		t.Fatalf("connect: %v, called %v", err, called)
	}
}

func TestTwoIssuancesInARowUseTheirOwnResolvers(t *testing.T) {
	first := newDNSHarness(t)
	g := first.guard(t.Context(), first.provider(tsigCreds(testTSIGSecret)), Deployment{Name: "web", Names: []string{"homelab.lan"}})
	if err := first.round(t.Context(), g, []acme.Authorization{first.authz("homelab.lan", false)}, func(acme.Authorization) error { return nil }); err != nil {
		t.Fatal(err)
	}
	second := newDNSHarness(t) // another server, the same zone name
	g = second.guard(t.Context(), second.provider(tsigCreds(testTSIGSecret)), Deployment{Name: "web", Names: []string{"homelab.lan"}})
	before := len(first.srv.Messages())
	if err := second.round(t.Context(), g, []acme.Authorization{second.authz("homelab.lan", false)}, func(acme.Authorization) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(first.srv.Messages()) != before || second.srv.Updates() != 2 {
		t.Fatalf("the second issuance used the first one's server: %d -> %d messages, %d updates at the second", before, len(first.srv.Messages()), second.srv.Updates())
	}
}

func TestLegoLogGoesToTheAgentLogWithoutSecrets(t *testing.T) {
	log, logs := captureLog()
	g := testGuard(t.Context(), newRecordingProvider(), log)
	restore := routeLegoLog(log, g)
	legolog.Infof("[%s] acme: Trying to solve DNS-01", "homelab.lan")
	legolog.Warnf("cleanup said %s", sentinelSecret)
	legolog.Printf("plain line with %s", sentinelSecret)
	restore()
	out := logs.String()
	if strings.Contains(out, sentinelSecret) || !strings.Contains(out, "level=DEBUG") || !strings.Contains(out, "Trying to solve DNS-01") || !strings.Contains(out, "level=WARN") {
		t.Fatalf("log: %s", out)
	}
	if _, ok := legolog.Logger.(legoLog); ok {
		t.Fatal("the logger was not restored")
	}
}

func TestScrubProviderEnvironment(t *testing.T) {
	for _, name := range []string{"LEGO_DEBUG_CLIENT_VERBOSE_ERROR", "CLOUDFLARE_DNS_API_TOKEN", "CLOUDFLARE_BASE_URL", "CF_API_EMAIL", "RFC2136_TSIG_SECRET", "lego_ca_certificates"} {
		t.Setenv(name, "x-"+sentinelSecret)
	}
	t.Setenv("MYOWNPKI_KEEP", "stays")
	removed := ScrubProviderEnvironment()
	if len(removed) < 6 {
		t.Fatalf("removed %v", removed)
	}
	for _, kv := range os.Environ() {
		upper := strings.ToUpper(kv)
		if strings.HasPrefix(upper, "LEGO_") || strings.HasPrefix(upper, "CLOUDFLARE_") || strings.HasPrefix(upper, "CF_") || strings.HasPrefix(upper, "RFC2136_") {
			t.Errorf("still set: %s", strings.SplitN(kv, "=", 2)[0])
		}
	}
	if os.Getenv("MYOWNPKI_KEEP") != "stays" {
		t.Fatal("an unrelated variable was removed")
	}
	for _, n := range removed {
		if strings.Contains(n, sentinelSecret) {
			t.Fatal("a value in the list of names")
		}
	}
}

// obtainWithClient connects the guarded provider to a real lego client, with
// the agent's resolver, and never builds an http-01 responder: here the order
// is refused by the fake CA, so no record was ever presented, and lego's log
// is back where it was.
func TestObtainWithClientWiresTheDNSProviderAndNoResponder(t *testing.T) {
	h := newDNSHarness(t)
	dir := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "https://" + r.Host
		switch r.URL.Path {
		case "/nonce":
			w.Header().Set("Replay-Nonce", "nonce-1")
			w.WriteHeader(http.StatusNoContent)
		case "/order":
			w.Header().Set("Replay-Nonce", "nonce-2")
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"type":"urn:ietf:params:acme:error:rejectedIdentifier","detail":"not covered by the names of this agent"}`))
		default:
			_ = json.NewEncoder(w).Encode(map[string]string{"newNonce": base + "/nonce", "newAccount": base + "/acct", "newOrder": base + "/order"})
		}
	}))
	t.Cleanup(dir.Close)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	user := &accountUser{key: key, reg: &registration.Resource{}}
	ac, err := lego.NewClient(&lego.Config{CADirURL: dir.URL, User: user, HTTPClient: dir.Client(), Certificate: lego.CertificateConfig{Timeout: time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	c := dnsTestConfig(t.TempDir())
	p := c.DNSProviders["homelab-dns"]
	p.Resolver = h.srv.Addr()
	c.DNSProviders["homelab-dns"] = p
	if verr := c.Validate(); verr != nil {
		t.Fatal(verr)
	}
	d := c.Deployments[0]
	rec := newRecordingProvider()
	log, _ := captureLog()
	// StandaloneAddr is invalid: an http-01 responder would fail on it.
	a := &Agent{cfg: c, log: log, StandaloneAddr: "256.0.0.1:bad", Now: time.Now,
		newDNSProvider: func(context.Context, string, DNSProvider, Deployment) (dnsProvider, error) { return rec, nil }}
	g, err := a.dnsProviderFor(t.Context(), d)
	if err != nil {
		t.Fatal(err)
	}
	before := legolog.Logger
	_, err = a.obtainWithClient(t.Context(), d, user, "acme-test", ac, nil, g)
	if err == nil || !strings.Contains(err.Error(), "ACME issuance") || !strings.Contains(err.Error(), "rejectedIdentifier") {
		t.Fatalf("obtainWithClient: %v", err)
	}
	if calls := rec.callList(); len(calls) != 0 {
		t.Fatalf("the provider was used without an authorization: %q", calls)
	}
	if legolog.Logger != before {
		t.Fatal("lego's logger was not restored")
	}
	// A dns-01 deployment without a provider is refused, not served by http-01.
	if _, err := a.obtainWithClient(t.Context(), d, user, "acme-test", ac, nil, nil); err == nil || !strings.Contains(err.Error(), "no DNS provider") {
		t.Fatalf("without a provider: %v", err)
	}
}

// The Cloudflare client trusts the system roots, and on Linux these two
// variables choose them: they would choose who may receive the API token.
func TestScrubProviderEnvironmentRemovesTheTrustStoreOverrides(t *testing.T) {
	t.Setenv("SSL_CERT_FILE", "/tmp/evil-ca.pem")
	t.Setenv("SSL_CERT_DIR", "/tmp/evil-cas")
	t.Setenv("SSL_CERT_OTHER", "stays") // only the two Go reads
	removed := ScrubProviderEnvironment()
	for _, name := range []string{"SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if !slices.Contains(removed, name) {
			t.Errorf("%s not reported: %v", name, removed)
		}
		if v, ok := os.LookupEnv(name); ok {
			t.Errorf("%s is still set (%d bytes)", name, len(v))
		}
	}
	if os.Getenv("SSL_CERT_OTHER") != "stays" || slices.Contains(removed, "SSL_CERT_OTHER") {
		t.Fatal("an unrelated variable was removed")
	}
	for _, n := range removed {
		if strings.Contains(n, "evil") {
			t.Fatalf("a value in the list of names: %v", removed)
		}
	}
}

// A CNAME at _acme-challenge may send the record to a zone the operator never
// configured; with zone set, the agent refuses that update and says why.
func TestRFC2136ConfiguredZoneRefusesACNAMETargetOutsideIt(t *testing.T) {
	h := newDNSHarness(t)
	h.store.AddZone("acme.example.")
	h.store.SetCNAME(testChallenge, "_acme-challenge.homelab.acme.example.")
	h.cfg.Zone = "homelab.lan"
	g := h.guard(t.Context(), h.provider(tsigCreds(testTSIGSecret)), Deployment{Name: "web", Names: []string{"homelab.lan"}})
	err := h.round(t.Context(), g, []acme.Authorization{h.authz("homelab.lan", false)}, func(acme.Authorization) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "zone mismatch") || !strings.Contains(err.Error(), "homelab.acme.example") || strings.Contains(err.Error(), testTSIGSecret) {
		t.Fatalf("round: %v", err)
	}
	if n := h.srv.Updates(); n != 0 {
		t.Fatalf("%d updates for a name outside the configured zone", n)
	}
	h.wantNoChallengeRecords()
	// A target inside the configured zone is fine.
	h.cfg.Zone = "acme.example"
	g = h.guard(t.Context(), h.provider(tsigCreds(testTSIGSecret)), Deployment{Name: "web", Names: []string{"homelab.lan"}})
	if err := h.round(t.Context(), g, []acme.Authorization{h.authz("homelab.lan", false)}, func(acme.Authorization) error { return nil }); err != nil {
		t.Fatal(err)
	}
	h.wantNoChallengeRecords()
}
