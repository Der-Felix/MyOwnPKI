package agent

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/go-acme/lego/v4/acme"

	"github.com/Der-Felix/MyOwnPKI/internal/testutil/dnsserver"
)

const testCFToken = "cf-API-TOKEN-0123456789-sentinel" //nolint:gosec // a test sentinel, not a credential

func cfCreds(token, zoneToken string) *dnsCredentials {
	c := &dnsCredentials{Type: DNSTypeCloudflare, APIToken: newSecret([]byte(token))}
	if zoneToken != "" {
		c.ZoneToken = newSecret([]byte(zoneToken))
	}
	return c
}

// cfHarness is the DNS harness (lego finds the zone through its SOA at the
// test server, as it does for the real Cloudflare zone) plus the stub that
// writes into the same store.
type cfHarness struct {
	*dnsHarness
	stub *dnsserver.CloudflareStub
}

func newCFHarness(t *testing.T, opts dnsserver.CloudflareOptions) *cfHarness {
	t.Helper()
	h := newDNSHarness(t)
	h.cfg = DNSProvider{Type: DNSTypeCloudflare, TTL: 120, Resolver: h.srv.Addr(), Propagation: PropagationResolver, PropagationTimeout: 120}
	return &cfHarness{dnsHarness: h, stub: dnsserver.StartCloudflare(t, h.store, opts)}
}

func (h *cfHarness) cf(creds *dnsCredentials) *cloudflareProvider {
	h.t.Helper()
	p, err := newCloudflareProvider(h.cfg, creds, "", &cloudflareTest{baseURL: h.stub.URL, roots: h.stub.Roots})
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(p.closeIdle)
	return p
}

func TestCloudflareProviderCreatesAndDeletesByID(t *testing.T) {
	h := newCFHarness(t, dnsserver.CloudflareOptions{Token: testCFToken})
	p := h.cf(cfCreds(testCFToken, ""))
	g := h.guard(t.Context(), p, wildcardDeployment())
	authzs := wildcardPair(h.dnsHarness)
	err := h.round(t.Context(), g, authzs, func(a acme.Authorization) error {
		if !h.visible(testChallenge, h.value(a)) {
			t.Errorf("value is not in the zone: %v", h.store.TXT(testChallenge))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	h.wantNoChallengeRecords()
	var posts, deletes, zoneLookups int
	for _, r := range h.stub.Requests() {
		if r.Authorization != "Bearer "+testCFToken {
			t.Errorf("%s %s sent %q", r.Method, r.Path, r.Authorization)
		}
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.Path, "/dns_records"):
			posts++
		case r.Method == http.MethodDelete && strings.Contains(r.Path, "/dns_records/rec"):
			deletes++
		case r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/zones"):
			zoneLookups++
			if !strings.Contains(r.Query, "name=homelab.lan") {
				t.Errorf("zone lookup %q", r.Query)
			}
		}
	}
	if posts != 2 || deletes != 2 || zoneLookups == 0 {
		t.Fatalf("posts %d, deletes %d, zone lookups %d: %+v", posts, deletes, zoneLookups, h.stub.Requests())
	}
	if w := g.Warnings(); len(w) != 0 {
		t.Fatalf("warnings %q", w)
	}
}

func TestCloudflareProviderUsesTheZoneTokenOnlyForTheZone(t *testing.T) {
	h := newCFHarness(t, dnsserver.CloudflareOptions{Token: testCFToken, ZoneToken: "zone-token-sentinel"})
	p := h.cf(cfCreds(testCFToken, "zone-token-sentinel"))
	g := h.guard(t.Context(), p, Deployment{Name: "web", Names: []string{"homelab.lan"}})
	if err := h.round(t.Context(), g, []acme.Authorization{h.authz("homelab.lan", false)}, func(acme.Authorization) error { return nil }); err != nil {
		t.Fatal(err)
	}
	h.wantNoChallengeRecords()
	for _, r := range h.stub.Requests() {
		want := "Bearer " + testCFToken
		if r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/zones") {
			want = "Bearer zone-token-sentinel"
		}
		if r.Authorization != want {
			t.Errorf("%s %s sent %q, want %q", r.Method, r.Path, r.Authorization, want)
		}
	}
}

func TestCloudflareWrongTokenFailsWithoutTheToken(t *testing.T) {
	h := newCFHarness(t, dnsserver.CloudflareOptions{Token: testCFToken})
	const wrong = "wrong-token-sentinel-9876"
	log, logs := captureLog()
	g := h.guard(t.Context(), h.cf(cfCreds(wrong, "")), Deployment{Name: "web", Names: []string{"homelab.lan"}})
	g.log = log
	err := h.round(t.Context(), g, []acme.Authorization{h.authz("homelab.lan", false)}, func(acme.Authorization) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "9109") || !strings.Contains(err.Error(), `dns provider "homelab-dns"`) {
		t.Fatalf("round: %v", err)
	}
	for _, text := range []string{err.Error(), logs.String(), strings.Join(g.Warnings(), "\n")} {
		if strings.Contains(text, wrong) || strings.Contains(text, testCFToken) {
			t.Fatalf("a token in %q", text)
		}
	}
	h.wantNoChallengeRecords()
}

// An API answer that quotes the token (a gateway that echoes headers) must
// not put it into an error or a log: the redaction removes the provider's own
// secret from whatever the API said.
func TestCloudflareTokenEchoedByTheAPIIsRedacted(t *testing.T) {
	const echoed = "echoed-token-sentinel-5555"
	h := newCFHarness(t, dnsserver.CloudflareOptions{Token: testCFToken})
	h.stub.ErrorText("your header was Bearer " + echoed)
	log, logs := captureLog()
	// The token is wrong, so the zone lookup fails with the stub's message.
	g := h.guard(t.Context(), h.cf(cfCreds(echoed, "")), Deployment{Name: "web", Names: []string{"homelab.lan"}})
	g.log = log
	err := h.round(t.Context(), g, []acme.Authorization{h.authz("homelab.lan", false)}, func(acme.Authorization) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "your header was Bearer") {
		t.Fatalf("round: %v", err)
	}
	for _, text := range []string{err.Error(), logs.String(), strings.Join(g.Warnings(), "\n")} {
		if strings.Contains(text, echoed) {
			t.Fatalf("the token in %q", text)
		}
	}
	if !strings.Contains(err.Error(), redacted) {
		t.Fatalf("no redaction mark: %v", err)
	}
}

func TestCloudflareDeleteFailureIsReturnedNotSwallowed(t *testing.T) {
	h := newCFHarness(t, dnsserver.CloudflareOptions{Token: testCFToken})
	log, logs := captureLog()
	g := h.guard(t.Context(), h.cf(cfCreds(testCFToken, "")), Deployment{Name: "web", Names: []string{"homelab.lan"}})
	g.log = log
	h.stub.FailDeletes(http.StatusInternalServerError)
	err := h.round(t.Context(), g, []acme.Authorization{h.authz("homelab.lan", false)}, func(acme.Authorization) error { return nil })
	if err != nil {
		t.Fatalf("the issuance keeps its result: %v", err)
	}
	// lego itself only logs the failed DELETE and returns nil; the leftover
	// record is recorded as a warning.
	if w := g.Warnings(); len(w) != 1 || !strings.Contains(w[0], "deleting the TXT record failed") || !strings.Contains(w[0], "500") {
		t.Fatalf("warnings %q", w)
	}
	if !strings.Contains(logs.String(), "cleanup failed") {
		t.Fatalf("no log line: %s", logs)
	}
	if left := h.store.ChallengeRecords(); len(left) != 1 {
		t.Fatalf("the stub should still hold the record: %+v", left)
	}
}

// A record that is already gone (404) is what a delete wants.
func TestCloudflareDeleteOfAnAlreadyRemovedRecordIsFine(t *testing.T) {
	h := newCFHarness(t, dnsserver.CloudflareOptions{Token: testCFToken})
	g := h.guard(t.Context(), h.cf(cfCreds(testCFToken, "")), Deployment{Name: "web", Names: []string{"homelab.lan"}})
	a := h.authz("homelab.lan", false)
	keyAuth, err := h.core.GetKeyAuthorization(a.Challenges[0].Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Present("homelab.lan", "t", keyAuth); err != nil {
		t.Fatal(err)
	}
	h.stub.FailDeletes(http.StatusNotFound)
	if err := g.CleanUp("homelab.lan", "t", keyAuth); err != nil {
		t.Fatalf("CleanUp after a 404: %v", err)
	}
}

func TestCloudflareHTMLAnswerNeverReachesAnError(t *testing.T) {
	h := newCFHarness(t, dnsserver.CloudflareOptions{Token: testCFToken})
	h.stub.NotJSON("<html><body>Welcome to the guest network. Token: leaked-portal-text</body></html>")
	p := h.cf(cfCreds(testCFToken, ""))
	err := p.Present("homelab.lan", "t", "ka")
	if err == nil || strings.Contains(err.Error(), "leaked-portal-text") || strings.Contains(err.Error(), "<html>") {
		t.Fatalf("error %v", err)
	}
	if !strings.Contains(err.Error(), "not the Cloudflare API") {
		t.Fatalf("error %v", err)
	}
}

func TestCloudflareStopsWhenTheContextIsCanceled(t *testing.T) {
	h := newCFHarness(t, dnsserver.CloudflareOptions{Token: testCFToken})
	p := h.cf(cfCreds(testCFToken, ""))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	p.useContext(ctx)
	if err := p.Present("homelab.lan", "t", "ka"); err == nil {
		t.Fatal("Present on a canceled context")
	}
	for _, r := range h.stub.Requests() {
		t.Errorf("a request reached the API: %+v", r)
	}
	// The cleanup context is another one and works.
	p.useContext(context.WithoutCancel(ctx))
	if err := p.Present("homelab.lan", "t", "ka"); err != nil {
		t.Fatal(err)
	}
	if err := p.CleanUp("homelab.lan", "t", "ka"); err != nil {
		t.Fatal(err)
	}
	h.wantNoChallengeRecords()
}

func TestCloudflareCleanUpWithoutASuccessfulPresentTouchesNothing(t *testing.T) {
	h := newCFHarness(t, dnsserver.CloudflareOptions{Token: testCFToken})
	p := h.cf(cfCreds(testCFToken, ""))
	if err := p.CleanUp("homelab.lan", "never-presented", "ka"); err != nil {
		t.Fatal(err)
	}
	if n := len(h.stub.Requests()); n != 0 {
		t.Fatalf("%d requests", n)
	}
}

// The agent's own client: system trust store, TLS 1.2, the proxy of
// agent.yaml and never the one of the environment.
func TestCloudflareHTTPClientSettings(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://environment-proxy.invalid:3128")
	t.Setenv("https_proxy", "http://environment-proxy.invalid:3128")
	api, err := url.Parse("https://api.cloudflare.com/client/v4/zones")
	if err != nil {
		t.Fatal(err)
	}
	cfg := DNSProvider{Type: DNSTypeCloudflare, TTL: 120, PropagationTimeout: 120}

	p, err := newCloudflareProvider(cfg, cfCreds(testCFToken, ""), "", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.closeIdle)
	base := p.tr.base
	if base.TLSClientConfig.MinVersion != tls.VersionTLS12 || base.TLSClientConfig.RootCAs != nil || base.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("TLS config %+v", base.TLSClientConfig)
	}
	if base.Proxy != nil {
		if u, _ := base.Proxy(&http.Request{URL: api}); u != nil {
			t.Fatalf("the environment's proxy %v is used", u)
		}
	}
	if base.ResponseHeaderTimeout != cloudflareHTTPTimeout || cloudflareHTTPTimeout.Seconds() != 30 {
		t.Fatalf("timeout %v", base.ResponseHeaderTimeout)
	}

	p2, err := newCloudflareProvider(cfg, cfCreds(testCFToken, ""), "http://172.20.23.25:8080", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p2.closeIdle)
	if u, err := p2.tr.base.Proxy(&http.Request{URL: api}); err != nil || u == nil || u.Host != "172.20.23.25:8080" {
		t.Fatalf("proxy %v, %v", u, err)
	}
	// A broken proxy setting is named, without echoing it.
	if _, err := newCloudflareProvider(cfg, cfCreds(testCFToken, ""), "http://%zz", nil); err == nil || strings.Contains(err.Error(), "%zz") {
		t.Fatalf("proxy error: %v", err)
	}
}
