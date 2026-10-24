package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

type passChecker struct{}

func (passChecker) Check(context.Context, string, string, string, string) error { return nil }

// newAgentsUIEnv is the UI with the agent service on (and ACME off).
func newAgentsUIEnv(t *testing.T) (*uiEnv, *agents.Service) {
	t.Helper()
	v := &uiEnv{Instance: testinstance.New(t, testinstance.Options{})}
	v.Unseal(t)
	ctx := t.Context()
	if _, err := v.Engine.CreateIntermediate(ctx, ca.IntermediateRequest{
		CASettings: ca.CASettings{Name: "agent-ca", BaseURL: "http://pki.homelab.lan"}, Parent: "root",
		Subject: ca.Subject{CommonName: "Agent CA"}, EKULimit: []string{"clientAuth"}, Who: testinstance.Console,
	}); err != nil {
		t.Fatal(err)
	}
	issuing := "issuing"
	if _, err := v.Engine.CreateDomain(ctx, ca.DomainRequest{Name: "homelab.lan", DomainSettings: ca.DomainSettings{CA: &issuing}, Who: testinstance.Console}); err != nil {
		t.Fatal(err)
	}
	settings := &tenant.Store{DB: v.SystemDB.Write, Clock: v.Clock}
	svc := &agents.Service{
		PKI: v.PKIDB.Write, Tenant: store.DefaultTenant, Engine: v.Engine, CA: "agent-ca", Checker: passChecker{}, Clock: v.Clock,
		Log:  slog.New(slog.DiscardHandler),
		Mode: func(ctx context.Context) (string, error) { return settings.AgentEnrollment(ctx, store.DefaultTenant) },
	}
	h, err := NewHandler(Options{Logger: slog.New(slog.NewJSONHandler(&v.logs, nil)), App: &AppDeps{
		Auth: v.Auth, Engine: v.Engine, Keys: v.Ring, Presets: v.Presets, Clock: v.Clock, Demo: true, Tenant: store.DefaultTenant,
		Settings: settings, TenantAudit: v.TenantAudit.Read, InstanceAudit: v.InstanceAudit.Read, Agents: svc,
	}})
	if err != nil {
		t.Fatal(err)
	}
	v.h = h
	return v, svc
}

func enroll(t *testing.T, svc *agents.Service, host, token, version string) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	out, err := svc.Enroll(t.Context(), agents.EnrollInput{Hostname: host, Token: token, Method: agents.MethodWebroot, OS: "linux", Arch: "amd64",
		Version: version, SourceIP: "192.0.2.60", CSRDER: csr})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EnrollStatus(t.Context(), agents.StatusInput{ID: out.ID, Handle: out.Handle, CheckReady: true}); err != nil {
		t.Fatal(err)
	}
	return out.ID
}

var reSecret = regexp.MustCompile(`mjt_[A-Za-z0-9_-]{43}`)

// TestAgentPages (docs/PHASE3.md, UI of v0.3.0): a join token is shown once
// (no-store); an enrollment waits in the queue and is approved by the form;
// the agent's page shows what it reported escaped; names, disable and
// revoke work; a viewer sees the pages without the forms; the tenant
// setting switches the mode.
func TestAgentPages(t *testing.T) {
	t.Parallel()
	v, svc := newAgentsUIEnv(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	token := b.csrf(t)

	// A join token: the secret is in the answer of the POST, not cached, and
	// never again on the list.
	r := b.post(t, "/agents/tokens", url.Values{"csrf_token": {token}, "label": {"proxy1"}, "names": {"proxy1.homelab.lan\n*.apps.homelab.lan"}, "hours": {"2"}})
	secret := reSecret.FindString(r.html())
	if r.Code != http.StatusOK || secret == "" || r.Header().Get("Cache-Control") != "no-store" || !strings.Contains(r.html(), "myownpki-agent enroll --token-file") {
		t.Fatalf("new token: %d %q %s", r.Code, r.Header().Get("Cache-Control"), r.html())
	}
	if list := b.get(t, "/agents/tokens").html(); strings.Contains(list, secret) || !strings.Contains(list, "*.apps.homelab.lan") || !strings.Contains(list, "unused") {
		t.Errorf("token list: %s", list)
	}
	if bad := b.post(t, "/agents/tokens", url.Values{"csrf_token": {token}, "names": {"*"}, "hours": {"2"}}); bad.Code != http.StatusSeeOther ||
		!strings.Contains(flashOf(t, b, "/agents/tokens"), "want a fully qualified name") {
		t.Errorf("a bad pattern: %d", bad.Code)
	}

	// The queue: verified, without a token – it waits; approved by the form.
	waiting := enroll(t, svc, "proxy2.homelab.lan", "", "0.3.0")
	queue := b.get(t, "/agents/enrollments").html()
	for _, want := range []string{"proxy2.homelab.lan", "pending approval", "none", "passed (webroot)", "Approve enrollment", "Enrollment mode of this tenant: verified"} {
		if !strings.Contains(queue, want) {
			t.Errorf("queue lacks %q", want)
		}
	}
	r = b.post(t, "/agents/enrollments/approve", url.Values{"csrf_token": {token}, "id": {waiting}})
	if r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, "/agents/enrollments"), "approved") {
		t.Fatalf("approve: %d", r.Code)
	}
	denied := enroll(t, svc, "proxy3.homelab.lan", "", "0.3.0")
	b.post(t, "/agents/enrollments/deny", url.Values{"csrf_token": {token}, "id": {denied}})
	if msg := flashOf(t, b, "/agents/enrollments"); !strings.Contains(msg, "refused") {
		t.Errorf("deny: %q", msg)
	}

	// An agent with a token; what it reported is attacker input.
	enroll(t, svc, "proxy1.homelab.lan", secret, "<script>x</script>")
	list := b.get(t, "/agents").html()
	if !strings.Contains(list, "proxy1.homelab.lan") || !strings.Contains(list, "proxy2.homelab.lan") || strings.Contains(list, "<script>x") {
		t.Fatalf("agent list: %s", list)
	}
	all, _ := svc.ListAgents(t.Context(), testinstance.Console)
	var id string
	for _, a := range all {
		if a.Hostname == "proxy1.homelab.lan" {
			id = a.ID
		}
	}
	detail := b.get(t, "/agents/"+id).html()
	for _, want := range []string{"*.apps.homelab.lan", "token", "Add name", "Disable agent", "Revoke agent", "&lt;script&gt;"} {
		if !strings.Contains(detail, want) {
			t.Errorf("agent page lacks %q", want)
		}
	}
	b.post(t, "/agents/"+id+"/names", url.Values{"csrf_token": {token}, "action": {"add"}, "name": {"wiki.homelab.lan"}})
	if msg := flashOf(t, b, "/agents/"+id); !strings.Contains(msg, "Names changed") {
		t.Errorf("add name: %q", msg)
	}
	b.post(t, "/agents/"+id+"/disable", url.Values{"csrf_token": {token}})
	if page := b.get(t, "/agents/"+id).html(); !strings.Contains(page, "disabled") || !strings.Contains(page, "Enable agent") {
		t.Error("not disabled")
	}
	b.post(t, "/agents/"+id+"/revoke", url.Values{"csrf_token": {token}})
	if page := b.get(t, "/agents/"+id).html(); !strings.Contains(page, "revoked") || strings.Contains(page, "Add name") {
		t.Error("not revoked, or still with forms")
	}
	if bogus := b.post(t, "/agents/"+id+"/bogus", url.Values{"csrf_token": {token}}); bogus.Code != http.StatusNotFound {
		t.Errorf("unknown action: %d", bogus.Code)
	}

	// The tenant setting.
	b.post(t, "/admin/settings", url.Values{"csrf_token": {token}, "agent_enrollment": {"manual"}, "acme_orders": {"300"}, "acme_failed": {"5"}, "acme_accounts": {"10"}})
	if mode, _ := (&tenant.Store{DB: v.SystemDB.Read, Clock: v.Clock}).AgentEnrollment(t.Context(), store.DefaultTenant); mode != "manual" {
		t.Errorf("mode %q", mode)
	}

	// A viewer: the pages, no forms.
	v.User(t, "viewer", false, authz.Binding{Role: authz.Viewer})
	vb := v.browser("192.0.2.2")
	vb.signIn(t, "viewer", testinstance.Password)
	for _, p := range []string{"/agents", "/agents/" + id, "/agents/enrollments", "/agents/tokens"} {
		page := vb.get(t, p)
		if page.Code != http.StatusOK || strings.Contains(page.html(), "Create token") || strings.Contains(page.html(), "Revoke agent") {
			t.Errorf("viewer %s: %d", p, page.Code)
		}
	}
}

// TestAgentPagesOff: without agent.base_url the pages say how to switch
// agents on.
func TestAgentPagesOff(t *testing.T) {
	t.Parallel()
	v := newUIEnvWith(t, false)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	for _, p := range []string{"/agents", "/agents/enrollments", "/agents/tokens"} {
		if page := b.get(t, p); page.Code != http.StatusOK || !strings.Contains(page.html(), "agent.base_url") {
			t.Errorf("%s: %d", p, page.Code)
		}
	}
}
