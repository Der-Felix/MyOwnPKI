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
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agentdist"
	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

type passChecker struct{}

func (passChecker) Check(context.Context, string, string, string, string) error { return nil }

// newAgentsUIEnv is the UI with the agent service on (and ACME off).
func newAgentsUIEnv(t *testing.T) (*uiEnv, *agents.Service) {
	t.Helper()
	return newAgentsUIEnvVersion(t, "v0.3.1")
}

func newAgentsUIEnvVersion(t *testing.T, version string) (*uiEnv, *agents.Service) {
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
	packageDir := t.TempDir()
	dist := agentdist.New(packageDir, version)
	for _, arch := range agentdist.Arches {
		for _, format := range agentdist.Formats {
			name, _ := dist.Name(format, arch)
			if err := os.WriteFile(filepath.Join(packageDir, name), []byte(name), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(packageDir, agentdist.Checksums), []byte("checksums\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(Options{Logger: slog.New(slog.NewJSONHandler(&v.logs, nil)), App: &AppDeps{
		Auth: v.Auth, Engine: v.Engine, Keys: v.Ring, Presets: v.Presets, Clock: v.Clock, Demo: true, Tenant: store.DefaultTenant,
		Settings: settings, TenantAudit: v.TenantAudit.Read, InstanceAudit: v.InstanceAudit.Read, Agents: svc,
		AgentDist: dist, AgentBaseURL: "https://pki.homelab.lan:8444", AgentTLSIssuer: "issuing", ServerVersion: version,
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
	caller := &agents.Caller{Agent: pkidb.Agent{ID: id}, Who: testinstance.Console}
	reports := []agents.DeploymentReport{
		{Name: "proxy", Profile: "nginx", Names: []string{"proxy1.homelab.lan", "other.homelab.lan"}, State: "deployed", Serial: "AA", NotAfter: v.Clock.Now().Add(24 * time.Hour).Format(time.RFC3339)},
		{Name: "broken", Profile: "file", Names: []string{"app.apps.homelab.lan"}, State: "failed", LastError: "<img src=x onerror=alert(1)>"},
		{Name: "removed", Profile: "file", State: "rolled_back"},
	}
	report := agents.ReportInput{Version: "<script>x</script>", OS: "linux", Arch: "amd64", Deployments: reports}
	if err := svc.Report(t.Context(), caller, report); err != nil {
		t.Fatal(err)
	}
	if err := svc.RequestRenewal(t.Context(), testinstance.Console, id, "removed"); err != nil {
		t.Fatal(err)
	}
	report.Deployments = reports[:2]
	if err := svc.Report(t.Context(), caller, report); err != nil {
		t.Fatal(err)
	}
	detail := b.get(t, "/agents/"+id).html()
	for _, want := range []string{"*.apps.homelab.lan", "token", "Add name", "Disable agent", "Revoke agent", "&lt;script&gt;",
		"deployed", "failed", "rolled back", "AA", "Renew now", "Renewal requested ·", "Withdraw", "not in the agent configuration", "&lt;img src=x onerror=alert(1)&gt;",
		"table-adaptive", "not covered by Names it may order: other.homelab.lan; the ACME server will refuse them", "View agent certificate", "st-info", "cmd cmd-danger"} {
		if !strings.Contains(detail, want) {
			t.Errorf("agent page lacks %q", want)
		}
	}
	if strings.Contains(detail, ">Requested</button>") {
		t.Error("renewal status is still rendered as a button")
	}
	if strings.Count(detail, ">Remove</button>") != 1 || strings.Contains(detail, "Remove a name") {
		t.Error("name removal is not a per-row action only for removable sources")
	}
	if strings.Contains(detail, "mode verified (mode verified)") || strings.Contains(detail, "Certificates: /certificates/") {
		t.Error("agent page repeats the enrollment mode or shows a naked certificate path")
	}
	if !strings.Contains(detail, `action="/agents/`+id+`/deployments/removed/withdraw"`) || !strings.Contains(detail, `name="csrf_token" value="`+token+`"`) {
		t.Error("withdraw has no form with the session's CSRF token")
	}
	if r := b.post(t, "/agents/"+id+"/deployments/proxy/renew", url.Values{"csrf_token": {token}, "predecessor": {"now"}}); r.Code != http.StatusSeeOther {
		t.Fatalf("renew: %d", r.Code)
	}
	if page := b.get(t, "/agents/"+id).html(); !strings.Contains(page, "Renewal requested") || !strings.Contains(page, "Withdraw") {
		t.Error("open request does not show requested and withdraw")
	}
	if r := b.post(t, "/agents/"+id+"/deployments/proxy/withdraw", url.Values{"csrf_token": {token}}); r.Code != http.StatusSeeOther {
		t.Fatalf("withdraw: %d", r.Code)
	}
	if page := b.get(t, "/agents/"+id).html(); !strings.Contains(page, "Renew now") {
		t.Error("withdraw did not re-enable renew")
	}
	b.post(t, "/agents/"+id+"/names", url.Values{"csrf_token": {token}, "action": {"add"}, "name": {"wiki.homelab.lan"}})
	if msg := flashOf(t, b, "/agents/"+id); !strings.Contains(msg, "Names changed") {
		t.Errorf("add name: %q", msg)
	}
	withAdded := b.get(t, "/agents/"+id).html()
	if strings.Count(withAdded, ">Remove</button>") != 2 || !strings.Contains(withAdded, `name="name" value="wiki.homelab.lan"`) {
		t.Error("an admin-added name has no row-level remove action")
	}
	b.post(t, "/agents/"+id+"/names", url.Values{"csrf_token": {token}, "action": {"remove"}, "name": {"wiki.homelab.lan"}})
	if msg := flashOf(t, b, "/agents/"+id); !strings.Contains(msg, "Names changed") || strings.Contains(b.get(t, "/agents/"+id).html(), `name="name" value="wiki.homelab.lan"`) {
		t.Error("row-level name removal failed")
	}

	v.User(t, "operator", false, authz.Binding{Role: authz.Operator})
	ob := v.browser("192.0.2.3")
	ob.signIn(t, "operator", testinstance.Password)
	operatorPage := ob.get(t, "/agents/"+id).html()
	if !strings.Contains(operatorPage, `href="/agents/`+id+`/deployments/proxy/renew"`) || strings.Contains(operatorPage, "disabled>Withdraw") {
		t.Error("operator does not get enabled renew/withdraw actions")
	}
	v.User(t, "viewer", false, authz.Binding{Role: authz.Viewer})
	vb := v.browser("192.0.2.2")
	vb.signIn(t, "viewer", testinstance.Password)
	viewerPage := vb.get(t, "/agents/"+id).html()
	if strings.Contains(viewerPage, `href="/agents/`+id+`/deployments/proxy/renew"`) || !strings.Contains(viewerPage, "disabled>Withdraw") {
		t.Error("viewer actions are not disabled")
	}
	viewerToken := vb.csrf(t)
	vb.post(t, "/agents/"+id+"/deployments/removed/withdraw", url.Values{"csrf_token": {viewerToken}})
	if msg := flashOf(t, vb, "/agents/"+id); !strings.Contains(msg, "role doesn") {
		t.Errorf("viewer withdrew a request: %q", msg)
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
	b.post(t, "/admin/settings", url.Values{"csrf_token": {token}, "agent_enrollment": {"manual"}, "acme_orders": {"300"}, "acme_failed": {"5"}, "acme_accounts": {"10"},
		"agent_predecessor": {"now"}, "other_predecessor": {"after"}, "other_predecessor_days": {"7"}})
	if mode, _ := (&tenant.Store{DB: v.SystemDB.Read, Clock: v.Clock}).AgentEnrollment(t.Context(), store.DefaultTenant); mode != "manual" {
		t.Errorf("mode %q", mode)
	}

	// A viewer: the pages, without management forms.
	for _, p := range []string{"/agents", "/agents/" + id, "/agents/enrollments", "/agents/tokens"} {
		page := vb.get(t, p)
		if page.Code != http.StatusOK || strings.Contains(page.html(), "Create token") || strings.Contains(page.html(), "Revoke agent") {
			t.Errorf("viewer %s: %d", p, page.Code)
		}
	}
}

func TestAgentSilentRenewalWaitsForAgent(t *testing.T) {
	t.Parallel()
	v, svc := newAgentsUIEnv(t)
	secret, _, err := svc.CreateJoinToken(t.Context(), testinstance.Console, "silent", []string{"proxy1.homelab.lan"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	enroll(t, svc, "proxy1.homelab.lan", secret, "0.3.0")
	list, err := svc.ListAgents(t.Context(), testinstance.Console)
	if err != nil || len(list) != 1 {
		t.Fatalf("agent missing: %v", err)
	}
	id := list[0].ID
	caller := &agents.Caller{Agent: pkidb.Agent{ID: id}, Who: testinstance.Console}
	if err := svc.Report(t.Context(), caller, agents.ReportInput{Deployments: []agents.DeploymentReport{{Name: "proxy", State: "deployed"}}}); err != nil {
		t.Fatal(err)
	}
	if err := svc.RequestRenewal(t.Context(), testinstance.Console, id, "proxy"); err != nil {
		t.Fatal(err)
	}
	v.Clock.Advance(15 * time.Minute)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	if page := b.get(t, "/agents/"+id).html(); !strings.Contains(page, "waiting for the agent (last seen ") {
		t.Error("a silent agent with an open request has no waiting explanation")
	}
}

func TestDashboardExcludesAgentIdentitiesAndWarnsPerAgent(t *testing.T) {
	t.Parallel()
	v, svc := newAgentsUIEnv(t)
	firstToken, _, err := svc.CreateJoinToken(t.Context(), testinstance.Console, "first", []string{"proxy1.homelab.lan"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	enroll(t, svc, "proxy1.homelab.lan", firstToken, "0.3.0")
	deployment, err := v.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{"app.homelab.lan"}, ValidityDays: 10, Who: testinstance.Console})
	if err != nil {
		t.Fatal(err)
	}
	v.Clock.Advance(5*24*time.Hour + 12*time.Hour)
	secondToken, _, err := svc.CreateJoinToken(t.Context(), testinstance.Console, "second", []string{"proxy2.homelab.lan"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	enroll(t, svc, "proxy2.homelab.lan", secondToken, "0.3.0")
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	page := b.get(t, "/").html()
	if !strings.Contains(page, "The agent certificate of proxy1.homelab.lan expires") || strings.Contains(page, "The agent certificate of proxy2.homelab.lan") {
		t.Error("dashboard does not warn only for the agent whose certificate has less than 48 hours left")
	}
	if !regexp.MustCompile(`(?s)<dt>Expire in 30 days</dt>\s*<dd>\s*<a[^>]*>1</a>`).MatchString(page) {
		t.Error("30-day count includes agent identity certificates")
	}
	_, expiring, found := strings.Cut(page, `id="h-expiring"`)
	if !found {
		t.Fatal("dashboard expiry section missing")
	}
	if strings.Contains(expiring, "proxy1.homelab.lan") || strings.Contains(expiring, "proxy2.homelab.lan") || !strings.Contains(expiring, deployment.SerialHex) {
		t.Error("dashboard expiry table does not contain exactly the end-entity certificates")
	}
	linked := b.get(t, "/certificates?status=expiring").html()
	if strings.Contains(linked, "proxy1.homelab.lan") || strings.Contains(linked, "proxy2.homelab.lan") || !strings.Contains(linked, deployment.SerialHex) {
		t.Error("Show expiring does not exclude only agent identity certificates")
	}
}

func TestAgentCertificateFilter(t *testing.T) {
	t.Parallel()
	v, svc := newAgentsUIEnv(t)
	secret, _, err := svc.CreateJoinToken(t.Context(), testinstance.Console, "filter", []string{"proxy1.homelab.lan"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	enroll(t, svc, "proxy1.homelab.lan", secret, "0.3.0")
	list, err := svc.ListAgents(t.Context(), testinstance.Console)
	if err != nil || len(list) != 1 || list[0].CertSerial == "" {
		t.Fatalf("agent identity certificate missing: %v", err)
	}
	who := keys.Who{Actor: audit.Actor{Type: audit.ActorACMEAccount, ID: "acct_agent", Name: "acme:acct_agent"}, Principal: authz.System("acme")}
	deployment, err := v.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{"app.homelab.lan"}, Who: who})
	if err != nil {
		t.Fatal(err)
	}
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	agentSerial := list[0].CertSerial
	defaultPage := b.get(t, "/certificates").html()
	if strings.Contains(defaultPage, agentSerial) || !strings.Contains(defaultPage, deployment.SerialHex) {
		t.Error("default filter does not hide only the agent identity certificate")
	}
	all := b.get(t, "/certificates?agent_filter=1").html()
	if !strings.Contains(all, agentSerial) || !strings.Contains(all, deployment.SerialHex) {
		t.Error("disabled filter does not show both certificate kinds")
	}
	hidden := b.get(t, "/certificates?agent_filter=1&hide_agents=yes").html()
	if strings.Contains(hidden, agentSerial) || !strings.Contains(hidden, deployment.SerialHex) {
		t.Error("explicitly enabled filter shows the wrong certificates")
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
