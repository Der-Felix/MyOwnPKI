package web

import (
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/monitor"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
	"github.com/Der-Felix/MyOwnPKI/internal/tlsscan"
)

// endpointsUIEnv is the UI with the TLS scan on: an unsealed instance with the
// domain homelab.lan, so that endpoints can be entered.
type endpointsUIEnv struct {
	*uiEnv
	scan      *tlsscan.Service
	endpoints *monitor.Endpoints
	alerts    *monitor.Store
}

func newEndpointsUIEnv(t *testing.T) *endpointsUIEnv {
	t.Helper()
	v := &uiEnv{Instance: testinstance.New(t, testinstance.Options{})}
	v.Unseal(t)
	issuing := "issuing"
	if _, err := v.Engine.CreateDomain(t.Context(), ca.DomainRequest{
		Name: "homelab.lan", DomainSettings: ca.DomainSettings{CA: &issuing, IPRanges: []string{"192.0.2.0/24"}}, Who: testinstance.Console,
	}); err != nil {
		t.Fatal(err)
	}
	e := &endpointsUIEnv{uiEnv: v, alerts: &monitor.Store{DB: v.SystemDB.Write, Tenant: store.DefaultTenant}}
	e.scan = &tlsscan.Service{
		PKI: v.PKIDB.Write, Tenant: store.DefaultTenant, Engine: v.Engine, Clock: v.Clock,
		Settings: tlsscan.Settings{Interval: 15 * time.Minute, Timeout: 10 * time.Second, MaxEndpoints: 100, Ports: []int{443, 465, 636, 853, 993, 995, 5061, 6514, 8443, 8883, 9443}},
	}
	e.endpoints = &monitor.Endpoints{
		Service: e.scan, Clock: v.Clock,
		Eval: &monitor.Evaluator{Engine: v.Engine, Seal: v.Ring.Status, Rules: monitor.DefaultRules(), Scan: e.scan,
			Who: keys.Who{Actor: audit.Actor{Type: audit.ActorSystem, Name: "monitor"}, Principal: authz.System("monitor")}},
	}
	h, err := NewHandler(Options{Logger: slog.New(slog.NewJSONHandler(&v.logs, nil)), App: &AppDeps{
		Auth: v.Auth, Engine: v.Engine, Keys: v.Ring, Presets: v.Presets, Clock: v.Clock, Demo: true, Tenant: store.DefaultTenant,
		Settings: &tenant.Store{DB: v.SystemDB.Write, Clock: v.Clock}, TenantAudit: v.TenantAudit.Read, InstanceAudit: v.InstanceAudit.Read,
		Alerts: e.alerts, Endpoints: e.endpoints,
	}})
	if err != nil {
		t.Fatal(err)
	}
	v.h = h
	return e
}

// add enters an endpoint through the service and returns its ID.
func (e *endpointsUIEnv) add(t *testing.T, host string, port int) string {
	t.Helper()
	ep, err := e.scan.Create(t.Context(), testinstance.Console, tlsscan.Request{Host: host, Port: port})
	if err != nil {
		t.Fatal(err)
	}
	return ep.ID
}

// serve records what a scan found, as the scanner would.
func (e *endpointsUIEnv) serve(t *testing.T, id, fingerprint, issuer, subject string, notAfter time.Time) {
	t.Helper()
	const layout = "2006-01-02T15:04:05Z"
	now := e.Clock.Now().UTC().Format(layout)
	_, err := e.PKIDB.Write.ExecContext(t.Context(), `UPDATE endpoints SET last_scan_at = ?, last_ok_at = ?, fail_streak = 0,
		last_error_kind = NULL, last_error = NULL, fingerprint = ?, serial = 'ABCD', subject = ?, issuer = ?, not_before = ?, not_after = ?,
		chain_len = 2, chain_state = 'trusted', tls_version = 'TLS 1.3', same_count = 2, fingerprint_since = ? WHERE id = ?`,
		now, now, fingerprint, subject, issuer, e.Clock.Now().Add(-24*time.Hour).UTC().Format(layout), notAfter.UTC().Format(layout), now, id)
	if err != nil {
		t.Fatal(err)
	}
}

func (e *endpointsUIEnv) fail(t *testing.T, id, kind string, streak int) {
	t.Helper()
	now := e.Clock.Now().UTC().Format("2006-01-02T15:04:05Z")
	_, err := e.PKIDB.Write.ExecContext(t.Context(),
		`UPDATE endpoints SET last_scan_at = ?, fail_streak = ?, last_error_kind = ?, last_error = ? WHERE id = ?`, now, streak, kind, kind, id)
	if err != nil {
		t.Fatal(err)
	}
}

// endpointAudit counts the endpoint entries of the tenant audit log.
func (e *endpointsUIEnv) endpointAudit(t *testing.T) map[string]int {
	t.Helper()
	e.Deliver(t)
	out := map[string]int{}
	for _, a := range testinstance.Audit(t, e.TenantAudit) {
		if strings.HasPrefix(a, "endpoint.") {
			out[a]++
		}
	}
	return out
}

// plainPage fails when a page carries what the CSP forbids or a class that
// web/styles does not define.
func plainPage(t *testing.T, html string) {
	t.Helper()
	for name, re := range map[string]*regexp.Regexp{"style attribute": reStyleAttr, "<script> tag": reScriptTag, "inline event (on*)": reEventAttr} {
		if m := re.FindString(html); m != "" {
			t.Errorf("the page has a %s: %q", name, m)
		}
	}
	defined := map[string]bool{}
	for _, src := range readStyles(t) {
		for _, m := range reCSSClass.FindAllStringSubmatch(src, -1) {
			defined[m[1]] = true
		}
	}
	for _, m := range reClassAttr.FindAllStringSubmatch(html, -1) {
		for _, class := range strings.Fields(m[1]) {
			if !defined[class] {
				t.Errorf("class %q is not defined in web/styles", class)
			}
		}
	}
}

// TestEndpointsPage: the table with the words of the states, the short
// fingerprint with the full one as its title, expiry, issuer and the error in
// words; the controls per role; nothing inline.
func TestEndpointsPage(t *testing.T) {
	t.Parallel()
	e := newEndpointsUIEnv(t)
	e.User(t, "viewer", false, authz.Binding{Role: authz.Viewer})
	e.User(t, "operator", false, authz.Binding{Role: authz.Operator})
	admin, viewer, operator := e.browser("192.0.2.1"), e.browser("192.0.2.2"), e.browser("192.0.2.3")
	admin.signIn(t, "demo", e.DemoPassword)
	viewer.signIn(t, "viewer", testinstance.Password)
	operator.signIn(t, "operator", testinstance.Password)

	// Nothing yet: plain words, the add form for the admin only.
	html := viewer.get(t, "/endpoints").html()
	for _, want := range []string{"<h1", "Endpoints", "No endpoint is entered.", `href="/endpoints"`} {
		if !strings.Contains(html, want) {
			t.Errorf("empty page lacks %q", want)
		}
	}
	if strings.Contains(html, "Add one below") || strings.Contains(html, "Add endpoint") {
		t.Error("a viewer is offered the add form")
	}
	html = admin.get(t, "/endpoints").html()
	for _, want := range []string{"No endpoint is entered. Add one below.", "Add endpoint", `action="/endpoints"`, `name="host"`, `name="port"`, `name="sni"`,
		"0 of 100 endpoints are entered", "443, 465, 636, 853, 993, 995, 5061, 6514, 8443, 8883, 9443", "monitor.scan_ports"} {
		if !strings.Contains(html, want) {
			t.Errorf("admin's empty page lacks %q", want)
		}
	}
	if strings.Contains(html, "Scanning is switched off") {
		t.Error("the page says scanning is off")
	}

	// A certificate of the PKI that is served, one nobody here issued, one that fails.
	issued, err := e.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{"proxy.homelab.lan"}, ValidityDays: 90, Who: testinstance.Console})
	if err != nil {
		t.Fatal(err)
	}
	okID := e.add(t, "proxy.homelab.lan", 443)
	foreignID := e.add(t, "web.homelab.lan", 8443)
	downID := e.add(t, "nas.homelab.lan", 443)
	e.add(t, "new.homelab.lan", 443) // not scanned yet
	e.Clock.Advance(10 * time.Minute)
	e.serve(t, okID, issued.Fingerprint, "CN=Issuing CA", "CN=proxy.homelab.lan", issued.NotAfter)
	e.Clock.Advance(5 * time.Minute)
	e.serve(t, foreignID, strings.Repeat("AB", 32), "CN=Some Other CA", "CN=web.homelab.lan", e.Clock.Now().Add(40*24*time.Hour+time.Hour))
	e.fail(t, downID, tlsscan.KindTimeout, 3)

	page := admin.get(t, "/endpoints")
	html = page.html()
	if page.Code != http.StatusOK {
		t.Fatalf("admin: %d", page.Code)
	}
	for _, want := range []string{
		"proxy.homelab.lan:443", "web.homelab.lan:8443", "nas.homelab.lan:443",
		">OK<", "Not issued by this PKI", "Unreachable", "3 scans failed", "Pending",
		`title="` + e.Clock.Now().UTC().Format("2006-01-02 15:04") + ` UTC">just now`,
		"5 minutes ago",
		">Not yet",
		issued.Fingerprint[:16] + "…", `title="` + issued.Fingerprint + `"`, `href="/certificates/` + issued.ID + `"`,
		"CN=Issuing CA", "CN=Some Other CA", "timed out",
		"in 40 days", e.Clock.Now().Add(40*24*time.Hour + time.Hour).UTC().Format("2006-01-02"),
		"Certificate (SHA-256)", "Last error", "Added by", "console:test",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	plainPage(t, html)

	// Roles: the viewer reads, the operator scans, only the admin adds and removes and sees who added.
	for name, tc := range map[string]struct {
		b                        *browser
		scan, remove, add, added bool
	}{
		"viewer": {viewer, false, false, false, false}, "operator": {operator, true, false, false, false}, "admin": {admin, true, true, true, true},
	} {
		h := tc.b.get(t, "/endpoints").html()
		if got := strings.Contains(h, `action="/endpoints/scan"`) && strings.Contains(h, "Scan now"); got != tc.scan {
			t.Errorf("%s: Scan now = %v", name, got)
		}
		if got := strings.Contains(h, `action="/endpoints/delete"`) && strings.Contains(h, "Remove"); got != tc.remove {
			t.Errorf("%s: Remove = %v", name, got)
		}
		if got := strings.Contains(h, "Add endpoint"); got != tc.add {
			t.Errorf("%s: add form = %v", name, got)
		}
		if got := strings.Contains(h, "Added by") || strings.Contains(h, "console:test"); got != tc.added {
			t.Errorf("%s: who added it = %v", name, got)
		}
		if !strings.Contains(h, "proxy.homelab.lan:443") {
			t.Errorf("%s does not see the table", name)
		}
	}
}

// TestEndpointsPageStates: each state is shown in the words of the plan with
// its qualifier; an expiring certificate says Expiring.
func TestEndpointsPageStates(t *testing.T) {
	t.Parallel()
	e := newEndpointsUIEnv(t)
	old, err := e.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{"old.homelab.lan"}, ValidityDays: 90, Who: testinstance.Console})
	if err != nil {
		t.Fatal(err)
	}
	e.Clock.Advance(2 * time.Hour)
	if _, ierr := e.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{"old.homelab.lan"}, ValidityDays: 365, Who: testinstance.Console}); ierr != nil {
		t.Fatal(ierr)
	}
	cur, err := e.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{"soon.homelab.lan"}, ValidityDays: 90, Who: testinstance.Console})
	if err != nil {
		t.Fatal(err)
	}
	olderID := e.add(t, "old.homelab.lan", 443)
	soonID := e.add(t, "soon.homelab.lan", 443)
	e.serve(t, olderID, old.Fingerprint, "CN=Issuing CA", "CN=old.homelab.lan", old.NotAfter)
	e.serve(t, soonID, cur.Fingerprint, "CN=Issuing CA", "CN=soon.homelab.lan", e.Clock.Now().Add(49*time.Hour))
	admin := e.browser("192.0.2.1") // signed in after the clock moved: a session idles out after 30 minutes
	admin.signIn(t, "demo", e.DemoPassword)
	html := admin.get(t, "/endpoints").html()
	for _, want := range []string{"Wrong certificate", "an older certificate of this PKI", "Expiring", "in 2 days"} {
		if !strings.Contains(html, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(html, ">OK<") {
		t.Error("an expiring endpoint is shown as OK")
	}
}

// TestEndpointsPageEscapesWhatTheRemoteHostSent: the issuer and the subject
// of a served certificate are the remote host's text.
func TestEndpointsPageEscapesWhatTheRemoteHostSent(t *testing.T) {
	t.Parallel()
	e := newEndpointsUIEnv(t)
	admin := e.browser("192.0.2.1")
	admin.signIn(t, "demo", e.DemoPassword)
	id := e.add(t, "web.homelab.lan", 443)
	e.serve(t, id, strings.Repeat("CD", 32), `<script>alert("issuer")</script>`, `"><img src=x onerror=alert(1)>`, e.Clock.Now().Add(60*24*time.Hour))
	html := admin.get(t, "/endpoints").html()
	if strings.Contains(html, "<script>alert") || strings.Contains(html, "<img src=x") {
		t.Fatalf("the remote host's text reached the page unescaped: %s", html)
	}
	for _, want := range []string{"&lt;script&gt;alert(&#34;issuer&#34;)&lt;/script&gt;", "Subject: &#34;&gt;&lt;img src=x onerror=alert(1)&gt;"} {
		if !strings.Contains(html, want) {
			t.Errorf("page lacks the escaped %q", want)
		}
	}
}

// TestEndpointsPageForARoleLimitedToOneCA: the endpoints name the hosts of the
// whole tenant, so such a role gets the refusal and no navigation entry.
func TestEndpointsPageForARoleLimitedToOneCA(t *testing.T) {
	t.Parallel()
	e := newEndpointsUIEnv(t)
	e.add(t, "proxy.homelab.lan", 443)
	e.User(t, "caadmin", false, authz.Binding{CA: "issuing", Role: authz.Admin})
	b := e.browser("192.0.2.1")
	b.signIn(t, "caadmin", testinstance.Password)
	page := b.get(t, "/endpoints")
	if page.Code != http.StatusForbidden || strings.Contains(page.html(), "proxy.homelab.lan") {
		t.Errorf("endpoints: %d", page.Code)
	}
	for _, target := range []string{"/", "/alerts"} {
		if h := b.get(t, target).html(); strings.Contains(h, `href="/endpoints"`) {
			t.Errorf("%s has the navigation entry", target)
		}
	}
	token := b.csrf(t)
	for target, form := range map[string]url.Values{
		"/endpoints":        {"csrf_token": {token}, "host": {"x.homelab.lan"}, "port": {"443"}},
		"/endpoints/scan":   {"csrf_token": {token}, "id": {"ep_x"}},
		"/endpoints/delete": {"csrf_token": {token}, "id": {"ep_x"}},
	} {
		if r := b.post(t, target, form); r.Code != http.StatusForbidden {
			t.Errorf("POST %s: %d", target, r.Code)
		}
	}
}

// TestEndpointsPageWithoutMonitoring: no navigation entry, a plain note.
func TestEndpointsPageWithoutMonitoring(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	page := b.get(t, "/endpoints")
	if page.Code != http.StatusNotFound || !strings.Contains(page.html(), "Monitoring is off.") {
		t.Errorf("endpoints: %d", page.Code)
	}
	if strings.Contains(b.get(t, "/").html(), `href="/endpoints"`) {
		t.Error("the navigation has Endpoints")
	}
	token := b.csrf(t)
	if r := b.post(t, "/endpoints", url.Values{"csrf_token": {token}, "host": {"x.homelab.lan"}, "port": {"443"}}); r.Code != http.StatusNotFound {
		t.Errorf("POST /endpoints: %d", r.Code)
	}
}

// TestEndpointsScanOff: with monitor.scan_interval: off the page says so in
// one sentence, offers no Scan now, and endpoints can still be added.
func TestEndpointsScanOff(t *testing.T) {
	t.Parallel()
	e := newEndpointsUIEnv(t)
	id := e.add(t, "proxy.homelab.lan", 443)
	e.scan.Settings.Interval = 0
	admin := e.browser("192.0.2.1")
	admin.signIn(t, "demo", e.DemoPassword)
	html := admin.get(t, "/endpoints").html()
	if !strings.Contains(html, "Scanning is switched off (monitor.scan_interval: off)") || strings.Contains(html, "Scan now") || !strings.Contains(html, "Remove") {
		t.Errorf("page: %s", html)
	}
	token := admin.csrf(t)
	if r := admin.post(t, "/endpoints/scan", url.Values{"csrf_token": {token}, "id": {id}}); r.Code != http.StatusSeeOther {
		t.Fatalf("scan: %d", r.Code)
	}
	if got := flashOf(t, admin, "/endpoints"); !strings.Contains(got, "scanning is switched off (monitor.scan_interval: off)") {
		t.Errorf("flash: %s", got)
	}
}

// TestEndpointActionsFromThePage: Post/Redirect/Get for add, scan now and
// remove, with the service's refusals as messages that name the field and the
// rule and never echo the input; the roles are the service's.
func TestEndpointActionsFromThePage(t *testing.T) {
	t.Parallel()
	e := newEndpointsUIEnv(t)
	e.User(t, "viewer", false, authz.Binding{Role: authz.Viewer})
	e.User(t, "operator", false, authz.Binding{Role: authz.Operator})
	admin, viewer, operator := e.browser("192.0.2.1"), e.browser("192.0.2.2"), e.browser("192.0.2.3")
	admin.signIn(t, "demo", e.DemoPassword)
	viewer.signIn(t, "viewer", testinstance.Password)
	operator.signIn(t, "operator", testinstance.Password)
	adminToken, viewerToken, operatorToken := admin.csrf(t), viewer.csrf(t), operator.csrf(t)

	// Without the CSRF token nothing happens.
	if r := admin.post(t, "/endpoints", url.Values{"host": {"proxy.homelab.lan"}, "port": {"443"}}); r.Code == http.StatusSeeOther && r.location() == "/endpoints" {
		t.Errorf("add without the CSRF token: %d %q", r.Code, r.location())
	}

	// Add: 303, a message, the row.
	res := admin.post(t, "/endpoints", url.Values{"csrf_token": {adminToken}, "host": {" Proxy.Homelab.LAN. "}, "port": {"443"}, "sni": {""}})
	if res.Code != http.StatusSeeOther || res.location() != "/endpoints" {
		t.Fatalf("add: %d %q", res.Code, res.location())
	}
	page := admin.get(t, "/endpoints").html()
	if !strings.Contains(strings.Join(messages(page), " "), "Endpoint proxy.homelab.lan:443 added. It is scanned within a minute.") || !strings.Contains(page, "proxy.homelab.lan:443") {
		t.Errorf("after the add: %v", messages(page))
	}
	if again := strings.Join(messages(admin.get(t, "/endpoints").html()), ""); strings.Contains(again, "added") {
		t.Error("the message stayed on the page")
	}

	// Refusals: the service's field and rule, nothing of the input.
	for name, tc := range map[string]struct {
		form url.Values
		want string
	}{
		"loopback":             {url.Values{"host": {"127.0.0.1"}, "port": {"443"}}, "Not added – host: this address range is never scanned"},
		"markup":               {url.Values{"host": {"<script>alert(1)</script>.homelab.lan"}, "port": {"443"}}, "Not added – host: a host name or IP address only"},
		"no domain":            {url.Values{"host": {"proxy.example.net"}, "port": {"443"}}, "Not added – host: no domain covers this host"},
		"a closed port":        {url.Values{"host": {"web.homelab.lan"}, "port": {"22"}}, "Not added – port: port 22 is not in the list of scannable ports (monitor.scan_ports: 443, 465"},
		"port as text":         {url.Values{"host": {"web.homelab.lan"}, "port": {"https"}}, "Not added – port: enter the port as a number"},
		"an SNI that is an IP": {url.Values{"host": {"web.homelab.lan"}, "port": {"443"}, "sni": {"192.0.2.9"}}, "Not added – sni: a DNS name"},
		"a duplicate":          {url.Values{"host": {"proxy.homelab.lan"}, "port": {"443"}}, "Not added – this endpoint is entered already."},
	} {
		tc.form.Set("csrf_token", adminToken)
		r := admin.post(t, "/endpoints", tc.form)
		got := flashOf(t, admin, "/endpoints")
		if r.Code != http.StatusSeeOther || !strings.Contains(got, tc.want) {
			t.Errorf("%s: %d, messages %s", name, r.Code, got)
		}
		if strings.Contains(got, "script") || strings.Contains(got, "127.0.0.1") {
			t.Errorf("%s: the message echoes the input: %s", name, got)
		}
	}
	// Refused adds are on record as denied; the one that worked as success.
	if got := e.endpointAudit(t); got["endpoint.create/success"] != 1 || got["endpoint.create/denied"] != 5 || got["endpoint.create/failure"] != 1 {
		t.Errorf("audit after the adds: %v", got)
	}

	// Viewer and operator cannot add or remove; the page answers 403 and nothing changes.
	list, err := e.scan.List(t.Context(), testinstance.Console)
	if err != nil || len(list) != 1 {
		t.Fatalf("endpoints: %v %v", list, err)
	}
	id := list[0].ID
	for name, b := range map[string]struct {
		b     *browser
		token string
	}{"viewer": {viewer, viewerToken}, "operator": {operator, operatorToken}} {
		if r := b.b.post(t, "/endpoints", url.Values{"csrf_token": {b.token}, "host": {"web.homelab.lan"}, "port": {"443"}}); r.Code != http.StatusForbidden {
			t.Errorf("%s add: %d", name, r.Code)
		}
		if r := b.b.post(t, "/endpoints/delete", url.Values{"csrf_token": {b.token}, "id": {id}}); r.Code != http.StatusForbidden {
			t.Errorf("%s remove: %d", name, r.Code)
		}
	}
	if r := viewer.post(t, "/endpoints/scan", url.Values{"csrf_token": {viewerToken}, "id": {id}}); r.Code != http.StatusForbidden {
		t.Errorf("viewer scan: %d", r.Code)
	}

	// Scan now: the operator may; a second click is told to wait.
	res = operator.post(t, "/endpoints/scan", url.Values{"csrf_token": {operatorToken}, "id": {id}})
	if res.Code != http.StatusSeeOther || res.location() != "/endpoints" || !strings.Contains(flashOf(t, operator, "/endpoints"), "Scan requested.") {
		t.Errorf("operator scan: %d %q", res.Code, res.location())
	}
	res = operator.post(t, "/endpoints/scan", url.Values{"csrf_token": {operatorToken}, "id": {id}})
	if got := flashOf(t, operator, "/endpoints"); res.Code != http.StatusSeeOther || !strings.Contains(got, "was scanned on request a moment ago") || !strings.Contains(got, "msg-warn") {
		t.Errorf("second scan: %d %s", res.Code, got)
	}
	e.Clock.Advance(61 * time.Second)
	if r := admin.post(t, "/endpoints/scan", url.Values{"csrf_token": {adminToken}, "id": {id}}); r.Code != http.StatusSeeOther {
		t.Errorf("admin scan after a minute: %d", r.Code)
	}
	_ = flashOf(t, admin, "/endpoints")
	if r := admin.post(t, "/endpoints/scan", url.Values{"csrf_token": {adminToken}, "id": {"ep_unknown"}}); r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, admin, "/endpoints"), "gone already") {
		t.Errorf("unknown endpoint: %d", r.Code)
	}

	// Remove.
	res = admin.post(t, "/endpoints/delete", url.Values{"csrf_token": {adminToken}, "id": {id}})
	if res.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, admin, "/endpoints"), "Endpoint removed.") {
		t.Errorf("remove: %d", res.Code)
	}
	if list, _ := e.scan.List(t.Context(), testinstance.Console); len(list) != 0 {
		t.Errorf("%d endpoints left", len(list))
	}
	if r := admin.post(t, "/endpoints/delete", url.Values{"csrf_token": {adminToken}, "id": {id}}); r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, admin, "/endpoints"), "gone already") {
		t.Errorf("second remove: %d", r.Code)
	}
	if got := e.endpointAudit(t); got["endpoint.delete/success"] != 1 || got["endpoint.scan/success"] != 2 || got["endpoint.delete/denied"] != 2 || got["endpoint.scan/denied"] != 1 {
		t.Errorf("audit at the end: %v", got)
	}
}

// TestEndpointActionsWithHostileIDs: the "id" of the scan and remove forms is
// attacker input. The role is checked first (403), the audit entry of that
// refusal names no ID that is not well-formed, and an admin who posts garbage
// gets the plain "gone already" message and no audit entry at all.
func TestEndpointActionsWithHostileIDs(t *testing.T) {
	t.Parallel()
	e := newEndpointsUIEnv(t)
	e.User(t, "viewer", false, authz.Binding{Role: authz.Viewer})
	admin, viewer := e.browser("192.0.2.1"), e.browser("192.0.2.2")
	admin.signIn(t, "demo", e.DemoPassword)
	viewer.signIn(t, "viewer", testinstance.Password)
	adminToken, viewerToken := admin.csrf(t), viewer.csrf(t)

	ids := map[string]string{
		"escape sequence": "ep_\x1b[31mred",
		"nul":             "ep_\x00x",
		"newline":         "ep_1\nendpoint.delete/success",
		"bidi override":   "ep_" + string(rune(0x202e)) + "1",
		"over-long":       strings.Repeat("a", 5000),
		"path":            "../../etc/passwd",
		"empty":           "",
	}
	for name, id := range ids {
		for _, path := range []string{"/endpoints/scan", "/endpoints/delete"} {
			if r := viewer.post(t, path, url.Values{"csrf_token": {viewerToken}, "id": {id}}); r.Code != http.StatusForbidden {
				t.Errorf("viewer %s %s: %d, want 403", path, name, r.Code)
			}
			r := admin.post(t, path, url.Values{"csrf_token": {adminToken}, "id": {id}})
			if got := flashOf(t, admin, "/endpoints"); r.Code != http.StatusSeeOther || !strings.Contains(got, "gone already") {
				t.Errorf("admin %s %s: %d, %s", path, name, r.Code, got)
			}
		}
	}
	e.Deliver(t)
	rows, err := e.TenantAudit.Read.QueryContext(t.Context(), `SELECT action, result, target_id, details_json FROM audit_entries WHERE action LIKE 'endpoint.%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	wellFormed := regexp.MustCompile(`^[0-9A-Za-z_-]{0,64}$`)
	n := 0
	for rows.Next() {
		var action, result, target, details string
		if err := rows.Scan(&action, &result, &target, &details); err != nil {
			t.Fatal(err)
		}
		n++
		if result != "denied" || !wellFormed.MatchString(target) || strings.ContainsAny(details, "\x1b"+string(rune(0x202e))) || len(details) > 600 {
			t.Errorf("audit entry %s/%s target %q details %q", action, result, target, details)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if want := 2 * len(ids); n != want { // the viewer's two refusals per ID; the admin's "not found" is no event
		t.Errorf("%d audit entries, want %d", n, want)
	}
}

// TestAlertKindsOfTheScan: the four scan kinds have their own names on the
// Alerts page, and the alert links to the Endpoints page.
func TestAlertKindsOfTheScan(t *testing.T) {
	t.Parallel()
	for kind, want := range map[string]string{
		monitor.KindScanMismatch: "Wrong certificate served", monitor.KindScanExpiry: "Served certificate expires",
		monitor.KindScanUnreachable: "Endpoint unreachable", monitor.KindScanChain: "Chain problem",
	} {
		if got := alertKind(kind); got != want {
			t.Errorf("alertKind(%s) = %q, want %q", kind, got, want)
		}
	}
	e := newEndpointsUIEnv(t)
	if _, err := e.alerts.Sync(t.Context(), e.Clock.Now(), []monitor.Finding{{
		Key: "scan_mismatch:ep_1", Kind: monitor.KindScanMismatch, Subject: "proxy.homelab.lan:443", Severity: monitor.Warning,
		Detail: "proxy.homelab.lan:443 serves an older certificate - reload the service.", Href: "/endpoints",
	}}); err != nil {
		t.Fatal(err)
	}
	b := e.browser("192.0.2.1")
	b.signIn(t, "demo", e.DemoPassword)
	html := b.get(t, "/alerts").html()
	for _, want := range []string{"Wrong certificate served", "proxy.homelab.lan:443", `<a href="/endpoints">proxy.homelab.lan:443 serves an older certificate - reload the service.</a>`} {
		if !strings.Contains(html, want) {
			t.Errorf("Alerts page lacks %q", want)
		}
	}
}

func TestAgo(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	for d, want := range map[time.Duration]string{
		-time.Minute: "just now", 0: "just now", 59 * time.Second: "just now", time.Minute: "1 minute ago", 5 * time.Minute: "5 minutes ago",
		59 * time.Minute: "59 minutes ago", time.Hour: "1 hour ago", 47 * time.Hour: "47 hours ago", 48 * time.Hour: "2 days ago", 10 * 24 * time.Hour: "10 days ago",
	} {
		if got := ago(now, now.Add(-d)); got != want {
			t.Errorf("ago(-%s) = %q, want %q", d, got, want)
		}
	}
}
