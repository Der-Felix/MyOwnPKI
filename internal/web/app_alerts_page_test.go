package web

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/monitor"
	"github.com/Der-Felix/MyOwnPKI/internal/notify"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// stubChannel is a notification channel that records what it was sent.
type stubChannel struct {
	name string
	err  error
	mu   sync.Mutex
	got  int
}

func (s *stubChannel) Name() string { return s.name }

func (s *stubChannel) Send(context.Context, notify.Digest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got++
	return s.err
}

func (s *stubChannel) sent() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.got
}

// alertsUIEnv is the UI with the monitoring on.
type alertsUIEnv struct {
	*uiEnv
	alerts *monitor.Store
	tester *notify.Tester
}

func newAlertsUIEnv(t *testing.T, channels ...notify.Channel) *alertsUIEnv {
	t.Helper()
	v := &uiEnv{Instance: testinstance.New(t, testinstance.Options{})}
	e := &alertsUIEnv{uiEnv: v, alerts: &monitor.Store{DB: v.SystemDB.Write, Tenant: store.DefaultTenant}}
	e.tester = &notify.Tester{Channels: channels, Server: "pki01", Clock: v.Clock, Audit: v.TenantAudit.Write, Scope: v.Engine.Scope, Tenant: store.DefaultTenant}
	h, err := NewHandler(Options{Logger: slog.New(slog.NewJSONHandler(&v.logs, nil)), App: &AppDeps{
		Auth: v.Auth, Engine: v.Engine, Keys: v.Ring, Presets: v.Presets, Clock: v.Clock, Demo: true, Tenant: store.DefaultTenant,
		Settings: &tenant.Store{DB: v.SystemDB.Write, Clock: v.Clock}, TenantAudit: v.TenantAudit.Read, InstanceAudit: v.InstanceAudit.Read,
		Alerts: e.alerts, Notifier: e.tester,
	}})
	if err != nil {
		t.Fatal(err)
	}
	v.h = h
	return e
}

func (e *alertsUIEnv) sync(t *testing.T, findings ...monitor.Finding) {
	t.Helper()
	if _, err := e.alerts.Sync(t.Context(), e.Clock.Now(), findings); err != nil {
		t.Fatal(err)
	}
}

// notified lists the notification entries of the tenant audit log.
func (e *alertsUIEnv) notified(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, a := range testinstance.Audit(t, e.TenantAudit) {
		if strings.HasPrefix(a, "notification.") {
			out = append(out, a)
		}
	}
	return out
}

var (
	sealedFinding = monitor.Finding{Key: "sealed", Kind: monitor.KindSealed, Subject: "Server sealed", Severity: monitor.Critical,
		Detail: "The server is sealed and a CRL ends in 5 hours - unseal it.", Href: "/unseal"}
	// The subject comes from a certificate: attacker input.
	hostileFinding = monitor.Finding{Key: "cert:1", Kind: monitor.KindCertExpiry, Subject: "<script>alert(1)</script>.homelab.lan", Severity: monitor.Warning,
		Detail: "Ends in 9 days - renew it.", Href: "/certificates/crt_1"}
)

// TestAlertsPage: open and resolved alerts in two tables with the detail as
// a link, hostile subjects escaped, empty states in plain words; a viewer
// reads it and sees no button; an admin gets the test button when a channel
// exists and the one-sentence note when none does.
func TestAlertsPage(t *testing.T) {
	t.Parallel()
	e := newAlertsUIEnv(t, &stubChannel{name: "email"}, &stubChannel{name: "webhook"})
	e.User(t, "viewer", false, authz.Binding{Role: authz.Viewer})
	e.User(t, "operator", false, authz.Binding{Role: authz.Operator})
	admin, viewer, operator := e.browser("192.0.2.1"), e.browser("192.0.2.2"), e.browser("192.0.2.3")
	admin.signIn(t, "demo", e.DemoPassword)
	viewer.signIn(t, "viewer", testinstance.Password)
	operator.signIn(t, "operator", testinstance.Password)

	// Nothing yet.
	html := viewer.get(t, "/alerts").html()
	for _, want := range []string{"<h1", "Alerts", "No alert is open.", "No alert was resolved in the last 7 days."} {
		if !strings.Contains(html, want) {
			t.Errorf("empty page lacks %q", want)
		}
	}

	e.sync(t, sealedFinding, hostileFinding)
	e.Clock.Advance(10 * time.Minute)
	e.sync(t, sealedFinding) // the hostile one is resolved
	page := viewer.get(t, "/alerts")
	html = page.html()
	if page.Code != http.StatusOK {
		t.Fatalf("viewer: %d", page.Code)
	}
	for _, want := range []string{
		"Open", "Resolved in the last 7 days", "critical", `<td class="nowrap">Server sealed `,
		`<a href="/unseal">The server is sealed and a CRL ends in 5 hours - unseal it.</a>`,
		"Certificate expires", "&lt;script&gt;alert(1)&lt;/script&gt;.homelab.lan", "today",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(html, "<script>alert") || strings.Contains(html, "Ends in 9 days") {
		t.Error("a certificate name reached the page unescaped, or the detail of a resolved alert is shown as open")
	}
	if !strings.Contains(html, `href="/alerts"`) {
		t.Error("the navigation lacks Alerts")
	}

	// The test button: admins only, and only with a channel.
	for name, b := range map[string]*browser{"viewer": viewer, "operator": operator} {
		h := b.get(t, "/alerts").html()
		if strings.Contains(h, "Send test message") || strings.Contains(h, "/alerts/test") || strings.Contains(h, "Notifications") {
			t.Errorf("%s sees the test: %s", name, h)
		}
	}
	h := admin.get(t, "/alerts").html()
	for _, want := range []string{"Send test message", `action="/alerts/test"`, "through email and webhook"} {
		if !strings.Contains(h, want) {
			t.Errorf("admin page lacks %q", want)
		}
	}

	// No channel: everybody reads the one sentence, nobody gets a button.
	e.tester.Channels = nil
	for name, b := range map[string]*browser{"viewer": viewer, "admin": admin} {
		h := b.get(t, "/alerts").html()
		if !strings.Contains(h, "No notification channel is configured, so nobody is told about alerts") || !strings.Contains(h, "notify.email or notify.webhook") || strings.Contains(h, "Send test message") {
			t.Errorf("%s without a channel: %s", name, h)
		}
	}
}

// TestAlertsPageForARoleLimitedToOneCA: the alerts name objects of the
// whole tenant; a role limited to one CA gets the refusal and no
// navigation entry.
func TestAlertsPageForARoleLimitedToOneCA(t *testing.T) {
	t.Parallel()
	e := newAlertsUIEnv(t, &stubChannel{name: "email"})
	e.User(t, "caviewer", false, authz.Binding{CA: "issuing", Role: authz.Viewer})
	e.sync(t, sealedFinding)
	b := e.browser("192.0.2.1")
	b.signIn(t, "caviewer", testinstance.Password)
	page := b.get(t, "/alerts")
	if page.Code != http.StatusForbidden || strings.Contains(page.html(), "Server sealed") {
		t.Errorf("alerts: %d %s", page.Code, page.html())
	}
	dash := b.get(t, "/")
	if dash.Code != http.StatusOK || strings.Contains(dash.html(), "Open alerts") || strings.Contains(dash.html(), `href="/alerts"`) {
		t.Errorf("dashboard: %d", dash.Code)
	}
}

// TestSendTestMessageFromThePage: the admin's POST sends through every
// channel and the Alerts page lists each channel's result; a failure names
// its reason; a second click is told to wait; a viewer is refused and
// nothing is sent.
func TestSendTestMessageFromThePage(t *testing.T) {
	t.Parallel()
	mail := &stubChannel{name: "email"}
	hook := &stubChannel{name: "webhook", err: errors.New("webhook hooks.homelab.lan answered 502 Bad Gateway")}
	e := newAlertsUIEnv(t, mail, hook)
	e.User(t, "viewer", false, authz.Binding{Role: authz.Viewer})
	admin, viewer := e.browser("192.0.2.1"), e.browser("192.0.2.2")
	admin.signIn(t, "demo", e.DemoPassword)
	viewer.signIn(t, "viewer", testinstance.Password)
	adminToken, viewerToken := admin.csrf(t), viewer.csrf(t)

	if r := viewer.post(t, "/alerts/test", url.Values{"csrf_token": {viewerToken}}); r.Code != http.StatusForbidden {
		t.Errorf("viewer: %d", r.Code)
	}
	if mail.sent()+hook.sent() != 0 {
		t.Fatal("a refused test was sent")
	}
	if r := admin.post(t, "/alerts/test", url.Values{}); r.Code == http.StatusSeeOther && r.location() == "/alerts" || mail.sent() != 0 {
		t.Errorf("without the CSRF token: %d %q", r.Code, r.location())
	}

	r := admin.post(t, "/alerts/test", url.Values{"csrf_token": {adminToken}})
	if r.Code != http.StatusSeeOther || r.location() != "/alerts" {
		t.Fatalf("admin: %d %q", r.Code, r.location())
	}
	msgs := strings.Join(messages(admin.get(t, "/alerts").html()), " | ")
	for _, want := range []string{"The test message went out through email.", "The test message through webhook failed: webhook hooks.homelab.lan answered 502 Bad Gateway"} {
		if !strings.Contains(msgs, want) {
			t.Errorf("messages lack %q: %s", want, msgs)
		}
	}
	if mail.sent() != 1 || hook.sent() != 1 {
		t.Errorf("sent: %d, %d", mail.sent(), hook.sent())
	}
	if got := e.notified(t); len(got) != 2 || got[0] != "notification.test/denied" || got[1] != "notification.test/failure" {
		t.Errorf("audit: %v", got)
	}

	// The message is gone after one view; a second click comes too soon.
	if again := strings.Join(messages(admin.get(t, "/alerts").html()), ""); strings.Contains(again, "went out") {
		t.Error("the result stayed on the page")
	}
	r = admin.post(t, "/alerts/test", url.Values{"csrf_token": {adminToken}})
	if r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, admin, "/alerts"), "a test message was sent a moment ago") || mail.sent() != 1 {
		t.Errorf("second click: %d, sent %d", r.Code, mail.sent())
	}

	// No channel: the page says so instead.
	e.Clock.Advance(time.Minute)
	e.tester.Channels = nil
	r = admin.post(t, "/alerts/test", url.Values{"csrf_token": {adminToken}})
	if r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, admin, "/alerts"), "no notification channel is configured") {
		t.Errorf("no channel: %d", r.Code)
	}
}

// TestDashboardLinksToTheAlerts: the open-alert figure names the critical
// ones and links to the page, and the attention block has "All alerts".
func TestDashboardLinksToTheAlerts(t *testing.T) {
	t.Parallel()
	e := newAlertsUIEnv(t)
	e.sync(t, sealedFinding, hostileFinding)
	b := e.browser("192.0.2.1")
	b.signIn(t, "demo", e.DemoPassword)
	html := b.get(t, "/").html()
	for _, want := range []string{"Open alerts, 1 critical", `<a href="/alerts">2</a>`, `<a href="/alerts">All alerts</a>`} {
		if !strings.Contains(html, want) {
			t.Errorf("dashboard lacks %q", want)
		}
	}
}
