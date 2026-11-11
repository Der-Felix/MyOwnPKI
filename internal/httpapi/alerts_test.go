package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/monitor"
)

// notified lists the notification entries of the tenant audit log.
func (v *env) notified(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, e := range v.audit(t, v.ta) {
		if strings.HasPrefix(e, "notification.") {
			out = append(out, e)
		}
	}
	return out
}

func (v *env) syncAlerts(t *testing.T, findings ...monitor.Finding) {
	t.Helper()
	if _, err := v.alerts.Sync(t.Context(), v.clk.Now(), findings); err != nil {
		t.Fatal(err)
	}
}

func alertFinding(key, severity string) monitor.Finding {
	return monitor.Finding{Key: key, Kind: monitor.KindCertExpiry, Subject: key + ".homelab.lan", Severity: severity,
		Detail: key + ".homelab.lan ends in 2 days - renew it.", Href: "/certificates/crt_" + key}
}

// alertClients signs in the roles of these tests.
func alertClients(t *testing.T, v *env) (admin, viewer, operator, caAdmin, nobody, anon *client) {
	t.Helper()
	v.user(t, "viewer", false, authz.Binding{Role: authz.Viewer})
	v.user(t, "operator", false, authz.Binding{Role: authz.Operator})
	v.user(t, "caadmin", false, authz.Binding{CA: "issuing", Role: authz.Admin})
	v.user(t, "nobody", false)
	admin, viewer, operator, caAdmin, nobody, anon = v.client("192.0.2.1"), v.client("192.0.2.2"), v.client("192.0.2.3"), v.client("192.0.2.4"), v.client("192.0.2.5"), v.client("192.0.2.9")
	admin.signIn(t, "demo", v.demoPass)
	viewer.signIn(t, "viewer", testPassword)
	operator.signIn(t, "operator", testPassword)
	caAdmin.signIn(t, "caadmin", testPassword)
	nobody.signIn(t, "nobody", testPassword)
	return
}

// alertList decodes the answer of GET /alerts.
func alertList(t *testing.T, r *resp) []map[string]any {
	t.Helper()
	var list []map[string]any
	if err := json.Unmarshal(r.Body.Bytes(), &list); err != nil {
		t.Fatalf("no alert list (%d): %s", r.Code, r.Body.String())
	}
	return list
}

// alertNames lists "name/state" of the answer.
func alertNames(t *testing.T, r *resp) []string {
	t.Helper()
	var out []string
	for _, m := range alertList(t, r) {
		s, _ := m["subject"].(string)
		state, _ := m["state"].(string)
		out = append(out, strings.TrimSuffix(s, ".homelab.lan")+"/"+state)
	}
	return out
}

// TestListAlerts: the open alerts come first, then those resolved in the
// last 7 days; viewers read it (also while the server is sealed), a role
// limited to one CA and users without a role do not.
func TestListAlerts(t *testing.T) {
	t.Parallel()
	v := newEnv(t) // sealed: the alerts are readable anyway
	admin, viewer, operator, caAdmin, nobody, anon := alertClients(t, v)

	v.syncAlerts(t, alertFinding("a", monitor.Critical), alertFinding("b", monitor.Warning), alertFinding("c", monitor.Warning))
	opened := v.clk.Now()
	v.clk.Advance(5 * time.Minute)
	v.syncAlerts(t, alertFinding("a", monitor.Critical)) // b and c are resolved
	resolved := v.clk.Now()

	r := viewer.do(t, http.MethodGet, "/alerts", nil)
	if r.Code != http.StatusOK {
		t.Fatalf("viewer: %d %s", r.Code, r.Body.String())
	}
	got := alertNames(t, r)
	if len(got) != 3 || got[0] != "a/open" || !slices.Contains(got, "b/resolved") || !slices.Contains(got, "c/resolved") {
		t.Fatalf("alerts: %v", got)
	}
	first := alertList(t, r)[0]
	for field, want := range map[string]any{
		"kind": "cert_expiry", "severity": "critical", "state": "open", "subject": "a.homelab.lan", "href": "/certificates/crt_a",
		"detail": "a.homelab.lan ends in 2 days - renew it.", "resolved_at": nil,
		"first_seen": opened.UTC().Format(time.RFC3339), "last_seen": resolved.UTC().Format(time.RFC3339),
	} {
		if first[field] != want {
			t.Errorf("%s = %v, want %v", field, first[field], want)
		}
	}
	if id, _ := first["id"].(string); !strings.HasPrefix(id, "alr_") || len(first) != 10 {
		t.Errorf("id %q, fields %v", id, first)
	}
	done := alertList(t, r)[1]
	if done["state"] != "resolved" || done["resolved_at"] != resolved.UTC().Format(time.RFC3339) {
		t.Errorf("resolved alert: %v", done)
	}

	// The filter.
	if got := alertNames(t, admin.do(t, http.MethodGet, "/alerts?state=open", nil)); len(got) != 1 || got[0] != "a/open" {
		t.Errorf("state=open: %v", got)
	}
	if got := alertNames(t, admin.do(t, http.MethodGet, "/alerts?state=resolved", nil)); len(got) != 2 || strings.HasSuffix(got[0], "/open") {
		t.Errorf("state=resolved: %v", got)
	}
	if r := admin.do(t, http.MethodGet, "/alerts?state=all", nil); r.Code != http.StatusBadRequest || r.problemType() != "bad-request" {
		t.Errorf("state=all: %d %s", r.Code, r.Body.String())
	}

	// Roles: an operator reads as well; a CA admin or a user without a role
	// does not read the alerts of the whole tenant.
	for name, c := range map[string]*client{"operator": operator, "admin": admin} {
		if r := c.do(t, http.MethodGet, "/alerts", nil); r.Code != http.StatusOK {
			t.Errorf("%s: %d", name, r.Code)
		}
	}
	for name, c := range map[string]*client{"caadmin": caAdmin, "nobody": nobody} {
		if r := c.do(t, http.MethodGet, "/alerts", nil); r.Code != http.StatusForbidden || r.problemType() != "forbidden" {
			t.Errorf("%s: %d %s", name, r.Code, r.Body.String())
		}
	}
	if r := anon.do(t, http.MethodGet, "/alerts", nil); r.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", r.Code)
	}
	if got := v.notified(t); len(got) != 0 {
		t.Errorf("reading wrote audit entries: %v", got)
	}

	// The window is 7 days from the resolution: the two stay for exactly
	// that long, the open one stays.
	v.clk.Advance(monitor.ResolvedWindow - 5*time.Minute)
	viewer.signIn(t, "viewer", testPassword) // the session ended long ago
	if got := alertNames(t, viewer.do(t, http.MethodGet, "/alerts", nil)); len(got) != 3 {
		t.Errorf("inside 7 days: %v", got)
	}
	v.clk.Advance(10 * time.Minute)
	viewer.signIn(t, "viewer", testPassword)
	if got := alertNames(t, viewer.do(t, http.MethodGet, "/alerts", nil)); len(got) != 1 || got[0] != "a/open" {
		t.Errorf("after 7 days: %v", got)
	}
}

// TestSendTestNotification: only an admin sends the test; it goes through
// every channel, is audited, is rate limited, and a failing channel shows
// up in the answer.
func TestSendTestNotification(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	admin, viewer, operator, caAdmin, nobody, anon := alertClients(t, v)
	url := "/notifications/test"

	for name, c := range map[string]*client{"viewer": viewer, "operator": operator, "caadmin": caAdmin, "nobody": nobody} {
		if r := c.do(t, http.MethodPost, url, nil); r.Code != http.StatusForbidden || r.problemType() != "forbidden" {
			t.Errorf("%s: %d %s", name, r.Code, r.Body.String())
		}
	}
	if r := anon.do(t, http.MethodPost, url, nil); r.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", r.Code)
	}
	if v.mail.sent()+v.hook.sent() != 0 {
		t.Fatal("a refused test sent a message")
	}
	if got := v.notified(t); len(got) != 4 || slices.ContainsFunc(got, func(e string) bool { return e != "notification.test/denied" }) {
		t.Errorf("audit after the refusals: %v", got)
	}

	r := admin.do(t, http.MethodPost, url, nil)
	if r.Code != http.StatusOK {
		t.Fatalf("admin: %d %s", r.Code, r.Body.String())
	}
	channels, _ := r.body["channels"].([]any)
	if len(channels) != 2 || strings.Contains(r.Body.String(), "error") {
		t.Fatalf("answer: %s", r.Body.String())
	}
	if first, _ := channels[0].(map[string]any); first["channel"] != "email" || first["ok"] != true {
		t.Errorf("first channel: %v", first)
	}
	if v.mail.sent() != 1 || v.hook.sent() != 1 || v.mail.got[0].Events[0].State != "test" || v.mail.got[0].Server != "pki01" {
		t.Errorf("sent: mail %d, hook %d", v.mail.sent(), v.hook.sent())
	}
	if got := v.notified(t); got[len(got)-1] != "notification.test/success" || len(got) != 5 {
		t.Errorf("audit: %v", got)
	}

	// Again at once: too soon.
	if again := admin.do(t, http.MethodPost, url, nil); again.Code != http.StatusTooManyRequests || again.problemType() != "rate-limited" || again.Header().Get("Retry-After") == "" {
		t.Errorf("second test: %d %s", again.Code, again.Body.String())
	}
	if v.mail.sent() != 1 {
		t.Error("the refused test was sent")
	}

	// A failing channel: the call works, the channel says why.
	v.clk.Advance(time.Minute)
	v.hook.err = errors.New("webhook hooks.homelab.lan answered 502 Bad Gateway")
	r = admin.do(t, http.MethodPost, url, nil)
	if r.Code != http.StatusOK {
		t.Fatalf("failing channel: %d %s", r.Code, r.Body.String())
	}
	failed, _ := r.body["channels"].([]any)[1].(map[string]any)
	if failed["channel"] != "webhook" || failed["ok"] != false || failed["error"] != "webhook hooks.homelab.lan answered 502 Bad Gateway" {
		t.Errorf("failing channel: %s", r.Body.String())
	}
	if got := v.notified(t); got[len(got)-1] != "notification.test/failure" {
		t.Errorf("audit: %v", got)
	}

	// An API token of the admin works as well (no step-up involved).
	admin.stepUp(t, "demo")
	tok := admin.do(t, http.MethodPost, "/tokens", map[string]any{"name": "alerts", "expires_at": v.clk.Now().Add(24 * time.Hour).Format(time.RFC3339),
		"roles": []map[string]any{{"role": "admin", "scope": map[string]string{"type": "tenant"}}}})
	secret, _ := tok.body["secret"].(string)
	if tok.Code != http.StatusCreated || secret == "" {
		t.Fatalf("token: %d %s", tok.Code, tok.Body.String())
	}
	v.hook.err = nil
	v.clk.Advance(time.Minute)
	bot := v.client("192.0.2.77")
	if viaToken := bot.do(t, http.MethodPost, url, nil, "Authorization", "Bearer "+secret); viaToken.Code != http.StatusOK {
		t.Errorf("token: %d %s", viaToken.Code, viaToken.Body.String())
	}

	// No channel configured: a clear refusal, nothing audited.
	before := len(v.notified(t))
	v.clk.Advance(time.Minute)
	v.tester.Channels = nil
	r = admin.do(t, http.MethodPost, url, nil)
	if r.Code != http.StatusConflict || r.problemType() != "conflict" || !strings.Contains(r.Body.String(), "notify.email or notify.webhook") {
		t.Errorf("no channel: %d %s", r.Code, r.Body.String())
	}
	if after := len(v.notified(t)); after != before {
		t.Errorf("audit entries %d -> %d", before, after)
	}
}
