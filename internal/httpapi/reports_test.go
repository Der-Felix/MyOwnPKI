package httpapi

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Der-Felix/MyOwnPKI/internal/analysis"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/monitor"
	"github.com/Der-Felix/MyOwnPKI/internal/report"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// asList reads a JSON array out of a decoded object.
func asList(t *testing.T, m map[string]any, keys ...string) []any {
	t.Helper()
	var n any = m
	for _, k := range keys {
		obj, ok := n.(map[string]any)
		if !ok {
			t.Fatalf("no object at %v in %v", keys, m)
		}
		n = obj[k]
	}
	list, ok := n.([]any)
	if !ok {
		t.Fatalf("%v is no list: %v", keys, n)
	}
	return list
}

// issueFor issues a server certificate for the names through the engine.
func (v *env) issueFor(t *testing.T, dns string) {
	t.Helper()
	if _, err := v.engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{dns}, Who: testinstance.Console}); err != nil {
		t.Fatal(err)
	}
}

// token makes an API token with one role and returns the bearer header.
func (v *env) token(t *testing.T, admin *client, name string, scope map[string]string) []string {
	t.Helper()
	admin.stepUp(t, "demo")
	r := admin.do(t, http.MethodPost, "/tokens", map[string]any{"name": name, "expires_at": v.clk.Now().Add(24 * time.Hour).Format(time.RFC3339),
		"roles": []map[string]any{{"role": "viewer", "scope": scope}}})
	if r.Code != http.StatusCreated {
		t.Fatalf("token %s: %d %s", name, r.Code, r.Body.String())
	}
	secret, _ := r.body["secret"].(string)
	return []string{"Authorization", "Bearer " + secret}
}

// TestGetReports: the report is readable by every role that may read the
// whole tenant (also while the server is sealed), by a token with a
// tenant-wide role, and by nobody else; the numbers follow the data, a
// second read inside a minute is the cached one, and the agent block is
// null while the agent listener is off.
func TestGetReports(t *testing.T) {
	t.Parallel()
	v := newEnv(t) // sealed: the report is readable anyway
	admin, viewer, operator, caAdmin, nobody, anon := alertClients(t, v)

	r := viewer.do(t, http.MethodGet, "/reports", nil)
	if r.Code != http.StatusOK {
		t.Fatalf("viewer: %d %s", r.Code, r.Body.String())
	}
	if cc := r.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control %q", cc)
	}
	// The shape: 13 expiry weeks from the Monday of this week, 12 issuance
	// weeks ending with this one, 5 alert weeks, a fleet block of zeros.
	weeks := asList(t, r.body, "expiry", "weeks")
	if len(weeks) != 13 || len(asList(t, r.body, "issuances", "weeks")) != 12 || len(asList(t, r.body, "alerts", "weeks")) != 5 {
		t.Fatalf("week counts: %d %d %d", len(weeks), len(asList(t, r.body, "issuances", "weeks")), len(asList(t, r.body, "alerts", "weeks")))
	}
	first, _ := weeks[0].(map[string]any)
	start, err := time.Parse(time.RFC3339, str(first, "start"))
	if err != nil || start.Weekday() != time.Monday || start.Hour() != 0 || start.Location() != time.UTC || start.After(v.clk.Now()) {
		t.Errorf("first week starts %v (%v)", first["start"], err)
	}
	if first["window"] != "critical" {
		t.Errorf("the current week is inside the critical window: %v", first)
	}
	if r.body["generated_at"] != v.clk.Now().UTC().Format(time.RFC3339) {
		t.Errorf("generated_at %v, now %s", r.body["generated_at"], v.clk.Now().UTC().Format(time.RFC3339))
	}
	fleet, ok := r.body["agents"].(map[string]any)
	if !ok || fleet["active"] != float64(0) || len(fleet) != 7 {
		t.Errorf("agents: %v", r.body["agents"])
	}
	before := r.body

	// The cache: new certificates are not in a read of the same minute, and
	// are in the first read of the next one.
	v.unseal(t)
	v.issueFor(t, "a.homelab.lan")
	v.issueFor(t, "b.homelab.lan")
	r = viewer.do(t, http.MethodGet, "/reports", nil)
	if cached := lastIssuances(t, r); r.Code != http.StatusOK || r.body["generated_at"] != before["generated_at"] || cached["ui"] != float64(0) {
		t.Errorf("a read inside the minute is the cached report: %d %v %v", r.Code, r.body["generated_at"], cached)
	}
	v.clk.Advance(report.CacheTTL + time.Second)
	r = viewer.do(t, http.MethodGet, "/reports", nil)
	if r.Code != http.StatusOK {
		t.Fatalf("after the cache: %d %s", r.Code, r.Body.String())
	}
	if r.body["generated_at"] == before["generated_at"] {
		t.Error("the report was not rebuilt after a minute")
	}
	last := lastIssuances(t, r)
	if last["ui"] != float64(2) || last["acme"] != float64(0) || last["agent"] != float64(0) {
		t.Errorf("this week's issuances: %v", last)
	}
	var found map[string]any
	for _, a := range asList(t, r.body, "authorities") {
		if m, _ := a.(map[string]any); m["name"] == "issuing" {
			found = m
		}
	}
	if found == nil || found["id"] != v.caIDs["issuing"] || found["valid"] != float64(2) || found["expiring"] != float64(0) || found["expired"] != float64(0) || found["revoked"] != float64(0) {
		t.Errorf("authority issuing: %v", found)
	}

	// Roles: everyone who reads the whole tenant; not a role limited to one
	// CA, not a user without a role, not a request without a session.
	for name, c := range map[string]*client{"operator": operator, "admin": admin, "viewer": viewer} {
		if rs := c.do(t, http.MethodGet, "/reports", nil); rs.Code != http.StatusOK {
			t.Errorf("%s: %d %s", name, rs.Code, rs.Body.String())
		}
	}
	for name, c := range map[string]*client{"caadmin": caAdmin, "nobody": nobody} {
		if rs := c.do(t, http.MethodGet, "/reports", nil); rs.Code != http.StatusForbidden || rs.problemType() != "forbidden" {
			t.Errorf("%s: %d %s", name, rs.Code, rs.Body.String())
		}
	}
	if rs := anon.do(t, http.MethodGet, "/reports", nil); rs.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", rs.Code)
	}
	// A refusal carries no data.
	if rs := caAdmin.do(t, http.MethodGet, "/reports", nil); strings.Contains(rs.Body.String(), "authorities") {
		t.Errorf("the refusal carries data: %s", rs.Body.String())
	}

	// API tokens: tenant-wide read works, a token limited to one CA is refused.
	wide := v.token(t, admin, "wide", map[string]string{"type": "tenant"})
	narrow := v.token(t, admin, "narrow", map[string]string{"type": "ca", "id": v.caIDs["issuing"]})
	bot := v.client("192.0.2.40")
	if rs := bot.do(t, http.MethodGet, "/reports", nil, wide...); rs.Code != http.StatusOK {
		t.Errorf("tenant-wide token: %d %s", rs.Code, rs.Body.String())
	}
	if rs := bot.do(t, http.MethodGet, "/reports", nil, narrow...); rs.Code != http.StatusForbidden || rs.problemType() != "forbidden" {
		t.Errorf("token limited to one CA: %d %s", rs.Code, rs.Body.String())
	}
	if rs := bot.do(t, http.MethodGet, "/reports", nil, "Authorization", "Bearer mop_wrong"); rs.Code != http.StatusUnauthorized {
		t.Errorf("unknown token: %d", rs.Code)
	}

	// No leak across tenants: the service of this tenant refuses a user of
	// another one, and what a refused call returns is nothing. (The API is
	// bound to one tenant and takes none from the request; a second tenant
	// has a service and a cache of its own: internal/report tests.)
	other := keys.Who{Principal: &authz.Principal{Kind: authz.KindUser, Username: "x", Bindings: []authz.Binding{{Tenant: "other", Role: authz.Admin}}}}
	if got, err := v.reports.Get(t.Context(), other); got != nil || err == nil {
		t.Errorf("a user of another tenant: %v %v", got, err)
	}

	// The agent listener off: the block is null, the key stays.
	v.api.d.Reports = report.NewService(report.Deps{Tenant: store.DefaultTenant, Engine: v.engine, Alerts: v.alerts, Rules: monitor.DefaultRules(), ServerVersion: "v0.3.8", Clock: v.clk})
	r = viewer.do(t, http.MethodGet, "/reports", nil)
	if v2, has := r.body["agents"]; r.Code != http.StatusOK || !has || v2 != nil {
		t.Errorf("without the agent listener: %d agents=%v present=%v", r.Code, v2, has)
	}
}

// ruleStates maps the id of each rule to its state in of an analysis answer.
func ruleStates(t *testing.T, r *resp) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, x := range asList(t, r.body, "rules") {
		m, _ := x.(map[string]any)
		out[m["id"].(string)], _ = m["state"].(string)
	}
	return out
}

// TestGetAnalysis: all ten rules in a fixed order, the findings of the ones
// that fire, the filter by rule, the refusal of an unknown rule, and the
// same permissions as the report.
func TestGetAnalysis(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.unseal(t)
	admin, viewer, operator, caAdmin, nobody, anon := alertClients(t, v)
	// The same names three times within minutes: a renewal loop (warning)
	// and three certificates from one source (info).
	for range 3 {
		v.issueFor(t, "loop.homelab.lan")
		v.clk.Advance(time.Minute)
	}
	v.issueFor(t, "single.homelab.lan")

	r := viewer.do(t, http.MethodGet, "/analysis", nil)
	if r.Code != http.StatusOK {
		t.Fatalf("viewer: %d %s", r.Code, r.Body.String())
	}
	var order []string
	for _, x := range asList(t, r.body, "rules") {
		order = append(order, str(asMap(x), "id"))
	}
	want := "orphaned_certificate duplicate_certificates renewal_loop expiry_wave weak_key weak_signature ca_cliff outdated_agent unused_acme_account unused_domain"
	if strings.Join(order, " ") != want {
		t.Errorf("rules: %v", order)
	}
	states := ruleStates(t, r)
	if states["renewal_loop"] != "findings" || states["duplicate_certificates"] != "findings" || states["weak_key"] != "ok" || states["expiry_wave"] != "unknown" {
		t.Errorf("states: %v", states)
	}
	if sum, _ := r.body["summary"].(map[string]any); sum["warning"] != float64(1) || sum["info"] != float64(1) || sum["critical"] != float64(0) || sum["unknown"] == float64(0) {
		t.Errorf("summary: %v", r.body["summary"])
	}
	findings := asList(t, r.body, "findings")
	if len(findings) != 2 {
		t.Fatalf("findings: %v", findings)
	}
	f, _ := findings[0].(map[string]any) // most severe first
	if f["rule"] != "renewal_loop" || f["severity"] != "warning" || f["subject"] != "loop.homelab.lan" || len(f) != 8 ||
		!strings.HasPrefix(str(f, "key"), "renewal_loop:") || !strings.HasPrefix(str(f, "href"), "/") || f["seen"] == "" || f["why"] == "" || f["recommendation"] == "" {
		t.Errorf("first finding: %v", f)
	}
	// The unknown rules say why.
	for _, x := range asList(t, r.body, "rules") {
		m, _ := x.(map[string]any)
		if (m["state"] == "unknown") != (m["unknown_reason"] != "") {
			t.Errorf("rule %v: state %v, reason %q", m["id"], m["state"], m["unknown_reason"])
		}
	}

	// The filter: one rule, its findings, a summary for it alone.
	r = viewer.do(t, http.MethodGet, "/analysis?rule=renewal_loop", nil)
	if r.Code != http.StatusOK || len(asList(t, r.body, "rules")) != 1 || len(asList(t, r.body, "findings")) != 1 {
		t.Fatalf("rule=renewal_loop: %d %s", r.Code, r.Body.String())
	}
	if sum, _ := r.body["summary"].(map[string]any); sum["warning"] != float64(1) || sum["info"] != float64(0) || sum["unknown"] != float64(0) {
		t.Errorf("summary of one rule: %v", r.body["summary"])
	}
	r = viewer.do(t, http.MethodGet, "/analysis?rule=weak_key", nil)
	if r.Code != http.StatusOK || len(asList(t, r.body, "rules")) != 1 || strings.Contains(r.Body.String(), `"findings":null`) || len(asList(t, r.body, "findings")) != 0 {
		t.Errorf("rule=weak_key: %d %s", r.Code, r.Body.String())
	}
	// An empty value is no filter.
	if r = viewer.do(t, http.MethodGet, "/analysis?rule=", nil); r.Code != http.StatusOK || len(asList(t, r.body, "rules")) != 10 {
		t.Errorf("rule=: %d", r.Code)
	}
	// An unknown rule is a bad request that names the field and the ids, not the input.
	for _, bad := range []string{"nope", "WEAK_KEY", "weak_key,renewal_loop", "<script>", strings.Repeat("a", 5000)} {
		r = viewer.do(t, http.MethodGet, "/analysis?rule="+strings.ReplaceAll(bad, "<", "%3C")[:min(len(bad), 300)], nil)
		if r.Code != http.StatusBadRequest || r.problemType() != "bad-request" {
			t.Errorf("rule=%.20s: %d %s", bad, r.Code, r.Body.String())
			continue
		}
		if strings.Contains(r.Body.String(), "script") || !strings.Contains(r.Body.String(), `"field":"rule"`) || !strings.Contains(r.Body.String(), "weak_key") {
			t.Errorf("rule=%.20s: the problem should name the field and the valid ids only: %s", bad, r.Body.String())
		}
	}

	// Permissions, like the report.
	for name, c := range map[string]*client{"operator": operator, "admin": admin} {
		if r := c.do(t, http.MethodGet, "/analysis", nil); r.Code != http.StatusOK {
			t.Errorf("%s: %d", name, r.Code)
		}
	}
	for name, c := range map[string]*client{"caadmin": caAdmin, "nobody": nobody} {
		for _, path := range []string{"/analysis", "/analysis?rule=weak_key"} {
			if r := c.do(t, http.MethodGet, path, nil); r.Code != http.StatusForbidden || r.problemType() != "forbidden" || strings.Contains(r.Body.String(), "findings") {
				t.Errorf("%s %s: %d %s", name, path, r.Code, r.Body.String())
			}
		}
	}
	if r := anon.do(t, http.MethodGet, "/analysis", nil); r.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: %d", r.Code)
	}
	wide := v.token(t, admin, "wide", map[string]string{"type": "tenant"})
	narrow := v.token(t, admin, "narrow", map[string]string{"type": "ca", "id": v.caIDs["issuing"]})
	bot := v.client("192.0.2.40")
	if r := bot.do(t, http.MethodGet, "/analysis?rule=renewal_loop", nil, wide...); r.Code != http.StatusOK || len(asList(t, r.body, "findings")) != 1 {
		t.Errorf("tenant-wide token: %d %s", r.Code, r.Body.String())
	}
	if r := bot.do(t, http.MethodGet, "/analysis", nil, narrow...); r.Code != http.StatusForbidden || r.problemType() != "forbidden" {
		t.Errorf("token limited to one CA: %d %s", r.Code, r.Body.String())
	}
	other := keys.Who{Principal: &authz.Principal{Kind: authz.KindUser, Username: "x", Bindings: []authz.Binding{{Tenant: "other", Role: authz.Admin}}}}
	if got, err := v.analysis.Get(t.Context(), other); got != nil || err == nil {
		t.Errorf("a user of another tenant: %v %v", got, err)
	}
	if got := v.notified(t); len(got) != 0 {
		t.Errorf("reading wrote notification entries: %v", got)
	}

	// The cache is shared: a read inside the minute is the same run.
	for range 3 {
		v.issueFor(t, "loop2.homelab.lan") // a second renewal loop the cached run does not know
	}
	if again := viewer.do(t, http.MethodGet, "/analysis?rule=renewal_loop", nil); len(asList(t, again.body, "findings")) != 1 {
		t.Errorf("a read inside the minute is the cached run: %s", again.Body.String())
	}
	v.clk.Advance(analysis.CacheTTL + time.Second)
	if again := viewer.do(t, http.MethodGet, "/analysis?rule=renewal_loop", nil); len(asList(t, again.body, "findings")) != 2 {
		t.Errorf("the next minute sees the new loop: %s", again.Body.String())
	}
}

// hostileEngine adds a CA to what the engine lists, as an operator could
// name it: markup, quotes and 4,000 characters.
type hostileEngine struct {
	*ca.Engine
	name string
	now  time.Time
}

func (h hostileEngine) CAs(ctx context.Context, who keys.Who) ([]ca.CAInfo, error) {
	list, err := h.Engine.CAs(ctx, who)
	if err != nil {
		return nil, err
	}
	end := h.now.UTC().Add(24 * time.Hour).Format(time.RFC3339)
	return append(list, ca.CAInfo{
		ID: "ca_hostile", Name: h.name, Kind: "intermediate", Status: ca.StatusActive, KeyMode: ca.KeyModeOnlineEncrypted, CurrentGeneration: 1,
		Generations: []ca.GenerationInfo{{Generation: 1, Current: true, NotAfter: end}},
	}), nil
}

// TestHostileNamesComeBackAsData: a CA named with markup reaches the
// findings and the report as JSON text; the finding clips it, nothing is
// HTML, and the encoder leaves no literal "<" in the body.
func TestHostileNamesComeBackAsData(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	_, viewer, _, _, _, _ := alertClients(t, v)
	evil := `<script>alert("x")</script>&'` + strings.Repeat("é", 4000)
	eng := hostileEngine{Engine: v.engine, name: evil, now: v.clk.Now()}
	v.api.d.Analysis = analysis.NewService(analysis.Deps{Tenant: store.DefaultTenant, Engine: eng, ServerVersion: "v0.3.8", Clock: v.clk})
	v.api.d.Reports = report.NewService(report.Deps{Tenant: store.DefaultTenant, Engine: eng, Alerts: v.alerts, Rules: monitor.DefaultRules(), ServerVersion: "v0.3.8", Clock: v.clk})

	r := viewer.do(t, http.MethodGet, "/analysis?rule=ca_cliff", nil)
	if r.Code != http.StatusOK || !strings.HasPrefix(r.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("analysis: %d %s %.300s", r.Code, r.Header().Get("Content-Type"), r.Body.String())
	}
	if strings.ContainsAny(r.Body.String(), "<>") || strings.Contains(r.Body.String(), "<script>") {
		t.Errorf("the body holds a literal angle bracket: %.200s", r.Body.String())
	}
	list := asList(t, r.body, "findings")
	if len(list) != 1 {
		t.Fatalf("findings: %v", list)
	}
	f, _ := list[0].(map[string]any)
	seen, subject := str(f, "seen"), str(f, "subject")
	if !strings.Contains(seen+subject, `<script>alert("x")</script>&'`) {
		t.Errorf("the name is not raw text: %q %q", subject, seen)
	}
	for name, text := range map[string]string{"subject": subject, "seen": seen, "key": str(f, "key"), "why": str(f, "why"), "recommendation": str(f, "recommendation")} {
		if utf8.RuneCountInString(text) > 600 || !utf8.ValidString(text) {
			t.Errorf("%s has %d runes (valid: %v)", name, utf8.RuneCountInString(text), utf8.ValidString(text))
		}
	}
	if strings.ContainsAny(str(f, "key")+str(f, "href"), `<>"'& `) {
		t.Errorf("key or href with markup characters: %v %v", f["key"], f["href"])
	}
	if len(r.Body.String()) > 20_000 {
		t.Errorf("the answer is %d bytes: the 4,000 characters were not clipped", len(r.Body.String()))
	}

	// The report carries the name as the operator set it, as data.
	r = viewer.do(t, http.MethodGet, "/reports", nil)
	if r.Code != http.StatusOK || strings.ContainsAny(r.Body.String(), "<>") {
		t.Fatalf("report: %d %.200s", r.Code, r.Body.String())
	}
	var got string
	for _, a := range asList(t, r.body, "authorities") {
		if m, _ := a.(map[string]any); m["id"] == "ca_hostile" {
			got, _ = m["name"].(string)
		}
	}
	if got != evil {
		t.Errorf("authority name: %d runes", utf8.RuneCountInString(got))
	}
}

// lastIssuances is the entry of the current week of the issuances.
func lastIssuances(t *testing.T, r *resp) map[string]any {
	t.Helper()
	weeks := asList(t, r.body, "issuances", "weeks")
	last, _ := weeks[len(weeks)-1].(map[string]any)
	return last
}

// str reads a string field of a decoded object ("" if it is none).
func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// asMap is a decoded JSON object (nil if it is none).
func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}
