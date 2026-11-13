package web

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/analysis"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/monitor"
	"github.com/Der-Felix/MyOwnPKI/internal/report"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// hostileName stands for the attacker-controlled names: CA, host, certificate.
const hostileName = `<script>alert(1)</script>"&'`

// cannedReports and cannedAnalysis answer fixed data, after the same
// tenant-wide ReadPKI check the real services make.
type cannedReports struct {
	v   *uiEnv
	rep *report.Report
	err error
}

func (s cannedReports) Get(_ context.Context, who keys.Who) (*report.Report, error) {
	if err := who.Principal.Check(authz.ReadPKI, authz.Resource{Tenant: store.DefaultTenant}, s.v.Clock.Now()); err != nil {
		return nil, err
	}
	return s.rep, s.err
}

type cannedAnalysis struct {
	v  *uiEnv
	an *analysis.Analysis
}

func (s cannedAnalysis) Get(_ context.Context, who keys.Who) (*analysis.Analysis, error) {
	if err := who.Principal.Check(authz.ReadPKI, authz.Resource{Tenant: store.DefaultTenant}, s.v.Clock.Now()); err != nil {
		return nil, err
	}
	return s.an, nil
}

// newReportsUIEnv is the UI with the reports and the analysis on: the real
// services over the test instance, or the canned ones when given.
func newReportsUIEnv(t *testing.T, reports func(*uiEnv) ReportSource, analyses func(*uiEnv) AnalysisSource) *uiEnv {
	t.Helper()
	v := &uiEnv{Instance: testinstance.New(t, testinstance.Options{})}
	deps := &AppDeps{
		Auth: v.Auth, Engine: v.Engine, Keys: v.Ring, Presets: v.Presets, Clock: v.Clock, Demo: true, Tenant: store.DefaultTenant,
		Settings: &tenant.Store{DB: v.SystemDB.Write, Clock: v.Clock}, TenantAudit: v.TenantAudit.Read, InstanceAudit: v.InstanceAudit.Read,
	}
	if reports == nil {
		deps.Reports = report.NewService(report.Deps{
			Tenant: store.DefaultTenant, Engine: v.Engine, Alerts: &monitor.Store{DB: v.SystemDB.Write, Tenant: store.DefaultTenant},
			Rules: monitor.DefaultRules(), ServerVersion: "0.3.8", Clock: v.Clock,
		})
	} else {
		deps.Reports = reports(v)
	}
	if analyses == nil {
		deps.Analysis = analysis.NewService(analysis.Deps{Tenant: store.DefaultTenant, Engine: v.Engine, ServerVersion: "0.3.8", Clock: v.Clock})
	} else {
		deps.Analysis = analyses(v)
	}
	h, err := NewHandler(Options{Logger: slog.New(slog.NewJSONHandler(&v.logs, nil)), App: deps})
	if err != nil {
		t.Fatal(err)
	}
	v.h = h
	return v
}

// cannedReport has data in every chart, a hostile CA name and a fleet.
func cannedReport(now time.Time) *report.Report {
	start := report.WeekStart(now)
	rep := &report.Report{GeneratedAt: now}
	for i := range report.ExpiryWeeks {
		w := report.ExpiryWeek{Start: start.AddDate(0, 0, 7*i), Count: (i * 3) % 7, Window: report.WindowNone}
		if i == 0 {
			w.Window = report.WindowCritical
		} else if i < 3 {
			w.Window = report.WindowWarning
		}
		rep.Expiry.Weeks = append(rep.Expiry.Weeks, w)
	}
	for i := range report.IssuanceWeeks {
		rep.Issuances.Weeks = append(rep.Issuances.Weeks, report.IssuanceWeek{Start: start.AddDate(0, 0, 7*(i-report.IssuanceWeeks+1)), ACME: i, Agent: i % 3, UI: 1})
	}
	rep.Authorities = []report.Authority{
		{ID: "ca_1", Name: hostileName + strings.Repeat("A", 4000), Valid: 9, Expiring: 2, Expired: 1, Revoked: 1},
		{ID: "ca_2", Name: "Issuing CA", Valid: 4},
		{External: true, Valid: 2},
	}
	rep.Alerts = report.Alerts{RetentionDays: 30, Open: 1, Weeks: []report.AlertWeek{{Start: start, Warning: 2, Critical: 1}, {Start: start.AddDate(0, 0, -7), Warning: 1}}}
	rep.Agents = &report.Fleet{Active: 3, SilentWarning: 1, Disabled: 1, Version: report.VersionCounts{Current: 2, Older: 1, Unknown: 1}, Deployments: report.DeploymentCounts{Deployed: 4, Failed: 1}}
	return rep
}

// newCannedAnalysis has findings of three severities, one with a hostile
// subject and hostile links, and rules that are ok, unknown or both.
func newCannedAnalysis(now time.Time) *analysis.Analysis {
	var results []analysis.Result
	for _, r := range analysis.Rules() {
		results = append(results, analysis.Result{ID: r.ID, Title: r.Title, State: analysis.StateOK})
	}
	set := func(id string, f func(*analysis.Result)) {
		for i := range results {
			if results[i].ID == id {
				f(&results[i])
			}
		}
	}
	finding := func(rule, sev, subject, href string) analysis.Finding {
		return analysis.Finding{Key: rule + ":" + subject, Rule: rule, Severity: sev, Subject: subject, Href: href,
			Seen: "It was seen: " + subject, Why: "Why it matters.", Recommendation: "What to do."}
	}
	set(analysis.RuleWeakKey, func(r *analysis.Result) {
		r.State = analysis.StateFindings
		r.Counts = analysis.Counts{Critical: 2}
		r.Findings = []analysis.Finding{
			finding(analysis.RuleWeakKey, analysis.SeverityCritical, hostileName, "/certificates/crt_1"),
			finding(analysis.RuleWeakKey, analysis.SeverityCritical, "javascript link", "javascript:alert(1)"),
		}
	})
	set(analysis.RuleExpiryWave, func(r *analysis.Result) {
		r.State = analysis.StateFindings
		r.Counts = analysis.Counts{Warning: 1}
		r.Findings = []analysis.Finding{finding(analysis.RuleExpiryWave, analysis.SeverityWarning, "2026-W47", "//evil.example/x")}
	})
	set(analysis.RuleUnusedDomain, func(r *analysis.Result) {
		r.State = analysis.StateFindings
		r.Counts = analysis.Counts{Info: 1}
		r.Findings = []analysis.Finding{finding(analysis.RuleUnusedDomain, analysis.SeverityInfo, "unused.homelab.lan", "/domains/dom_1")}
		r.Unassessed, r.UnknownReason = 2, "the domain list is incomplete"
	})
	set(analysis.RuleOrphanedCertificate, func(r *analysis.Result) {
		r.State, r.UnknownReason = analysis.StateUnknown, "the TLS scan is off"
	})
	set(analysis.RuleCACliff, func(r *analysis.Result) {
		r.State, r.UnknownReason = analysis.StateUnknown, `no CA has a signed certificate <b>yet</b>`
	})
	return &analysis.Analysis{GeneratedAt: now, Results: results, Findings: analysis.Findings(results), Summary: analysis.Summarize(results)}
}

// cannedAllUnknown is an analysis where no rule has a finding and two cannot
// be assessed.
func cannedAllUnknown(now time.Time) *analysis.Analysis {
	var results []analysis.Result
	for i, r := range analysis.Rules() {
		res := analysis.Result{ID: r.ID, Title: r.Title, State: analysis.StateOK}
		if i < 2 {
			res.State, res.UnknownReason = analysis.StateUnknown, "the TLS scan is off"
		}
		results = append(results, res)
	}
	return &analysis.Analysis{GeneratedAt: now, Results: results, Findings: analysis.Findings(results), Summary: analysis.Summarize(results)}
}

var (
	reIDAttr = regexp.MustCompile(`\sid="([^"]*)"`)
	reH1     = regexp.MustCompile(`(?s)<h1[^>]*>(.*?)</h1>`)
	reH2     = regexp.MustCompile(`(?s)<h2[^>]*>(.*?)</h2>`)
	reH3     = regexp.MustCompile(`<h3[ >]`)
)

// duplicateIDs lists the ids that occur more than once in a page.
func duplicateIDs(html string) []string {
	seen := map[string]bool{}
	var dup []string
	for _, m := range reIDAttr.FindAllStringSubmatch(html, -1) {
		if seen[m[1]] {
			dup = append(dup, m[1])
		}
		seen[m[1]] = true
	}
	return dup
}

func texts(re *regexp.Regexp, html string) []string {
	var out []string
	for _, m := range re.FindAllStringSubmatch(html, -1) {
		out = append(out, m[1])
	}
	return out
}

// checkPlainHTML is what every page must keep: no inline style or script,
// the chart SVG shape, no duplicate id, one h1 and no h3 without a section.
func checkPlainHTML(t *testing.T, name, html string) {
	t.Helper()
	for what, re := range map[string]*regexp.Regexp{"style attribute": reStyleAttr, "<style>": reStyleTag, "<script>": reScriptTag, "on* attribute": reEventAttr, "javascript: URL": reJSURL} {
		if m := re.FindString(html); m != "" {
			t.Errorf("%s has a %s: %q", name, what, m)
		}
	}
	for _, v := range svgViolations(html, reRenderedChartSVG) {
		t.Errorf("%s: %s", name, v)
	}
	if d := duplicateIDs(html); len(d) > 0 {
		t.Errorf("%s repeats the ids %v", name, d)
	}
	if h := texts(reH1, html); len(h) != 1 {
		t.Errorf("%s has %d h1: %v", name, len(h), h)
	}
	if reH3.MatchString(html) {
		t.Errorf("%s has an h3", name)
	}
}

// navEntry matches the entry in the navigation that layout C and the small
// screens show too (nav-primary).
func navEntry(path string) *regexp.Regexp {
	return regexp.MustCompile(`<a class="nav-link nav-primary" href="` + regexp.QuoteMeta(path) + `"`)
}

func cannedReportEnv(t *testing.T) *uiEnv {
	t.Helper()
	return newReportsUIEnv(t, func(v *uiEnv) ReportSource { return cannedReports{v: v, rep: cannedReport(v.Clock.Now())} },
		func(v *uiEnv) AnalysisSource { return cannedAnalysis{v: v, an: newCannedAnalysis(v.Clock.Now())} })
}

// TestReportsPage: every role that reads the tenant gets the page with a
// heading per section, expiry and authorities open and the others closed, a
// numbers table per chart with data, and the navigation entries.
func TestReportsPage(t *testing.T) {
	t.Parallel()
	e := newReportsUIEnv(t, nil, nil)
	e.Unseal(t)
	for _, name := range []string{"a", "b"} {
		if _, err := e.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{name + ".homelab.lan"}, ValidityDays: 20, Who: testinstance.Console}); err != nil {
			t.Fatal(err)
		}
	}
	e.User(t, "viewer", false, authz.Binding{Role: authz.Viewer})
	e.User(t, "operator", false, authz.Binding{Role: authz.Operator})
	for i, who := range []struct{ name, password string }{{"demo", e.DemoPassword}, {"viewer", testinstance.Password}, {"operator", testinstance.Password}} {
		b := e.browser("192.0.2." + strconv.Itoa(i+1))
		b.signIn(t, who.name, who.password)
		resp := b.get(t, "/reports")
		html := resp.html()
		if resp.Code != http.StatusOK {
			t.Fatalf("%s: %d", who.name, resp.Code)
		}
		checkPlainHTML(t, who.name+" /reports", html)
		if got, want := texts(reH2, html), []string{"Expiry", "Issuances", "Authorities", "Alerts"}; strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%s: sections %v, want %v (no Agents without the agent listener)", who.name, got, want)
		}
		for _, want := range []string{
			`<h1>Reports</h1>`, "Computed at ", "refreshed at most once a minute",
			`<details class="fold" id="sec-expiry" open>`, `<details class="fold" id="sec-authorities" open>`,
			`<details class="fold" id="sec-issuances">`, `<details class="fold" id="sec-alerts">`,
			`<title id="chart-expiry-title">`, `<title id="chart-issuances-title">`, `<title id="chart-authorities-title">`,
			"No alerts were opened in the last 30 days.", // the empty state, in words
			"issuing",
		} {
			if !strings.Contains(html, want) {
				t.Errorf("%s: the page lacks %q", who.name, want)
			}
		}
		// Every chart that has data comes with its numbers as a table.
		if got := strings.Count(html, `<details class="chart-numbers">`); got != 3 {
			t.Errorf("%s: %d numbers tables, want 3 (expiry, issuances, authorities)", who.name, got)
		}
		if !navEntry("/reports").MatchString(html) || !navEntry("/analysis").MatchString(html) {
			t.Errorf("%s: the navigation lacks Reports or Analysis", who.name)
		}
	}
}

// TestReportsPageWithData: the canned report fills every section, the agent
// section appears, and every chart id is on the page once.
func TestReportsPageWithData(t *testing.T) {
	t.Parallel()
	e := cannedReportEnv(t)
	b := e.browser("192.0.2.1")
	b.signIn(t, "demo", e.DemoPassword)
	html := b.get(t, "/reports").html()
	checkPlainHTML(t, "/reports", html)
	if got, want := texts(reH2, html), []string{"Expiry", "Issuances", "Authorities", "Alerts", "Agents"}; strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("sections %v, want %v", got, want)
	}
	// Five chart groups, seven charts, and each has its numbers table.
	if got := strings.Count(html, `<details class="chart-numbers">`); got != 7 {
		t.Errorf("%d numbers tables, want 7", got)
	}
	for _, id := range []string{"chart-expiry", "chart-issuances", "chart-authorities", "chart-alerts", "chart-fleet-agents", "chart-fleet-versions", "chart-fleet-deployments"} {
		if strings.Count(html, `<title id="`+id+`-title">`) != 1 {
			t.Errorf("the chart %s is not on the page exactly once", id)
		}
	}
	// The hostile CA name is text: escaped, clipped, never markup.
	if strings.Contains(html, "<script>alert(1)") || strings.Contains(html, strings.Repeat("A", 100)) || !strings.Contains(html, "&lt;script&gt;alert(1)") {
		t.Error("the CA name is not escaped and clipped")
	}
}

// TestReportsPageRoles: a role limited to one CA is refused and has no
// navigation entry; nobody signed in is sent to the sign-in page.
func TestReportsPageRoles(t *testing.T) {
	t.Parallel()
	e := cannedReportEnv(t)
	e.User(t, "caviewer", false, authz.Binding{CA: "issuing", Role: authz.Viewer})
	b := e.browser("192.0.2.1")
	b.signIn(t, "caviewer", testinstance.Password)
	for _, path := range []string{"/reports", "/analysis", "/analysis?rule=weak_key"} {
		resp := b.get(t, path)
		if resp.Code != http.StatusForbidden || strings.Contains(resp.html(), "Issuing CA") || strings.Contains(resp.html(), "unused.homelab.lan") {
			t.Errorf("%s: %d", path, resp.Code)
		}
		if navEntry("/reports").MatchString(resp.html()) || navEntry("/analysis").MatchString(resp.html()) {
			t.Errorf("%s has a navigation entry for a role without ReadPKI", path)
		}
	}
	dash := b.get(t, "/")
	if dash.Code != http.StatusOK || strings.Contains(dash.html(), "chart-expiry") || strings.Contains(dash.html(), "dash-expiry") || strings.Contains(dash.html(), `href="/reports"`) {
		t.Errorf("dashboard for a CA-limited role: %d, with charts or a link", dash.Code)
	}
	for _, path := range []string{"/reports", "/analysis"} {
		resp := e.browser("192.0.2.9").get(t, path)
		if resp.Code != http.StatusSeeOther || !strings.HasPrefix(resp.location(), "/login") {
			t.Errorf("anonymous %s: %d %q", path, resp.Code, resp.location())
		}
	}
}

// TestReportsPagesWithoutMonitoring: no services, no pages, no entries.
func TestReportsPagesWithoutMonitoring(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	for _, path := range []string{"/reports", "/analysis"} {
		resp := b.get(t, path)
		if resp.Code != http.StatusNotFound || !strings.Contains(resp.html(), "Monitoring is off.") {
			t.Errorf("%s: %d", path, resp.Code)
		}
	}
	dash := b.get(t, "/").html()
	if navEntry("/reports").MatchString(dash) || navEntry("/analysis").MatchString(dash) || strings.Contains(dash, "chart-expiry") {
		t.Error("the dashboard shows reports without the service")
	}
}

// TestReportsPagesWhileSealed: reading needs no signing key, so the pages
// render with the sealed notice, like the Alerts page.
func TestReportsPagesWhileSealed(t *testing.T) {
	t.Parallel()
	e := newReportsUIEnv(t, nil, nil)
	b := e.browser("192.0.2.1")
	b.signIn(t, "demo", e.DemoPassword)
	for _, path := range []string{"/reports", "/analysis", "/"} {
		resp := b.get(t, path)
		if resp.Code != http.StatusOK || !strings.Contains(resp.html(), "Signing is off") {
			t.Errorf("%s while sealed: %d", path, resp.Code)
		}
	}
}

// TestDashboardCharts: the two charts sit below the tables, open, with the
// link to the reports, for a role that may read the tenant; a failing build
// costs the charts and not the dashboard, and does not leak the cause.
func TestDashboardCharts(t *testing.T) {
	t.Parallel()
	e := cannedReportEnv(t)
	e.User(t, "viewer", false, authz.Binding{Role: authz.Viewer})
	for i, who := range []struct{ name, password string }{{"demo", e.DemoPassword}, {"viewer", testinstance.Password}} {
		b := e.browser("192.0.2." + strconv.Itoa(i+1))
		b.signIn(t, who.name, who.password)
		html := b.get(t, "/").html()
		checkPlainHTML(t, who.name+" /", html)
		for _, want := range []string{
			`<details class="fold" id="dash-expiry" open>`, `<details class="fold" id="dash-authorities" open>`,
			`<title id="chart-expiry-title">`, `<title id="chart-authorities-title">`, `<a href="/reports">All reports</a>`,
		} {
			if !strings.Contains(html, want) {
				t.Errorf("%s: the dashboard lacks %q", who.name, want)
			}
		}
		if strings.Contains(html, "chart-issuances") || strings.Contains(html, "chart-alerts") {
			t.Errorf("%s: the dashboard shows more than two charts", who.name)
		}
		if strings.Index(html, "Expiring in the next 30 days") > strings.Index(html, `id="dash-expiry"`) {
			t.Errorf("%s: the charts come before the tables", who.name)
		}
	}

	failing := newReportsUIEnv(t, func(v *uiEnv) ReportSource {
		return cannedReports{v: v, err: errors.New("pki.db: disk I/O error at /var/lib/myownpki")}
	}, nil)
	fb := failing.browser("192.0.2.1")
	fb.signIn(t, "demo", failing.DemoPassword)
	resp := fb.get(t, "/")
	if resp.Code != http.StatusOK || !strings.Contains(resp.html(), "The charts could not be built.") || strings.Contains(resp.html(), "disk I/O") {
		t.Errorf("failing build: %d", resp.Code)
	}
	if !strings.Contains(failing.logs.String(), "disk I/O error") {
		t.Error("the cause is not in the log")
	}
}

// TestAnalysisPage: the summary line, the findings with a severity label and
// a link, the ten rules with their states, hostile text escaped, hostile
// links dropped, and the heading structure.
func TestAnalysisPage(t *testing.T) {
	t.Parallel()
	e := cannedReportEnv(t)
	e.User(t, "viewer", false, authz.Binding{Role: authz.Viewer})
	b := e.browser("192.0.2.1")
	b.signIn(t, "viewer", testinstance.Password)
	resp := b.get(t, "/analysis")
	html := resp.html()
	if resp.Code != http.StatusOK {
		t.Fatal(resp.Code)
	}
	checkPlainHTML(t, "/analysis", html)
	if got, want := texts(reH2, html), []string{"Findings", "Rules", "How this works"}; strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("sections %v, want %v", got, want)
	}
	for _, want := range []string{
		`<h1>Analysis</h1>`, `<p id="analysis-summary">4 findings: 2 critical, 1 warning, 1 info; 2 rules cannot be assessed.</p>`,
		`st-crit"><span class="st-dot" aria-hidden="true"></span>critical`, `st-warn"><span class="st-dot" aria-hidden="true"></span>warning`, `st-info"><span class="st-dot" aria-hidden="true"></span>info`,
		`<a href="/certificates/crt_1">`, `<a href="/domains/dom_1">`, "What was seen", "Why it matters", "What to do",
		"&lt;script&gt;alert(1)&lt;/script&gt;", // the hostile subject, as text
		`<a href="/analysis?rule=weak_key">Weak key</a>`, `<a href="/analysis?rule=expiry_wave">Expiry wave</a>`,
		"unknown: the TLS scan is off", "findings; 2 not assessed: the domain list is incomplete",
		"no CA has a signed certificate &lt;b&gt;yet&lt;/b&gt;",
		"Nothing leaves the server",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	for _, bad := range []string{"<script>alert", `href="javascript:`, `href="//evil`, "<b>yet</b>"} {
		if strings.Contains(html, bad) {
			t.Errorf("the page contains %q", bad)
		}
	}
	// A finding with an unusable link keeps its row; only the link goes.
	if !strings.Contains(html, "javascript link") || !strings.Contains(html, "2026-W47") {
		t.Error("a finding with an unusable link was dropped")
	}
	// All ten rules are in the rules table.
	for _, r := range analysis.Rules() {
		if !hasRule(html, r.Title) {
			t.Errorf("the rules table lacks %q", r.Title)
		}
	}
	if !navEntry("/analysis").MatchString(html) {
		t.Error("the navigation lacks Analysis")
	}
}

// TestAnalysisUnknownIsNotAFinding: a rule without data is "unknown" with the
// reason in the neutral status, adds no finding, and the empty state says so.
func TestAnalysisUnknownIsNotAFinding(t *testing.T) {
	t.Parallel()
	e := newReportsUIEnv(t, nil, func(v *uiEnv) AnalysisSource { return cannedAnalysis{v: v, an: cannedAllUnknown(v.Clock.Now())} })
	b := e.browser("192.0.2.1")
	b.signIn(t, "demo", e.DemoPassword)
	html := b.get(t, "/analysis").html()
	checkPlainHTML(t, "/analysis", html)
	for _, want := range []string{
		`<p id="analysis-summary">No findings; 2 rules cannot be assessed.</p>`,
		`<p class="empty">No rule found anything to report.</p>`,
		`st-neutral"><span class="st-dot" aria-hidden="true"></span>unknown: the TLS scan is off`,
		`st-ok"><span class="st-dot" aria-hidden="true"></span>ok`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	for _, bad := range []string{"st-crit", "st-warn", "st-info"} {
		if strings.Contains(html, bad) {
			t.Errorf("an unknown rule is shown as a problem: %q", bad)
		}
	}
}

// TestAnalysisRuleFilter: ?rule= limits the findings to one rule and links
// back; a rule without findings says so; an unknown id is a 400 that does
// not echo the input.
func TestAnalysisRuleFilter(t *testing.T) {
	t.Parallel()
	e := cannedReportEnv(t)
	b := e.browser("192.0.2.1")
	b.signIn(t, "demo", e.DemoPassword)
	html := b.get(t, "/analysis?rule=expiry_wave").html()
	for _, want := range []string{"2026-W47", `<a href="/analysis">Show all findings</a>`, "Only the rule Expiry wave."} {
		if !strings.Contains(html, want) {
			t.Errorf("the filtered page lacks %q", want)
		}
	}
	if strings.Contains(html, "unused.homelab.lan") || strings.Contains(html, "javascript link") {
		t.Error("the filter shows other rules")
	}
	if html := b.get(t, "/analysis?rule=renewal_loop").html(); !strings.Contains(html, "This rule found nothing to report.") {
		t.Error("a rule without findings has no empty state")
	}
	resp := b.get(t, "/analysis?rule=%3Cscript%3Ealert(1)%3C/script%3E")
	if resp.Code != http.StatusBadRequest || strings.Contains(resp.html(), "alert(1)") {
		t.Errorf("unknown rule: %d", resp.Code)
	}
}

// TestAnalysisPageRealService: the real analysis over the test instance has
// all ten rules and a summary line.
func TestAnalysisPageRealService(t *testing.T) {
	t.Parallel()
	e := newReportsUIEnv(t, nil, nil)
	b := e.browser("192.0.2.1")
	b.signIn(t, "demo", e.DemoPassword)
	resp := b.get(t, "/analysis")
	if resp.Code != http.StatusOK {
		t.Fatal(resp.Code)
	}
	html := resp.html()
	checkPlainHTML(t, "/analysis", html)
	for _, r := range analysis.Rules() {
		if !hasRule(html, r.Title) {
			t.Errorf("the rules table lacks %q", r.Title)
		}
	}
	if !strings.Contains(html, `id="analysis-summary"`) {
		t.Error("no summary line")
	}
}

var (
	reportPagesOnce sync.Once
	reportPagesHTML map[string]string
)

// reportPages renders the new pages once for the HTML rules of server_test.go
// (inline styles, classes, tokens).
func reportPages(t *testing.T) map[string]string {
	t.Helper()
	reportPagesOnce.Do(func() {
		e := cannedReportEnv(t)
		b := e.browser("192.0.2.1")
		b.signIn(t, "demo", e.DemoPassword)
		reportPagesHTML = map[string]string{}
		for _, p := range []string{"/", "/reports", "/analysis", "/analysis?rule=weak_key"} {
			reportPagesHTML["reports env "+p] = b.get(t, p).html()
		}
	})
	if reportPagesHTML == nil {
		t.Fatal("the report pages could not be rendered")
	}
	return reportPagesHTML
}

// hasRule: the rules table has a row for the rule, linked or not (a plain
// cell ends with a space before its closing tag).
func hasRule(html, title string) bool {
	return strings.Contains(html, ">"+title+" </td>") || strings.Contains(html, ">"+title+"</a>")
}

// TestAnalysisSummaryAndLinks: the words of the summary line and the links
// a finding may carry.
func TestAnalysisSummaryAndLinks(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		s    analysis.Summary
		want string
	}{
		{analysis.Summary{}, "No findings."},
		{analysis.Summary{Unknown: 1}, "No findings; 1 rule cannot be assessed."},
		{analysis.Summary{Info: 1}, "1 finding: 1 info."},
		{analysis.Summary{Critical: 1, Warning: 1, Info: 1, Unknown: 2}, "3 findings: 1 critical, 1 warning, 1 info; 2 rules cannot be assessed."},
	} {
		if got := analysisSummary(tt.s); got != tt.want {
			t.Errorf("%+v: %q, want %q", tt.s, got, tt.want)
		}
	}
	for href, want := range map[string]string{
		"/certificates/crt_1": "/certificates/crt_1", "": "", "javascript:alert(1)": "", "//evil.example": "", "https://evil.example": "",
		`/a\b`: "", "/a\r\nSet-Cookie: x": "",
		// Browsers strip TAB, CR and LF from a URL: "/<TAB>/evil" would be "//evil".
		"/\t/evil.example": "", "/\n/evil.example": "", "/\x00/x": "", "/\x1f/x": "", "/\x7f/x": "", "/a\tb": "",
	} {
		if got := uiPath(href); got != want {
			t.Errorf("uiPath(%q) = %q, want %q", href, got, want)
		}
	}
}
