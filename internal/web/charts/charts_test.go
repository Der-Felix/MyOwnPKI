package charts

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/report"
	"github.com/Der-Felix/MyOwnPKI/internal/web/components"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

var monday = time.Date(2026, time.November, 16, 0, 0, 0, 0, time.UTC)

func render(t *testing.T, c view.Chart) string {
	t.Helper()
	var b bytes.Buffer
	if err := components.Chart(c).Render(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestExpiry(t *testing.T) {
	t.Parallel()
	var e report.Expiry
	for i := 0; i < report.ExpiryWeeks; i++ {
		w := report.ExpiryWeek{Start: monday.AddDate(0, 0, 7*i), Count: i, Window: report.WindowNone}
		switch {
		case i == 0:
			w.Window = report.WindowCritical
		case i < 3:
			w.Window = report.WindowWarning
		}
		e.Weeks = append(e.Weeks, w)
	}
	c := Expiry(e)
	if len(c.Categories) != 13 || c.Kind != view.ChartColumns {
		t.Fatalf("chart: %+v", c)
	}
	// W47 starts 2026-11-16; the colors follow the window.
	if c.Categories[0].Label != "W47" || c.Categories[0].Name != "2026-W47, week of 2026-11-16" {
		t.Errorf("first category: %+v", c.Categories[0])
	}
	if c.Categories[0].Series != 0 || c.Categories[1].Series != 1 || c.Categories[2].Series != 1 || c.Categories[3].Series != 2 {
		t.Errorf("window series: %+v", c.Categories[:4])
	}
	// 78 certificates in total, 0+1+2 = 3 of them in the warning or critical weeks.
	if want := "78 certificates end in the next 13 weeks, 3 of them in weeks that start inside the warning or critical window."; c.Summary != want {
		t.Errorf("summary %q, want %q", c.Summary, want)
	}
	out := render(t, c)
	for _, want := range []string{`<th scope="row">2026-W47, week of 2026-11-16</th><td class="ch-num">0</td><td>Critical window</td>`, `<td>Warning window</td>`, `<td>Later</td>`} {
		if !strings.Contains(out, want) {
			t.Errorf("table lacks %q", want)
		}
	}
	// Year border: ISO week 53 of 2026 and week 1 of 2027.
	if weekLabel(time.Date(2026, 12, 28, 0, 0, 0, 0, time.UTC)) != "W53" || weekLabel(time.Date(2027, 1, 4, 0, 0, 0, 0, time.UTC)) != "W01" {
		t.Error("ISO week labels at the year border")
	}
	// An empty forecast says so.
	if out := render(t, Expiry(report.Expiry{})); !strings.Contains(out, `class="empty"`) || strings.Contains(out, "<svg") {
		t.Errorf("empty forecast: %s", out)
	}
	if one := Expiry(report.Expiry{Weeks: e.Weeks[1:2]}); !strings.Contains(one.Summary, "1 certificate ends") {
		t.Errorf("singular: %q", one.Summary)
	}
}

func TestIssuances(t *testing.T) {
	t.Parallel()
	var i report.Issuances
	for n := 0; n < report.IssuanceWeeks; n++ {
		i.Weeks = append(i.Weeks, report.IssuanceWeek{Start: monday.AddDate(0, 0, 7*(n-11)), ACME: n, Agent: 1, UI: 2})
	}
	c := Issuances(i)
	if len(c.Categories) != 12 || c.Kind != view.ChartStacked || len(c.Series) != 3 {
		t.Fatalf("chart: %+v", c)
	}
	if c.Series[0].Class != view.ChartS1 || c.Series[1].Class != view.ChartS2 || c.Series[2].Class != view.ChartS3 {
		t.Errorf("series: %+v", c.Series)
	}
	if want := "102 certificates were issued in the last 12 weeks: 66 through ACME, 12 through agents, 24 in the UI or API."; c.Summary != want {
		t.Errorf("summary %q, want %q", c.Summary, want)
	}
	if c.Categories[11].Values[0] != 11 || c.Categories[11].Values[2] != 2 {
		t.Errorf("last week: %+v", c.Categories[11])
	}
}

func TestAuthorities(t *testing.T) {
	t.Parallel()
	c := Authorities([]report.Authority{
		{ID: "a", Name: "homelab-issuing", Valid: 100, Expiring: 10, Expired: 5, Revoked: 2},
		{External: true, Valid: 3, Expired: 1},
	})
	if c.Kind != view.ChartStackedBars || len(c.Categories) != 2 {
		t.Fatalf("chart: %+v", c)
	}
	// Valid includes expiring: the stack draws valid minus expiring.
	if v := c.Categories[0].Values; v[0] != 90 || v[1] != 10 || v[2] != 5 || v[3] != 2 {
		t.Errorf("values: %v", v)
	}
	if c.Categories[1].Label != "External certificates" {
		t.Errorf("external label: %+v", c.Categories[1])
	}
	if c.Series[1].Label != "Expiring (30 days)" {
		t.Errorf("series: %+v", c.Series)
	}
	if want := "111 certificates in 2 CAs: 103 valid (10 of them expiring), 6 expired, 2 revoked."; c.Summary != want {
		t.Errorf("summary %q, want %q", c.Summary, want)
	}
	// Inconsistent input cannot give a negative segment.
	if v := Authorities([]report.Authority{{Name: "x", Valid: 1, Expiring: 3}}).Categories[0].Values; v[0] != 0 {
		t.Errorf("negative segment: %v", v)
	}
}

func TestAuthoritiesHostileNameIsEscaped(t *testing.T) {
	t.Parallel()
	const hostile = `"><script>alert(1)</script>`
	c := Authorities([]report.Authority{{ID: "x", Name: hostile, Valid: 5}})
	if c.Categories[0].Name != hostile {
		t.Error("the adapter must pass the name on untouched; escaping is the job of the component")
	}
	out := render(t, c)
	if strings.Contains(out, "<script") || strings.Contains(out, "alert(1)</") {
		t.Errorf("hostile CA name reached the page as markup:\n%s", out)
	}
	if strings.Count(out, "&lt;script&gt;") < 3 { // tooltip, label (clipped), table
		t.Errorf("hostile CA name missing as text:\n%s", out)
	}
}

func TestAlerts(t *testing.T) {
	t.Parallel()
	a := report.Alerts{RetentionDays: 30, Open: 2}
	for n := 0; n < report.AlertWeeks; n++ {
		a.Weeks = append(a.Weeks, report.AlertWeek{Start: monday.AddDate(0, 0, 7*(n-4)), Warning: n, Critical: 1})
	}
	c := Alerts(a)
	if len(c.Categories) != 5 || c.Series[0].Class != view.ChartWarn || c.Series[1].Class != view.ChartCrit {
		t.Fatalf("chart: %+v", c)
	}
	if want := "15 alerts were opened in the last 30 days (10 warning, 5 critical); 2 hold right now."; c.Summary != want {
		t.Errorf("summary %q, want %q", c.Summary, want)
	}
	if out := render(t, Alerts(report.Alerts{RetentionDays: 30})); !strings.Contains(out, "No alerts were opened in the last 30 days.") {
		t.Errorf("empty: %s", out)
	}
}

func TestFleet(t *testing.T) {
	t.Parallel()
	if Fleet(nil) != nil {
		t.Error("no fleet while the listener is off")
	}
	list := Fleet(&report.Fleet{
		Active: 4, SilentWarning: 1, SilentCritical: 2, Disabled: 3, Revoked: 5,
		Version:     report.VersionCounts{Current: 3, Older: 2, Unknown: 1},
		Deployments: report.DeploymentCounts{Deployed: 9, Pending: 1, Failed: 1, RolledBack: 2},
	})
	if len(list) != 3 {
		t.Fatalf("%d charts", len(list))
	}
	ids := map[string]bool{}
	for _, c := range list {
		ids[c.ID] = true
		if c.Kind != view.ChartBars {
			t.Errorf("%s: kind %s", c.ID, c.Kind)
		}
		for i, cat := range c.Categories {
			if cat.Series != i || c.Series[i].Label != cat.Label {
				t.Errorf("%s: category %d is not tied to its own series", c.ID, i)
			}
		}
	}
	if len(ids) != 3 {
		t.Error("chart ids are not unique")
	}
	if want := "15 in total: 4 active, 1 silent (warning), 2 silent (critical), 3 disabled, 5 revoked."; list[0].Summary != want {
		t.Errorf("summary %q, want %q", list[0].Summary, want)
	}
	if list[2].Series[1].Class != view.ChartInfo {
		t.Errorf("pending deployments use the info color: %+v", list[2].Series)
	}
	// A fleet of zero agents draws nothing but says so.
	if out := render(t, Fleet(&report.Fleet{})[0]); !strings.Contains(out, "No agents are enrolled.") || strings.Contains(out, "<svg") {
		t.Errorf("empty fleet: %s", out)
	}
}

// Every chart id on one page must be unique: the SVG ids refer to them.
func TestChartIDsAreUnique(t *testing.T) {
	t.Parallel()
	all := []view.Chart{Expiry(report.Expiry{}), Issuances(report.Issuances{}), Authorities(nil), Alerts(report.Alerts{})}
	all = append(all, Fleet(&report.Fleet{})...)
	seen := map[string]bool{}
	for _, c := range all {
		if seen[c.ID] {
			t.Errorf("duplicate chart id %q", c.ID)
		}
		seen[c.ID] = true
	}
}

func TestGrp(t *testing.T) {
	t.Parallel()
	for in, want := range map[int64]string{0: "0", 12: "12", 999: "999", 1000: "1,000", 1278: "1,278", 1234567: "1,234,567", -1234: "-1,234", -123: "-123"} {
		if got := grp(in); got != want {
			t.Errorf("grp(%d) = %q, want %q", in, got, want)
		}
	}
}
