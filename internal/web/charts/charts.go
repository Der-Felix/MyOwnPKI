// Package charts turns the datasets of internal/report into the plain chart
// descriptions that components.Chart draws (docs/PHASE3.md section 14). It
// holds the texts of the Reports page and the dashboard charts: titles, the
// one-sentence summaries, the empty states and the table headers.
//
// Names from the datasets (CA names) are passed on as they are: they are
// attacker-controlled, and components.Chart cleans, clips and escapes them.
// The summaries use numbers and fixed words only.
package charts

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/report"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// externalName is the label of the certificates without a CA.
const externalName = "External certificates"

// weekLabel is "W47"; weekName is "2026-W47, week of 2026-11-16" (UTC).
func weekLabel(start time.Time) string {
	_, w := start.UTC().ISOWeek()
	return fmt.Sprintf("W%02d", w)
}

func weekName(start time.Time) string {
	y, w := start.UTC().ISOWeek()
	return fmt.Sprintf("%d-W%02d, week of %s", y, w, start.UTC().Format("2006-01-02"))
}

func plural(n int64, one, many string) string {
	if n == 1 {
		return grp(n) + " " + one
	}
	return grp(n) + " " + many
}

// Expiry is the expiry timeline: one column per week, colored by the monitor
// window the week starts in (the table repeats the window as text).
func Expiry(e report.Expiry) view.Chart {
	c := view.Chart{
		ID:             "chart-expiry",
		Kind:           view.ChartColumns,
		Title:          "Expiry timeline",
		Empty:          "No certificate ends in " + expiryReach(len(e.Weeks)) + ".",
		CategoryHeader: "Week",
		ValueHeader:    "Certificates",
		SeriesHeader:   "Window",
		Legend:         true,
		Series: []view.ChartSeries{
			{Label: "Critical window", Class: view.ChartCrit},
			{Label: "Warning window", Class: view.ChartWarn},
			{Label: "Later", Class: view.ChartNeutral},
		},
	}
	var total, soon int64
	for _, w := range e.Weeks {
		series := 2
		switch w.Window { //nolint:exhaustive // the others keep the "later" series
		case report.WindowCritical:
			series = 0
		case report.WindowWarning:
			series = 1
		}
		n := int64(w.Count)
		total += n
		if series < 2 {
			soon += n
		}
		c.Categories = append(c.Categories, view.ChartCategory{
			Label: weekLabel(w.Start), Name: weekName(w.Start), Series: series, Values: []int64{n},
		})
	}
	c.Summary = plural(total, "certificate ends", "certificates end") + " in " + expiryReach(len(e.Weeks)) +
		", " + grp(soon) + " of them in weeks that start inside the warning or critical window."
	return c
}

// expiryReach says what the timeline covers: the dataset starts at the current
// ISO week and ends with the last of its weeks, so "the next 13 weeks" would
// be wrong (it is up to 97 days, counted to the end of the last week).
func expiryReach(weeks int) string {
	if weeks <= 1 {
		return "the current week"
	}
	return "the current week and the next " + strconv.Itoa(weeks-1) + " weeks"
}

// Issuances is the issuances per week, stacked by source.
func Issuances(i report.Issuances) view.Chart {
	c := view.Chart{
		ID:             "chart-issuances",
		Kind:           view.ChartStacked,
		Title:          "Issuances per week",
		Empty:          "No certificates were issued in the last " + strconv.Itoa(len(i.Weeks)) + " weeks.",
		CategoryHeader: "Week",
		Legend:         true,
		Series: []view.ChartSeries{
			{Label: "ACME", Class: view.ChartS1},
			{Label: "Agent", Class: view.ChartS2},
			{Label: "UI and API", Class: view.ChartS3},
		},
	}
	var acme, agent, ui int64
	for _, w := range i.Weeks {
		acme += int64(w.ACME)
		agent += int64(w.Agent)
		ui += int64(w.UI)
		c.Categories = append(c.Categories, view.ChartCategory{
			Label: weekLabel(w.Start), Name: weekName(w.Start),
			Values: []int64{int64(w.ACME), int64(w.Agent), int64(w.UI)},
		})
	}
	c.Summary = plural(acme+agent+ui, "certificate was", "certificates were") + " issued in the last " + strconv.Itoa(len(i.Weeks)) +
		" weeks: " + grp(acme) + " through ACME, " + grp(agent) + " through agents, " +
		grp(ui) + " in the UI or API."
	return c
}

// Authorities is the certificates per CA, stacked by status.
func Authorities(list []report.Authority) view.Chart {
	days := int(ca.ExpiringWindow / (24 * time.Hour))
	c := view.Chart{
		ID:             "chart-authorities",
		Kind:           view.ChartStackedBars,
		Title:          "Certificates per CA and status",
		Empty:          "There are no certificates yet.",
		CategoryHeader: "CA",
		Legend:         true,
		Series: []view.ChartSeries{
			{Label: "Valid", Class: view.ChartOK},
			{Label: "Expiring (" + strconv.Itoa(days) + " days)", Class: view.ChartWarn},
			{Label: "Expired", Class: view.ChartCrit},
			{Label: "Revoked", Class: view.ChartNeutral},
		},
	}
	var valid, expiring, expired, revoked int64
	for _, a := range list {
		name := a.Name
		if a.External {
			name = externalName
		}
		// Valid includes Expiring; the column shows the rest.
		plain := max(a.Valid-a.Expiring, 0)
		valid += plain
		expiring += a.Expiring
		expired += a.Expired
		revoked += a.Revoked
		c.Categories = append(c.Categories, view.ChartCategory{
			Label: name, Name: name, Values: []int64{plain, a.Expiring, a.Expired, a.Revoked},
		})
	}
	c.Summary = plural(valid+expiring+expired+revoked, "certificate", "certificates") + " in " + plural(int64(len(list)), "CA", "CAs") +
		": " + grp(valid+expiring) + " valid (" + grp(expiring) + " of them expiring), " +
		grp(expired) + " expired, " + grp(revoked) + " revoked."
	return c
}

// Alerts is the alert history: alerts opened per week, by severity.
func Alerts(a report.Alerts) view.Chart {
	c := view.Chart{
		ID:             "chart-alerts",
		Kind:           view.ChartStacked,
		Title:          "Alerts opened per week",
		Empty:          "No alerts were opened in the last " + strconv.Itoa(a.RetentionDays) + " days.",
		CategoryHeader: "Week",
		Legend:         true,
		Series: []view.ChartSeries{
			{Label: "Warning", Class: view.ChartWarn},
			{Label: "Critical", Class: view.ChartCrit},
		},
	}
	var warn, crit int64
	for _, w := range a.Weeks {
		warn += int64(w.Warning)
		crit += int64(w.Critical)
		c.Categories = append(c.Categories, view.ChartCategory{
			Label: weekLabel(w.Start), Name: weekName(w.Start), Values: []int64{int64(w.Warning), int64(w.Critical)},
		})
	}
	c.Summary = plural(warn+crit, "alert was", "alerts were") + " opened in the last " + strconv.Itoa(a.RetentionDays) +
		" days (" + grp(warn) + " warning, " + grp(crit) + " critical); " +
		grp(int64(a.Open)) + " hold right now."
	return c
}

// bar is one category of a bars chart: its own color, no further series.
type bar struct {
	label string
	class view.ChartClass
	n     int
}

func bars(id, title, empty, header, valueHeader string, list []bar) view.Chart {
	c := view.Chart{ID: id, Kind: view.ChartBars, Title: title, Empty: empty, CategoryHeader: header, ValueHeader: valueHeader}
	var total int64
	for i, b := range list {
		c.Series = append(c.Series, view.ChartSeries{Label: b.label, Class: b.class})
		c.Categories = append(c.Categories, view.ChartCategory{Label: b.label, Series: i, Values: []int64{int64(b.n)}})
		total += int64(b.n)
	}
	c.Summary = grp(total) + " in total: "
	for i, b := range list {
		if i > 0 {
			c.Summary += ", "
		}
		c.Summary += grp(int64(b.n)) + " " + strings.ToLower(b.label)
	}
	c.Summary += "."
	return c
}

// Fleet is the agent fleet: states, versions and deployments, one bar chart
// each. It returns nil while the agent listener is off (no fleet).
func Fleet(f *report.Fleet) []view.Chart {
	if f == nil {
		return nil
	}
	return []view.Chart{
		bars("chart-fleet-agents", "Agents by state", "No agents are enrolled.", "State", "Agents", []bar{
			{"Active", view.ChartOK, f.Active},
			{"Silent (warning)", view.ChartWarn, f.SilentWarning},
			{"Silent (critical)", view.ChartCrit, f.SilentCritical},
			{"Disabled", view.ChartNeutral, f.Disabled},
			{"Revoked", view.ChartNeutral, f.Revoked},
		}),
		bars("chart-fleet-versions", "Agent versions compared with the server", "No active agent reports a version.", "Version", "Agents", []bar{
			{"Current or newer", view.ChartOK, f.Version.Current},
			{"Older", view.ChartWarn, f.Version.Older},
			{"Unknown", view.ChartNeutral, f.Version.Unknown},
		}),
		bars("chart-fleet-deployments", "Deployments by state", "No deployments.", "State", "Deployments", []bar{
			{"Deployed", view.ChartOK, f.Deployments.Deployed},
			{"Pending", view.ChartInfo, f.Deployments.Pending},
			{"Failed", view.ChartCrit, f.Deployments.Failed},
			{"Rolled back", view.ChartWarn, f.Deployments.RolledBack},
		}),
	}
}

// grp writes a count with thousands separators (1,278).
func grp(v int64) string {
	s := strconv.FormatInt(v, 10)
	for i := len(s) - 3; i > 0 && s[i-1] != '-'; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
