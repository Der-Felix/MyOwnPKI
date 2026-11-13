package httpapi

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/analysis"
	"github.com/Der-Felix/MyOwnPKI/internal/report"
)

// Reports and analysis (v0.3.8, docs/PHASE3.md §14): the datasets behind the
// Reports page and the findings of the analysis rules. The services do the
// tenant-wide ReadPKI check and keep the one-minute cache; the handlers only
// translate. Every string is raw text: the JSON encoder escapes it, and a
// page that shows it escapes it again for HTML.

type reportJSON struct {
	GeneratedAt time.Time       `json:"generated_at"`
	Expiry      expiryJSON      `json:"expiry"`
	Issuances   issuancesJSON   `json:"issuances"`
	Authorities []authorityJSON `json:"authorities"`
	Alerts      alertHistJSON   `json:"alerts"`
	Agents      *fleetJSON      `json:"agents"` // null while the agent listener is off
}

type expiryJSON struct {
	Weeks []expiryWeekJSON `json:"weeks"`
}

type expiryWeekJSON struct {
	Start  time.Time `json:"start"`
	Count  int       `json:"count"`
	Window string    `json:"window"`
}

type issuancesJSON struct {
	Weeks []issuanceWeekJSON `json:"weeks"`
}

type issuanceWeekJSON struct {
	Start time.Time `json:"start"`
	ACME  int       `json:"acme"`
	Agent int       `json:"agent"`
	UI    int       `json:"ui"`
}

type authorityJSON struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Valid    int64  `json:"valid"`
	Expiring int64  `json:"expiring"`
	Expired  int64  `json:"expired"`
	Revoked  int64  `json:"revoked"`
}

type alertHistJSON struct {
	RetentionDays int             `json:"retention_days"`
	Weeks         []alertWeekJSON `json:"weeks"`
	Open          int             `json:"open"`
}

type alertWeekJSON struct {
	Start    time.Time `json:"start"`
	Warning  int       `json:"warning"`
	Critical int       `json:"critical"`
}

type fleetJSON struct {
	Active         int `json:"active"`
	SilentWarning  int `json:"silent_warning"`
	SilentCritical int `json:"silent_critical"`
	Disabled       int `json:"disabled"`
	Revoked        int `json:"revoked"`
	Version        struct {
		Current int `json:"current"`
		Older   int `json:"older"`
		Unknown int `json:"unknown"`
	} `json:"version"`
	Deployments struct {
		Deployed   int `json:"deployed"`
		Pending    int `json:"pending"`
		Failed     int `json:"failed"`
		RolledBack int `json:"rolled_back"`
	} `json:"deployments"`
}

func toReportJSON(r *report.Report) reportJSON {
	out := reportJSON{
		GeneratedAt: r.GeneratedAt.UTC().Truncate(time.Second), // whole seconds: the page shows the minute anyway
		Expiry:      expiryJSON{Weeks: make([]expiryWeekJSON, 0, len(r.Expiry.Weeks))},
		Issuances:   issuancesJSON{Weeks: make([]issuanceWeekJSON, 0, len(r.Issuances.Weeks))},
		Authorities: make([]authorityJSON, 0, len(r.Authorities)),
		Alerts:      alertHistJSON{RetentionDays: r.Alerts.RetentionDays, Open: r.Alerts.Open, Weeks: make([]alertWeekJSON, 0, len(r.Alerts.Weeks))},
	}
	for _, w := range r.Expiry.Weeks {
		out.Expiry.Weeks = append(out.Expiry.Weeks, expiryWeekJSON{Start: w.Start.UTC(), Count: w.Count, Window: string(w.Window)})
	}
	for _, w := range r.Issuances.Weeks {
		out.Issuances.Weeks = append(out.Issuances.Weeks, issuanceWeekJSON{Start: w.Start.UTC(), ACME: w.ACME, Agent: w.Agent, UI: w.UI})
	}
	for _, a := range r.Authorities {
		// An external entry has no CA: its ID and name are empty already.
		out.Authorities = append(out.Authorities, authorityJSON{ID: a.ID, Name: a.Name, Valid: a.Valid, Expiring: a.Expiring, Expired: a.Expired, Revoked: a.Revoked})
	}
	for _, w := range r.Alerts.Weeks {
		out.Alerts.Weeks = append(out.Alerts.Weeks, alertWeekJSON{Start: w.Start.UTC(), Warning: w.Warning, Critical: w.Critical})
	}
	if f := r.Agents; f != nil {
		j := &fleetJSON{Active: f.Active, SilentWarning: f.SilentWarning, SilentCritical: f.SilentCritical, Disabled: f.Disabled, Revoked: f.Revoked}
		j.Version.Current, j.Version.Older, j.Version.Unknown = f.Version.Current, f.Version.Older, f.Version.Unknown
		j.Deployments.Deployed, j.Deployments.Pending, j.Deployments.Failed, j.Deployments.RolledBack =
			f.Deployments.Deployed, f.Deployments.Pending, f.Deployments.Failed, f.Deployments.RolledBack
		out.Agents = j
	}
	return out
}

func (a *API) getReports(c *call) error {
	if a.d.Reports == nil {
		return c.problem(http.StatusNotFound, "not-found", "reports are not available", nil)
	}
	r, err := a.d.Reports.Get(c.ctx(), c.who())
	if err != nil {
		return err
	}
	return c.reply(http.StatusOK, toReportJSON(r))
}

type analysisJSON struct {
	GeneratedAt time.Time          `json:"generated_at"`
	Summary     analysisSummary    `json:"summary"`
	Rules       []analysisRuleJSON `json:"rules"`
	Findings    []findingJSON      `json:"findings"`
}

type analysisSummary struct {
	Critical int `json:"critical"`
	Warning  int `json:"warning"`
	Info     int `json:"info"`
	Unknown  int `json:"unknown"`
}

type analysisRuleJSON struct {
	ID            string `json:"id"`
	Title         string `json:"title"`
	State         string `json:"state"`
	Count         int    `json:"count"`
	UnknownReason string `json:"unknown_reason"`
}

type findingJSON struct {
	Key            string `json:"key"`
	Rule           string `json:"rule"`
	Severity       string `json:"severity"`
	Subject        string `json:"subject"`
	Seen           string `json:"seen"`
	Why            string `json:"why"`
	Recommendation string `json:"recommendation"`
	Href           string `json:"href"`
}

func toAnalysisJSON(an *analysis.Analysis) analysisJSON {
	out := analysisJSON{
		GeneratedAt: an.GeneratedAt.UTC().Truncate(time.Second),
		Summary:     analysisSummary{Critical: an.Summary.Critical, Warning: an.Summary.Warning, Info: an.Summary.Info, Unknown: an.Summary.Unknown},
		Rules:       make([]analysisRuleJSON, 0, len(an.Results)),
		Findings:    make([]findingJSON, 0, len(an.Findings)),
	}
	for _, r := range an.Results {
		out.Rules = append(out.Rules, analysisRuleJSON{ID: r.ID, Title: r.Title, State: r.State, Count: r.Counts.Total(), UnknownReason: r.UnknownReason})
	}
	for _, f := range an.Findings {
		// The rules clean their findings already; the translation does not
		// rely on it, because the link and the text are the last step before a
		// consumer that may put them on a page.
		out.Findings = append(out.Findings, findingJSON{Key: f.Key, Rule: f.Rule, Severity: f.Severity, Subject: analysis.CleanText(f.Subject),
			Seen: analysis.CleanText(f.Seen), Why: analysis.CleanText(f.Why), Recommendation: analysis.CleanText(f.Recommendation), Href: analysis.SafeHref(f.Href)})
	}
	return out
}

// getAnalysis: ?rule=<id> narrows the answer to one rule. An id that is no
// rule is 400 (a bad query value, like ?state= of GET /alerts), checked
// against the fixed list of rules before anything is read.
func (a *API) getAnalysis(c *call) error {
	if a.d.Analysis == nil {
		return c.problem(http.StatusNotFound, "not-found", "the analysis is not available", nil)
	}
	rule := c.r.URL.Query().Get("rule")
	if rule != "" && !knownRule(rule) {
		return badRequest("rule", "one of %s", strings.Join(ruleIDs(), ", "))
	}
	an, err := a.d.Analysis.Get(c.ctx(), c.who())
	if err != nil {
		return err
	}
	if rule != "" {
		one, ok := an.Only(rule)
		if !ok {
			return badRequest("rule", "one of %s", strings.Join(ruleIDs(), ", "))
		}
		an = one
	}
	return c.reply(http.StatusOK, toAnalysisJSON(an))
}

func ruleIDs() []string {
	rules := analysis.Rules()
	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.ID
	}
	return ids
}

func knownRule(id string) bool { return slices.Contains(ruleIDs(), id) }
