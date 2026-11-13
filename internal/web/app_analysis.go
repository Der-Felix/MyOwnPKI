package web

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/analysis"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/admin"
	pageanalysis "github.com/Der-Felix/MyOwnPKI/internal/web/pages/analysis"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// AnalysisSource is what the UI reads of the analysis (v0.3.8): the findings
// and the state of the ten rules, if who passes the tenant-wide authz.ReadPKI
// check. The service keeps the result for a minute; it is shared, never
// change it.
type AnalysisSource interface {
	Get(ctx context.Context, who keys.Who) (*analysis.Analysis, error)
}

// findingStatus is the fixed status color of a severity (D10); the text
// label is always shown with it.
func findingStatus(severity string) view.Status {
	switch severity {
	case analysis.SeverityCritical:
		return view.StatusCrit
	case analysis.SeverityWarning:
		return view.StatusWarn
	default:
		return view.StatusInfo
	}
}

// analysisSummary is the one line above the tables: findings by severity,
// then the rules that cannot be assessed.
func analysisSummary(s analysis.Summary) string {
	count := func(n int, one, many string) string {
		if n == 1 {
			return "1 " + one
		}
		return strconv.Itoa(n) + " " + many
	}
	total := s.Critical + s.Warning + s.Info
	out := "No findings"
	if total > 0 {
		var parts []string
		for _, p := range []struct {
			n    int
			word string
		}{{s.Critical, "critical"}, {s.Warning, "warning"}, {s.Info, "info"}} {
			if p.n > 0 {
				parts = append(parts, strconv.Itoa(p.n)+" "+p.word)
			}
		}
		out = count(total, "finding", "findings") + ": " + strings.Join(parts, ", ")
	}
	if s.Unknown > 0 {
		out += "; " + count(s.Unknown, "rule cannot", "rules cannot") + " be assessed"
	}
	return out + "."
}

// ruleState is the text and status of a rule in the rules table. A rule that
// has no data to judge is "unknown: <reason>" in the neutral status, never
// shown as a problem (D9).
func ruleState(r analysis.Result) (string, view.Status) {
	switch r.State {
	case analysis.StateUnknown:
		if r.UnknownReason == "" {
			return "unknown", view.StatusNeutral
		}
		return "unknown: " + r.UnknownReason, view.StatusNeutral
	case analysis.StateFindings:
		worst := analysis.SeverityInfo
		if r.Counts.Critical > 0 {
			worst = analysis.SeverityCritical
		} else if r.Counts.Warning > 0 {
			worst = analysis.SeverityWarning
		}
		text := "findings"
		if r.Unassessed > 0 && r.UnknownReason != "" {
			text += "; " + strconv.Itoa(r.Unassessed) + " not assessed: " + r.UnknownReason
		}
		return text, findingStatus(worst)
	default:
		return "ok", view.StatusOK
	}
}

// uiPath keeps a link of a finding inside the UI: a path that starts with one
// slash and holds no backslash and no control character (browsers strip TAB,
// CR and LF, so "/<TAB>/host" would turn into "//host"). Anything else is
// dropped (the text stays, the link goes).
func uiPath(href string) string { return analysis.SafeHref(href) }

// analysisPage shows the findings of the ten rules, the state of every rule
// and how this works. ?rule=<id> limits the findings to one rule. A role
// limited to one CA gets the refusal, like the Reports page.
func (a *app) analysisPage(c *rc) {
	if a.d.Analysis == nil {
		c.notice(http.StatusNotFound, "Not found", view.Message{Kind: view.MessageError, Text: "Monitoring is off."})
		return
	}
	titles := map[string]string{}
	for _, r := range analysis.Rules() {
		titles[r.ID] = r.Title
	}
	filter := c.r.URL.Query().Get("rule")
	if _, ok := titles[filter]; filter != "" && !ok {
		c.notice(http.StatusBadRequest, "Unknown rule", view.Message{Kind: view.MessageError, Text: "There is no such rule. Pick one from the rules table."})
		return
	}
	an, err := a.d.Analysis.Get(c.r.Context(), c.who())
	if err != nil {
		c.fail(err)
		return
	}

	d := pageanalysis.Data{
		Messages: c.messages(),
		Summary:  analysisSummary(an.Summary),
		How: []string{
			"Each rule is a short piece of code that reads the certificates, agents, domains and TLS scan results this server already holds. Nothing leaves the server and nothing is stored: the analysis is computed again at most once a minute.",
			"A finding says what was seen, why it matters and what to do. It is advice: it raises no alert and sends no message. A rule that has no data to judge says \"unknown\" and the reason. That is not a problem.",
		},
		Findings: admin.TableData{
			Empty: "No rule found anything to report.",
			Columns: []admin.Column{
				{Label: "Severity"}, {Label: "Rule"}, {Label: "Subject"},
				{Label: "What was seen"}, {Label: "Why it matters"}, {Label: "What to do"},
			},
		},
		Rules: admin.TableData{
			Columns: []admin.Column{{Label: "Rule"}, {Label: "State"}, {Label: "Findings", Num: true}},
		},
	}
	if filter != "" {
		d.Filter, d.ShowAll = titles[filter], "/analysis"
		d.Findings.Empty = "This rule found nothing to report."
	}
	for _, f := range an.Findings {
		if filter != "" && f.Rule != filter {
			continue
		}
		d.Findings.Rows = append(d.Findings.Rows, []admin.Cell{
			{Text: f.Severity, Status: findingStatus(f.Severity)},
			{Text: titles[f.Rule], NoWrap: true},
			{Text: f.Subject, Href: uiPath(f.Href), Break: true},
			{Text: f.Seen}, {Text: f.Why}, {Text: f.Recommendation},
		})
	}
	for _, r := range an.Results {
		if r.Counts.Total() > len(r.Findings) {
			d.Truncated = true
		}
		state, status := ruleState(r)
		title := admin.Cell{Text: titles[r.ID], NoWrap: true}
		if r.Counts.Total() > 0 {
			title.Href = "/analysis?rule=" + url.QueryEscape(r.ID)
		}
		d.Rules.Rows = append(d.Rules.Rows, []admin.Cell{
			title, {Text: state, Status: status}, {Text: strconv.Itoa(r.Counts.Total()), Num: true},
		})
	}
	p := c.page("Analysis", "analysis")
	p.Description = "What the data suggests, from ten fixed rules. Computed at " + dateTime(an.GeneratedAt) + "."
	render(c.w, c.r, a.log, http.StatusOK, pageanalysis.Page(p, d))
}
