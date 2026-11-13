package web

import (
	"context"
	"net/http"
	"strconv"

	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/report"
	"github.com/Der-Felix/MyOwnPKI/internal/web/charts"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/reports"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// ReportSource is what the UI reads of the reports (v0.3.8): the five chart
// datasets of the tenant, if who passes the tenant-wide authz.ReadPKI check.
// The service keeps them for a minute; the report is shared, never change it.
type ReportSource interface {
	Get(ctx context.Context, who keys.Who) (*report.Report, error)
}

// reportsPage shows the five chart groups. Expiry and authorities are open,
// the rest is closed until opened. A role limited to one CA gets the refusal:
// the report names the CAs, agents and alerts of the whole tenant.
func (a *app) reportsPage(c *rc) {
	if a.d.Reports == nil {
		c.notice(http.StatusNotFound, "Not found", view.Message{Kind: view.MessageError, Text: "Monitoring is off."})
		return
	}
	rep, err := a.d.Reports.Get(c.r.Context(), c.who())
	if err != nil {
		c.fail(err)
		return
	}
	days := strconv.Itoa(rep.Alerts.RetentionDays)
	d := reports.Data{
		Messages: c.messages(),
		Sections: []reports.Section{
			{
				ID: "sec-expiry", Title: "Expiry", Open: true,
				Note:   "One column per week, Monday to Sunday, in UTC. Revoked certificates and the identity certificates of agents are not counted.",
				Charts: []view.Chart{charts.Expiry(rep.Expiry)},
			},
			{
				ID: "sec-issuances", Title: "Issuances",
				Note:   "Only certificates this server issued are counted, not imported or external ones, and not the identity certificates of agents. A certificate counts as ACME or agent when an ACME order made it, and as UI and API otherwise.",
				Charts: []view.Chart{charts.Issuances(rep.Issuances)},
			},
			{
				ID: "sec-authorities", Title: "Authorities", Open: true,
				Note:   "Certificates per CA and status. Certificates without a CA of this server are listed as external.",
				Charts: []view.Chart{charts.Authorities(rep.Authorities)},
			},
			{
				ID: "sec-alerts", Title: "Alerts",
				Note:   "The server keeps alerts for " + days + " days, so this is all the history there is.",
				Charts: []view.Chart{charts.Alerts(rep.Alerts)},
			},
		},
	}
	if fleet := charts.Fleet(rep.Agents); fleet != nil {
		d.Sections = append(d.Sections, reports.Section{
			ID: "sec-agents", Title: "Agents",
			Note:   "Versions and deployments count the agents that are neither disabled nor revoked.",
			Charts: fleet,
		})
	}
	p := c.page("Reports", "reports")
	p.Description = "Computed at " + dateTime(rep.GeneratedAt) + ". The numbers are refreshed at most once a minute."
	render(c.w, c.r, a.log, http.StatusOK, reports.Page(p, d))
}
