package web

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/monitor"
	"github.com/Der-Felix/MyOwnPKI/internal/notify"
	"github.com/Der-Felix/MyOwnPKI/internal/web/components"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/admin"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// alertNumber is the dashboard figure of the open alerts: red with a
// critical one, amber with warnings only. It links to the Alerts page.
func alertNumber(open []monitor.Alert) components.Number {
	status := view.Status("")
	critical := 0
	for _, a := range open {
		if a.Severity == monitor.Critical {
			status = view.StatusCrit
			critical++
		} else if status == "" {
			status = view.StatusWarn
		}
	}
	label := "Open alerts"
	if critical > 0 {
		label += ", " + strconv.Itoa(critical) + " critical"
	}
	return components.Number{Label: label, Value: strconv.Itoa(len(open)), Status: status, Href: "/alerts"}
}

// alertMessages are the alerts the dashboard doesn't find on its own: CRLs,
// CA certificates and agent certificates it checks itself (without the
// minute delay of the monitoring), so they would show twice.
func alertMessages(open []monitor.Alert) []view.Message {
	var out []view.Message
	for _, a := range open {
		switch a.Kind {
		case monitor.KindAgentSilent, monitor.KindDeployFailed:
		case monitor.KindCertExpiry:
			if a.Severity != monitor.Critical {
				continue // warnings are in "Expiring in the next 30 days"
			}
		default:
			continue
		}
		kind := view.MessageWarning
		if a.Severity == monitor.Critical {
			kind = view.MessageError
		}
		out = append(out, view.Message{Kind: kind, Text: a.Detail, Href: a.Href, LinkText: "Open"})
	}
	return out
}

// alertKinds are the names of the alert kinds in the tables.
var alertKinds = map[string]string{
	monitor.KindCertExpiry:       "Certificate expires",
	monitor.KindCAExpiry:         "CA certificate expires",
	monitor.KindCRL:              "Revocation list",
	monitor.KindSealed:           "Server sealed",
	monitor.KindAgentSilent:      "Agent silent",
	monitor.KindAgentCertificate: "Agent certificate",
	monitor.KindDeployFailed:     "Deployment failed",
	monitor.KindScanMismatch:     "Wrong certificate served",
	monitor.KindScanExpiry:       "Served certificate expires",
	monitor.KindScanUnreachable:  "Endpoint unreachable",
	monitor.KindScanChain:        "Chain problem",
}

func alertKind(kind string) string {
	if s, ok := alertKinds[kind]; ok {
		return s
	}
	return kind
}

// alertsPage lists the open alerts and those resolved in the last 7 days;
// admins also get the test of the notification channels.
func (a *app) alertsPage(c *rc) {
	if a.d.Alerts == nil {
		c.notice(http.StatusNotFound, "Not found", view.Message{Kind: view.MessageError, Text: "Monitoring is off."})
		return
	}
	now := a.now()
	open, resolved, err := a.d.Alerts.List(c.r.Context(), c.who(), now)
	if err != nil {
		c.fail(err)
		return
	}
	openTable := admin.TableData{
		Empty:   "No alert is open.",
		Columns: []admin.Column{{Label: "Severity"}, {Label: "Alert"}, {Label: "Subject"}, {Label: "Since"}, {Label: "What to do"}},
	}
	for _, al := range open {
		st := admin.Cell{Text: al.Severity, Status: view.StatusWarn}
		if al.Severity == monitor.Critical {
			st.Status = view.StatusCrit
		}
		openTable.Rows = append(openTable.Rows, []admin.Cell{
			st, {Text: alertKind(al.Kind), NoWrap: true}, {Text: al.Subject, Mono: true, Break: true},
			{Text: dateTime(al.FirstSeen), Rel: view.Relative(now, al.FirstSeen), NoWrap: true},
			{Text: al.Detail, Href: al.Href, Break: true},
		})
	}
	doneTable := admin.TableData{
		Empty:   "No alert was resolved in the last 7 days.",
		Columns: []admin.Column{{Label: "Was"}, {Label: "Alert"}, {Label: "Subject"}, {Label: "Opened"}, {Label: "Resolved"}},
	}
	for _, al := range resolved {
		doneTable.Rows = append(doneTable.Rows, []admin.Cell{
			{Text: al.Severity, Status: view.StatusNeutral}, {Text: alertKind(al.Kind), NoWrap: true}, {Text: al.Subject, Mono: true, Break: true},
			{Text: dateTime(al.FirstSeen), NoWrap: true}, {Text: dateTime(al.Resolved), Rel: view.Relative(now, al.Resolved), NoWrap: true},
		})
	}
	sections := []admin.Section{
		{Title: "Open", Table: &openTable},
		{Title: "Resolved in the last 7 days", Table: &doneTable},
	}
	if s, ok := c.notifySection(); ok {
		sections = append(sections, s)
	}
	p := c.page("Alerts", "alerts")
	p.Description = "What needs an admin: certificates and CA certificates that end soon, revocation lists, a sealed server, silent agents, failed deployments and TLS endpoints that serve the wrong certificate or do not answer. Checked every minute."
	render(c.w, c.r, a.log, http.StatusOK, admin.DetailPage(p, admin.DetailData{Messages: c.messages(), Sections: sections}))
}

// notifySection tells who is notified; for admins it holds the test button.
// Nothing for a server without monitoring.
func (c *rc) notifySection() (admin.Section, bool) {
	if c.a.d.Notifier == nil {
		return admin.Section{}, false
	}
	channels := c.a.d.Notifier.Names()
	if len(channels) == 0 {
		return admin.Section{Title: "Notifications", Text: []string{
			"No notification channel is configured, so nobody is told about alerts – they show only here. Set notify.email or notify.webhook in the server's configuration.",
		}}, true
	}
	s := admin.Section{Title: "Notifications"}
	if !c.may(authz.TestNotify, "") {
		return s, false
	}
	s.Text = []string{"New, rising and resolved alerts go out as one message through " + strings.Join(channels, " and ") + ". A test message shows that the channels work."}
	s.Forms = []admin.FormData{c.form(admin.FormData{Action: "/alerts/test", Submit: "Send test message"})}
	return s, true
}

// alertsTest sends the test message and shows the result of each channel on
// the Alerts page (Post/Redirect/Get, like every action of the UI).
func (a *app) alertsTest(c *rc) {
	if a.d.Notifier == nil {
		c.notice(http.StatusNotFound, "Not found", view.Message{Kind: view.MessageError, Text: "Monitoring is off."})
		return
	}
	results, err := a.d.Notifier.Send(c.r.Context(), c.who())
	var wait *notify.WaitError
	switch {
	case errors.Is(err, authz.ErrDenied):
		c.fail(err)
		return
	case errors.Is(err, notify.ErrNoChannel), errors.As(err, &wait):
		c.setFlash(view.Message{Kind: view.MessageWarning, Text: err.Error() + "."})
		c.redirect("/alerts")
		return
	case err != nil && results == nil:
		c.fail(err)
		return
	}
	var msgs []view.Message
	for _, r := range results {
		if r.OK {
			msgs = append(msgs, view.Message{Kind: view.MessageSuccess, Text: "The test message went out through " + r.Channel + "."})
			continue
		}
		msgs = append(msgs, view.Message{Kind: view.MessageError, Text: "The test message through " + r.Channel + " failed: " + r.Error})
	}
	if err != nil {
		// Sent, but the audit entry is missing: say so, log the cause.
		a.log.ErrorContext(c.r.Context(), "audit of the test notification", slog.Any("error", err))
		msgs = append(msgs, view.Message{Kind: view.MessageError, Text: "The audit entry of this test could not be written – the server log has the details."})
	}
	c.setFlash(msgs...)
	c.redirect("/alerts")
}
