package httpapi

import (
	"net/http"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/monitor"
)

// Monitoring (v0.3.3, docs/PHASE3.md §9): the alerts and the test of the
// notification channels.

type alertJSON struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`
	Subject    string     `json:"subject"`
	Severity   string     `json:"severity"`
	State      string     `json:"state"`
	FirstSeen  time.Time  `json:"first_seen"`
	LastSeen   time.Time  `json:"last_seen"`
	ResolvedAt *time.Time `json:"resolved_at"`
	Detail     string     `json:"detail"`
	Href       string     `json:"href"`
}

func toAlertJSON(a monitor.Alert) alertJSON {
	out := alertJSON{ID: a.ID, Kind: a.Kind, Subject: a.Subject, Severity: a.Severity, State: "open",
		FirstSeen: a.FirstSeen, LastSeen: a.LastSeen, Detail: a.Detail, Href: a.Href}
	if !a.Open() {
		out.State = "resolved"
		out.ResolvedAt = timeOrNil(a.Resolved)
	}
	return out
}

func (a *API) listAlerts(c *call) error {
	if a.d.Alerts == nil {
		return c.problem(http.StatusNotFound, "not-found", "monitoring is off", nil)
	}
	state := c.r.URL.Query().Get("state")
	if state != "" && state != "open" && state != "resolved" {
		return badRequest("state", "open or resolved")
	}
	open, resolved, err := a.d.Alerts.List(c.ctx(), c.who(), a.now())
	if err != nil {
		return err
	}
	out := make([]alertJSON, 0, len(open)+len(resolved))
	if state != "resolved" {
		for _, al := range open {
			out = append(out, toAlertJSON(al))
		}
	}
	if state != "open" {
		for _, al := range resolved {
			out = append(out, toAlertJSON(al))
		}
	}
	return c.reply(http.StatusOK, out)
}

func (a *API) sendTestNotification(c *call) error {
	if a.d.Notify == nil {
		return c.problem(http.StatusNotFound, "not-found", "monitoring is off", nil)
	}
	results, err := a.d.Notify.Send(c.ctx(), c.who())
	if err != nil {
		return err
	}
	return c.reply(http.StatusOK, map[string]any{"channels": results})
}
