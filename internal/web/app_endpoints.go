package web

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/monitor"
	"github.com/Der-Felix/MyOwnPKI/internal/tlsscan"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/admin"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// The Endpoints page (v0.3.4, docs/PHASE3.md §10): the TLS services the
// server scans and what each one serves. Everything the remote host sent
// (subject, issuer) is attacker input – it only ever reaches the page through
// templ, which escapes it; the error is a word from a fixed vocabulary. The
// tlsscan service checks the roles and writes the audit entries; this file
// decides what to offer.

// ago describes a past time in whole minutes, hours or days ("5 minutes ago").
func ago(now, t time.Time) string {
	d := now.Sub(t)
	plural := func(n int, unit string) string {
		if n == 1 {
			return "1 " + unit + " ago"
		}
		return strconv.Itoa(n) + " " + unit + "s ago"
	}
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return plural(int(d/time.Minute), "minute")
	case d < 48*time.Hour:
		return plural(int(d/time.Hour), "hour")
	default:
		return plural(int(d/(24*time.Hour)), "day")
	}
}

func severityStatus(severity string) view.Status {
	if severity == tlsscan.Critical {
		return view.StatusCrit
	}
	return view.StatusWarn
}

// endpointState is the state column: the words of docs/PHASE3.md §10.2 with
// the fixed status colors, and a short qualifier that says what is wrong.
func endpointState(s monitor.EndpointState) admin.Cell {
	ep, as := s.Endpoint, s.Assessment
	switch as.State {
	case tlsscan.StateOK:
		if as.Expiry != nil {
			return admin.Cell{Text: "Expiring", Status: severityStatus(as.Expiry.Severity), NoWrap: true}
		}
		return admin.Cell{Text: "OK", Status: view.StatusOK, NoWrap: true}
	case tlsscan.StateUnmanaged:
		return admin.Cell{Text: "Not issued by this PKI", Status: view.StatusInfo, NoWrap: true}
	case tlsscan.StateOlder:
		return admin.Cell{Text: "Wrong certificate", Status: view.StatusWarn, Rel: "an older certificate of this PKI", NoWrap: true}
	case tlsscan.StateForeign:
		return admin.Cell{Text: "Wrong certificate", Status: view.StatusWarn, Rel: "not issued by this PKI", NoWrap: true}
	case tlsscan.StateWrongName:
		return admin.Cell{Text: "Wrong certificate", Status: view.StatusWarn, Rel: "not valid for this name", NoWrap: true}
	case tlsscan.StateRevoked:
		return admin.Cell{Text: "Wrong certificate", Status: view.StatusCrit, Rel: "revoked", NoWrap: true}
	case tlsscan.StateChain:
		why := "does not lead to this PKI"
		if ep.ChainState == tlsscan.ChainIncomplete {
			why = "the intermediate CA is not sent"
		}
		return admin.Cell{Text: "Chain problem", Status: view.StatusWarn, Rel: why, NoWrap: true}
	case tlsscan.StateUnreachable:
		status := view.StatusWarn
		if as.Unreachable != nil {
			status = severityStatus(as.Unreachable.Severity)
		}
		return admin.Cell{Text: "Unreachable", Status: status, Rel: strconv.Itoa(ep.FailStreak) + " scans failed", NoWrap: true}
	case tlsscan.StateRefused:
		return admin.Cell{Text: "Refused", Status: view.StatusWarn, Rel: "not scanned", NoWrap: true}
	}
	return admin.Cell{Text: "Pending", Status: view.StatusNeutral, Rel: "not scanned yet", NoWrap: true}
}

// endpointRow is one table row; manage and scan say which buttons to offer.
func (c *rc) endpointRow(s monitor.EndpointState, now time.Time, manage, scan bool) []admin.Cell {
	ep := s.Endpoint
	target := admin.Cell{Text: ep.Target(), Mono: true, NoWrap: true}
	if ep.SNI != "" {
		target.Rel = "SNI " + ep.SNI
	}
	lastScan := admin.Cell{Text: "Not yet", NoWrap: true}
	if ep.Scanned() {
		lastScan = admin.Cell{Text: ago(now, ep.LastScanAt), Title: dateTime(ep.LastScanAt), NoWrap: true}
	}
	fingerprint := admin.Cell{Text: "–"}
	if fp := ep.Fingerprint; fp != "" {
		fingerprint = admin.Cell{Text: fp, Title: fp, Mono: true, NoWrap: true}
		if len(fp) > 16 {
			fingerprint.Text = fp[:16] + "…"
		}
		if s.ServedID != "" {
			fingerprint.Href = "/certificates/" + s.ServedID
		}
	}
	expires := admin.Cell{Text: "–"}
	if !ep.NotAfter.IsZero() {
		expires = admin.Cell{Text: view.Date(ep.NotAfter), Rel: view.Relative(now, ep.NotAfter), NoWrap: true}
		if al := s.Assessment.Expiry; al != nil {
			expires.Status = severityStatus(al.Severity)
		}
	}
	issuer := admin.Cell{Text: orDash(ep.Issuer), Break: true}
	if ep.Subject != "" {
		issuer.Title = "Subject: " + ep.Subject
	}
	lastError := admin.Cell{Text: "–"}
	if tlsscan.KnownKind(ep.LastErrorKind) {
		lastError = admin.Cell{Text: ep.LastErrorKind}
	}
	row := []admin.Cell{target, endpointState(s), lastScan, fingerprint, expires, issuer, lastError}
	if manage {
		row = append(row, admin.Cell{Text: orDash(ep.CreatedBy), NoWrap: true})
	}
	if manage || scan {
		var posts []admin.PostCommand
		field := []admin.PostField{{Name: "id", Value: ep.ID}}
		if scan {
			posts = append(posts, admin.PostCommand{Action: "/endpoints/scan", CSRF: c.sess.CSRFToken, Label: "Scan now", Command: true, Fields: field})
		}
		if manage {
			posts = append(posts, admin.PostCommand{Action: "/endpoints/delete", CSRF: c.sess.CSRFToken, Label: "Remove", Command: true, Danger: true, Fields: field})
		}
		row = append(row, admin.Cell{Posts: posts})
	}
	return row
}

func joinPorts(ports []int) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ", ")
}

func (a *app) endpointsPage(c *rc) {
	if a.d.Endpoints == nil {
		c.notice(http.StatusNotFound, "Not found", view.Message{Kind: view.MessageError, Text: "Monitoring is off."})
		return
	}
	states, err := a.d.Endpoints.List(c.r.Context(), c.who())
	if err != nil {
		c.fail(err)
		return
	}
	now := a.now()
	settings := a.d.Endpoints.Settings()
	manage := c.may(authz.ManageEndpoints, "")
	scan := c.may(authz.ScanEndpoint, "") && !settings.Off()

	table := admin.TableData{
		Empty: "No endpoint is entered.",
		Columns: []admin.Column{{Label: "Endpoint"}, {Label: "State"}, {Label: "Last scan"}, {Label: "Certificate (SHA-256)"},
			{Label: "Expires"}, {Label: "Issuer"}, {Label: "Last error"}},
	}
	if manage {
		table.Empty += " Add one below."
		table.Columns = append(table.Columns, admin.Column{Label: "Added by"})
	}
	if manage || scan {
		table.Columns = append(table.Columns, admin.Column{Label: ""})
	}
	ipWithoutName := false
	for _, s := range states {
		table.Rows = append(table.Rows, c.endpointRow(s, now, manage, scan))
		if s.Assessment.State == tlsscan.StateUnmanaged && s.Endpoint.IsIP() && s.Endpoint.SNI == "" {
			ipWithoutName = true
		}
	}
	list := admin.Section{Title: "Endpoints", Table: &table}
	if ipWithoutName {
		list.Text = append(list.Text, "An endpoint entered by IP address has no name to compare the certificate with. Remove it and add it again with an SNI.")
	}
	sections := []admin.Section{list}
	if manage {
		sections = append(sections, admin.Section{Forms: []admin.FormData{c.form(admin.FormData{
			Title: "Add an endpoint",
			Intro: []string{
				fmt.Sprintf("The server connects to the host and port, reads the certificate it serves and compares it with what this PKI issued for the name. The host must be covered by a domain of this PKI. %d of %d endpoints are entered.", len(states), settings.MaxEndpoints),
				"Ports the server scans (monitor.scan_ports): " + joinPorts(settings.Ports) + ".",
			},
			Action: "/endpoints", Submit: "Add endpoint",
			Fields: []admin.Field{
				{ID: "host", Label: "Host", Required: true, Hint: "A fully qualified name such as proxy.homelab.lan, or an IP address."},
				{ID: "port", Label: "Port", Required: true, Value: "443"},
				{ID: "sni", Label: "SNI (optional)", Hint: "The name to send and to expect the certificate for. An IP address needs one."},
			},
		})}})
	}
	var msgs []view.Message
	if settings.Off() {
		msgs = append(msgs, view.Message{Kind: view.MessageWarning, Text: "Scanning is switched off (monitor.scan_interval: off), so no endpoint is scanned and the states below are the last known ones."})
	}
	p := c.page("Endpoints", "endpoints")
	p.Description = "TLS services this server connects to, to check that each one serves the certificate this PKI issued for its name. A scan is one TLS handshake: no request is sent and nothing on the host changes."
	render(c.w, c.r, a.log, http.StatusOK, admin.DetailPage(p, admin.DetailData{Messages: c.messages(msgs...), Sections: sections}))
}

// sentence makes s end with a period.
func sentence(s string) string {
	if strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

// endpointRefused answers a refused or failed action with a message on the
// Endpoints page (Post/Redirect/Get). A refusal for the role is the 403 page.
// The service's refusals name the field and the rule and never an address
// that was resolved or the text of the input.
func (c *rc) endpointRefused(err error, notDone string) {
	var invalid *tlsscan.InvalidError
	var wait *tlsscan.WaitError
	switch {
	case errors.Is(err, authz.ErrDenied):
		c.fail(err)
		return
	case errors.As(err, &invalid):
		c.setFlash(view.Message{Kind: view.MessageError, Text: sentence(fmt.Sprintf("%s – %s: %s", notDone, invalid.Field, invalid.Rule))})
	case errors.As(err, &wait):
		c.setFlash(view.Message{Kind: view.MessageWarning, Text: sentence(wait.Error())})
	case errors.Is(err, tlsscan.ErrNotFound):
		c.setFlash(view.Message{Kind: view.MessageWarning, Text: "That endpoint is gone already."})
	case errors.Is(err, tlsscan.ErrConflict):
		c.setFlash(view.Message{Kind: view.MessageError, Text: sentence(notDone + " – " + strings.TrimPrefix(err.Error(), tlsscan.ErrConflict.Error()+": "))})
	default:
		c.a.log.ErrorContext(c.r.Context(), "ui endpoint action", slog.String("path", c.r.URL.Path), slog.Any("error", err))
		c.setFlash(view.Message{Kind: view.MessageError, Text: "Something went wrong – the server log has the details."})
	}
	c.redirect("/endpoints")
}

func (a *app) endpointCreate(c *rc) {
	if a.d.Endpoints == nil {
		c.notice(http.StatusNotFound, "Not found", view.Message{Kind: view.MessageError, Text: "Monitoring is off."})
		return
	}
	port, perr := strconv.Atoi(strings.TrimSpace(c.r.PostFormValue("port")))
	if perr != nil {
		c.setFlash(view.Message{Kind: view.MessageError, Text: "Not added – port: enter the port as a number, for example 443."})
		c.redirect("/endpoints")
		return
	}
	ep, err := a.d.Endpoints.Create(c.r.Context(), c.who(), tlsscan.Request{
		Host: c.r.PostFormValue("host"), Port: port, SNI: c.r.PostFormValue("sni"),
	})
	if err != nil {
		c.endpointRefused(err, "Not added")
		return
	}
	c.done("/endpoints", "Endpoint "+ep.Target()+" added. It is scanned within a minute.")
}

func (a *app) endpointScan(c *rc) {
	if a.d.Endpoints == nil {
		c.notice(http.StatusNotFound, "Not found", view.Message{Kind: view.MessageError, Text: "Monitoring is off."})
		return
	}
	if err := a.d.Endpoints.ScanNow(c.r.Context(), c.who(), c.r.PostFormValue("id")); err != nil {
		c.endpointRefused(err, "Not scanned")
		return
	}
	c.done("/endpoints", "Scan requested. The result shows here within a minute.")
}

func (a *app) endpointDelete(c *rc) {
	if a.d.Endpoints == nil {
		c.notice(http.StatusNotFound, "Not found", view.Message{Kind: view.MessageError, Text: "Monitoring is off."})
		return
	}
	if err := a.d.Endpoints.Delete(c.r.Context(), c.who(), c.r.PostFormValue("id")); err != nil {
		c.endpointRefused(err, "Not removed")
		return
	}
	c.done("/endpoints", "Endpoint removed. Its alerts resolve within a minute.")
}
