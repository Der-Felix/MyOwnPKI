package web

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/admin"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// Agents (v0.3, docs/PHASE3.md): the agents, the approval queue and the
// join tokens. The agent service decides; these pages show and ask. What
// agents reported is shown as text (templ escapes it), never as markup.

// agentsOff explains why the agent pages are empty.
func (a *app) agentsOff(c *rc, title, key string) bool {
	if a.d.Agents != nil {
		return false
	}
	render(c.w, c.r, a.log, http.StatusOK, admin.DetailPage(c.page(title, key), admin.DetailData{Sections: []admin.Section{{Text: []string{
		"Agents are off. The agent listener starts when agent.base_url, agent.tls_issuer and agent.ca are set in the configuration (OPERATIONS.md, chapter Agent).",
	}}}}))
	return true
}

func dateTime(t time.Time) string {
	if t.IsZero() {
		return "–"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

func (a *app) agentStatus(ag agents.Agent) admin.Cell {
	switch {
	case ag.Status == agents.StatusRevoked:
		return admin.Cell{Text: "revoked", Status: view.StatusCrit}
	case ag.Status == agents.StatusDisabled:
		return admin.Cell{Text: "disabled", Status: view.StatusNeutral}
	case ag.Silent(a.now()):
		return admin.Cell{Text: "silent", Status: view.StatusWarn}
	}
	return admin.Cell{Text: "active", Status: view.StatusOK}
}

func (a *app) agentList(c *rc) {
	if a.agentsOff(c, "Agents", "agents") {
		return
	}
	list, err := a.d.Agents.ListAgents(c.r.Context(), c.who())
	if err != nil {
		c.fail(err)
		return
	}
	d := admin.TableData{Messages: c.messages(), Empty: "No agents yet – see Enrollment requests and Join tokens.",
		Columns: []admin.Column{{Label: "Host"}, {Label: "Status"}, {Label: "Last seen"}, {Label: "Version"}, {Label: "System"}, {Label: "Admitted"}}}
	for _, ag := range list {
		d.Rows = append(d.Rows, []admin.Cell{
			{Text: ag.Hostname, Href: "/agents/" + ag.ID, Mono: true}, a.agentStatus(ag), {Text: dateTime(ag.LastSeenAt), NoWrap: true},
			{Text: orDash(ag.Version), Mono: true}, {Text: ag.OS + "/" + ag.Arch, Mono: true}, {Text: dateTime(ag.ApprovedAt) + " (" + ag.ApprovedBy + ")"},
		})
	}
	p := c.page("Agents", "agents")
	p.Description = "Hosts with myownpki-agent. An agent gets certificates by ACME for its names only."
	render(c.w, c.r, a.log, http.StatusOK, admin.TablePage(p, d))
}

func (a *app) agentDetail(c *rc) {
	if a.agentsOff(c, "Agent", "agents") {
		return
	}
	ag, err := a.d.Agents.GetAgent(c.r.Context(), c.who(), c.r.PathValue("id"))
	if err != nil {
		c.fail(err)
		return
	}
	cert := "–"
	if ag.CertificateID != "" {
		cert = ag.CertSerial
	}
	st := a.agentStatus(*ag)
	sections := []admin.Section{{Text: []string{"The agent certificate is valid for 7 days and renewed by the agent at 2/3 of its lifetime."}, KV: []view.KV{
		{Key: "Host", Value: ag.Hostname}, {Key: "Status", Value: st.Text}, {Key: "Agent", Value: ag.ID},
		{Key: "System", Value: ag.OS + "/" + ag.Arch + ", agent " + orDash(ag.Version)}, {Key: "Last seen", Value: dateTime(ag.LastSeenAt)},
		{Key: "Admitted", Value: dateTime(ag.ApprovedAt) + " by " + ag.ApprovedBy},
		{Key: "Agent certificate (serial)", Value: cert, Mono: true},
	}}}
	deployments := a.agentDeploymentTable(c, ag)
	deployments.RefreshURL = "/agents/" + ag.ID + "/deployments"
	sections = append(sections, admin.Section{Table: &deployments})
	if ag.CertificateID != "" {
		sections[0].KV = append(sections[0].KV, view.KV{Key: "Certificate page", Value: "View agent certificate", Href: "/certificates/" + ag.CertificateID})
	}
	base := "/agents/" + ag.ID
	canManage := c.may(authz.ManageAgents, "") && ag.Status != agents.StatusRevoked
	names := &admin.TableData{Title: "Names it may order", Empty: "None.", Columns: []admin.Column{{Label: "Name"}, {Label: "From"}, {Label: "Added"}, {Label: ""}}}
	for _, n := range ag.Names {
		row := []admin.Cell{{Text: n.Pattern, Mono: true}, {Text: n.Source}, {Text: dateTime(n.AddedAt) + " – " + n.AddedBy}}
		if canManage && n.Source != "hostname" {
			row = append(row, admin.Cell{Posts: []admin.PostCommand{{Action: base + "/names", CSRF: c.sess.CSRFToken, Label: "Remove", Command: true, Danger: true,
				Fields: []admin.PostField{{Name: "action", Value: "remove"}, {Name: "name", Value: n.Pattern}}}}})
		} else {
			row = append(row, admin.Cell{})
		}
		names.Rows = append(names.Rows, row)
	}
	sections = append(sections, admin.Section{Text: []string{
		"The ACME server refuses an order of this agent for any other name. *.suffix covers every name below the suffix.",
	}, Table: names})
	if canManage {
		forms := []admin.FormData{c.form(admin.FormData{
			Title: "Add a name", Action: base + "/names", Submit: "Add name",
			Fields: []admin.Field{{ID: "action", Type: "hidden", Value: "add"}, {ID: "name", Label: "Name or pattern", Required: true, Hint: "e.g. wiki.homelab.lan or *.apps.homelab.lan"}},
		})}
		agentPolicyFields := predecessorFields("predecessor", "predecessor_days", ag.EffectivePolicy)
		agentPolicyFields = append(agentPolicyFields, admin.Field{ID: "inherit", Label: "Inherit the tenant agent default", Type: "checkbox", Checked: ag.Predecessor == nil})
		forms = append(forms, c.form(admin.FormData{Title: "Agent predecessor default", Action: base + "/predecessor-policy", Submit: "Save predecessor default", Fields: agentPolicyFields}))
		for _, deployment := range ag.Deployments {
			fields := predecessorFields("predecessor", "predecessor_days", deployment.EffectivePolicy)
			fields = append(fields, admin.Field{ID: "inherit", Label: "Inherit the agent default", Type: "checkbox", Checked: deployment.Predecessor == nil})
			forms = append(forms, c.form(admin.FormData{Title: "Predecessor default: " + deployment.Name,
				Action: base + "/deployments/" + deployment.Name + "/predecessor-policy", Submit: "Save deployment default", Fields: fields}))
		}
		if ag.Status == agents.StatusActive {
			forms = append(forms, c.form(admin.FormData{Title: "Disable", Action: base + "/disable", Submit: "Disable agent",
				Intro: []string{"Cut off at its next call; its certificates stay valid. Enable it again here."}}))
		} else {
			forms = append(forms, c.form(admin.FormData{Title: "Enable", Action: base + "/enable", Submit: "Enable agent"}))
		}
		forms = append(forms, c.form(admin.FormData{Title: "Revoke", Action: base + "/revoke", Submit: "Revoke agent",
			Intro: []string{"For good: cut off at its next call, its agent certificates on the CRL. The certificates it deployed stay valid – revoke them under Certificates if needed."}}))
		sections = append(sections, admin.Section{Forms: forms})
	}
	crumbs := []view.Crumb{{Label: "Agents", Href: "/agents"}}
	p := c.page(ag.Hostname, "agents", crumbs...)
	p.Description = "Renew now asks this host to renew a deployment. Administrative changes need a fresh second factor."
	render(c.w, c.r, a.log, http.StatusOK, admin.DetailPage(p, admin.DetailData{Messages: c.messages(), Sections: sections}))
}

func (a *app) agentDeploymentTable(c *rc, ag *agents.Agent) admin.TableData {
	t := admin.TableData{Title: "Deployments", Empty: "This agent has not reported any deployments yet.", Adaptive: true, Columns: []admin.Column{
		{Label: "Deployment"}, {Label: "State"}, {Label: "Serial"}, {Label: "Expires"}, {Label: "Last error"}, {Label: "Renewal"},
	}}
	patterns := make([]string, 0, len(ag.Names))
	for _, name := range ag.Names {
		patterns = append(patterns, name.Pattern)
	}
	lastSeen := ag.LastSeenAt
	if lastSeen.IsZero() {
		lastSeen = ag.ApprovedAt
	}
	for _, d := range ag.Deployments {
		status := view.StatusNeutral
		switch d.State {
		case "deployed":
			status = view.StatusOK
		case "failed":
			status = view.StatusCrit
		case "rolled_back":
			status = view.StatusWarn
		}
		serial := admin.Cell{Text: orDash(d.Serial), Mono: true}
		if d.CertificateID != "" {
			serial.Href = "/certificates/" + d.CertificateID
		}
		details := d.Profile
		if len(d.Names) > 0 {
			if details != "" {
				details += " · "
			}
			details += strings.Join(d.Names, ", ")
		}
		var refused []string
		for _, name := range d.Names {
			if !agents.MatchesAny(patterns, name) {
				refused = append(refused, name)
			}
		}
		if len(refused) > 0 {
			if details != "" {
				details += " · "
			}
			details += "not covered by Names it may order: " + strings.Join(refused, ", ") + "; the ACME server will refuse them"
		}
		if d.Removed {
			if details != "" {
				details += " · "
			}
			details += "not in the agent configuration"
		}
		pending := !d.RenewRequestedAt.IsZero()
		renewal := admin.Cell{}
		if !pending && !d.Removed && ag.Status == agents.StatusActive && c.may(authz.RenewAgent, "") {
			renewal.Text = "Renew now"
			renewal.Href = "/agents/" + ag.ID + "/deployments/" + d.Name + "/renew"
		}
		if pending {
			renewal.Text = "Renewal requested · " + dateTime(d.RenewRequestedAt) + " by " + d.RenewRequestedBy
			renewal.Status = view.StatusInfo
			if ag.Silent(a.now()) {
				renewal.Text = "waiting for the agent (last seen " + dateTime(lastSeen) + ")"
				renewal.Status = view.StatusWarn
			}
			renewal.Posts = []admin.PostCommand{{Action: "/agents/" + ag.ID + "/deployments/" + d.Name + "/withdraw",
				CSRF: c.sess.CSRFToken, Label: "Withdraw", Disabled: !c.may(authz.RenewAgent, "")}}
		}
		if d.RevocationPlannedAt != nil {
			renewal.Text = "Revocation planned · " + view.Date(*d.RevocationPlannedAt)
			renewal.Status = view.StatusInfo
		}
		t.Rows = append(t.Rows, []admin.Cell{{Text: d.Name, Rel: details},
			{Text: strings.ReplaceAll(d.State, "_", " "), Status: status}, serial, {Text: dateTime(d.NotAfter), NoWrap: true},
			{Text: d.LastError, Break: true}, renewal})
	}
	return t
}

func (a *app) agentDeployments(c *rc) {
	if a.d.Agents == nil {
		http.NotFound(c.w, c.r)
		return
	}
	ag, err := a.d.Agents.GetAgent(c.r.Context(), c.who(), c.r.PathValue("id"))
	if err != nil {
		c.fail(err)
		return
	}
	render(c.w, c.r, a.log, http.StatusOK, admin.Table(a.agentDeploymentTable(c, ag)))
}

func (a *app) agentRenewPage(c *rc) {
	if a.d.Agents == nil {
		http.NotFound(c.w, c.r)
		return
	}
	id, name := c.r.PathValue("id"), c.r.PathValue("name")
	ag, err := a.d.Agents.GetAgent(c.r.Context(), c.who(), id)
	if err != nil {
		c.fail(err)
		return
	}
	back := "/agents/" + id
	for _, deployment := range ag.Deployments {
		if deployment.Name != name {
			continue
		}
		render(c.w, c.r, a.log, http.StatusOK, admin.FormPage(c.page("Renew "+name, "agents", view.Crumb{Label: "Agents", Href: "/agents"}, view.Crumb{Label: ag.Hostname, Href: back}), c.form(admin.FormData{
			Intro:  []string{"Renewal starts on the agent. The predecessor action happens only after an accepted deployed report with its TLS check."},
			Action: back + "/deployments/" + name + "/renew", Submit: "Renew now", Cancel: back,
			Fields: predecessorFields("predecessor", "predecessor_days", deployment.EffectivePolicy),
		})))
		return
	}
	c.fail(ca.ErrNotFound)
}

func (a *app) agentRenew(c *rc) {
	if a.d.Agents == nil {
		http.NotFound(c.w, c.r)
		return
	}
	id := c.r.PathValue("id")
	policy := predecessorFromForm(c.r.PostFormValue, "predecessor", "predecessor_days")
	if err := a.d.Agents.RequestRenewal(c.r.Context(), c.who(), id, c.r.PathValue("name"), policy); err != nil {
		c.refused(err, "/agents/"+id+"/deployments/"+c.r.PathValue("name")+"/renew")
		return
	}
	c.done("/agents/"+id, "Renewal requested; predecessor: "+predecessorText(policy)+".")
}

func (a *app) agentPredecessorPolicy(c *rc) {
	if a.d.Agents == nil {
		http.NotFound(c.w, c.r)
		return
	}
	id, name := c.r.PathValue("id"), c.r.PathValue("name")
	back := "/agents/" + id
	if yes(c.r.PostFormValue("inherit")) {
		if err := a.d.Agents.SetPredecessorPolicy(c.r.Context(), c.who(), id, name, nil); err != nil {
			c.refused(err, back)
			return
		}
	} else {
		policy := predecessorFromForm(c.r.PostFormValue, "predecessor", "predecessor_days")
		if err := a.d.Agents.SetPredecessorPolicy(c.r.Context(), c.who(), id, name, &policy); err != nil {
			c.refused(err, back)
			return
		}
	}
	c.done(back, "Predecessor policy saved.")
}

func (a *app) agentWithdraw(c *rc) {
	if a.d.Agents == nil {
		http.NotFound(c.w, c.r)
		return
	}
	id := c.r.PathValue("id")
	if err := a.d.Agents.WithdrawRenewal(c.r.Context(), c.who(), id, c.r.PathValue("name")); err != nil {
		c.refused(err, "/agents/"+id)
		return
	}
	c.done("/agents/"+id, "Renewal request withdrawn.")
}

func (a *app) agentNames(c *rc) {
	if a.agentsOff(c, "Agent", "agents") {
		return
	}
	id, name := c.r.PathValue("id"), c.r.PostFormValue("name")
	back := "/agents/" + id
	var err error
	if c.r.PostFormValue("action") == "remove" {
		err = a.d.Agents.RemoveName(c.r.Context(), c.who(), id, name)
	} else {
		err = a.d.Agents.AddName(c.r.Context(), c.who(), id, name)
	}
	if err != nil {
		c.refused(err, back)
		return
	}
	c.done(back, "Names changed.")
}

func (a *app) agentAction(c *rc) {
	if a.agentsOff(c, "Agent", "agents") {
		return
	}
	id := c.r.PathValue("id")
	back := "/agents/" + id
	var err error
	var text string
	switch c.r.PathValue("action") {
	case "disable":
		err, text = a.d.Agents.SetDisabled(c.r.Context(), c.who(), id, true), "Agent disabled."
	case "enable":
		err, text = a.d.Agents.SetDisabled(c.r.Context(), c.who(), id, false), "Agent enabled."
	case "revoke":
		err, text = a.d.Agents.Revoke(c.r.Context(), c.who(), id), "Agent revoked."
	default:
		c.fail(ca.ErrNotFound)
		return
	}
	if err != nil {
		c.refused(err, back)
		return
	}
	c.done(back, text)
}

func enrollmentRow(e agents.Enrollment) []admin.Cell {
	token := admin.Cell{Text: "valid", Status: view.StatusOK}
	switch {
	case e.KnownAgent:
		token = admin.Cell{Text: "known agent key", Status: view.StatusOK}
	case !e.TokenValid && e.TokenProblem != "":
		token = admin.Cell{Text: e.TokenProblem, Status: view.StatusWarn, Break: true}
	case !e.TokenValid:
		token = admin.Cell{Text: "none", Status: view.StatusNeutral}
	}
	check := admin.Cell{Text: e.CheckState + " (" + e.CheckMethod + ")", Status: view.StatusNeutral}
	switch e.CheckState {
	case "passed":
		check.Status = view.StatusOK
	case "failed":
		check = admin.Cell{Text: "failed: " + e.CheckError, Status: view.StatusCrit, Break: true}
	}
	return []admin.Cell{{Text: e.Hostname, Mono: true}, {Text: strings.ReplaceAll(e.State, "_", " ")}, token, check,
		{Text: e.SourceIP, Mono: true}, {Text: dateTime(e.CreatedAt), NoWrap: true}, {Text: dateTime(e.ExpiresAt), NoWrap: true}}
}

func (a *app) enrollmentList(c *rc) {
	if a.agentsOff(c, "Enrollment requests", "enrollment") {
		return
	}
	open, err := a.d.Agents.ListEnrollments(c.r.Context(), c.who(), true)
	if err != nil {
		c.fail(err)
		return
	}
	all, err := a.d.Agents.ListEnrollments(c.r.Context(), c.who(), false)
	if err != nil {
		c.fail(err)
		return
	}
	cols := []admin.Column{{Label: "Host"}, {Label: "State"}, {Label: "Join token"}, {Label: "Check"}, {Label: "From"}, {Label: "Asked"}, {Label: "Expires"}}
	queue := &admin.TableData{Title: "Waiting", Columns: cols, Empty: "No enrollment waits."}
	var opts []admin.Option
	for _, e := range open {
		queue.Rows = append(queue.Rows, enrollmentRow(e))
		if e.State == agents.StatePending {
			opts = append(opts, admin.Option{Value: e.ID, Label: e.Hostname + " from " + e.SourceIP + " (" + dateTime(e.CreatedAt) + ")"})
		}
	}
	decided := &admin.TableData{Title: "Decided and expired", Columns: cols, Empty: "Nothing yet."}
	for _, e := range all {
		if e.State != agents.StatePending && e.State != agents.StateWaitingForCheck {
			decided.Rows = append(decided.Rows, enrollmentRow(e))
		}
	}
	mode := "verified"
	if s, serr := a.d.Settings.Get(c.r.Context(), a.d.Tenant, c.who()); serr == nil && s.AgentEnrollment != nil {
		mode = *s.AgentEnrollment
	}
	sections := []admin.Section{{Text: []string{
		"An agent proves control of its hostname: the server fetches a file from http://<host>/.well-known/acme-challenge/ (the agent's own port 80, or the web server's webroot).",
		"A passed check proves control of the name, not that you want the host – that is what the join token says. Enrollment mode of this tenant: " + mode + " (Tenant settings).",
		"Approve only hosts you expect: compare the host and the address with the machine you set up.",
	}}, {Table: queue}}
	if len(opts) > 0 && c.may(authz.ManageAgents, "") {
		sections = append(sections, admin.Section{Forms: []admin.FormData{
			c.form(admin.FormData{Title: "Approve", Action: "/agents/enrollments/approve", Submit: "Approve enrollment",
				Fields: []admin.Field{{ID: "id", Label: "Enrollment", Type: "select", Options: opts}}}),
			c.form(admin.FormData{Title: "Refuse", Action: "/agents/enrollments/deny", Submit: "Refuse enrollment",
				Fields: []admin.Field{{ID: "id", Label: "Enrollment", Type: "select", Options: opts}}}),
		}})
	}
	sections = append(sections, admin.Section{Table: decided})
	p := c.page("Enrollment requests", "enrollment")
	p.Description = "Hosts that asked to become agents (like salt-key). Decisions need a fresh second factor."
	render(c.w, c.r, a.log, http.StatusOK, admin.DetailPage(p, admin.DetailData{Messages: c.messages(), Sections: sections}))
}

func (a *app) enrollmentDecide(c *rc) {
	if a.agentsOff(c, "Enrollment requests", "enrollment") {
		return
	}
	id := c.r.PostFormValue("id")
	var err error
	text := "Enrollment approved – the agent gets its certificate within 30 seconds."
	if strings.HasSuffix(c.r.URL.Path, "/deny") {
		err, text = a.d.Agents.Deny(c.r.Context(), c.who(), id), "Enrollment refused."
	} else {
		err = a.d.Agents.Approve(c.r.Context(), c.who(), id)
	}
	if err != nil {
		c.refused(err, "/agents/enrollments")
		return
	}
	c.done("/agents/enrollments", text)
}

func (a *app) joinTokens(c *rc) {
	if a.agentsOff(c, "Join tokens", "join-tokens") {
		return
	}
	list, err := a.d.Agents.ListJoinTokens(c.r.Context(), c.who())
	if err != nil {
		c.fail(err)
		return
	}
	t := &admin.TableData{Title: "Tokens", Empty: "No join tokens yet.",
		Columns: []admin.Column{{Label: "Label"}, {Label: "For"}, {Label: "Status"}, {Label: "Expires"}, {Label: "Created by"}}}
	var unused []admin.Option
	now := a.now()
	for _, j := range list {
		st := admin.Cell{Text: "unused", Status: view.StatusOK}
		switch {
		case !j.UsedAt.IsZero():
			st = admin.Cell{Text: "used " + dateTime(j.UsedAt), Status: view.StatusNeutral}
		case !now.Before(j.ExpiresAt):
			st = admin.Cell{Text: "expired", Status: view.StatusNeutral}
		default:
			unused = append(unused, admin.Option{Value: j.ID, Label: orDash(j.Label) + " – " + strings.Join(j.Patterns, ", ")})
		}
		t.Rows = append(t.Rows, []admin.Cell{{Text: orDash(j.Label)}, {Text: strings.Join(j.Patterns, ", "), Mono: true, Break: true}, st,
			{Text: dateTime(j.ExpiresAt), NoWrap: true}, {Text: j.CreatedBy}})
	}
	sections := []admin.Section{{Text: []string{
		"A join token lets one host enroll; in the mode verified it is needed together with a passed check. It works once, expires, and only for hosts whose name matches.",
		"Its secret is shown once – put it into a file on the host and run myownpki-agent enroll --token-file FILE.",
	}}}
	if c.may(authz.ManageAgents, "") {
		forms := []admin.FormData{c.form(admin.FormData{
			Title: "New token", Action: "/agents/tokens", Submit: "Create token",
			Fields: []admin.Field{
				{ID: "label", Label: "Label", Hint: "What it is for, e.g. the host."},
				{ID: "names", Label: "Host names", Type: "textarea", Rows: 3, Required: true, Hint: "One per line, an exact name or *.suffix – the host's name must match one."},
				{ID: "hours", Label: "Valid for hours", Type: "number", Value: "24", Hint: "1 to 720."},
			},
		})}
		if len(unused) > 0 {
			forms = append(forms, c.form(admin.FormData{Title: "Withdraw", Action: "/agents/tokens/delete", Submit: "Withdraw token",
				Fields: []admin.Field{{ID: "id", Label: "Token", Type: "select", Options: unused}}}))
		}
		sections = append(sections, admin.Section{Forms: forms})
	}
	sections = append(sections, admin.Section{Table: t})
	p := c.page("Join tokens", "join-tokens")
	p.Description = "Single-use tokens for enrolling hosts. Creating one needs a fresh second factor."
	render(c.w, c.r, a.log, http.StatusOK, admin.DetailPage(p, admin.DetailData{Messages: c.messages(), Sections: sections}))
}

func (a *app) joinTokenCreate(c *rc) {
	if a.agentsOff(c, "Join tokens", "join-tokens") {
		return
	}
	var names []string
	for _, line := range strings.FieldsFunc(c.r.PostFormValue("names"), func(r rune) bool { return r == '\n' || r == ',' || r == ' ' || r == '\r' }) {
		if line = strings.TrimSpace(line); line != "" {
			names = append(names, line)
		}
	}
	hours, err := strconv.Atoi(strings.TrimSpace(c.r.PostFormValue("hours")))
	if err != nil || hours < 1 || hours > 720 {
		c.refused(agents.ErrInvalid, "/agents/tokens")
		return
	}
	secret, jt, err := a.d.Agents.CreateJoinToken(c.r.Context(), c.who(), c.r.PostFormValue("label"), names, time.Duration(hours)*time.Hour)
	if err != nil {
		c.refused(err, "/agents/tokens")
		return
	}
	crumbs := []view.Crumb{{Label: "Join tokens", Href: "/agents/tokens"}}
	c.once(c.page("New join token", "join-tokens", crumbs...), admin.DetailData{Sections: []admin.Section{
		{Text: []string{"Copy the token now – it is not shown again. It works once, for " + strings.Join(jt.Patterns, ", ") + ", until " + dateTime(jt.ExpiresAt) + "."},
			KV: []view.KV{{Key: "Join token", Value: secret}}},
		{Title: "On the host", Pre: []admin.Pre{{Title: "Enroll", Text: "umask 077\nprintf '%s\\n' '" + secret + "' > /root/join-token\n" +
			"myownpki-agent enroll --token-file /root/join-token\nrm /root/join-token\nsystemctl enable --now myownpki-agent"}}},
	}})
}

func (a *app) joinTokenDelete(c *rc) {
	if a.agentsOff(c, "Join tokens", "join-tokens") {
		return
	}
	if err := a.d.Agents.DeleteJoinToken(c.r.Context(), c.who(), c.r.PostFormValue("id")); err != nil {
		c.refused(err, "/agents/tokens")
		return
	}
	c.done("/agents/tokens", "Join token withdrawn.")
}
