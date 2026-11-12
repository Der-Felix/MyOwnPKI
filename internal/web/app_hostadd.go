package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agentdist"
	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/recipe"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/web/components"
	"github.com/Der-Felix/MyOwnPKI/internal/web/pages/admin"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// The Add host assistant (docs/PHASE3.md section 11, step 32): a short,
// server-rendered flow of plain forms. Step 1 asks for the host, the service
// and the challenge. Step 2 shows how the host is admitted and, once the admin
// has chosen (and, for a token, confirmed with the second factor), the commands
// to paste on the host. Step 3 is a progress page that reloads itself with a
// <meta http-equiv="refresh"> while the host is on its way; the UI ships no
// script. Only an admin (agent.manage) creates a token; everybody who may read
// the agents sees the pages. Nothing is stored for the assistant.

func hostAddSteps(current int) []components.Step {
	labels := []string{"Host", "Admission and commands", "Progress"}
	out := make([]components.Step, len(labels))
	for i, l := range labels {
		state := "todo"
		switch {
		case i+1 < current:
			state = "done"
		case i+1 == current:
			state = "current"
		}
		out[i] = components.Step{Label: l, State: state}
	}
	return out
}

func (a *app) hostAddCrumbs() []view.Crumb { return []view.Crumb{{Label: "Agents", Href: "/agents"}} }

// hostAddAllowed lets through whoever may read the agents (tenant-wide).
func (a *app) hostAddAllowed(c *rc, title string) bool {
	if a.agentsOff(c, title, hostAddNavKey) {
		return false
	}
	if !c.may(authz.ReadPKI, "") {
		c.fail(authz.ErrDenied)
		return false
	}
	return true
}

// enrollmentMode is the enrollment mode of the tenant (verified unless set).
func (a *app) enrollmentMode(c *rc) string {
	if a.d.Settings != nil {
		if s, err := a.d.Settings.Get(c.r.Context(), a.d.Tenant, c.who()); err == nil && s.AgentEnrollment != nil {
			return *s.AgentEnrollment
		}
	}
	return tenant.EnrollVerified
}

func (a *app) hostPlanFromForm(c *rc) (hostPlan, error) {
	return parseHostPlan(c.r.PostFormValue, a.d.AgentDist != nil)
}

// nameCheck asks the domain rules the same question the enrollment check and
// the ACME server ask, and answers in words. A name no domain covers, or a
// domain without http-01, is refused: the host could never finish.
func (a *app) nameCheck(ctx context.Context, name string) (string, error) {
	d, err := a.d.Engine.DomainFor(ctx, "dns", name)
	if err != nil {
		return "", err
	}
	if d == nil {
		return "", fmt.Errorf("%w: no domain of this PKI covers %s. An admin has to add one under ACME > Domains first; until then neither the enrollment check nor a certificate order for it can succeed", agents.ErrInvalid, name)
	}
	if !d.AllowsChallenge(ca.ChallengeHTTP01) {
		return "", fmt.Errorf("%w: the domain %s covers %s but does not allow http-01, and the agent proves names with http-01 only. Allow it under ACME > Domains first", agents.ErrInvalid, d.Name, name)
	}
	return name + " is covered by the domain " + d.Name + " (CA " + d.CA + "), which allows http-01.", nil
}

// checkPlan runs the domain rules over every name of the plan and the ACME
// directory of this server. It returns one sentence per name.
func (a *app) checkPlan(c *rc, p hostPlan) ([]string, string, error) {
	acme, err := acmeDirectoryFor(a.d.ACMEDirectory)
	if err != nil {
		return nil, "", err
	}
	var words []string
	for _, name := range p.Names {
		w, nameErr := a.nameCheck(c.r.Context(), name)
		if nameErr != nil {
			return nil, "", nameErr
		}
		words = append(words, w)
	}
	return words, acme, nil
}

// ---------------------------------------------------------------- step 1

func (a *app) hostAddPage(c *rc) {
	if !a.hostAddAllowed(c, "Add host") {
		return
	}
	services := make([]admin.Option, 0, len(hostServices))
	for i, s := range hostServices {
		services = append(services, admin.Option{Value: s.ID, Label: s.Label, Selected: i == 0})
	}
	formats := []admin.Option{{Value: "none", Label: "already installed"}}
	if a.d.AgentDist != nil {
		formats = []admin.Option{{Value: "deb", Label: ".deb (Debian, Ubuntu)", Selected: true}, {Value: "rpm", Label: ".rpm"}, {Value: "tarball", Label: "tarball"},
			{Value: "none", Label: "already installed – skip the package"}}
	}
	form := c.form(admin.FormData{
		Steps: hostAddSteps(1), Action: hostAddPath, Submit: "Next: admission",
		Intro: []string{
			"Add host takes you from a new host name to a deployed certificate: you answer a few questions here, paste two command blocks on the host, and this page then follows the host until its first certificate is in place. Nothing is stored for it.",
			"The server checks that the host controls its name with http-01: it fetches a file from http://<host>/.well-known/acme-challenge/ on port 80. With standalone the agent opens port 80 briefly itself, so nothing else may listen there; with webroot your web server keeps port 80 and the agent only writes the file into the webroot directory.",
		},
		Fields: []admin.Field{
			{ID: "hostname", Label: "Host name", Required: true, Hint: "One exact, fully qualified, lower case name that a domain of this PKI covers, for example proxy1.homelab.lan."},
			{ID: "service", Label: "Service", Type: "select", Options: services, Hint: "Fills hooks, files, local check and systemd sandbox. The Postfix, Dovecot and Proxmox recipes are examples written from the documentation and not yet verified on a live host: try them on a test host first."},
			{ID: "challenge", Label: "http-01 challenge", Type: "select", Options: []admin.Option{
				{Value: "webroot", Label: "webroot – my web server answers on port 80", Selected: true},
				{Value: "standalone", Label: "standalone – the agent answers on port 80 itself"}}},
			{ID: "webroot", Label: "Webroot directory", Value: "/var/www/acme", Hint: "For webroot: an absolute directory on the host that the web server serves under /.well-known/acme-challenge/, letters, digits and . _ - / only."},
			{ID: "names", Label: "More certificate names", Type: "textarea", Rows: 3, Hint: "Optional, one per line. The certificate covers the host name; extra names need the one-use token of the next step and a domain that covers them."},
			{ID: "format", Label: "Agent package", Type: "select", Options: formats, Hint: "Downloaded over HTTPS with the verified root and checked against the SHA-256 shown in the next step."},
			{ID: "arch", Label: "Architecture", Type: "select", Options: []admin.Option{{Value: "amd64", Label: "linux/amd64", Selected: true}, {Value: "arm64", Label: "linux/arm64"}}},
		},
	})
	if !c.may(authz.ManageAgents, "") {
		form.Messages = append(form.Messages, view.Message{Kind: view.MessageInfo, Text: "You can look through the assistant. Creating a join token needs an admin with a fresh second factor; without one the host is admitted by an admin's approval."})
	}
	p := c.page("Add host", hostAddNavKey, a.hostAddCrumbs()...)
	p.Description = "From a new host name to a deployed certificate."
	render(c.w, c.r, a.log, http.StatusOK, admin.FormPage(p, form))
}

// ---------------------------------------------------------------- step 2

// activePassFor is an enrollment pass that could admit the host right now.
func (a *app) activePassFor(c *rc, host string, now time.Time) *agents.JoinToken {
	list, err := a.d.Agents.ListJoinTokens(c.r.Context(), c.who())
	if err != nil {
		return nil
	}
	for i := range list {
		j := &list[i]
		if j.Kind == agents.KindPass && j.Usable(now) && agents.MatchesAny(j.Patterns, host) {
			return j
		}
	}
	return nil
}

// hostAddNext is step 1 -> step 2. It changes nothing, so it answers with the
// page itself (like the steps of the certificate wizard); a mistake goes back
// to step 1 with the reason.
func (a *app) hostAddNext(c *rc) {
	if !a.hostAddAllowed(c, "Add host") {
		return
	}
	plan, err := a.hostPlanFromForm(c)
	if err != nil {
		c.refused(err, hostAddPath)
		return
	}
	words, _, err := a.checkPlan(c, plan)
	if err != nil {
		c.refused(err, hostAddPath)
		return
	}
	now := a.now()
	mode := a.enrollmentMode(c)
	mayToken := c.may(authz.ManageAgents, "")

	var existing *agents.Agent
	if list, listErr := a.d.Agents.ListAgents(c.r.Context(), c.who()); listErr == nil {
		existing = pickAgent(list, plan.Host)
		if existing != nil && existing.Status == agents.StatusRevoked {
			existing = nil
		}
	}
	var pass *agents.JoinToken
	if len(plan.Names) == 1 && existing == nil {
		pass = a.activePassFor(c, plan.Host, now)
	}

	rows := &admin.TableData{Title: "Ways to be admitted", Columns: []admin.Column{{Label: "Admission"}, {Label: "What happens"}, {Label: "Approval"}}}
	var options []admin.Option
	add := func(value, label, extra string, selected bool) {
		approval, text := admissionOutcome(mode, value)
		need := "none"
		if approval {
			need = "one approval by an admin"
		}
		rows.Rows = append(rows.Rows, []admin.Cell{{Text: label}, {Text: extra + text, Break: true}, {Text: need}})
		options = append(options, admin.Option{Value: value, Label: label, Selected: selected})
	}
	if mayToken {
		add(admitToken, "Single-use join token for this host", "The assistant creates a token that works once, for 15 minutes, for "+strings.Join(plan.Names, ", ")+" only. Creating it needs your second factor. ", true)
	}
	if pass != nil {
		add(admitPass, "Enrollment pass \""+clipText(pass.Label, 60)+"\"", fmt.Sprintf("An admin made this pass earlier (%d of %d uses taken, until %s). This page never shows a pass; you type or paste it on the host. It grants the host its own name only. ", pass.UseCount, pass.MaxUses, dateTime(pass.ExpiresAt)), !mayToken)
	}
	if len(plan.Names) == 1 {
		add(admitNone, "No secret", "", !mayToken && pass == nil)
	}

	sections := []admin.Section{{Title: "Your answers", KV: []view.KV{
		{Key: "Host", Value: plan.Host, Mono: true},
		{Key: "Service", Value: plan.Service.Label},
		{Key: "Challenge", Value: challengeText(plan)},
		{Key: "Certificate names", Value: strings.Join(plan.Names, ", "), Mono: true},
		{Key: "Agent package", Value: packageText(plan)},
	}}, {Title: "Domain check", Text: words}}

	var notes []view.Message
	if plan.Service.Recipe != "" {
		if r, ok := recipe.Get(plan.Service.Recipe); ok && r.Example {
			notes = append(notes, view.Message{Kind: view.MessageWarning, Text: "The " + plan.Service.ID + " recipe is an example written from the documentation of the service and not yet verified on a live host. Try it on a test host first."})
		}
	}
	if plan.Service.ID == "nginx" && plan.Challenge == "standalone" {
		notes = append(notes, view.Message{Kind: view.MessageWarning, Text: "nginx normally listens on port 80, and standalone needs that port free while the agent proves the name. Choose webroot unless nginx does not serve port 80."})
	}
	if existing != nil {
		notes = append(notes, view.Message{Kind: view.MessageWarning, Text: "An agent for " + plan.Host + " exists already (" + existing.Status + "). You do not need to enroll it again: run only the deployment block on the host. A pass refuses such a host."})
	}
	if len(plan.Names) > 1 {
		notes = append(notes, view.Message{Kind: view.MessageInfo, Text: "More than the host name means only the one-use token fits: its names become the names the agent may order. With no secret or a pass the agent may order its host name only."})
	}
	if !mayToken {
		notes = append(notes, view.Message{Kind: view.MessageInfo, Text: "Creating a join token needs an admin with a fresh second factor, so it is not offered to you. Ask an admin to run this assistant, or use the way below: the host enrolls without a secret and an admin approves it."})
	}
	if len(options) == 0 {
		notes = append(notes, view.Message{Kind: view.MessageError, Text: "Extra certificate names need the one-use join token, which only an admin can create. Remove the extra names or ask an admin."})
	}

	p := c.page("Add host: "+plan.Host, hostAddNavKey, a.hostAddCrumbs()...)
	p.Description = "Step 2: how the host is admitted. The tenant's enrollment mode is " + mode + "."
	sections = append(sections, admin.Section{Table: rows})
	if len(options) > 0 {
		hidden := func(id, value string) admin.Field { return admin.Field{ID: id, Type: "hidden", Value: value} }
		fields := []admin.Field{hidden("hostname", plan.Host), hidden("service", plan.Service.ID), hidden("challenge", plan.Challenge), hidden("webroot", plan.Webroot),
			hidden("names", strings.Join(plan.ExtraNames(), "\n")), hidden("format", plan.Format), hidden("arch", plan.Arch),
			{ID: "admission", Label: "Admission", Type: "select", Options: options}}
		sections = append(sections, admin.Section{Forms: []admin.FormData{c.form(admin.FormData{
			Action: hostAddCommands, Submit: "Show the commands", Cancel: hostAddPath, Fields: fields,
			Intro: []string{"The commands appear once. With the token, this step asks for your second factor first and creates the token."},
		})}})
	}
	render(c.w, c.r, a.log, http.StatusOK, admin.DetailPage(p, admin.DetailData{Steps: hostAddSteps(2), Messages: c.messages(notes...), Sections: sections}))
}

func challengeText(p hostPlan) string {
	if p.Challenge == "webroot" {
		return "webroot " + p.Webroot
	}
	return "standalone (the agent answers on port 80)"
}

func packageText(p hostPlan) string {
	if p.Format == "none" {
		return "already installed"
	}
	if p.Format == "tarball" {
		return "tarball for linux/" + p.Arch
	}
	return "." + p.Format + " for linux/" + p.Arch
}

// ---------------------------------------------------------------- the commands

// hostAddShow is step 2 -> the commands. For a token it needs the admin role
// and a fresh second factor (the route is protected, so the form travels
// through the step-up page and back); everything that can fail is checked
// before the token exists. The answer to the POST is the page itself, never
// cached: that is the only place the secret ever appears.
func (a *app) hostAddShow(c *rc) {
	if !a.hostAddAllowed(c, "Add host") {
		return
	}
	plan, err := a.hostPlanFromForm(c)
	if err != nil {
		c.refused(err, hostAddPath)
		return
	}
	if _, _, err = a.checkPlan(c, plan); err != nil {
		c.refused(err, hostAddPath)
		return
	}
	acme, _ := acmeDirectoryFor(a.d.ACMEDirectory)
	if len(plan.Names) > 1 && plan.Admission != admitToken {
		c.refused(fmt.Errorf("%w: more certificate names than the host name need the one-use join token", agents.ErrInvalid), hostAddPath)
		return
	}
	now := a.now()
	var pass *agents.JoinToken
	switch plan.Admission {
	case admitToken:
		if !c.may(authz.ManageAgents, "") {
			c.fail(authz.ErrDenied)
			return
		}
	case admitPass:
		if list, listErr := a.d.Agents.ListAgents(c.r.Context(), c.who()); listErr == nil {
			if have := pickAgent(list, plan.Host); have != nil && have.Status != agents.StatusRevoked {
				c.refused(fmt.Errorf("%w: an agent for %s exists; a pass admits new hosts only", agents.ErrInvalid, plan.Host), hostAddPath)
				return
			}
		}
		if pass = a.activePassFor(c, plan.Host, now); pass == nil {
			c.refused(fmt.Errorf("%w: no active enrollment pass covers %s any more; choose another way", agents.ErrInvalid, plan.Host), hostAddPath)
			return
		}
	}
	trust, err := a.agentTLSTrust(c)
	if err != nil {
		c.fail(err)
		return
	}
	var artifact agentdist.Artifact
	if plan.Format != "none" {
		if artifact, err = a.d.AgentDist.Artifact(plan.Format, plan.Arch); err != nil {
			c.fail(ca.ErrNotFound)
			return
		}
	}
	secret := ""
	if plan.Admission == admitToken {
		if err = c.sess.Principal.FreshStepUp(now); err != nil {
			c.refused(err, hostAddPath)
			return
		}
		secret, _, err = a.d.Agents.CreateJoinToken(c.r.Context(), c.who(), "Add host "+plan.Host, plan.Names, hostAddTokenTTL*time.Minute)
		if err != nil {
			c.refused(err, hostAddPath)
			return
		}
	}
	install := ""
	if plan.Format != "none" {
		install = a.packageInstallLines(artifact, plan.Format)
	}
	mode := a.enrollmentMode(c)
	approval, outcome := admissionOutcome(mode, plan.Admission)

	var sections []admin.Section
	switch plan.Admission {
	case admitToken:
		sections = append(sections, admin.Section{Title: "One-use join token — shown only now", Text: []string{
			"This token is valid for " + strconv.Itoa(hostAddTokenTTL) + " minutes and works once, for " + strings.Join(plan.Names, ", ") + ". It is absent from URLs, process arguments, action summaries and later pages.",
		}, Pre: []admin.Pre{{Title: "1. Write the root-only token file", Text: tokenFileCommands(secret)}}})
	case admitPass:
		sections = append(sections, admin.Section{Title: "Enrollment pass \"" + clipText(pass.Label, 60) + "\"", Text: []string{
			"The pass is not shown here; this page never knows it. Type or paste it when the command asks: it goes into the root-only token file, and setup deletes the file once the host is admitted.",
		}, Pre: []admin.Pre{{Title: "1. Write the pass to the root-only token file", Text: passFileCommands()}}})
	default:
		sections = append(sections, admin.Section{Title: "No secret", Text: []string{
			"The host enrolls without a token. The server checks its name with http-01 and an admin decides.",
		}})
	}
	values := []view.KV{{Key: "Root SHA-256 (DER, authoritative)", Value: trust.rootSHA256, Mono: true}}
	if plan.Format != "none" {
		values = append(values, view.KV{Key: "Package SHA-256", Value: artifact.SHA256, Mono: true})
	}
	setupTitle := "2. Verify the root and run setup"
	setupIntro := "Run as root on " + plan.Host + ". The root comes over HTTP and is accepted only after its DER SHA-256 matches the independent value shown here; the package and its checksums then use HTTPS with that verified root."
	if plan.Format != "none" {
		setupTitle = "2. Verify the root, install the agent and run setup"
	} else {
		setupIntro += " The agent must be installed already."
	}
	hostWord := shellQuote(plan.Host)
	sections = append(sections,
		admin.Section{Title: "Independent values from this authenticated UI", Text: []string{"Compare these literals yourself; neither the downloaded root nor checksums.txt supplies an expected value."}, KV: values},
		admin.Section{Title: "On the host", Text: []string{setupIntro},
			Pre: []admin.Pre{{Title: setupTitle, Text: a.hostSetupCommands(trust, hostWord, plan.Webroot, install, plan.Admission != admitNone)}}},
		admin.Section{Title: "Add the deployment", Text: a.deploymentExplanation(plan),
			Pre: []admin.Pre{{Title: "3. Add the deployment and restart the agent", Text: deploymentAddCommand(plan, acme)}}},
		admin.Section{Title: "Check", Text: []string{"Lists the deployment the agent now knows."},
			Pre: []admin.Pre{{Title: "4. Verify on the host", Text: verifyCommand()}}},
	)
	next := []string{outcome}
	if approval {
		next = append(next, "Open the progress page: it shows the waiting enrollment with an Approve button for admins.")
	}
	next = append(next, "If setup says the enrollment is pending, approve it, then run systemctl enable myownpki-agent once so the agent also starts at boot. The progress page reloads every "+strconv.Itoa(hostAddRefresh)+" seconds until the first certificate is deployed.")
	sections = append(sections, admin.Section{Title: "What happens next", Text: next})

	p := c.page("Add host: "+plan.Host, hostAddNavKey, a.hostAddCrumbs()...)
	p.Description = "Step 2: the commands for the host. They are shown once."
	c.once(p, admin.DetailData{Steps: hostAddSteps(2), Sections: sections,
		Commands: []admin.Command{{Label: "Show progress", Href: hostAddPath + "/" + plan.Host, Primary: true}}})
}

// deploymentExplanation says what the recipe will set up, from the recipe data.
func (a *app) deploymentExplanation(p hostPlan) []string {
	if p.Service.Recipe == "" {
		return []string{"The deployment writes fullchain.pem and privkey.pem (key mode 0600) to " + certDirRoot + "/" + p.Host + " and runs no hook: point your service at them yourself."}
	}
	r, ok := recipe.Get(p.Service.Recipe)
	if !ok {
		return nil
	}
	var parts []string
	if r.Profile == "nginx" {
		parts = append(parts, "files fullchain.pem and privkey.pem in "+strings.ReplaceAll(r.Dir, "{name}", p.Service.ID))
	} else {
		parts = append(parts, "files "+strings.Join(nonEmpty(r.Fullchain, r.Certificate, r.Chain, r.Key), ", "))
	}
	for _, h := range r.Hooks {
		parts = append(parts, "hook "+h.Name+": "+strings.Join(h.Command, " "))
	}
	if r.Check != "" {
		parts = append(parts, "local TLS check "+r.Check)
	}
	if len(r.SandboxWrite) > 0 {
		parts = append(parts, "sandbox may write "+strings.Join(r.SandboxWrite, ", "))
	}
	if r.LowPorts {
		parts = append(parts, "hooks may bind ports below 1024")
	}
	out := []string{"The " + r.Name + " recipe sets up: " + strings.Join(parts, "; ") + ". The command writes agent.yaml and the systemd drop-ins in one step, keeps the old agent.yaml as agent.yaml.bak and restarts the agent."}
	if r.Example {
		out = append(out, "Example recipe: test it on a non-production host first.")
	}
	return append(out, r.Notes...)
}

func nonEmpty(values ...string) []string {
	var out []string
	for _, v := range values {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// ---------------------------------------------------------------- step 3

// hostFromPath validates the {host} of a progress URL; anything else is a 404
// that says nothing about the value.
func hostFromPath(c *rc) (string, bool) {
	raw := c.r.PathValue("host")
	host, err := agents.CheckPattern(raw)
	if err != nil || host != raw || strings.Contains(host, "*") {
		c.fail(ca.ErrNotFound)
		return "", false
	}
	return host, true
}

// hostAddProgress shows where the host is. The first view comes from a link or
// a redirect and counts as activity; it points its refresh at the passive
// /status route, whose reloads do not keep the session alive.
func (a *app) hostAddProgress(c *rc) {
	if !a.hostAddAllowed(c, "Add host") {
		return
	}
	host, ok := hostFromPath(c)
	if !ok {
		return
	}
	ctx := c.r.Context()
	var ag *agents.Agent
	list, err := a.d.Agents.ListAgents(ctx, c.who())
	if err != nil {
		c.fail(err)
		return
	}
	if picked := pickAgent(list, host); picked != nil {
		if ag, err = a.d.Agents.GetAgent(ctx, c.who(), picked.ID); err != nil {
			c.fail(err)
			return
		}
	}
	enrollments, err := a.d.Agents.ListEnrollments(ctx, c.who(), false)
	if err != nil {
		c.fail(err)
		return
	}
	prog := buildHostProgress(a.now(), host, ag, enrollments)

	table := admin.TableData{Title: "Progress", Adaptive: true, Columns: []admin.Column{{Label: "Stage"}, {Label: "State"}, {Label: "Details"}}}
	for _, s := range prog.Stages {
		detail := admin.Cell{Text: s.Detail, Break: true, Href: s.Link}
		table.Rows = append(table.Rows, []admin.Cell{{Text: s.Name}, {Text: s.State, Status: s.Status}, detail})
	}
	intro := "The page reloads every " + strconv.Itoa(hostAddRefresh) + " seconds until the first certificate is deployed."
	if prog.Complete {
		intro = "Done: the certificate is deployed. This page no longer reloads."
	}
	sections := []admin.Section{{Text: []string{intro}, Table: &table}}
	if prog.Pending != nil && c.may(authz.ManageAgents, "") {
		decide := func(title, verb, submit string, danger bool) admin.FormData {
			return c.form(admin.FormData{Title: title, Action: hostAddPath + "/" + host + "/" + verb, Submit: submit, Danger: danger,
				Fields: []admin.Field{{ID: "id", Type: "hidden", Value: prog.Pending.ID}}})
		}
		sections = append(sections, admin.Section{Forms: []admin.FormData{
			decide("Approve", "approve", "Approve enrollment", false),
			decide("Refuse", "deny", "Refuse enrollment", true),
		}})
	} else if prog.Pending != nil {
		sections = append(sections, admin.Section{Text: []string{"An admin with a fresh second factor has to approve this enrollment."}})
	}
	p := c.page("Add host: "+host, hostAddNavKey, a.hostAddCrumbs()...)
	p.Description = "Step 3: progress of " + host + "."
	if !prog.Complete {
		p.RefreshSeconds = hostAddRefresh
		p.RefreshURL = hostAddPath + "/" + url.PathEscape(host) + "/status"
	}
	render(c.w, c.r, a.log, http.StatusOK, admin.DetailPage(p, admin.DetailData{Steps: hostAddSteps(3), Messages: c.messages(), Sections: sections,
		Commands: []admin.Command{{Label: "Add another host", Href: hostAddPath}, {Label: "Agent list", Href: "/agents"}}}))
}

// hostAddDecide approves or refuses the enrollment that waits for the host,
// through the same service calls and step-up as the approval queue, and comes
// back to the progress page.
func (a *app) hostAddDecide(c *rc) {
	if !a.hostAddAllowed(c, "Add host") {
		return
	}
	host, ok := hostFromPath(c)
	if !ok {
		return
	}
	back := hostAddPath + "/" + host
	id := c.r.PostFormValue("id")
	open, err := a.d.Agents.ListEnrollments(c.r.Context(), c.who(), true)
	if err != nil {
		c.fail(err)
		return
	}
	found := false
	for _, e := range open {
		if e.ID == id && e.Hostname == host && e.State == agents.StatePending {
			found = true
		}
	}
	if !found {
		c.refused(fmt.Errorf("%w: that enrollment does not wait for a decision any more", agents.ErrInvalid), back)
		return
	}
	text := "Enrollment approved – the agent gets its certificate within 30 seconds."
	if strings.HasSuffix(c.r.URL.Path, "/deny") {
		err, text = a.d.Agents.Deny(c.r.Context(), c.who(), id), "Enrollment refused."
	} else {
		err = a.d.Agents.Approve(c.r.Context(), c.who(), id)
	}
	if err != nil {
		c.refused(err, back)
		return
	}
	c.done(back, text)
}
