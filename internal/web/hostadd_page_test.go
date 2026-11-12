package web

import (
	stdhtml "html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agentdist"
	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

func hostForm(csrf string, change map[string]string) url.Values {
	form := map[string]string{"hostname": "proxy1.homelab.lan", "service": "nginx", "challenge": "webroot", "webroot": "/var/www/acme", "names": "",
		"format": "deb", "arch": "amd64"}
	for k, v := range change {
		form[k] = v
	}
	out := url.Values{"csrf_token": {csrf}}
	for k, v := range form {
		out.Set(k, v)
	}
	return out
}

func commandsForm(csrf, admission string, change map[string]string) url.Values {
	f := hostForm(csrf, change)
	f.Set("admission", admission)
	return f
}

var reRefreshMeta = regexp.MustCompile(`<meta http-equiv="refresh" content="([^"]*)"`)

// noScript is what every page of the assistant must lack: the UI ships no htmx
// and no script, and the CSP forbids inline ones.
func noScript(t *testing.T, name, html string) {
	t.Helper()
	for _, banned := range []string{"hx-", "<script", "style=", "onclick", "htmx"} {
		if strings.Contains(html, banned) {
			t.Errorf("%s contains %q", name, banned)
		}
	}
	plainPage(t, html)
}

func TestAddHostStepsForAnAdminWithToken(t *testing.T) {
	t.Parallel()
	v, svc := newAgentsUIEnv(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	csrf := b.csrf(t)

	// Step 1: the form, the nav entry, no refresh.
	r := b.get(t, hostAddPath)
	step1 := r.html()
	if r.Code != http.StatusOK || reRefreshMeta.MatchString(step1) {
		t.Fatalf("step 1: %d", r.Code)
	}
	for _, want := range []string{`aria-current="step">Host</li>`, "Admission and commands", `action="/hosts/add"`, "Next: admission", "Host name", "Service", "http-01 challenge",
		"port 80", "Certificate files only", "Postfix (example recipe)", `value="/var/www/acme"`, "More certificate names", "Agent package", `href="/hosts/add"`} {
		if !strings.Contains(step1, want) {
			t.Errorf("step 1 lacks %q", want)
		}
	}
	noScript(t, "step 1", step1)

	// Step 2: the domain check in words, the ways to be admitted, the hidden copy.
	r = b.post(t, hostAddPath, hostForm(csrf, nil))
	step2 := r.html()
	if r.Code != http.StatusOK || reRefreshMeta.MatchString(step2) {
		t.Fatalf("step 2: %d", r.Code)
	}
	for _, want := range []string{`aria-current="step">Admission and commands`, "proxy1.homelab.lan is covered by the domain homelab.lan (CA issuing), which allows http-01.",
		"Single-use join token for this host", "second factor", "No secret", "The tenant&#39;s enrollment mode is verified.", "without an approval", "one approval by an admin",
		`action="/hosts/add/commands"`, `name="admission"`, `name="hostname" value="proxy1.homelab.lan"`, `name="webroot" value="/var/www/acme"`, "Show the commands"} {
		if !strings.Contains(step2, want) {
			t.Errorf("step 2 lacks %q", want)
		}
	}
	noScript(t, "step 2", step2)
	if strings.Contains(step2, "mjt_") || len(mustTokens(t, svc)) != 0 {
		t.Error("step 2 created or showed a token")
	}

	// The commands: the token needs the second factor, then shows once.
	v.Clock.Advance(authz.StepUpWindow + time.Second)
	r = b.post(t, hostAddCommands, commandsForm(csrf, admitToken, nil))
	if r.Code != http.StatusSeeOther || r.location() != "/step-up" || len(mustTokens(t, svc)) != 0 {
		t.Fatalf("commands without a fresh second factor: %d %q", r.Code, r.location())
	}
	challenge := b.get(t, "/step-up").html()
	if !strings.Contains(challenge, "Create a one-use join token for proxy1.homelab.lan and show the Add host commands") {
		t.Errorf("action summary: %s", challenge)
	}
	r = confirmPending(t, b, csrf, "demo")
	if r.Code != http.StatusOK || r.Header().Get("Cache-Control") != "no-store" || reRefreshMeta.MatchString(r.html()) {
		t.Fatalf("continued commands: %d %q", r.Code, r.Header().Get("Cache-Control"))
	}
	shown := r.html()
	secret := reSecret.FindString(shown)
	if secret == "" {
		t.Fatal("the token was not shown")
	}
	noScript(t, "commands", shown)
	text := stdhtml.UnescapeString(shown)
	for _, want := range []string{
		"cat > /root/myownpki-join-token <<'MYOWNPKI_TOKEN'\n" + secret + "\nMYOWNPKI_TOKEN\n",
		"Root SHA-256 (DER, authoritative)", "Package SHA-256", "--cacert /root/myownpki-root.pem", "apt-get install -y /root/myownpki-agent_0.3.1_linux_amd64.deb",
		`--package-format "$format" --hostname 'proxy1.homelab.lan' --webroot '/var/www/acme' --token-file /root/myownpki-join-token )`,
		"deployment add 'nginx' \\\n  --recipe nginx \\\n  --name 'proxy1.homelab.lan' \\\n  --challenge webroot --webroot '/var/www/acme' \\\n  --acme-directory 'https://pki.homelab.lan/acme/directory' \\\n  --restart",
		"install -d -m 0755 '/etc/ssl/myownpki'", agentdist.BinaryPath + " deployment list", "The nginx recipe sets up: files fullchain.pem and privkey.pem in /etc/ssl/myownpki/nginx",
		"hook nginx-test: /usr/sbin/nginx -t", "sandbox may write /var/log/nginx", "valid for 15 minutes", "Show progress", `href="/hosts/add/proxy1.homelab.lan"`,
		"without an approval", "systemctl enable myownpki-agent",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("commands page lacks %q:\n%s", want, text)
		}
	}
	checkAgentCalls(t, text, "setup --server")
	checkAgentCalls(t, text, "deployment add 'nginx'")
	checkAgentCalls(t, text, "deployment list")
	if strings.Contains(shown, "--token ") || strings.Contains(r.location(), secret) || strings.Contains(v.logs.String(), secret) {
		t.Error("the token is an argument, in a URL or in the log")
	}
	tokens := mustTokens(t, svc)
	if len(tokens) != 1 || len(tokens[0].Patterns) != 1 || tokens[0].Patterns[0] != "proxy1.homelab.lan" || tokens[0].ExpiresAt.Sub(tokens[0].CreatedAt) != 15*time.Minute || tokens[0].Kind != agents.KindToken {
		t.Errorf("token: %+v", tokens)
	}
	// Once: no later page shows it again.
	for _, target := range []string{hostAddPath, hostAddPath + "/proxy1.homelab.lan", hostAddPath + "/proxy1.homelab.lan/status", "/agents/tokens", "/agents", "/agents/enrollments"} {
		if strings.Contains(b.get(t, target).html(), secret) {
			t.Errorf("the token is on %s", target)
		}
	}
	// The pending action was used once.
	if replay := b.post(t, "/step-up", url.Values{"csrf_token": {csrf}, "pending_id": {"x"}, "code": {v.Code("demo")}}); replay.Code != http.StatusBadRequest {
		t.Errorf("replay: %d", replay.Code)
	}
	if len(mustTokens(t, svc)) != 1 {
		t.Error("more than one token")
	}
}

func mustTokens(t *testing.T, svc *agents.Service) []agents.JoinToken {
	t.Helper()
	list, err := svc.ListJoinTokens(t.Context(), testinstance.Console)
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func TestAddHostWithoutSecretAndWithExtraNames(t *testing.T) {
	t.Parallel()
	v, svc := newAgentsUIEnv(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	csrf := b.csrf(t)
	// No secret: no step-up needed, no token file, a standalone challenge, Postfix.
	v.Clock.Advance(authz.StepUpWindow + time.Second)
	r := b.post(t, hostAddCommands, commandsForm(csrf, admitNone, map[string]string{"service": "postfix", "challenge": "standalone", "webroot": "", "format": "none"}))
	text := stdhtml.UnescapeString(r.html())
	if r.Code != http.StatusOK || r.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("no secret: %d", r.Code)
	}
	for _, want := range []string{"No secret", "waits in the queue", "Approve button", "--package-format \"$format\" --hostname 'proxy1.homelab.lan' )",
		"install -d -m 0755 '/etc/ssl/myownpki/postfix'", "deployment add 'postfix' \\\n  --recipe postfix \\\n", "--challenge standalone \\\n", "The agent must be installed already."} {
		if !strings.Contains(text, want) {
			t.Errorf("no-secret page lacks %q", want)
		}
	}
	for _, banned := range []string{"--token-file", "MYOWNPKI_TOKEN", "--webroot", "apt-get", "mjt_"} {
		if strings.Contains(text, banned) {
			t.Errorf("no-secret page contains %q", banned)
		}
	}
	if len(mustTokens(t, svc)) != 0 {
		t.Error("a token was created")
	}
	// Extra names need the token: both the page and the POST say so.
	extra := map[string]string{"names": "www.homelab.lan\nmail.homelab.lan"}
	step2 := b.post(t, hostAddPath, hostForm(csrf, extra)).html()
	if !strings.Contains(step2, "Single-use join token") || strings.Contains(step2, `value="none"`) || !strings.Contains(step2, "www.homelab.lan, mail.homelab.lan") {
		t.Errorf("step 2 with extra names:\n%s", step2)
	}
	if r = b.post(t, hostAddCommands, commandsForm(csrf, admitNone, extra)); r.Code != http.StatusSeeOther || r.location() != hostAddPath ||
		!strings.Contains(flashOf(t, b, hostAddPath), "need the one-use join token") {
		t.Errorf("extra names without a token: %d %q", r.Code, r.location())
	}
	r = b.post(t, hostAddCommands, commandsForm(csrf, admitToken, extra))
	if r.Code != http.StatusSeeOther || r.location() != "/step-up" {
		t.Fatalf("extra names with a token: %d %q", r.Code, r.location())
	}
	if r = confirmPending(t, b, csrf, "demo"); r.Code != http.StatusOK {
		t.Fatalf("extra names with a token, confirmed: %d %q", r.Code, r.location())
	}
	if text = stdhtml.UnescapeString(r.html()); !strings.Contains(text, "--name 'proxy1.homelab.lan' \\\n  --name 'www.homelab.lan' \\\n  --name 'mail.homelab.lan' \\\n") {
		t.Errorf("names in the line:\n%s", text)
	}
	if tokens := mustTokens(t, svc); len(tokens) != 1 || len(tokens[0].Patterns) != 3 {
		t.Errorf("token patterns: %+v", tokens)
	}
}

func TestAddHostRefusesWhatCannotWork(t *testing.T) {
	t.Parallel()
	v, svc := newAgentsUIEnv(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	csrf := b.csrf(t)
	for name, tc := range map[string]struct {
		change map[string]string
		want   string
	}{
		"no domain":        {map[string]string{"hostname": "proxy1.other.lan"}, "no domain of this PKI covers proxy1.other.lan"},
		"extra no domain":  {map[string]string{"names": "x.other.lan"}, "no domain of this PKI covers x.other.lan"},
		"injection":        {map[string]string{"hostname": "proxy1.homelab.lan';id;'"}, "one exact, fully qualified"},
		"wildcard":         {map[string]string{"hostname": "*.homelab.lan"}, "one exact, fully qualified"},
		"hostile webroot":  {map[string]string{"webroot": "/var/www/$(reboot)"}, "only letters, digits"},
		"system webroot":   {map[string]string{"webroot": "/etc"}, "system directory"},
		"relative webroot": {map[string]string{"webroot": "www"}, "absolute path"},
		"standalone+root":  {map[string]string{"challenge": "standalone"}, "belongs to the webroot challenge"},
		"unknown service":  {map[string]string{"service": "apache"}, "choose one of the listed services"},
		"script in names":  {map[string]string{"names": "<script>alert(1)</script>.homelab.lan"}, "no wildcard"},
	} {
		r := b.post(t, hostAddPath, hostForm(csrf, tc.change))
		flash := flashOf(t, b, hostAddPath)
		if r.Code != http.StatusSeeOther || r.location() != hostAddPath || !strings.Contains(flash, tc.want) {
			t.Errorf("%s: %d %q %q", name, r.Code, r.location(), flash)
		}
		if strings.Contains(flash, "<script>") || strings.Contains(flash, "';id;'") {
			t.Errorf("%s: raw input in the message: %s", name, flash)
		}
		// The commands route refuses the same input; no token comes of it.
		r = b.post(t, hostAddCommands, commandsForm(csrf, admitToken, tc.change))
		if r.Code != http.StatusSeeOther || r.location() != hostAddPath {
			t.Errorf("%s commands: %d %q", name, r.Code, r.location())
		}
	}
	if len(mustTokens(t, svc)) != 0 {
		t.Error("a refused request created a token")
	}
	// A domain without http-01.
	issuing := "issuing"
	if _, err := v.Engine.CreateDomain(t.Context(), ca.DomainRequest{Name: "dnsonly.lan",
		DomainSettings: ca.DomainSettings{CA: &issuing, ChallengeTypes: []string{ca.ChallengeDNS01}}, Who: testinstance.Console}); err != nil {
		t.Fatal(err)
	}
	r := b.post(t, hostAddPath, hostForm(csrf, map[string]string{"hostname": "a.dnsonly.lan"}))
	if flash := flashOf(t, b, hostAddPath); r.Code != http.StatusSeeOther || !strings.Contains(flash, "does not allow http-01") {
		t.Errorf("dns-01 only domain: %d %q", r.Code, flash)
	}
	// An unknown field is refused outright by the step-up allowlist.
	f := commandsForm(csrf, admitNone, nil)
	f.Set("hook", "x='/bin/sh'")
	if r = b.post(t, hostAddCommands, f); r.Code != http.StatusBadRequest {
		t.Errorf("injected field: %d", r.Code)
	}
}

func TestAddHostRolesAndAccess(t *testing.T) {
	t.Parallel()
	v, svc := newAgentsUIEnv(t)
	for _, role := range []authz.Role{authz.Viewer, authz.Operator} {
		name := string(role)
		v.User(t, name, false, authz.Binding{Role: role})
		b := v.browser("192.0.2." + string(rune('2'+len(name)%5)))
		b.signIn(t, name, testinstance.Password)
		csrf := b.csrf(t)
		first := b.get(t, hostAddPath)
		if first.Code != http.StatusOK || !strings.Contains(first.html(), "Creating a join token needs an admin") || !strings.Contains(first.html(), `href="/hosts/add"`) {
			t.Errorf("%s step 1: %d", role, first.Code)
		}
		step2 := b.post(t, hostAddPath, hostForm(csrf, nil))
		if step2.Code != http.StatusOK || strings.Contains(step2.html(), "Single-use join token") || !strings.Contains(step2.html(), "No secret") || !strings.Contains(step2.html(), "so it is not offered to you") {
			t.Errorf("%s step 2: %d\n%s", role, step2.Code, step2.html())
		}
		if r := b.post(t, hostAddCommands, commandsForm(csrf, admitToken, nil)); r.Code != http.StatusForbidden {
			t.Errorf("%s token: %d", role, r.Code)
		}
		if r := b.post(t, hostAddCommands, commandsForm(csrf, admitNone, nil)); r.Code != http.StatusOK || strings.Contains(r.html(), "mjt_") || strings.Contains(r.html(), "MYOWNPKI_TOKEN") {
			t.Errorf("%s without a secret: %d", role, r.Code)
		}
		// The progress page: read-only.
		id := enroll(t, svc, "waiting-"+name+".homelab.lan", "", "0.3.5")
		prog := b.get(t, hostAddPath+"/waiting-"+name+".homelab.lan")
		if prog.Code != http.StatusOK || strings.Contains(prog.html(), "Approve enrollment") || !strings.Contains(prog.html(), "An admin with a fresh second factor has to approve") {
			t.Errorf("%s progress: %d", role, prog.Code)
		}
		if r := b.post(t, hostAddPath+"/waiting-"+name+".homelab.lan/approve", url.Values{"csrf_token": {csrf}, "id": {id}}); r.Code != http.StatusSeeOther ||
			!strings.Contains(stdhtml.UnescapeString(flashOf(t, b, hostAddPath+"/waiting-"+name+".homelab.lan")), "Your role doesn't allow this") {
			t.Errorf("%s approve: %d %q", role, r.Code, r.location())
		}
		open, _ := svc.ListEnrollments(t.Context(), testinstance.Console, true)
		if len(open) == 0 || open[0].State != agents.StatePending {
			t.Errorf("%s: the enrollment was decided", role)
		}
		if !strings.Contains(b.get(t, "/").html(), `href="/hosts/add"`) {
			t.Errorf("%s: no nav entry", role)
		}
	}
	// A role limited to one CA reads no agents: 403 everywhere, no nav entry.
	v.User(t, "caviewer", false, authz.Binding{CA: "issuing", Role: authz.Viewer})
	b := v.browser("192.0.2.9")
	b.signIn(t, "caviewer", testinstance.Password)
	csrf := b.csrf(t)
	for _, target := range []string{hostAddPath, hostAddPath + "/proxy1.homelab.lan", hostAddPath + "/proxy1.homelab.lan/status"} {
		if r := b.get(t, target); r.Code != http.StatusForbidden && r.Code != http.StatusUnauthorized {
			t.Errorf("CA-limited GET %s: %d", target, r.Code)
		}
	}
	for _, r := range []page{b.post(t, hostAddPath, hostForm(csrf, nil)), b.post(t, hostAddCommands, commandsForm(csrf, admitNone, nil))} {
		if r.Code != http.StatusForbidden {
			t.Errorf("CA-limited POST: %d", r.Code)
		}
	}
	if strings.Contains(b.get(t, "/").html(), `href="/hosts/add"`) {
		t.Error("CA-limited user sees the nav entry")
	}
	// Signed out: the sign-in page, with the way back. An API token is no session.
	anon := v.browser("192.0.2.10")
	if r := anon.get(t, hostAddPath); r.Code != http.StatusSeeOther || !strings.HasPrefix(r.location(), "/login") {
		t.Errorf("anonymous: %d %q", r.Code, r.location())
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://pki.homelab.lan"+hostAddPath, nil)
	req.Header.Set("Authorization", "Bearer mjt_notasession")
	if r := anon.send(t, req); r.Code != http.StatusSeeOther || !strings.HasPrefix(r.location(), "/login") {
		t.Errorf("API token: %d %q", r.Code, r.location())
	}
	status := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://pki.homelab.lan"+hostAddPath+"/proxy1.homelab.lan/status", nil)
	if r := anon.send(t, status); r.Code != http.StatusUnauthorized {
		t.Errorf("anonymous status poll: %d", r.Code)
	}
}

// With agents off the assistant says so and has no nav entry.
func TestAddHostWithAgentsOff(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	if page := b.get(t, hostAddPath); page.Code != http.StatusOK || !strings.Contains(page.html(), "Agents are off") {
		t.Errorf("agents off: %d", page.Code)
	}
	if strings.Contains(b.get(t, "/").html(), `href="/hosts/add"`) {
		t.Error("nav entry with agents off")
	}
}

func TestAddHostOffersAnExistingPassAndNeverShowsIt(t *testing.T) {
	t.Parallel()
	v, svc := newAgentsUIEnv(t)
	secret, _, err := svc.CreateEnrollmentPass(t.Context(), testinstance.Console, `<b>salt</b> "rollout"`, []string{"*.homelab.lan"}, 5, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	csrf := b.csrf(t)
	step2 := b.post(t, hostAddPath, hostForm(csrf, nil)).html()
	for _, want := range []string{"Enrollment pass &#34;&lt;b&gt;salt&lt;/b&gt; &#34;rollout&#34;&#34;", "0 of 5 uses taken", "never shows a pass", "grants the host its own name only"} {
		if !strings.Contains(strings.ReplaceAll(step2, "&#34;", `"`), strings.ReplaceAll(want, "&#34;", `"`)) && !strings.Contains(step2, want) {
			t.Errorf("step 2 lacks %q", want)
		}
	}
	if strings.Contains(step2, "<b>salt</b>") || strings.Contains(step2, secret) {
		t.Error("the label is not escaped or the pass is shown")
	}
	// With extra names a pass is not offered (it grants the host name only).
	if strings.Contains(b.post(t, hostAddPath, hostForm(csrf, map[string]string{"names": "www.homelab.lan"})).html(), "Enrollment pass") {
		t.Error("a pass offered for extra names")
	}
	// The commands for a pass: the secret is typed on the host, never part of the page, no step-up.
	v.Clock.Advance(authz.StepUpWindow + time.Second)
	r := b.post(t, hostAddCommands, commandsForm(csrf, admitPass, nil))
	text := stdhtml.UnescapeString(r.html())
	if r.Code != http.StatusOK || strings.Contains(text, secret) || strings.Contains(text, "mjp_") {
		t.Fatalf("pass commands: %d", r.Code)
	}
	for _, want := range []string{"read -r -s -p 'Enrollment pass: ' pass", "> /root/myownpki-join-token", "--hostname 'proxy1.homelab.lan' --webroot '/var/www/acme' --token-file /root/myownpki-join-token )", "is not shown here"} {
		if !strings.Contains(text, want) {
			t.Errorf("pass commands lack %q", want)
		}
	}
	// A pass that is revoked (or for another name) is refused when the commands are asked for.
	list := mustTokens(t, svc)
	if err = svc.RevokeJoinToken(t.Context(), testinstance.Console, list[0].ID); err != nil {
		t.Fatal(err)
	}
	if r = b.post(t, hostAddCommands, commandsForm(csrf, admitPass, nil)); r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, hostAddPath), "no active enrollment pass covers") {
		t.Errorf("revoked pass: %d", r.Code)
	}
	// An existing agent for the host: a note, and no pass.
	agentSecret, _, err := svc.CreateJoinToken(t.Context(), testinstance.Console, "x", []string{"proxy1.homelab.lan"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	enroll(t, svc, "proxy1.homelab.lan", agentSecret, "0.3.5")
	if step2 = b.post(t, hostAddPath, hostForm(csrf, nil)).html(); !strings.Contains(step2, "An agent for proxy1.homelab.lan exists already") {
		t.Errorf("no note about the existing agent:\n%s", step2)
	}
	if r = b.post(t, hostAddCommands, commandsForm(csrf, admitPass, nil)); r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, hostAddPath), "a pass admits new hosts only") {
		t.Errorf("a pass for a host with an agent: %d", r.Code)
	}
}

func TestAddHostModeAndApprovalWords(t *testing.T) {
	t.Parallel()
	v, _ := newAgentsUIEnv(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	csrf := b.csrf(t)
	for mode, want := range map[string]string{"manual": "manual mode: every enrollment waits", "auto": "auto mode", "verified": "without an approval"} {
		setEnrollmentMode(t, v, mode)
		step2 := b.post(t, hostAddPath, hostForm(csrf, nil)).html()
		if !strings.Contains(step2, "enrollment mode is "+mode) || !strings.Contains(step2, want) {
			t.Errorf("mode %s: %s", mode, want)
		}
	}
}

func setEnrollmentMode(t *testing.T, v *uiEnv, mode string) {
	t.Helper()
	st := &tenant.Store{DB: v.SystemDB.Write, Clock: v.Clock}
	cur, err := st.Get(t.Context(), store.DefaultTenant, testinstance.Console)
	if err != nil {
		t.Fatal(err)
	}
	cur.AgentEnrollment = &mode
	if err = st.Set(t.Context(), store.DefaultTenant, *cur, testinstance.Console); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------- progress

func TestHostProgressStages(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	const host = "proxy1.homelab.lan"
	admitted := func(mod func(*agents.Agent)) *agents.Agent {
		a := &agents.Agent{ID: "agt_1", Hostname: host, Status: agents.StatusActive, ApprovedAt: now.Add(-time.Hour), ApprovedBy: "demo", LastSeenAt: now.Add(-time.Minute), Version: "0.3.5"}
		if mod != nil {
			mod(a)
		}
		return a
	}
	deployment := func(state, errText string) agents.Deployment {
		d := agents.Deployment{Name: "nginx", State: state, LastError: errText}
		if state == "deployed" {
			d.Serial, d.NotAfter, d.CertificateID = "AB12", now.Add(48*time.Hour), "crt_1"
		}
		return d
	}
	enrollment := func(state string) []agents.Enrollment {
		return []agents.Enrollment{{ID: "enr_1", Hostname: host, State: state, SourceIP: "192.0.2.60", CheckState: "passed", CreatedAt: now.Add(-time.Minute), TokenValid: false}}
	}
	type want struct {
		enrolled, online, cert string
		complete               bool
		pending                bool
	}
	for name, tc := range map[string]struct {
		agent       *agents.Agent
		enrollments []agents.Enrollment
		want        want
	}{
		"nothing yet":       {nil, nil, want{"waiting for the host", "not yet", "not yet", false, false}},
		"checking":          {nil, enrollment(agents.StateWaitingForCheck), want{"checking", "not yet", "not yet", false, false}},
		"pending":           {nil, enrollment(agents.StatePending), want{"waiting for your approval", "not yet", "not yet", false, true}},
		"denied":            {nil, enrollment(agents.StateDenied), want{"refused", "not yet", "not yet", false, false}},
		"expired":           {nil, enrollment(agents.StateExpired), want{"expired", "not yet", "not yet", false, false}},
		"other host":        {nil, []agents.Enrollment{{ID: "e", Hostname: "other.homelab.lan", State: agents.StatePending}}, want{"waiting for the host", "not yet", "not yet", false, false}},
		"first report open": {admitted(func(a *agents.Agent) { a.LastSeenAt = time.Time{}; a.ApprovedAt = now.Add(-time.Minute) }), nil, want{"admitted", "waiting for the first report", "not yet", false, false}},
		"no deployment":     {admitted(nil), nil, want{"admitted", "online", "not yet", false, false}},
		"pending deploy": {admitted(func(a *agents.Agent) { a.Deployments = []agents.Deployment{deployment("pending", "")} }), nil,
			want{"admitted", "online", "pending", false, false}},
		"failed": {admitted(func(a *agents.Agent) { a.Deployments = []agents.Deployment{deployment("failed", "reload hook failed")} }), nil,
			want{"admitted", "online", "failed", false, false}},
		"rolled back": {admitted(func(a *agents.Agent) { a.Deployments = []agents.Deployment{deployment("rolled_back", "check failed")} }), nil,
			want{"admitted", "online", "rolled back", false, false}},
		"deployed": {admitted(func(a *agents.Agent) { a.Deployments = []agents.Deployment{deployment("deployed", "")} }), nil,
			want{"admitted", "online", "deployed", true, false}},
		"one of two failed": {admitted(func(a *agents.Agent) {
			second := deployment("failed", "x")
			second.Name = "other"
			a.Deployments = []agents.Deployment{deployment("deployed", ""), second}
		}), nil, want{"admitted", "online", "deployed", false, false}},
		"removed ignored": {admitted(func(a *agents.Agent) {
			gone := deployment("failed", "x")
			gone.Removed = true
			a.Deployments = []agents.Deployment{deployment("deployed", ""), gone}
		}), nil, want{"admitted", "online", "deployed", true, false}},
		"silent": {admitted(func(a *agents.Agent) {
			a.LastSeenAt = now.Add(-20 * time.Minute)
			a.Deployments = []agents.Deployment{deployment("deployed", "")}
		}), nil, want{"admitted", "silent", "deployed", false, false}},
		"disabled": {admitted(func(a *agents.Agent) {
			a.Status = agents.StatusDisabled
			a.Deployments = []agents.Deployment{deployment("deployed", "")}
		}), nil, want{"admitted", "disabled", "deployed", false, false}},
		"revoked": {admitted(func(a *agents.Agent) { a.Status = agents.StatusRevoked }), nil, want{"agent revoked", "not yet", "not yet", false, false}},
	} {
		p := buildHostProgress(now, host, tc.agent, tc.enrollments)
		got := want{enrolled: p.Stages[0].State, online: p.Stages[1].State, cert: p.Stages[len(p.Stages)-1].State, complete: p.Complete, pending: p.Pending != nil}
		if name == "one of two failed" {
			got.cert = p.Stages[2].State // the first deployment row
		}
		if got != tc.want {
			t.Errorf("%s: %+v, want %+v", name, got, tc.want)
		}
	}
	// Fixed status colors.
	p := buildHostProgress(now, host, admitted(func(a *agents.Agent) {
		a.Deployments = []agents.Deployment{deployment("failed", "boom")}
	}), nil)
	if p.Stages[0].Status != view.StatusOK || p.Stages[1].Status != view.StatusOK || p.Stages[2].Status != view.StatusCrit {
		t.Errorf("status colors: %+v", p.Stages)
	}
	if got := pickAgent([]agents.Agent{{ID: "old", Hostname: host, Status: agents.StatusRevoked, ApprovedAt: now}, {ID: "dis", Hostname: host, Status: agents.StatusDisabled},
		{ID: "act", Hostname: host, Status: agents.StatusActive, ApprovedAt: now.Add(-time.Hour)}, {ID: "x", Hostname: "x.homelab.lan", Status: agents.StatusActive}}, host); got == nil || got.ID != "act" {
		t.Errorf("pickAgent: %+v", got)
	}
	if since(now, now.Add(-90*time.Second)) != "1 minutes ago" || since(now, now.Add(-3*time.Hour)) != "3 hours ago" || since(now, now.Add(-72*time.Hour)) != "3 days ago" || since(now, now) != "just now" {
		t.Error("since")
	}
}

// The pages: a host walks from nothing to deployed, with the fake clock. The
// refresh meta is there only while it is on its way.
func TestHostProgressPageWalk(t *testing.T) {
	t.Parallel()
	v, svc := newAgentsUIEnv(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	csrf := b.csrf(t)
	const host = "proxy2.homelab.lan"
	progress := hostAddPath + "/" + host
	refresh := func(html string) string {
		if m := reRefreshMeta.FindStringSubmatch(html); m != nil {
			return m[1]
		}
		return ""
	}
	wantRefresh := "10;url=" + progress + "/status"

	// Nothing yet: the first view and the passive route both refresh.
	first := b.get(t, progress)
	noScript(t, "progress", first.html())
	for _, want := range []string{`aria-current="step">Progress`, "waiting for the host", "Host enrolled", "Agent online", "First certificate", "reloads every 10 seconds", "st-neutral"} {
		if !strings.Contains(first.html(), want) {
			t.Errorf("first view lacks %q", want)
		}
	}
	if refresh(first.html()) != wantRefresh || refresh(b.get(t, progress+"/status").html()) != wantRefresh {
		t.Errorf("refresh: %q / %q", refresh(first.html()), refresh(b.get(t, progress+"/status").html()))
	}

	// The host asks and waits for an admin: the buttons, the facts, escaped.
	id := enroll(t, svc, host, "", "0.3.5")
	waiting := b.get(t, progress).html()
	for _, want := range []string{"waiting for your approval", "From 192.0.2.60", "no join token", "the http-01 check passed", "Approve enrollment", "Refuse enrollment",
		`action="/hosts/add/proxy2.homelab.lan/approve"`, `action="/hosts/add/proxy2.homelab.lan/deny"`, `value="` + id + `"`, "st-warn"} {
		if !strings.Contains(waiting, want) {
			t.Errorf("waiting view lacks %q", want)
		}
	}
	if refresh(waiting) != wantRefresh {
		t.Errorf("refresh while waiting: %q", refresh(waiting))
	}

	// Approve: the second factor first, then once, back to the progress page.
	v.Clock.Advance(authz.StepUpWindow + time.Second)
	r := b.post(t, progress+"/approve", url.Values{"csrf_token": {csrf}, "id": {id}})
	if r.Code != http.StatusSeeOther || r.location() != "/step-up" {
		t.Fatalf("approve without a fresh factor: %d %q", r.Code, r.location())
	}
	if !strings.Contains(b.get(t, "/step-up").html(), "Approve enrollment for "+host) {
		t.Error("action summary of the approval")
	}
	pending := pendingID(t, b)
	r = confirmPending(t, b, csrf, "demo")
	if r.Code != http.StatusSeeOther || r.location() != progress {
		t.Fatalf("continued approval: %d %q", r.Code, r.location())
	}
	if flash := flashOf(t, b, progress); !strings.Contains(flash, "Enrollment approved") {
		t.Errorf("flash: %s", flash)
	}
	if replay := b.post(t, "/step-up", url.Values{"csrf_token": {csrf}, "pending_id": {pending}, "code": {v.Code("demo")}}); replay.Code != http.StatusBadRequest {
		t.Errorf("replayed approval: %d", replay.Code)
	}
	list, err := svc.ListAgents(t.Context(), testinstance.Console)
	if err != nil {
		t.Fatal(err)
	}
	var agentID string
	for _, a := range list {
		if a.Hostname == host {
			agentID = a.ID
		}
	}
	if agentID == "" {
		t.Fatal("approval did not admit the host")
	}
	// Another decision for the same enrollment is refused with a reason.
	v.Clock.Advance(authz.StepUpWindow + time.Second)
	if r = b.post(t, progress+"/approve", url.Values{"csrf_token": {csrf}, "id": {id}}); r.Code != http.StatusSeeOther || r.location() != progress {
		t.Errorf("second approval: %d %q", r.Code, r.location())
	}
	if flash := flashOf(t, b, progress); !strings.Contains(flash, "does not wait for a decision") {
		t.Errorf("second approval: %s", flash)
	}

	admitted := b.get(t, progress).html()
	for _, want := range []string{"admitted", "waiting for the first report", "st-ok", "st-info"} {
		if !strings.Contains(admitted, want) {
			t.Errorf("admitted view lacks %q", want)
		}
	}
	if strings.Contains(admitted, "Approve enrollment") {
		t.Error("buttons after the decision")
	}

	// The agent reports: pending, then failed with hostile text, then deployed.
	caller := &agents.Caller{Agent: pkidb.Agent{ID: agentID}, Who: testinstance.Console}
	report := func(d agents.DeploymentReport) {
		t.Helper()
		in := agents.ReportInput{Version: "0.3.5", OS: "linux", Arch: "amd64", Deployments: []agents.DeploymentReport{d}}
		if err := svc.Report(t.Context(), caller, in); err != nil {
			t.Fatal(err)
		}
	}
	report(agents.DeploymentReport{Name: "nginx", Profile: "nginx", Names: []string{host}, State: "pending"})
	online := b.get(t, progress).html()
	for _, want := range []string{"online", "version 0.3.5", "pending", "The agent is working on it."} {
		if !strings.Contains(online, want) {
			t.Errorf("online view lacks %q", want)
		}
	}
	hostile := "<script>alert(1)</script>" + strings.Repeat("e", 900)
	report(agents.DeploymentReport{Name: "nginx", Profile: "nginx", Names: []string{host}, State: "failed", LastError: hostile})
	failed := b.get(t, progress).html()
	if !strings.Contains(failed, "failed") || !strings.Contains(failed, "st-crit") || !strings.Contains(failed, "&lt;script&gt;alert(1)&lt;/script&gt;") ||
		strings.Contains(failed, "<script>alert") || strings.Contains(failed, strings.Repeat("e", 400)) || !strings.Contains(failed, "…") {
		t.Errorf("failed view: hostile text not escaped or not clipped")
	}
	noScript(t, "failed progress", failed)
	if refresh(failed) != wantRefresh {
		t.Error("a failed deployment stops the refresh")
	}
	report(agents.DeploymentReport{Name: "nginx", Profile: "nginx", Names: []string{host}, State: "deployed", Serial: "ab12cd", NotAfter: v.Clock.Now().Add(72 * time.Hour).Format(time.RFC3339)})
	done := b.get(t, progress).html()
	if !strings.Contains(done, "deployed") || !strings.Contains(done, "Serial AB12CD") || !strings.Contains(done, "Done: the certificate is deployed. This page no longer reloads.") {
		t.Errorf("done view:\n%s", done)
	}
	if refresh(done) != "" || refresh(b.get(t, progress+"/status").html()) != "" {
		t.Error("the page still refreshes when complete")
	}
	noScript(t, "done progress", done)

	// The agent goes quiet: not complete any more, refreshing again.
	v.Clock.Advance(20 * time.Minute)
	silent := b.get(t, progress).html()
	if !strings.Contains(silent, "silent") || refresh(silent) != wantRefresh {
		t.Errorf("silent agent: refresh %q", refresh(silent))
	}

	// A hostile name in the path says nothing back.
	for _, bad := range []string{"%3Cscript%3Ealert(1)%3C%2Fscript%3E", "nohost", "A.Homelab.LAN", "x.homelab.lan%27%3Bid%3B%27", "%2A.homelab.lan"} {
		r := b.get(t, hostAddPath+"/"+bad)
		if r.Code != http.StatusNotFound || strings.Contains(r.html(), "script") && strings.Contains(r.html(), "alert") {
			t.Errorf("GET %s: %d", bad, r.Code)
		}
	}
}

// Every page lists exactly the nav entry once and keeps the refresh to the
// progress route.
func TestRefreshOnlyOnProgressPages(t *testing.T) {
	t.Parallel()
	v, _ := newAgentsUIEnv(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	for _, target := range []string{"/", "/agents", "/agents/tokens", "/agents/enrollments", "/agents/install", hostAddPath} {
		if html := b.get(t, target).html(); reRefreshMeta.MatchString(html) || strings.Count(html, `href="/hosts/add"`) < 1 {
			t.Errorf("%s: refresh %v / nav entry %d", target, reRefreshMeta.MatchString(html), strings.Count(html, `href="/hosts/add"`))
		}
	}
}
