package web

import (
	"database/sql"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/guides"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

const testDirectory = "https://pki.homelab.lan/acme/directory"

// stepsOf returns the rows of the page: title -> state text.
func stepsOf(t *testing.T, html string) map[string]string {
	t.Helper()
	re := regexp.MustCompile(`(?s)<tr><th scope="row">([^<]*)</th><td><span class="st st-[a-z]+"><span class="st-dot" aria-hidden="true"></span>([^<]*)</span></td>`)
	out := map[string]string{}
	for _, m := range re.FindAllStringSubmatch(html, -1) {
		out[m[1]] = m[2]
	}
	if len(out) != 10 {
		t.Fatalf("%d rows, want 10:\n%s", len(out), html)
	}
	return out
}

func mainOf(t *testing.T, html string) string {
	t.Helper()
	start, end := strings.Index(html, "<main"), strings.Index(html, "</main>")
	if start < 0 || end < start {
		t.Fatal("no main element")
	}
	return html[start:end]
}

func withACME(d *AppDeps) { d.ACMEDirectory = testDirectory }

func signedInAdmin(t *testing.T, v *uiEnv, ip string) *browser {
	t.Helper()
	b := v.browser(ip)
	b.signIn(t, "demo", v.DemoPassword)
	return b
}

const newBanner = "Your instance is new – see First steps."

// TestFirstStepsEmptyThenFilled: a new instance shows the banner and open rows;
// as the CA, the domain and a certificate appear, the rows turn done and the
// banner goes away. Nothing is stored for this: it is derived on each request.
func TestFirstStepsEmptyThenFilled(t *testing.T) {
	t.Parallel()
	v := newCustomUIEnvWith(t, testinstance.Options{NoCA: true}, withACME)
	v.Unseal(t)
	b := signedInAdmin(t, v, "192.0.2.1")

	r := b.get(t, "/first-steps")
	html := r.html()
	if r.Code != http.StatusOK || r.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("first steps: %d", r.Code)
	}
	rows := stepsOf(t, html)
	for title, want := range map[string]string{"Unseal the server": "Done", "Create a certificate authority": "Open", "Public base URL and CRL": "Open", "Add a domain": "Open",
		"Turn on ACME": "Done", "Issue a first certificate": "Open", "Add a host with an agent (optional)": "Open", "Back up the instance": "Not detected",
		"Trust the root on your devices": "Not detected", "Set up notifications (optional)": "Not detected"} {
		if rows[title] != want {
			t.Errorf("%s: %q, want %q", title, rows[title], want)
		}
	}
	for _, want := range []string{"<h1>First steps</h1>", "There is no CA yet.", `<a href="/authorities/new">New CA</a>`, `aria-current="page">First steps</a>`,
		`<caption class="visually-hidden">`, `<th scope="col">Step</th>`, `<th scope="col">State</th>`, "Agents are off", `rel="noopener noreferrer">Trust the root (documentation site)</a>`} {
		if !strings.Contains(html, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if !strings.Contains(b.get(t, "/").html(), newBanner) || !strings.Contains(b.get(t, "/").html(), `href="/first-steps"`) {
		t.Error("the dashboard of a new instance does not say so")
	}

	// A CA: the CA rows turn done, the banner stays (no certificate, no domain).
	if _, err := v.Engine.CreateRoot(t.Context(), ca.RootRequest{Name: "root", BaseURL: "http://pki.homelab.lan", Subject: ca.Subject{CommonName: "Root"}, Who: testinstance.Console}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Engine.CreateIntermediate(t.Context(), ca.IntermediateRequest{Name: "issuing", BaseURL: "http://pki.homelab.lan",
		Parent: "root", Subject: ca.Subject{CommonName: "Issuing"}, Who: testinstance.Console}); err != nil {
		t.Fatal(err)
	}
	rows = stepsOf(t, b.get(t, "/first-steps").html())
	if rows["Create a certificate authority"] != "Done" || rows["Public base URL and CRL"] != "Done" || rows["Add a domain"] != "Open" {
		t.Errorf("after the CAs: %v", rows)
	}
	if !strings.Contains(b.get(t, "/").html(), newBanner) {
		t.Error("the banner went away with only the CAs")
	}

	// A domain and a certificate: everything the data can show is done, no banner.
	issuing := "issuing"
	if _, err := v.Engine.CreateDomain(t.Context(), ca.DomainRequest{Name: "homelab.lan", CA: &issuing, Who: testinstance.Console}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.get(t, "/").html(), newBanner) == false {
		t.Error("the banner went away before a certificate exists")
	}
	if _, err := v.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}, Who: testinstance.Console}); err != nil {
		t.Fatal(err)
	}
	rows = stepsOf(t, b.get(t, "/first-steps").html())
	for _, title := range []string{"Create a certificate authority", "Public base URL and CRL", "Add a domain", "Turn on ACME", "Issue a first certificate"} {
		if rows[title] != "Done" {
			t.Errorf("%s: %q after the data exists", title, rows[title])
		}
	}
	if strings.Contains(b.get(t, "/").html(), newBanner) {
		t.Error("the banner stays although there is a CA, a domain and a certificate")
	}
}

// TestFirstStepsSealedAndRoles: a sealed server asks an instance admin to
// unseal and nobody else; a viewer reads every row and gets no action.
func TestFirstStepsSealedAndRoles(t *testing.T) {
	t.Parallel()
	v := newCustomUIEnv(t, withACME)
	v.User(t, "viewer", false, authz.Binding{Role: authz.Viewer})
	admin := signedInAdmin(t, v, "192.0.2.1")
	html := admin.get(t, "/first-steps").html()
	if rows := stepsOf(t, html); rows["Unseal the server"] != "Open" {
		t.Errorf("sealed: %q", rows["Unseal the server"])
	}
	if !strings.Contains(html, `<a href="/unseal">Unseal</a>`) {
		t.Error("an instance admin gets the link to unseal")
	}
	vb := v.browser("192.0.2.2")
	vb.signIn(t, "viewer", testinstance.Password)
	html = vb.get(t, "/first-steps").html()
	if strings.Contains(mainOf(t, html), `href="/unseal"`) || !strings.Contains(html, "Ask one to unseal it.") {
		t.Error("a viewer is not offered the unseal page")
	}

	v.Unseal(t)
	html = vb.get(t, "/first-steps").html()
	rows := stepsOf(t, html)
	if rows["Unseal the server"] != "Done" || rows["Create a certificate authority"] != "Done" || rows["Add a domain"] != "Open" {
		t.Errorf("viewer: %v", rows)
	}
	for _, action := range []string{`href="/authorities/new"`, `href="/domains/new"`, `href="/certificates/new"`, `href="/unseal"`, `href="/hosts/add"`} {
		if strings.Contains(mainOf(t, html), action) {
			t.Errorf("a viewer is offered %s", action)
		}
	}
	// The banner is the viewer's too: the instance has no certificate.
	if !strings.Contains(vb.get(t, "/").html(), newBanner) {
		t.Error("a viewer of the whole tenant sees no banner on a new instance")
	}
}

// TestFirstStepsForARoleLimitedToOneCA: such a role reads its own CA and learns
// nothing tenant-wide: no domain, no certificate count, no ACME address, no
// banner.
func TestFirstStepsForARoleLimitedToOneCA(t *testing.T) {
	t.Parallel()
	v := newCustomUIEnv(t, withACME)
	v.Unseal(t)
	v.User(t, "scoped", false, authz.Binding{CA: "issuing", Role: authz.Operator})
	b := v.browser("192.0.2.3")
	b.signIn(t, "scoped", testinstance.Password)
	r := b.get(t, "/first-steps")
	if r.Code != http.StatusOK {
		t.Fatalf("scoped: %d", r.Code)
	}
	rows := stepsOf(t, r.html())
	for title, want := range map[string]string{"Unseal the server": "Done", "Create a certificate authority": "Done", "Public base URL and CRL": "Done", "Add a domain": "Not available to your role",
		"Turn on ACME": "Not available to your role", "Issue a first certificate": "Not available to your role", "Add a host with an agent (optional)": "Not available to your role",
		"Set up notifications (optional)": "Not available to your role", "Back up the instance": "Not detected"} {
		if rows[title] != want {
			t.Errorf("%s: %q, want %q", title, rows[title], want)
		}
	}
	if strings.Contains(mainOf(t, r.html()), "acme/directory") || strings.Contains(mainOf(t, r.html()), "homelab.lan/acme") {
		t.Error("the ACME address reached a role limited to one CA")
	}
	if strings.Contains(b.get(t, "/").html(), newBanner) {
		t.Error("a role limited to one CA is told the instance is new")
	}
}

// TestFirstStepsAcmeOff: with ACME off the ACME row is open and a missing domain
// does not keep the banner on the dashboard.
func TestFirstStepsAcmeOff(t *testing.T) {
	t.Parallel()
	v := newCustomUIEnv(t, nil)
	v.Unseal(t)
	b := signedInAdmin(t, v, "192.0.2.1")
	if _, err := v.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}, Who: testinstance.Console}); err != nil {
		t.Fatal(err)
	}
	html := b.get(t, "/first-steps").html()
	rows := stepsOf(t, html)
	if rows["Turn on ACME"] != "Open" || rows["Add a domain"] != "Open" || rows["Issue a first certificate"] != "Done" || !strings.Contains(html, "acme.base_url is empty") {
		t.Errorf("ACME off: %v", rows)
	}
	if strings.Contains(b.get(t, "/").html(), newBanner) {
		t.Error("the banner waits for a domain although ACME is off")
	}
}

// TestFirstStepsWritesNothing: a GET of the checklist, the dashboard and the
// guides changes no row and no audit entry (decision 11).
func TestFirstStepsWritesNothing(t *testing.T) {
	t.Parallel()
	v := newCustomUIEnv(t, withACME)
	v.Unseal(t)
	b := signedInAdmin(t, v, "192.0.2.1")
	count := func() map[string]int {
		out := map[string]int{}
		for _, tb := range []struct {
			db    *sql.DB
			table string
		}{
			{v.PKIDB.Read, "certificates"}, {v.PKIDB.Read, "cas"}, {v.PKIDB.Read, "domains"}, {v.PKIDB.Read, "outbox"}, {v.PKIDB.Read, "keys"}, {v.PKIDB.Read, "agents"},
			{v.PKIDB.Read, "agent_enrollments"}, {v.PKIDB.Read, "join_tokens"}, {v.PKIDB.Read, "acme_accounts"}, {v.PKIDB.Read, "acme_eab_keys"}, {v.PKIDB.Read, "settings_versions"},
			{v.TenantAudit.Read, "audit_entries"}, {v.InstanceAudit.Read, "audit_entries"},
		} {
			var n int
			if err := tb.db.QueryRowContext(t.Context(), "SELECT count(*) FROM "+tb.table).Scan(&n); err != nil {
				t.Fatalf("count %s: %v", tb.table, err)
			}
			out[tb.table+fmt.Sprintf("/%p", tb.db)] = n
		}
		return out
	}
	before := count()
	for _, target := range []string{"/first-steps", "/", "/guides", "/guides/using-the-guides", "/first-steps"} {
		if r := b.get(t, target); r.Code != http.StatusOK {
			t.Fatalf("%s: %d", target, r.Code)
		}
	}
	if after := count(); !reflect.DeepEqual(before, after) {
		t.Errorf("a GET wrote rows:\nbefore %v\nafter  %v", before, after)
	}
}

// TestFirstStepsIsReadOnlyMarkup: no form, no button, no field in the page
// itself; no script, no inline style; every value is escaped.
func TestFirstStepsIsReadOnlyMarkup(t *testing.T) {
	t.Parallel()
	v := newCustomUIEnv(t, func(d *AppDeps) { d.ACMEDirectory = "https://x.example/<script>alert(1)</script>" })
	v.Unseal(t)
	b := signedInAdmin(t, v, "192.0.2.1")
	html := b.get(t, "/first-steps").html()
	body := mainOf(t, html)
	for _, bad := range []string{"<form", "<button", "<input", "<select", "<textarea", "csrf_token", "<script", "hx-"} {
		if strings.Contains(body, bad) {
			t.Errorf("the page contains %q", bad)
		}
	}
	noScript(t, "first steps", html)
	if !strings.Contains(html, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("the configured address is not shown as escaped text")
	}
	if strings.Count(html, "<h1>") != 1 || !strings.Contains(html, `<section class="section" aria-labelledby="h-checklist">`) || !strings.Contains(html, `<h2 id="h-checklist">Checklist</h2>`) {
		t.Error("headings and landmarks")
	}
	// A POST to the page does not exist.
	if r := b.post(t, "/first-steps", map[string][]string{"csrf_token": {b.csrf(t)}}); r.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /first-steps: %d", r.Code)
	}
	// Signed out: the sign-in page.
	if r := v.browser("192.0.2.77").get(t, "/first-steps"); r.Code != http.StatusSeeOther || !strings.HasPrefix(r.location(), "/login") {
		t.Errorf("anonymous: %d %q", r.Code, r.location())
	}
}

// TestFirstStepsLinksAreServed: every link of the page leads somewhere that
// exists, and the guide links follow the guides of the build.
func TestFirstStepsLinksAreServed(t *testing.T) {
	t.Parallel()
	body := "## Part\n\nText.\n"
	files := map[string]string{}
	for _, slug := range []string{guideBuildCA, guideOfflineRoot, guideCertbot, guideAgent, guideBackup} {
		files[slug] = body
	}
	reg := registryOf(t, files)
	v := newCustomUIEnv(t, func(d *AppDeps) { d.ACMEDirectory = testDirectory; d.Guides = reg })
	v.Unseal(t)
	b := signedInAdmin(t, v, "192.0.2.1")
	html := b.get(t, "/first-steps").html()
	hrefs := regexp.MustCompile(`href="(/[^"]*)"`).FindAllStringSubmatch(mainOf(t, html), -1)
	if len(hrefs) < 12 {
		t.Fatalf("only %d links", len(hrefs))
	}
	seen := map[string]bool{}
	for _, m := range hrefs {
		href := strings.ReplaceAll(m[1], "&amp;", "&")
		if seen[href] {
			continue
		}
		seen[href] = true
		if got := b.get(t, href).Code; got == http.StatusNotFound || got == http.StatusMethodNotAllowed || got >= 500 {
			t.Errorf("the page links to %s, which answers %d", href, got)
		}
	}
	for _, slug := range []string{guideBuildCA, guideOfflineRoot, guideCertbot, guideAgent, guideBackup} {
		if !seen["/guides/"+slug] {
			t.Errorf("no link to the guide %s", slug)
		}
	}
	// The binary's own guides: the checklist works with whichever of the five
	// exist. Step 74 adds them; until then the rows simply have no guide link.
	embedded, err := guides.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, slug := range []string{guideBuildCA, guideOfflineRoot, guideCertbot, guideAgent, guideBackup} {
		if _, ok := embedded.Get(slug); !ok {
			t.Logf("the guide %q is not embedded yet; First steps leaves its link out", slug)
		}
	}
}

// registryOf builds a registry from slug -> body.
func registryOf(t *testing.T, bodies map[string]string) *guides.Registry {
	t.Helper()
	m := fstest.MapFS{}
	for slug, body := range bodies {
		m["g/"+slug+".md"] = guideFile("Guide "+slug, 10, body)
	}
	reg, err := guides.NewRegistry(m, "g")
	if err != nil {
		t.Fatal(err)
	}
	return reg
}
