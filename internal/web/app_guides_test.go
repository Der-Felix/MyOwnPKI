package web

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/guides"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// newCustomUIEnv is the real UI on a test instance with the dependencies the
// test adjusts (ACME off).
func newCustomUIEnv(t *testing.T, adjust func(*AppDeps)) *uiEnv {
	t.Helper()
	v := &uiEnv{Instance: testinstance.New(t, testinstance.Options{})}
	deps := &AppDeps{
		Auth: v.Auth, Engine: v.Engine, Keys: v.Ring, Presets: v.Presets, Clock: v.Clock, Demo: true, Tenant: store.DefaultTenant,
		Settings: &tenant.Store{DB: v.SystemDB.Write, Clock: v.Clock}, TenantAudit: v.TenantAudit.Read, InstanceAudit: v.InstanceAudit.Read,
	}
	if adjust != nil {
		adjust(deps)
	}
	h, err := NewHandler(Options{Logger: slog.New(slog.NewJSONHandler(&v.logs, nil)), App: deps})
	if err != nil {
		t.Fatal(err)
	}
	v.h = h
	return v
}

// guideFile builds one guide file for a test registry.
func guideFile(title string, order int, body string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte(fmt.Sprintf("---\ntitle: %s\nsummary: About %s.\naudience: Everyone\norder: %d\nsite: /guides/certbot/\n---\n\n%s\n", title, title, order, body))}
}

func testRegistry(t *testing.T) *guides.Registry {
	t.Helper()
	reg, err := guides.NewRegistry(fstest.MapFS{
		"g/zeta.md":  guideFile("Zeta guide", 20, "## Zeta part\n\nSee [Alpha](/guides/alpha).\n\n```bash\ncurl --silent {acme_directory}\nopenssl x509 -in {ca_name}.pem -noout -dates\n```"),
		"g/alpha.md": guideFile("Alpha guide", 10, "## Alpha part\n\nA < b & c, and **bold** with `code`.\n\n- [Domains](/domains)\n- [Back](#alpha-part)\n\n> **Warning:** Careful."),
	}, "g")
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func TestGuideList(t *testing.T) {
	t.Parallel()
	v := newCustomUIEnv(t, func(d *AppDeps) { d.Guides = testRegistry(t) })
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	r := b.get(t, "/guides")
	html := r.html()
	if r.Code != http.StatusOK || r.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("/guides: %d %q", r.Code, r.Header().Get("Cache-Control"))
	}
	for _, want := range []string{"<h1>Guides</h1>", `<a href="/guides/alpha">Alpha guide</a>`, `<a href="/guides/zeta">Zeta guide</a>`, "About Alpha guide.", "Everyone",
		`>Guide</th>`, `>For</th>`, `aria-current="page">Guides</a>`, "Help"} {
		if !strings.Contains(html, want) {
			t.Errorf("/guides lacks %q", want)
		}
	}
	if strings.Index(html, "Alpha guide") > strings.Index(html, "Zeta guide") {
		t.Error("the list is not in the order of the guides")
	}
	noScript(t, "/guides", html)
	if strings.Contains(html, "<form") && strings.Contains(html, `method="post"`) && strings.Contains(html, `action="/guides`) {
		t.Error("the list has a form")
	}
}

func TestGuidePage(t *testing.T) {
	t.Parallel()
	v := newCustomUIEnv(t, func(d *AppDeps) {
		d.Guides = testRegistry(t)
		d.ACMEDirectory = "https://pki.example.test/acme/directory"
	})
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)

	r := b.get(t, "/guides/alpha")
	html := r.html()
	if r.Code != http.StatusOK {
		t.Fatalf("/guides/alpha: %d", r.Code)
	}
	for _, want := range []string{
		"<h1>Alpha guide</h1>", "About Alpha guide.", `<li><a href="/guides">Guides</a></li>`, `<li aria-current="page">Alpha guide</li>`,
		`<h2 id="g-alpha-part">Alpha part</h2>`, "A &lt; b &amp; c, and <strong>bold</strong> with <code>code</code>.",
		`<a href="/domains">Domains</a>`, `<a href="#g-alpha-part">Back</a>`, `<span class="msg-label">Warning:</span>`,
		"This guide is complete on its own.", `href="https://der-felix.github.io/MyOwnPKI/guides/certbot/"`, `<main id="main"`, `<h1>`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("/guides/alpha lacks %q", want)
		}
	}
	noScript(t, "/guides/alpha", html)
	if strings.Count(html, "<h1>") != 1 {
		t.Error("a guide page has exactly one h1")
	}

	// The placeholders carry the values of this instance.
	zeta := b.get(t, "/guides/zeta").html()
	if !strings.Contains(zeta, "curl --silent https://pki.example.test/acme/directory\n") || strings.Contains(zeta, "{acme_directory}") || strings.Contains(zeta, "{ca_name}") {
		t.Errorf("placeholders: %s", zeta)
	}
	if !strings.Contains(zeta, "openssl x509 -in issuing.pem -noout -dates") {
		t.Error("{ca_name} is not the name of a CA of the instance")
	}
	if !strings.Contains(zeta, `<a href="/guides/alpha">Alpha</a>`) {
		t.Error("the link to another guide is missing")
	}
}

// TestGuidePlaceholdersNeverComeFromTheRequest: the Host header, the query and
// hostile configuration cannot reach a command.
func TestGuidePlaceholdersNeverComeFromTheRequest(t *testing.T) {
	t.Parallel()
	v := newCustomUIEnv(t, func(d *AppDeps) {
		d.Guides = testRegistry(t)
		d.ACMEDirectory = `https://x.example/"; rm -rf / #<script>`
	})
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	html := b.get(t, "/guides/zeta?acme_directory=https://evil.example/d&ca_name=evil").html()
	if !strings.Contains(html, "curl --silent https://pki.homelab.lan/acme/directory\n") {
		t.Errorf("a hostile configuration value must give the example: %s", html)
	}
	for _, bad := range []string{"evil", "rm -rf", "<script"} {
		if strings.Contains(html, bad) {
			t.Errorf("the page contains %q", bad)
		}
	}
	// A Host header changes nothing.
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://attacker.example/guides/zeta", nil)
	req.Host = "attacker.example"
	if page := b.send(t, req).html(); strings.Contains(page, "attacker.example") {
		t.Error("the Host header reached the page")
	}
}

func TestGuideUnknownSlug(t *testing.T) {
	t.Parallel()
	v := newCustomUIEnv(t, func(d *AppDeps) { d.Guides = testRegistry(t) })
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	for _, target := range []string{"/guides/nope", "/guides/ALPHA", "/guides/alpha%2F..", "/guides/a_b", "/guides/%3Cscript%3E", "/guides/alpha/"} {
		r := b.get(t, target)
		if r.Code != http.StatusNotFound && r.Code != http.StatusMovedPermanently {
			t.Errorf("%s: %d", target, r.Code)
		}
		if strings.Contains(r.html(), "<script>") {
			t.Errorf("%s: the slug reached the page", target)
		}
	}
	if r := b.get(t, "/guides/nope"); !strings.Contains(r.html(), "There is no such object, or you may not see it.") {
		t.Errorf("the 404 is not the standard page: %s", r.html())
	}
}

// TestGuidesAreForEverySignedInUser: any role reads them; nobody else; no POST.
func TestGuidesAreForEverySignedInUser(t *testing.T) {
	t.Parallel()
	v := newCustomUIEnv(t, func(d *AppDeps) { d.Guides = testRegistry(t) })
	v.User(t, "viewer", false, authz.Binding{Role: authz.Viewer})
	v.User(t, "scoped", false, authz.Binding{CA: "issuing", Role: authz.Operator})
	v.User(t, "noroles", false)
	for _, name := range []string{"viewer", "scoped", "noroles"} {
		b := v.browser("192.0.2." + fmt.Sprint(10+len(name)))
		b.signIn(t, name, testinstance.Password)
		for _, target := range []string{"/guides", "/guides/alpha"} {
			if r := b.get(t, target); r.Code != http.StatusOK {
				t.Errorf("%s %s: %d", name, target, r.Code)
			}
		}
		if !strings.Contains(b.get(t, "/").html(), `href="/guides"`) {
			t.Errorf("%s: no Guides entry in the navigation", name)
		}
		csrf := b.csrf(t)
		for _, target := range []string{"/guides", "/guides/alpha"} {
			if r := b.post(t, target, map[string][]string{"csrf_token": {csrf}}); r.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s POST %s: %d", name, target, r.Code)
			}
		}
	}
	anon := v.browser("192.0.2.99")
	for _, target := range []string{"/guides", "/guides/alpha"} {
		if r := anon.get(t, target); r.Code != http.StatusSeeOther || !strings.HasPrefix(r.location(), "/login") {
			t.Errorf("anonymous %s: %d %q", target, r.Code, r.location())
		}
	}
}

// TestEveryEmbeddedGuideRenders: the guides of the binary render with every
// instance value empty and with real ones, and every link in them is served
// (not a 404 or a 405) for an admin. This is the "UI paths that exist" rule of
// decision 12.
func TestEveryEmbeddedGuideRenders(t *testing.T) {
	t.Parallel()
	v := newCustomUIEnv(t, nil)
	v.Unseal(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	reg, err := guides.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range reg.List() {
		r := b.get(t, "/guides/"+g.Slug)
		if r.Code != http.StatusOK {
			t.Errorf("/guides/%s: %d", g.Slug, r.Code)
			continue
		}
		noScript(t, "/guides/"+g.Slug, r.html())
		if strings.ContainsAny(r.html(), "{}") && strings.Contains(r.html(), "{acme_directory}") {
			t.Errorf("%s: an unresolved placeholder", g.Slug)
		}
		for _, l := range g.Links() {
			var path string
			switch l.Target {
			case guides.LinkUI, guides.LinkGuide:
				path, _, _ = strings.Cut(l.Href, "#")
			case guides.LinkAnchor, guides.LinkSite:
				continue
			}
			if got := b.get(t, path).Code; got == http.StatusNotFound || got == http.StatusMethodNotAllowed || got >= 500 {
				t.Errorf("%s links to %s, which answers %d", g.Slug, l.Href, got)
			}
		}
	}
}
