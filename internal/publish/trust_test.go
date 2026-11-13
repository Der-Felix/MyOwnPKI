package publish

import (
	"bytes"
	"context"
	"crypto/x509"
	"html"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
	"github.com/Der-Felix/MyOwnPKI/internal/trustkit"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
	styles "github.com/Der-Felix/MyOwnPKI/web"
)

type answer struct {
	code int
	body []byte
	h    http.Header
}

// fetch is a GET; pairs of header name and value follow the path. No answer of
// this handler is ever a redirect, so none may carry a Location header.
func fetch(t *testing.T, h http.Handler, path string, hdr ...string) answer {
	t.Helper()
	return fetchMethod(t, h, http.MethodGet, path, hdr...)
}

func fetchMethod(t *testing.T, h http.Handler, method, path string, hdr ...string) answer {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Result().Body)
	if loc := rec.Header().Get("Location"); loc != "" || (rec.Code >= 300 && rec.Code < 400 && rec.Code != http.StatusNotModified) {
		t.Errorf("%s %s: a redirect (%d, Location %q)", method, path, rec.Code, loc)
	}
	return answer{rec.Code, body, rec.Header()}
}

func trustSetup(t *testing.T) (*testinstance.Instance, http.Handler, *tenant.Store) {
	t.Helper()
	v := testinstance.New(t, testinstance.Options{})
	settings := &tenant.Store{DB: v.SystemDB.Write, Clock: v.Clock}
	h := New(v.PKIDB.Read, nil).WithTrustPage(TrustPage{
		Enabled: func(ctx context.Context) (bool, error) { return settings.TrustPage(ctx, store.DefaultTenant) }, Clock: v.Clock,
	})
	return v, h, settings
}

var (
	reClass = regexp.MustCompile(`class="([^"]+)"`)
	reRef   = regexp.MustCompile(`(?:href|src)="(/[^"]*)"`)
	reCSS   = regexp.MustCompile(`\.([a-zA-Z][a-zA-Z0-9_-]*)`)
)

// definedClasses is every class name the app's stylesheets mention.
var definedClasses = sync.OnceValue(func() map[string]bool {
	defined := map[string]bool{}
	_ = fs.WalkDir(styles.Static, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := fs.ReadFile(styles.Static, p)
			for _, m := range reCSS.FindAllStringSubmatch(string(b), -1) {
				defined[m[1]] = true
			}
		}
		return nil
	})
	return defined
})

// checkPage applies the rules every page of the portal obeys: the strict CSP
// (the constant, and the constant is the one the plan fixed), no script and no
// inline style, only classes of web/styles, and every link is served.
func checkPage(t *testing.T, h http.Handler, a answer) {
	t.Helper()
	if a.code != http.StatusOK || a.h.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("page: %d %s", a.code, a.h.Get("Content-Type"))
	}
	const want = "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	if TrustCSP != want || a.h.Get("Content-Security-Policy") != want || strings.Contains(want, "script-src") {
		t.Errorf("CSP: %q", a.h.Get("Content-Security-Policy"))
	}
	if a.h.Get("X-Content-Type-Options") != "nosniff" || a.h.Get("Vary") != "User-Agent" {
		t.Errorf("headers: nosniff %q, Vary %q", a.h.Get("X-Content-Type-Options"), a.h.Get("Vary"))
	}
	page := string(a.body)
	lower := strings.ToLower(page)
	for _, bad := range []string{"<script", " style=", "<style", "<form", "<iframe", "<object", "<embed", "javascript:", " onclick=", " onload=", "<meta http-equiv", "https://"} {
		if strings.Contains(lower, bad) {
			t.Errorf("the page contains %q", bad)
		}
	}
	if strings.Contains(lower, "secure") {
		t.Error("the page claims something is secure")
	}
	for _, m := range reClass.FindAllStringSubmatch(page, -1) {
		for _, c := range strings.Fields(m[1]) {
			if !definedClasses()[c] {
				t.Errorf("class %q is not in web/styles", c)
			}
		}
	}
	seen := map[string]bool{}
	for _, m := range reRef.FindAllStringSubmatch(page, -1) {
		if seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		if r := fetch(t, h, html.UnescapeString(m[1])); r.code != http.StatusOK {
			t.Errorf("%s: %d", m[1], r.code)
		} else if strings.HasSuffix(m[1], ".css") && r.h.Get("Content-Type") != "text/css; charset=utf-8" {
			t.Errorf("%s: %s", m[1], r.h.Get("Content-Type"))
		}
	}
}

// TestTrustPage: the page without a User-Agent: warning first, the roots
// table, the platform list, the intermediates as downloads; strict CSP, no
// script, cache headers; every class exists and every link is served.
func TestTrustPage(t *testing.T) {
	t.Parallel()
	_, h, _ := trustSetup(t)
	a := fetch(t, h, "/")
	checkPage(t, h, a)
	if a.h.Get("Cache-Control") != "public, max-age=300" || a.h.Get("ETag") == "" {
		t.Errorf("cache headers: %v", a.h)
	}
	if again := fetch(t, h, "/", "If-None-Match", a.h.Get("ETag")); again.code != http.StatusNotModified {
		t.Errorf("conditional request: %d", again.code)
	}
	if head := fetchMethod(t, h, http.MethodHead, "/"); head.code != http.StatusOK || len(head.body) != 0 || head.h.Get("ETag") != a.h.Get("ETag") {
		t.Errorf("HEAD: %d %d bytes", head.code, len(head.body))
	}
	root := fetch(t, h, "/ca/root/1.crt")
	rootCert, err := x509.ParseCertificate(root.body)
	if err != nil {
		t.Fatal(err)
	}
	page := string(a.body)
	for _, want := range []string{
		"Before you install anything", "plain HTTP", "Nothing on it proves itself, not even the fingerprints",
		"<code>myownpki ca show NAME</code>", "<em>Authorities</em>", "openssl x509 -inform DER -in FILE -noout -fingerprint -sha256",
		"Root certificates", "Intermediate certificates", "install nothing",
		rootCert.Subject.CommonName, view.Fingerprint(trustkit.ColonHex(trustkit.SHA256Hex(root.body))),
		rootCert.NotAfter.UTC().Format("2006-01-02"),
		`href="/ca/root/1.crt" download="root.crt"`, `href="/ca/root/1.pem" download="root.pem"`, `href="/ca/issuing/1.crt"`,
		"This page could not tell your system. Choose it:",
		`href="/?os=windows"`, `href="/?os=macos"`, `href="/?os=ios"`, `href="/?os=android"`, `href="/?os=debian"`,
		`href="/?os=fedora"`, `href="/?os=firefox"`, `href="/?os=java"`, `href="/?os=all"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	// The warning and the out-of-band text come first, then the roots, then the intermediates.
	idx := func(s string) int { return strings.Index(page, s) }
	if idx("Before you install anything") >= idx("Root certificates") || idx("Root certificates") >= idx("Your system") || idx("Your system") >= idx("Intermediate certificates") {
		t.Error("the sections are in the wrong order")
	}
	// Nothing to install without a platform: no steps and no commands.
	for _, bad := range []string{`id="h-windows"`, "curl -fsS", "Import-Certificate", "/trust/", "PayloadType"} {
		if strings.Contains(page, bad) {
			t.Errorf("the chooser page contains %q", bad)
		}
	}
	// The intermediate is a download row only.
	if strings.Contains(page, "/trust/issuing/") || strings.Contains(page, "issuing – Intermediate CA") {
		t.Error("the intermediate has more than a downloads row")
	}
}

// TestTrustPageAllPlatforms: ?os=all is the all-in-one guide of the older
// page: every platform, every link served, and the texts the plan requires.
func TestTrustPageAllPlatforms(t *testing.T) {
	t.Parallel()
	_, h, _ := trustSetup(t)
	a := fetch(t, h, "/?os=all")
	checkPage(t, h, a)
	if a.h.Get("Cache-Control") != "public, max-age=300" {
		t.Errorf("explicit choice: %q", a.h.Get("Cache-Control"))
	}
	page := string(a.body)
	text := html.UnescapeString(page)
	for _, p := range trustkit.Platforms() {
		if !strings.Contains(page, `id="h-`+string(p)+`"`) {
			t.Errorf("no section for %s", p)
		}
	}
	root := fetch(t, h, "/ca/root/1.crt").body
	issuing, err := x509.ParseCertificate(fetch(t, h, "/ca/issuing/1.crt").body)
	if err != nil {
		t.Fatal(err)
	}
	url := issuing.IssuingCertificateURL[0] // the root's DER URL, from the database's base URL
	sum := trustkit.SHA256Hex(root)
	for _, want := range []string{
		"curl -fsS -o root.crt '" + url + "' \\\n  && echo '" + sum + "  root.crt' | sha256sum -c - \\\n",
		"sudo update-ca-certificates", "sudo update-ca-trust", "shasum -a 256 -c -", "sudo security add-trusted-cert",
		"-Uri '" + url + "'", "'" + strings.ToUpper(sum) + "'", `Cert:\CurrentUser\Root`, `Cert:\LocalMachine\Root`,
		"keytool -importcert", "security.enterprise_roots.enabled",
		"Certificate Trust Settings", "Not Signed", "API 24", "only checks the download against this page",
		`href="/trust/root/1/machine.cmd"`, `href="/trust/root/1/user.cmd"`, `href="/trust/root/1/profile.mobileconfig"`,
		`download="root.cer"`, "SHA-1 fingerprint (Windows certificate dialog comparison only):",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if strings.Contains(text, "-noprompt") {
		t.Error("keytool -noprompt")
	}
	// Roots get steps; an intermediate never gets commands or a profile.
	for _, bad := range []string{"/trust/issuing/", "myownpki-issuing", "/ca/issuing/1.crt'"} {
		if strings.Contains(text, bad) {
			t.Errorf("the page contains %q for an intermediate", bad)
		}
	}
}

// TestTrustDownloads: PEM = DER, the helper embeds exactly the CA's root
// certificate, only roots on the page get one, and the setting switches
// page and helpers off – never what certificates point to.
func TestTrustDownloads(t *testing.T) {
	t.Parallel()
	v, h, settings := trustSetup(t)
	der := fetch(t, h, "/ca/root/1.crt").body
	if p := fetch(t, h, "/ca/root/1.pem"); p.code != http.StatusOK || !bytes.Equal(p.body, pemOf(der)) || p.h.Get("Content-Type") != "application/x-pem-file" {
		t.Errorf("PEM: %d %s", p.code, p.h.Get("Content-Type"))
	}
	for scope, file := range map[string]string{ScopeMachine: "root-trust-computer.cmd", ScopeUser: "root-trust-user.cmd"} {
		a := fetch(t, h, "/trust/root/1/"+scope+".cmd")
		if a.code != http.StatusOK || !bytes.Equal(embeddedDER(t, a.body), der) || a.h.Get("Content-Disposition") != `attachment; filename="`+file+`"` {
			t.Errorf("%s helper: %d %v", scope, a.code, a.h)
		}
	}
	for _, p := range []string{
		"/trust/issuing/1/machine.cmd", "/trust/root/2/user.cmd", "/trust/root/1/admin.cmd", "/trust/root/0/user.cmd", "/trust/Root/1/user.cmd",
		"/trust/issuing/1/profile.mobileconfig", "/trust/root/2/profile.mobileconfig", "/trust/root/1/profile.plist", "/trust/root/1/profile.mobileconfig.cmd",
		"/trust/root/1/Profile.mobileconfig", "/trust/root/01x/profile.mobileconfig", "/trust/root/-1/profile.mobileconfig", "/trust/root/1/.cmd",
	} {
		if a := fetch(t, h, p); a.code != http.StatusNotFound {
			t.Errorf("%s: %d", p, a.code)
		}
	}

	// A renewed root: the older generation stays on the page while valid.
	v.Unseal(t)
	if _, err := v.Engine.RenewCA(t.Context(), ca.RenewRequest{Name: "root", Who: testinstance.Console}); err != nil {
		t.Fatal(err)
	}
	page := string(fetch(t, h, "/?os=debian").body)
	text := html.UnescapeString(page)
	if !strings.Contains(page, `download="root-1.crt"`) || !strings.Contains(page, "older generation 1, still valid") {
		t.Errorf("the older generation is not marked:\n%s", page)
	}
	if strings.Index(page, `/ca/root/2.crt`) > strings.Index(page, `/ca/root/1.crt`) {
		t.Error("the older generation comes first")
	}
	// One block per root generation, each with its own URL, hash and file names.
	for _, want := range []string{
		"/ca/root/2.crt'", "/ca/root/1.crt'", "myownpki-root.crt", "myownpki-root-1.crt",
		trustkit.SHA256Hex(fetch(t, h, "/ca/root/2.crt").body), trustkit.SHA256Hex(fetch(t, h, "/ca/root/1.crt").body),
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the Debian steps after the renewal lack %q", want)
		}
	}
	if n := strings.Count(text, "sudo update-ca-certificates"); n != 2 {
		t.Errorf("%d command blocks for 2 root generations", n)
	}
	for scope, wantName := range map[string]string{ScopeMachine: "root-1-trust-computer.cmd", ScopeUser: "root-1-trust-user.cmd"} {
		if a := fetch(t, h, "/trust/root/1/"+scope+".cmd"); a.code != http.StatusOK || a.h.Get("Content-Disposition") != `attachment; filename="`+wantName+`"` {
			t.Errorf("older helper: %d %v", a.code, a.h)
		}
		// The generation in the file name is the normalized number, not the text of
		// the request: "+1" and many leading zeros parse to 1 and name the same file.
		for _, spelled := range []string{"+1", "01", "0000000001", strings.Repeat("0", 30) + "1"} {
			a := fetch(t, h, "/trust/root/"+spelled+"/"+scope+".cmd")
			if a.code != http.StatusOK && a.code != http.StatusNotFound {
				t.Errorf("%s: %d", spelled, a.code)
			}
			if cd := a.h.Get("Content-Disposition"); a.code == http.StatusOK && cd != `attachment; filename="`+wantName+`"` {
				t.Errorf("generation spelled %q: Content-Disposition %q, want the name %q", spelled, cd, wantName)
			}
		}
	}

	off := false
	s, err := settings.Get(t.Context(), store.DefaultTenant, testinstance.Console)
	if err != nil {
		t.Fatal(err)
	}
	s.TrustPage = &off
	if err := settings.Set(t.Context(), store.DefaultTenant, *s, testinstance.Console); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/", "/?os=windows", "/?os=all", "/trust/root/2/user.cmd", "/trust/root/2/machine.cmd", "/trust/root/2/profile.mobileconfig", "/trust/root/1/profile.mobileconfig"} {
		if a := fetch(t, h, p, "User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"); a.code != http.StatusNotFound {
			t.Errorf("off: %s answers %d", p, a.code)
		}
	}
	for _, p := range []string{"/ca/root/1.crt", "/ca/root/1.pem", "/ca/root/2.crt", "/crl/issuing/1.crl"} {
		if a := fetch(t, h, p); a.code != http.StatusOK {
			t.Errorf("off: %s answers %d – it must stay", p, a.code)
		}
	}
}
