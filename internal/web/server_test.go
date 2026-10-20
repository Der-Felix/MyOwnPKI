package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	assets "github.com/Der-Felix/MyOwnPKI/web"

	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

func newTestHandler(t *testing.T, dev bool) http.Handler {
	t.Helper()
	h, err := NewHandler(Options{Dev: dev})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// do sends a request; extra headers are given as "Name: value".
func do(t *testing.T, h http.Handler, method, target string, form url.Values, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if form != nil {
		req = httptest.NewRequestWithContext(t.Context(), method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequestWithContext(t.Context(), method, target, nil)
	}
	for _, hdr := range headers {
		k, v, _ := strings.Cut(hdr, ": ")
		req.Header.Add(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func get(t *testing.T, h http.Handler, target string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	return do(t, h, http.MethodGet, target, nil, headers...)
}

// devPages are all GET pages of the prototype.
var devPages = []string{
	"/",
	"/certificates",
	"/certificates?status=expiring&q=lan",
	"/certificates/c-0101",
	"/certificates/c-0104",
	"/certificates/c-0102/extensions",
	"/certificates/c-0101/chain",
	"/certificates/c-0101/history",
	"/certificates/new",
	"/authorities",
	"/authorities/homelab-issuing",
	"/authorities/homelab-root",
	"/admin/appearance",
	"/design",
}

func TestRoutes(t *testing.T) {
	t.Parallel()
	dev := newTestHandler(t, true)
	prod := newTestHandler(t, false)
	tests := []struct {
		name       string
		h          http.Handler
		method     string
		target     string
		wantStatus int
		wantType   string
	}{
		{"dashboard", dev, http.MethodGet, "/", http.StatusOK, "text/html; charset=utf-8"},
		{"design", dev, http.MethodGet, "/design", http.StatusOK, "text/html; charset=utf-8"},
		{"css", dev, http.MethodGet, "/static/styles/tokens.css", http.StatusOK, "text/css; charset=utf-8"},
		{"no directory listing", dev, http.MethodGet, "/static/styles/", http.StatusNotFound, ""},
		{"logo", prod, http.MethodGet, "/static/brand/logo-small-on-dark.svg", http.StatusOK, "image/svg+xml"},
		{"favicon svg", prod, http.MethodGet, "/static/brand/favicon.svg", http.StatusOK, "image/svg+xml"},
		{"favicon ico at the root", prod, http.MethodGet, "/favicon.ico", http.StatusOK, "image/x-icon"},
		{"apple touch icon", prod, http.MethodGet, "/static/brand/png/apple-touch-icon.png", http.StatusOK, "image/png"},
		{"brand files not embedded", prod, http.MethodGet, "/static/brand/app.ico", http.StatusNotFound, ""},
		{"brand README not served", prod, http.MethodGet, "/static/brand/README.md", http.StatusNotFound, ""},
		{"no brand directory listing", prod, http.MethodGet, "/static/brand/", http.StatusNotFound, ""},
		{"missing asset", dev, http.MethodGet, "/static/missing.css", http.StatusNotFound, ""},
		{"path cleaning", dev, http.MethodGet, "/static/../web.go", http.StatusTemporaryRedirect, ""},
		{"unknown certificate", dev, http.MethodGet, "/certificates/nope", http.StatusNotFound, ""},
		{"unknown tab", dev, http.MethodGet, "/certificates/c-0101/bogus", http.StatusNotFound, ""},
		{"overview tab has no suffix", dev, http.MethodGet, "/certificates/c-0101/overview", http.StatusNotFound, ""},
		{"unknown CA", dev, http.MethodGet, "/authorities/nope", http.StatusNotFound, ""},
		{"wrong method", dev, http.MethodPost, "/design", http.StatusMethodNotAllowed, ""},
		{"prototype hidden outside dev mode", prod, http.MethodGet, "/certificates", http.StatusNotFound, ""},
		{"root redirects outside dev mode", prod, http.MethodGet, "/", http.StatusSeeOther, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := do(t, tt.h, tt.method, tt.target, nil)
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantType != "" && rec.Header().Get("Content-Type") != tt.wantType {
				t.Errorf("Content-Type = %q, want %q", rec.Header().Get("Content-Type"), tt.wantType)
			}
			// Security headers on every response, including errors and redirects.
			if got := rec.Header().Get("Content-Security-Policy"); got != ContentSecurityPolicy {
				t.Errorf("CSP = %q", got)
			}
			for header, want := range map[string]string{
				"X-Content-Type-Options": "nosniff",
				"Referrer-Policy":        "same-origin",
				"X-Frame-Options":        "DENY",
			} {
				if got := rec.Header().Get(header); got != want {
					t.Errorf("%s = %q, want %q", header, got, want)
				}
			}
		})
	}
}

func TestDevPagesRender(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, true)
	for _, page := range devPages {
		rec := get(t, h, page)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d", page, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "DEV MODE – no TLS, no auth") {
			t.Errorf("GET %s lacks the DEV MODE banner", page)
		}
	}
	if strings.Contains(get(t, newTestHandler(t, false), "/design").Body.String(), "DEV MODE") {
		t.Error("banner shown outside dev mode")
	}
}

var (
	reStyleAttr   = regexp.MustCompile(`(?i)\sstyle\s*=`)
	reStyleTag    = regexp.MustCompile(`(?i)<style[\s>]`)
	reScriptTag   = regexp.MustCompile(`(?i)<script[\s>]`)
	reEventAttr   = regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
	reJSURL       = regexp.MustCompile(`(?i)(href|src|action)\s*=\s*"\s*javascript:`)
	reIcon        = regexp.MustCompile(`(?i)<svg[\s>]`)
	reImgTag      = regexp.MustCompile(`(?is)<img\b[^>]*>`)
	reClassAttr   = regexp.MustCompile(`\sclass="([^"]*)"`)
	reCSSClass    = regexp.MustCompile(`\.([a-zA-Z][a-zA-Z0-9_-]*)`)
	reCSSVarUse   = regexp.MustCompile(`var\((--[a-z0-9-]+)\)`)
	reCSSVarDef   = regexp.MustCompile(`(--[a-z0-9-]+)\s*:`)
	reCSSHexColor = regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b`)
	reCSSComment  = regexp.MustCompile(`(?s)/\*.*?\*/`)
)

// renderedPages returns the HTML of every prototype page plus a wizard error
// state, and every page of the real UI (realPages).
func renderedPages(t *testing.T) map[string]string {
	t.Helper()
	h := newTestHandler(t, true)
	out := map[string]string{}
	for _, p := range devPages {
		out[p] = get(t, h, p).Body.String()
	}
	out["wizard error"] = do(t, h, http.MethodPost, "/certificates/new", wizardForm(3, "next", url.Values{"dns": {"bad..name"}})).Body.String()
	out["wizard review"] = do(t, h, http.MethodPost, "/certificates/new", wizardForm(3, "next", url.Values{"keymode": {"server"}})).Body.String()
	for k, html := range realPages(t) {
		out[k] = html
	}
	return out
}

// TestNoInlineStylesOrScripts enforces ADR-12, the CSP and the "no icons"
// design rule on every rendered page.
func TestNoInlineStylesOrScripts(t *testing.T) {
	t.Parallel()
	checks := map[string]*regexp.Regexp{
		"style attribute":    reStyleAttr,
		"<style> block":      reStyleTag,
		"<script> tag":       reScriptTag,
		"inline event (on*)": reEventAttr,
		"javascript: URL":    reJSURL,
		"inline <svg> icon":  reIcon,
	}
	for page, html := range renderedPages(t) {
		for name, re := range checks {
			if m := re.FindString(html); m != "" {
				t.Errorf("%s contains a %s: %q", page, name, m)
			}
		}
		for _, img := range nonBrandImages(html) {
			t.Errorf("%s contains an image that is not a brand file with alt text: %q", page, img)
		}
	}
}

// nonBrandImages returns every <img> that does not show a file of
// assets/brand or lacks an alt attribute: the logo is the only image in the
// UI ("no icons", frontend.md).
func nonBrandImages(src string) []string {
	var bad []string
	for _, img := range reImgTag.FindAllString(src, -1) {
		if !strings.Contains(img, `"/static/brand/`) || !strings.Contains(img, " alt=") {
			bad = append(bad, img)
		}
	}
	return bad
}

// TestTemplSourcesHaveNoInlineStyles scans the .templ sources, so a page that is
// not covered by a render test still can't sneak in inline styles.
func TestTemplSourcesHaveNoInlineStyles(t *testing.T) {
	t.Parallel()
	sources := os.DirFS(".")
	err := fs.WalkDir(sources, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".templ") {
			return err
		}
		src, err := fs.ReadFile(sources, path)
		if err != nil {
			return err
		}
		for name, re := range map[string]*regexp.Regexp{
			"style attribute": reStyleAttr, "<style> block": reStyleTag,
			"<script> tag": reScriptTag, "inline event (on*)": reEventAttr, "inline <svg> icon": reIcon,
		} {
			if m := re.FindString(string(src)); m != "" {
				t.Errorf("%s contains a %s: %q", path, name, m)
			}
		}
		for _, img := range nonBrandImages(string(src)) {
			t.Errorf("%s contains an image that is not a brand file with alt text: %q", path, img)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func readStyles(t *testing.T) map[string]string {
	t.Helper()
	files, err := fs.Glob(assets.Static, "styles/*.css")
	if err != nil || len(files) == 0 {
		t.Fatalf("no stylesheets: %v", err)
	}
	css := map[string]string{}
	for _, f := range files {
		b, err := fs.ReadFile(assets.Static, f)
		if err != nil {
			t.Fatal(err)
		}
		css[f] = reCSSComment.ReplaceAllString(string(b), "")
	}
	return css
}

// TestUsedClassesAreDefined: every class on every page exists in web/styles.
func TestUsedClassesAreDefined(t *testing.T) {
	t.Parallel()
	defined := map[string]bool{}
	for _, src := range readStyles(t) {
		for _, m := range reCSSClass.FindAllStringSubmatch(src, -1) {
			defined[m[1]] = true
		}
	}
	missing := map[string]string{}
	for page, html := range renderedPages(t) {
		for _, m := range reClassAttr.FindAllStringSubmatch(html, -1) {
			for _, class := range strings.Fields(m[1]) {
				if !defined[class] {
					missing[class] = page
				}
			}
		}
	}
	for class, page := range missing {
		t.Errorf("class %q (used on %s) is not defined in web/styles", class, page)
	}
}

// TestStylesUseTokensOnly: colors live only in tokens.css, and every var()
// refers to a defined token (ADR-12: themes change tokens only).
func TestStylesUseTokensOnly(t *testing.T) {
	t.Parallel()
	css := readStyles(t)
	tokens := map[string]bool{}
	for _, m := range reCSSVarDef.FindAllStringSubmatch(css["styles/tokens.css"], -1) {
		tokens[m[1]] = true
	}
	for file, src := range css {
		if file == "styles/tokens.css" {
			continue
		}
		if m := reCSSHexColor.FindString(src); m != "" {
			t.Errorf("%s: hard-coded color %s – use a token from tokens.css", file, m)
		}
		for _, m := range reCSSVarUse.FindAllStringSubmatch(src, -1) {
			if !tokens[m[1]] {
				t.Errorf("%s: var(%s) is not defined in tokens.css", file, m[1])
			}
		}
	}
}

func TestAppearanceCookie(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, true)

	rec := do(t, h, http.MethodPost, "/admin/appearance", url.Values{"layout": {"c"}, "theme": {"dark"}, "density": {"compact"}},
		"Sec-Fetch-Site: same-origin")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save: status %d, body %s", rec.Code, rec.Body.String())
	}
	cookie := rec.Result().Cookies()
	if len(cookie) != 1 || cookie[0].Value != "c.dark.compact" || !cookie[0].HttpOnly || cookie[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("unexpected cookie: %+v", cookie)
	}

	html := get(t, h, "/", "Cookie: "+view.PrefsCookie+"=c.dark.compact").Body.String()
	for _, want := range []string{`data-theme="dark"`, `data-density="compact"`, `data-layout="c"`} {
		if !strings.Contains(html, want) {
			t.Errorf("page with cookie lacks %s", want)
		}
	}

	// A tampered cookie falls back to the defaults; nothing from it reaches the page.
	html = get(t, h, "/", "Cookie: "+view.PrefsCookie+`=x."><b>.y`).Body.String()
	if !strings.Contains(html, `data-theme="light"`) || strings.Contains(html, "<b>") {
		t.Error("tampered cookie was not replaced by defaults")
	}

	rec = do(t, h, http.MethodPost, "/admin/appearance", url.Values{"layout": {"z"}, "theme": {"dark"}, "density": {"compact"}},
		"Sec-Fetch-Site: same-origin")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid value: status %d, want 400", rec.Code)
	}
}

func TestCrossOriginPostIsRejected(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, true)
	form := url.Values{"layout": {"a"}, "theme": {"light"}, "density": {"compact"}}
	if rec := do(t, h, http.MethodPost, "/admin/appearance", form, "Sec-Fetch-Site: cross-site"); rec.Code != http.StatusForbidden {
		t.Errorf("cross-site POST: status %d, want 403", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/admin/appearance", form, "Origin: https://evil.example"); rec.Code != http.StatusForbidden {
		t.Errorf("foreign Origin POST: status %d, want 403", rec.Code)
	}
}

func TestCertificateFiltersAndActions(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, true)

	html := get(t, h, "/certificates?status=revoked").Body.String()
	if !strings.Contains(html, "radius.homelab.lan") || strings.Contains(html, "nas.homelab.lan") {
		t.Error("status filter 'revoked' returned the wrong rows")
	}

	rec := do(t, h, http.MethodPost, "/certificates/actions", url.Values{"action": {"revoke"}, "id": {"c-0101", "c-0102", "unknown"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/certificates?msg=revoke&n=2" {
		t.Errorf("revoke: %d %q (unknown IDs must not be counted)", rec.Code, rec.Header().Get("Location"))
	}
	if html := get(t, h, "/certificates?msg=revoke").Body.String(); !strings.Contains(html, "Select at least one certificate") {
		t.Error("revoke without selection shows no error")
	}
	if html := get(t, h, "/certificates?msg=%3Cscript%3E").Body.String(); strings.Contains(html, "msg-") {
		t.Error("unknown message code produced a message bar")
	}
	if rec := do(t, h, http.MethodPost, "/certificates/actions", url.Values{"action": {"delete"}}); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown action: status %d, want 400", rec.Code)
	}
}

// wizardForm is a complete, valid wizard state; override changes single fields.
func wizardForm(from int, goTo string, override url.Values) url.Values {
	f := url.Values{
		"from": {strconv.Itoa(from)}, "go": {goTo},
		"preset": {"server"}, "ca": {"homelab-issuing"},
		"cn": {"nas.homelab.lan"}, "dns": {"nas.homelab.lan"}, "ip": {"192.168.10.20"},
		"keymode": {"server"}, "alg": {"ecdsa-p256"}, "days": {"397"},
	}
	for k, v := range override {
		f[k] = v
	}
	return f
}

func testCSR(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "nas.homelab.lan"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestIssueWizard(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, true)
	tests := []struct {
		name       string
		form       url.Values
		wantStatus int
		want       string
	}{
		{"step 1 → 2", wizardForm(1, "next", nil), http.StatusOK, `aria-current="step">Key`},
		{"offline root can't sign", wizardForm(1, "next", url.Values{"ca": {"homelab-root"}}), http.StatusUnprocessableEntity, "Choose a CA whose key is online"},
		{"name constraints", wizardForm(3, "next", url.Values{"dns": {"nas.example.org"}}), http.StatusUnprocessableEntity, "outside the name constraints of homelab-issuing"},
		{"IP outside constraints", wizardForm(3, "next", url.Values{"ip": {"8.8.8.8"}}), http.StatusUnprocessableEntity, "8.8.8.8 is outside the name constraints"},
		{"double wildcard", wizardForm(3, "next", url.Values{"dns": {"*.*.homelab.lan"}}), http.StatusUnprocessableEntity, "not a valid DNS name"},
		{"server needs a SAN", wizardForm(3, "next", url.Values{"dns": {""}, "ip": {""}}), http.StatusUnprocessableEntity, "needs at least one DNS name or IP address"},
		{"step 2 → 3", wizardForm(2, "next", nil), http.StatusOK, `aria-current="step">Names`},
		{"bad CSR", wizardForm(2, "next", url.Values{"keymode": {"csr"}, "csr": {"hello"}}), http.StatusUnprocessableEntity, "Paste a PEM certificate request"},
		{"too long", wizardForm(2, "next", url.Values{"days": {"398"}}), http.StatusUnprocessableEntity, "the maximum validity of homelab-issuing"},
		{"review with CSR", wizardForm(3, "next", url.Values{"keymode": {"csr"}, "csr": {testCSR(t)}}), http.StatusOK, "From the uploaded request: ECDSA P-256"},
		{"review shows preset extensions", wizardForm(3, "next", url.Values{"alg": {"rsa-3072"}}), http.StatusOK, "digitalSignature, keyEncipherment (critical)"},
		{"back", wizardForm(3, "back", nil), http.StatusOK, `aria-current="step">Key`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rec := do(t, h, http.MethodPost, "/certificates/new", tt.form)
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if !strings.Contains(rec.Body.String(), tt.want) {
				t.Errorf("response lacks %q", tt.want)
			}
		})
	}

	t.Run("issue re-validates every step", func(t *testing.T) {
		t.Parallel()
		rec := do(t, h, http.MethodPost, "/certificates/new", wizardForm(4, "issue", url.Values{"dns": {"evil.example.org"}}))
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "outside the name constraints") {
			t.Errorf("tampered hidden field accepted: %d", rec.Code)
		}
		rec = do(t, h, http.MethodPost, "/certificates/new", wizardForm(4, "issue", nil))
		if rec.Code != http.StatusSeeOther || !slices.Contains([]string{"/certificates?msg=issued"}, rec.Header().Get("Location")) {
			t.Errorf("valid request: %d %q", rec.Code, rec.Header().Get("Location"))
		}
	})
}

var (
	reCSSPx       = regexp.MustCompile(`-?\b\d+(\.\d+)?px\b`)
	reCSSTokenDef = regexp.MustCompile(`(--[a-z0-9-]+)\s*:\s*(\d+)px\s*;`)
)

// TestStrictGrid: outside tokens.css only hairlines (1px, 2px) may be written
// as pixels – every other size comes from a token. Spacing and size tokens are
// multiples of 4 (Fluent-style 4 px grid); only font sizes and the radius differ.
func TestStrictGrid(t *testing.T) {
	t.Parallel()
	css := readStyles(t)
	for file, src := range css {
		if file == "styles/tokens.css" {
			continue
		}
		for i, line := range strings.Split(src, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "@media") {
				continue // breakpoints can't use custom properties
			}
			for _, px := range reCSSPx.FindAllString(line, -1) {
				if !slices.Contains([]string{"1px", "2px", "-1px", "-2px"}, px) {
					t.Errorf("%s:%d: raw %s – use a token from tokens.css", file, i+1, px)
				}
			}
		}
	}
	for _, m := range reCSSTokenDef.FindAllStringSubmatch(css["styles/tokens.css"], -1) {
		name, value := m[1], m[2]
		if strings.HasPrefix(name, "--fs-") || name == "--radius" {
			continue
		}
		if n, _ := strconv.Atoi(value); n%4 != 0 {
			t.Errorf("token %s: %spx is not a multiple of 4", name, value)
		}
	}
}

func TestPageHeaderConventions(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, true)

	if html := get(t, h, "/").Body.String(); strings.Contains(html, `aria-label="Breadcrumb"`) {
		t.Error("the dashboard must not have a breadcrumb")
	}
	for _, page := range devPages[1:] {
		html := get(t, h, page).Body.String()
		if !strings.Contains(html, `<ol class="breadcrumb"><li><a href="/">Dashboard</a></li>`) {
			t.Errorf("%s: breadcrumb must start with Dashboard", page)
		}
		if strings.Count(html, `<header class="page-header">`) != 1 || strings.Count(html, "<h1>") != 1 {
			t.Errorf("%s: exactly one page header and one h1 expected", page)
		}
	}

	detail := get(t, h, "/certificates/c-0101").Body.String()
	if !regexp.MustCompile(`([0-9A-F]{2}:){15}[0-9A-F]{2}:\n([0-9A-F]{2}:){15}[0-9A-F]{2}`).MatchString(detail) {
		t.Error("SHA-256 fingerprint is not shown as two lines of 16 colon-separated bytes")
	}
	list := get(t, h, "/certificates").Body.String()
	if !regexp.MustCompile(`<span class="trunc" title="[0-9A-F]{32}">[0-9A-F]{32}</span>`).MatchString(list) {
		t.Error("serial numbers in the list are not truncated with the full value in title")
	}
}
