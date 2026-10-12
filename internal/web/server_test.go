package web

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	assets "github.com/Der-Felix/MyOwnPKI/web"
)

func newTestHandler(t *testing.T, dev bool) http.Handler {
	t.Helper()
	h, err := NewHandler(Options{Dev: dev})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func get(t *testing.T, h http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), method, target, nil))
	return rec
}

// designHTML renders /design and returns the HTML.
func designHTML(t *testing.T, dev bool) string {
	t.Helper()
	return get(t, newTestHandler(t, dev), http.MethodGet, "/design").Body.String()
}

func TestRoutes(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t, true)
	tests := []struct {
		method, target string
		wantStatus     int
		wantType       string
	}{
		{http.MethodGet, "/design", http.StatusOK, "text/html; charset=utf-8"},
		{http.MethodGet, "/", http.StatusSeeOther, ""},
		{http.MethodGet, "/static/styles/tokens.css", http.StatusOK, "text/css; charset=utf-8"},
		{http.MethodGet, "/static/styles/components.css", http.StatusOK, "text/css; charset=utf-8"},
		{http.MethodGet, "/static/icons.svg", http.StatusOK, "image/svg+xml"},
		{http.MethodGet, "/static/styles/", http.StatusNotFound, ""},
		{http.MethodGet, "/static/missing.css", http.StatusNotFound, ""},
		// ServeMux cleans ".." and redirects to /web.go – which doesn't exist.
		{http.MethodGet, "/static/../web.go", http.StatusTemporaryRedirect, ""},
		{http.MethodGet, "/web.go", http.StatusNotFound, ""},
		{http.MethodGet, "/nope", http.StatusNotFound, ""},
		{http.MethodPost, "/design", http.StatusMethodNotAllowed, ""},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.target, func(t *testing.T) {
			t.Parallel()
			rec := get(t, h, tt.method, tt.target)
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

func TestDevBanner(t *testing.T) {
	t.Parallel()
	const banner = "DEV MODE – no TLS, no auth"
	if html := designHTML(t, true); !strings.Contains(html, banner) {
		t.Error("dev mode page lacks the DEV MODE banner")
	}
	if html := designHTML(t, false); strings.Contains(html, banner) {
		t.Error("banner shown outside dev mode")
	}
}

var (
	reStyleAttr   = regexp.MustCompile(`(?i)\sstyle\s*=`)
	reStyleTag    = regexp.MustCompile(`(?i)<style[\s>]`)
	reScriptTag   = regexp.MustCompile(`(?i)<script[\s>]`)
	reEventAttr   = regexp.MustCompile(`(?i)\son[a-z]+\s*=`)
	reJSURL       = regexp.MustCompile(`(?i)(href|src)\s*=\s*"\s*javascript:`)
	reClassAttr   = regexp.MustCompile(`\sclass="([^"]*)"`)
	reCSSClass    = regexp.MustCompile(`\.([a-zA-Z][a-zA-Z0-9_-]*)`)
	reCSSVarUse   = regexp.MustCompile(`var\((--[a-z0-9-]+)\)`)
	reCSSVarDef   = regexp.MustCompile(`(--[a-z0-9-]+)\s*:`)
	reCSSHexColor = regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b`)
	reCSSComment  = regexp.MustCompile(`(?s)/\*.*?\*/`)
)

// TestNoInlineStylesOrScripts enforces ADR-12 and the CSP on the rendered
// page: everything visual comes from web/styles, nothing executes inline.
func TestNoInlineStylesOrScripts(t *testing.T) {
	t.Parallel()
	html := designHTML(t, true)
	checks := map[string]*regexp.Regexp{
		"style attribute":    reStyleAttr,
		"<style> block":      reStyleTag,
		"<script> tag":       reScriptTag,
		"inline event (on*)": reEventAttr,
		"javascript: URL":    reJSURL,
	}
	for name, re := range checks {
		if m := re.FindString(html); m != "" {
			t.Errorf("rendered /design contains a %s: %q", name, m)
		}
	}
}

// TestTemplSourcesHaveNoInlineStyles scans the .templ sources, so a future page
// that is not covered by a render test still can't sneak in inline styles.
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
			"<script> tag": reScriptTag, "inline event (on*)": reEventAttr,
		} {
			if m := re.FindString(string(src)); m != "" {
				t.Errorf("%s contains a %s: %q", path, name, m)
			}
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

// TestUsedClassesAreDefined: every class on /design exists in web/styles, so
// the gallery can't show something the stylesheet doesn't provide.
func TestUsedClassesAreDefined(t *testing.T) {
	t.Parallel()
	defined := map[string]bool{}
	for _, src := range readStyles(t) {
		for _, m := range reCSSClass.FindAllStringSubmatch(src, -1) {
			defined[m[1]] = true
		}
	}
	html := designHTML(t, true)
	var missing []string
	for _, m := range reClassAttr.FindAllStringSubmatch(html, -1) {
		for _, class := range strings.Fields(m[1]) {
			if !defined[class] && !slices.Contains(missing, class) {
				missing = append(missing, class)
			}
		}
	}
	if len(missing) > 0 {
		t.Errorf("classes used on /design but not defined in web/styles: %v", missing)
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
