package publish

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
	styles "github.com/Der-Felix/MyOwnPKI/web"
)

type answer struct {
	code int
	body []byte
	h    http.Header
}

func fetch(t *testing.T, h http.Handler, path string, hdr ...string) answer {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Result().Body)
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

// TestTrustPage: the CAs (roots first) with name, common name, validity,
// the fingerprint and the downloads; guides for every platform; a strict
// CSP and no script; cache headers; every class exists in the app's
// stylesheets and every linked file is served.
func TestTrustPage(t *testing.T) {
	t.Parallel()
	v, h, _ := trustSetup(t)
	a := fetch(t, h, "/")
	if a.code != http.StatusOK || a.h.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("/: %d %s", a.code, a.h.Get("Content-Type"))
	}
	page := string(a.body)
	if a.h.Get("Content-Security-Policy") != TrustCSP || !strings.Contains(TrustCSP, "default-src 'none'") || strings.Contains(TrustCSP, "script-src") {
		t.Errorf("CSP: %q", a.h.Get("Content-Security-Policy"))
	}
	if strings.Contains(strings.ToLower(page), "<script") || strings.Contains(page, " style=") || strings.Contains(page, "<style") {
		t.Error("the page has a script or an inline style")
	}
	if a.h.Get("Cache-Control") != "public, max-age=300" || a.h.Get("ETag") == "" {
		t.Errorf("cache headers: %v", a.h)
	}
	if again := fetch(t, h, "/", "If-None-Match", a.h.Get("ETag")); again.code != http.StatusNotModified {
		t.Errorf("conditional request: %d", again.code)
	}
	root := fetch(t, h, "/ca/root/1.crt")
	rootCert, err := x509.ParseCertificate(root.body)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"root – Root CA", "issuing – Intermediate CA", rootCert.Subject.CommonName,
		"SHA-256 fingerprint (authoritative)", view.Fingerprint(colonHex(root.body)),
		"SHA-1 fingerprint (Windows certificate dialog comparison only)", view.Fingerprint(sha1ColonHex(root.body)),
		rootCert.NotAfter.UTC().Format("2006-01-02"),
		`href="/ca/root/1.crt" download="root.crt"`, `href="/ca/root/1.pem" download="root.pem"`,
		`href="/trust/root/1/machine.cmd"`, `href="/trust/root/1/user.cmd"`, `href="/ca/issuing/1.crt"`,
		`id="h-windows"`, `id="h-macos"`, `id="h-ios"`, `id="h-android"`, `id="h-linux"`, `id="h-firefox"`,
		"Certificate Trust Settings", "certutil -addstore -f Root root.crt", "plain HTTP",
		// One command per line (templ would join lines of plain text).
		"/usr/local/share/ca-certificates/root.crt\nsudo update-ca-certificates", "/etc/pki/ca-trust/source/anchors/\nsudo update-ca-trust",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if strings.Index(page, "root – Root CA") > strings.Index(page, "issuing – Intermediate CA") {
		t.Error("the intermediate comes before the root")
	}
	if strings.Contains(page, "/trust/issuing/") {
		t.Error("a Windows helper for an intermediate")
	}

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
	for _, m := range reClass.FindAllStringSubmatch(page, -1) {
		for _, c := range strings.Fields(m[1]) {
			if !defined[c] {
				t.Errorf("class %q is not in web/styles", c)
			}
		}
	}
	for _, m := range reRef.FindAllStringSubmatch(page, -1) {
		if r := fetch(t, h, m[1]); r.code != http.StatusOK {
			t.Errorf("%s: %d", m[1], r.code)
		} else if strings.HasSuffix(m[1], ".css") && r.h.Get("Content-Type") != "text/css; charset=utf-8" {
			t.Errorf("%s: %s", m[1], r.h.Get("Content-Type"))
		}
	}
	_ = v
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
	for _, p := range []string{"/trust/issuing/1/machine.cmd", "/trust/root/2/user.cmd", "/trust/root/1/admin.cmd", "/trust/root/0/user.cmd", "/trust/Root/1/user.cmd"} {
		if a := fetch(t, h, p); a.code != http.StatusNotFound {
			t.Errorf("%s: %d", p, a.code)
		}
	}

	// A renewed root: the older generation stays on the page while valid.
	v.Unseal(t)
	if _, err := v.Engine.RenewCA(t.Context(), ca.RenewRequest{Name: "root", Who: testinstance.Console}); err != nil {
		t.Fatal(err)
	}
	page := string(fetch(t, h, "/").body)
	if !strings.Contains(page, `href="/trust/root/2/machine.cmd"`) || !strings.Contains(page, `download="root-1.crt"`) || !strings.Contains(page, "older generation 1, still valid") {
		t.Errorf("after the root renewal:\n%s", page)
	}
	if strings.Index(page, `/ca/root/2.crt`) > strings.Index(page, `/ca/root/1.crt`) {
		t.Error("the older generation comes first")
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
	for _, p := range []string{"/", "/trust/root/1/user.cmd"} {
		if a := fetch(t, h, p); a.code != http.StatusNotFound {
			t.Errorf("off: %s answers %d", p, a.code)
		}
	}
	for _, p := range []string{"/ca/root/1.crt", "/ca/root/1.pem", "/crl/issuing/1.crl"} {
		if a := fetch(t, h, p); a.code != http.StatusOK {
			t.Errorf("off: %s answers %d – it must stay", p, a.code)
		}
	}
}
