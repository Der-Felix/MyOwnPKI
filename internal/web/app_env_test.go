package web

import (
	"bytes"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/auth"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// uiEnv is an initialized instance with the real UI on top. Requests go to
// the handler directly, so the client address can be chosen.
type uiEnv struct {
	*testinstance.Instance
	h    http.Handler
	logs bytes.Buffer
}

func newUIEnv(t *testing.T) *uiEnv {
	t.Helper()
	v := &uiEnv{Instance: testinstance.New(t, testinstance.Options{})}
	h, err := NewHandler(Options{Logger: slog.New(slog.NewJSONHandler(&v.logs, nil)), App: &AppDeps{
		Auth: v.Auth, Engine: v.Engine, Keys: v.Ring, Presets: v.Presets, Clock: v.Clock, Demo: true, Tenant: store.DefaultTenant,
		Settings: &tenant.Store{DB: v.SystemDB.Write, Clock: v.Clock}, TenantAudit: v.TenantAudit.Read, InstanceAudit: v.InstanceAudit.Read,
	}})
	if err != nil {
		t.Fatal(err)
	}
	v.h = h
	return v
}

// browser keeps the cookies of one client.
type browser struct {
	v       *uiEnv
	ip      string
	cookies map[string]string
}

func (v *uiEnv) browser(ip string) *browser {
	return &browser{v: v, ip: ip, cookies: map[string]string{}}
}

// page is a recorded answer.
type page struct {
	*httptest.ResponseRecorder
}

func (p page) html() string     { return p.Body.String() }
func (p page) location() string { return p.Header().Get("Location") }

func (b *browser) send(t *testing.T, req *http.Request) page {
	t.Helper()
	req.RemoteAddr = b.ip + ":50000"
	for name, value := range b.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	rec := httptest.NewRecorder()
	b.v.h.ServeHTTP(rec, req)
	for _, ck := range rec.Result().Cookies() {
		if ck.MaxAge < 0 || ck.Value == "" {
			delete(b.cookies, ck.Name)
		} else {
			b.cookies[ck.Name] = ck.Value
		}
	}
	return page{rec}
}

func (b *browser) get(t *testing.T, target string) page {
	t.Helper()
	return b.send(t, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://pki.homelab.lan"+target, nil))
}

var reCSRFField = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// csrf reads the token of the session from a signed-in page.
func (b *browser) csrf(t *testing.T) string {
	t.Helper()
	m := reCSRFField.FindStringSubmatch(b.get(t, "/admin/appearance").html())
	if m == nil {
		t.Fatal("no CSRF token on the page")
	}
	return m[1]
}

// post sends a urlencoded form.
func (b *browser) post(t *testing.T, target string, form url.Values) page {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://pki.homelab.lan"+target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return b.send(t, req)
}

// postFile sends a multipart form with one file.
func (b *browser) postFile(t *testing.T, target string, form url.Values, field, name string, data []byte) page {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, vs := range form {
		for _, v := range vs {
			_ = mw.WriteField(k, v)
		}
	}
	fw, err := mw.CreateFormFile(field, name)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(fw, bytes.NewReader(data))
	_ = mw.Close()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://pki.homelab.lan"+target, &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return b.send(t, req)
}

// signIn signs name in fully through the pages and returns where it landed.
func (b *browser) signIn(t *testing.T, name, password string) string {
	t.Helper()
	b.v.Clock.Advance(30 * time.Second)
	r := b.post(t, "/login", url.Values{"username": {name}, "password": {password}})
	if r.Code != http.StatusSeeOther || !strings.HasPrefix(r.location(), "/login/code") {
		t.Fatalf("login %s: %d %q", name, r.Code, r.location())
	}
	r = b.post(t, "/login/code", url.Values{"code": {b.v.Code(name)}})
	if r.Code != http.StatusSeeOther || b.cookies[auth.CookieName] == "" {
		t.Fatalf("code %s: %d %q", name, r.Code, r.location())
	}
	return r.location()
}

var reMessage = regexp.MustCompile(`(?s)<div class="msg msg-[a-z]+"[^>]*>.*?</div>`)

// messages are the message bars of a page.
func messages(html string) []string { return reMessage.FindAllString(html, -1) }
