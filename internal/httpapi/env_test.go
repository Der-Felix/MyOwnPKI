package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/auth"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

var console = testinstance.Console

const testPassword = testinstance.Password

// env is an initialized instance (testinstance) with the API on top.
// Requests go to the handler directly, so the client address can be chosen.
type env struct {
	in          *testinstance.Instance
	api         *API
	auth        *auth.Service
	engine      *ca.Engine
	ring        *keys.Keyring
	clk         *clock.Fake
	sys, ia, ta *store.DB
	passphrase  string
	demoPass    string // password of the init user "demo"
	caIDs       map[string]string
	logs        bytes.Buffer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	in := testinstance.New(t, testinstance.Options{})
	v := &env{
		in: in, auth: in.Auth, engine: in.Engine, ring: in.Ring, clk: in.Clock,
		sys: in.SystemDB, ia: in.InstanceAudit, ta: in.TenantAudit,
		passphrase: in.Passphrase, demoPass: in.DemoPassword, caIDs: in.CAIDs,
	}
	v.api = New(Deps{
		Auth: in.Auth, Engine: in.Engine, Keys: in.Ring, Presets: in.Presets, Clock: in.Clock,
		Log: slog.New(slog.NewJSONHandler(&v.logs, nil)), Version: "test", Demo: true,
	})
	return v
}

func (v *env) user(t *testing.T, name string, instanceAdmin bool, roles ...authz.Binding) {
	t.Helper()
	v.in.User(t, name, instanceAdmin, roles...)
}

func (v *env) code(name string) string { return v.in.Code(name) }

func (v *env) unseal(t *testing.T) {
	t.Helper()
	v.in.Unseal(t)
}

func (v *env) deliver(t *testing.T) {
	t.Helper()
	v.in.Deliver(t)
}

func (v *env) audit(t *testing.T, db *store.DB) []string {
	t.Helper()
	return testinstance.Audit(t, db)
}

// client is one browser: its cookies and address.
type client struct {
	v       *env
	ip      string
	cookies map[string]*http.Cookie
	csrf    string
}

func (v *env) client(ip string) *client {
	return &client{v: v, ip: ip, cookies: map[string]*http.Cookie{}}
}

// resp is a recorded answer.
type resp struct {
	*httptest.ResponseRecorder
	body map[string]any
}

func (r *resp) problemType() string {
	s, _ := r.body["type"].(string)
	return strings.TrimPrefix(s, problemPrefix)
}

// do sends a request; body nil = none, a string is sent as is, anything else
// as JSON. The CSRF token of the last session answer goes along.
func (c *client) do(t *testing.T, method, path string, body any, header ...string) *resp {
	t.Helper()
	var rd io.Reader
	isJSON := false
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		data, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		rd, isJSON = bytes.NewReader(data), true
	}
	req := httptest.NewRequestWithContext(t.Context(), method, "https://pki.homelab.lan"+BasePath+path, rd)
	req.RemoteAddr = c.ip + ":50000"
	if isJSON {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.csrf != "" {
		req.Header.Set(auth.CSRFHeader, c.csrf)
	}
	for i := 0; i+1 < len(header); i += 2 {
		if header[i+1] == "" {
			req.Header.Del(header[i])
		} else {
			req.Header.Set(header[i], header[i+1])
		}
	}
	for _, ck := range c.cookies {
		req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	rec := httptest.NewRecorder()
	c.v.api.ServeHTTP(rec, req)
	for _, ck := range rec.Result().Cookies() {
		if ck.MaxAge < 0 {
			delete(c.cookies, ck.Name)
		} else {
			c.cookies[ck.Name] = ck
		}
	}
	out := &resp{ResponseRecorder: rec}
	if ct := rec.Header().Get("Content-Type"); strings.Contains(ct, "json") {
		var m any
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatalf("%s %s: answer is no JSON: %v\n%s", method, path, err, rec.Body.String())
		}
		out.body, _ = m.(map[string]any)
	}
	if tok, ok := out.body["csrf_token"].(string); ok {
		c.csrf = tok
	}
	return out
}

// signIn signs name in fully: password, then the TOTP code. The clock moves
// to the next TOTP step first – a code works once.
func (c *client) signIn(t *testing.T, name, password string) {
	t.Helper()
	c.v.clk.Advance(30 * time.Second)
	if r := c.do(t, http.MethodPost, "/auth/login", map[string]string{"username": name, "password": password}); r.Code != http.StatusOK {
		t.Fatalf("login %s: %d %s", name, r.Code, r.Body.String())
	}
	if r := c.do(t, http.MethodPost, "/auth/totp", map[string]string{"code": c.v.code(name)}); r.Code != http.StatusOK {
		t.Fatalf("totp %s: %d %s", name, r.Code, r.Body.String())
	}
}

// stepUp confirms with a fresh code.
func (c *client) stepUp(t *testing.T, name string) {
	t.Helper()
	c.v.clk.Advance(30 * time.Second)
	if r := c.do(t, http.MethodPost, "/auth/step-up", map[string]string{"code": c.v.code(name)}); r.Code != http.StatusOK {
		t.Fatalf("step-up %s: %d %s", name, r.Code, r.Body.String())
	}
}
