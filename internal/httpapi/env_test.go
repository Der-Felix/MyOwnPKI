package httpapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- TOTP (RFC 6238) is HMAC-SHA1 by design; test helper only
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/auth"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/ca/preset"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/setup"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
)

var console = keys.Who{Actor: audit.Actor{Type: audit.ActorUser, Name: "console:test"}, Principal: authz.Console()}

const testPassword = "a long password for the API test"

// env is an initialized instance (init --demo with the test CA) with the
// services wired like the server does, and the API on top. Requests go to
// the handler directly, so the client address can be chosen.
type env struct {
	api         *API
	auth        *auth.Service
	engine      *ca.Engine
	ring        *keys.Keyring
	clk         *clock.Fake
	sys, ia, ta *store.DB
	passphrase  string
	demoPass    string            // password of the init user "demo"
	secrets     map[string][]byte // TOTP secrets by user name
	caIDs       map[string]string // CA IDs by name
	logs        bytes.Buffer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	// Not on a whole second: the engine works in seconds, sessions in
	// milliseconds – the tests must see both (live run finding 2026-10-17).
	v := &env{clk: clock.NewFake(time.Now().UTC().Truncate(time.Second).Add(700 * time.Millisecond)), secrets: map[string][]byte{}, caIDs: map[string]string{}}
	res, err := setup.Run(t.Context(), setup.Options{
		Config: cfg, Mode: setup.Demo, WithCA: true, CABaseURL: "http://pki.homelab.lan", Hostname: "pki01", Clock: v.clk, Who: console,
	}, setup.NewLineInput(strings.NewReader(""), io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	demo, err := os.ReadFile(res.DemoSecretsFile)
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(demo), "\n") {
		line = strings.TrimRight(line, "\r")
		if p, ok := strings.CutPrefix(line, "unseal passphrase: "); ok {
			v.passphrase = p
		}
		if p, ok := strings.CutPrefix(line, "admin password: "); ok {
			v.demoPass = p
		}
		if s, ok := strings.CutPrefix(line, "secret:"); ok {
			v.secrets["demo"] = decodeSecret(t, s)
		}
	}

	l := store.Layout{DataDir: cfg.DataDir}
	open := func(path string) *store.DB {
		db, oerr := store.Open(t.Context(), path)
		if oerr != nil {
			t.Fatal(oerr)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	pkiPath, _ := l.TenantDB(store.DefaultTenant, store.KindPKI)
	taPath, _ := l.TenantDB(store.DefaultTenant, store.KindAudit)
	v.sys = open(l.SystemDB())
	v.ia = open(l.InstanceAuditDB())
	pki := open(pkiPath)
	v.ta = open(taPath)

	key, _, err := auth.LoadKey(cfg.AuthKeyFile())
	if err != nil {
		t.Fatal(err)
	}
	v.ring = keys.New(v.sys.Write, v.ia.Write, v.clk)
	presets, err := preset.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	v.engine = &ca.Engine{
		PKI: pki.Write, Audit: v.ta.Write, Scope: store.TenantScope(store.DefaultTenant), Keys: v.ring, Presets: presets, Clock: v.clk,
		ServerKeygen: func(context.Context) (bool, error) { return true, nil },
	}
	v.auth = auth.NewService(v.sys.Write, v.ia.Write, key, v.clk)
	v.auth.Hasher = auth.NewHasher(auth.Params{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}, 4, time.Second)
	v.api = New(Deps{
		Auth: v.auth, Engine: v.engine, Keys: v.ring, Presets: presets, Clock: v.clk,
		Log: slog.New(slog.NewJSONHandler(&v.logs, nil)), Version: "test", Demo: true,
	})
	cas, err := ca.ListCAs(t.Context(), pki.Read)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cas {
		v.caIDs[c.Name] = c.ID
	}
	return v
}

func decodeSecret(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", "")))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// user creates a user with roles in the default tenant.
func (v *env) user(t *testing.T, name string, instanceAdmin bool, roles ...authz.Binding) {
	t.Helper()
	for i := range roles {
		roles[i].Tenant = store.DefaultTenant
	}
	enr, err := v.auth.CreateUser(t.Context(), auth.NewUserRequest{Username: name, Password: testPassword, InstanceAdmin: instanceAdmin, Roles: roles, Who: console})
	if err != nil {
		t.Fatal(err)
	}
	v.secrets[name] = decodeSecret(t, enr.Secret)
}

// code is the TOTP code of name now (RFC 6238: HMAC-SHA1, 30 s, 6 digits).
func (v *env) code(name string) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(v.clk.Now().Unix()/30)) // #nosec G115 -- a time after 1970
	mac := hmac.New(sha1.New, v.secrets[name])
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", n%1_000_000)
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

// unseal unlocks the keyring as the console.
func (v *env) unseal(t *testing.T) {
	t.Helper()
	if err := v.ring.Unseal(t.Context(), []byte(v.passphrase), console); err != nil {
		t.Fatal(err)
	}
}

// audit lists "action/result" of an audit log (direct entries are there at
// once; outbox entries need a delivery, which these tests don't run).
func (v *env) audit(t *testing.T, db *store.DB) []string {
	t.Helper()
	rows, err := db.Read.QueryContext(t.Context(), `SELECT action, result FROM audit_entries ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var a, r string
		if err := rows.Scan(&a, &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, a+"/"+r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
