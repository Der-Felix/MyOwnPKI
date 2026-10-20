package httpapi

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/auth"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/testutil"
)

func count(list []string, item string) int {
	n := 0
	for _, s := range list {
		if s == item {
			n++
		}
	}
	return n
}

// TestSignInWhileSealed (owner 2026-10-17): the browser must be able to sign
// in and unseal; reading works sealed, issuing is 503 sealed.
func TestSignInWhileSealed(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	admin := v.client("192.0.2.1")
	admin.signIn(t, "demo", v.demoPass)
	if r := admin.do(t, http.MethodGet, "/system/status", nil); r.Code != 200 || r.body["sealed"] != true || r.body["sealed_since"] == nil || r.body["demo"] != true {
		t.Fatalf("status: %d %v", r.Code, r.body)
	}
	if r := admin.do(t, http.MethodGet, "/cas", nil); r.Code != 200 || !strings.Contains(r.Body.String(), `"name":"issuing"`) {
		t.Errorf("CAs while sealed: %d %s", r.Code, r.Body.String())
	}
	if r := admin.do(t, http.MethodGet, "/certificates", nil); r.Code != 200 {
		t.Errorf("certificates while sealed: %d", r.Code)
	}
	issue := map[string]any{"ca_id": v.caIDs["issuing"], "preset": "server", "sans": map[string]any{"dns": []string{"nas.homelab.lan"}}, "key": map[string]string{"algorithm": "ecdsa-p256"}}
	if r := admin.do(t, http.MethodPost, "/certificates", issue); r.Code != 503 || r.problemType() != "sealed" {
		t.Errorf("issue while sealed: %d %s", r.Code, r.Body.String())
	}
	if r := admin.do(t, http.MethodPost, "/system/unseal", map[string]string{"passphrase": v.passphrase}); r.Code != 200 || r.body["sealed"] != false || r.body["sealed_since"] != nil {
		t.Fatalf("unseal: %d %s", r.Code, r.Body.String())
	}
	if r := admin.do(t, http.MethodPost, "/certificates", issue); r.Code != 201 {
		t.Errorf("issue after unseal: %d %s", r.Code, r.Body.String())
	}
}

// TestUnsealIsThrottledPerInstanceAndAddress: wrong passphrases slow down
// the instance and the address, every attempt is audited, a success resets
// the instance and its address – not the address that guessed.
func TestUnsealIsThrottledPerInstanceAndAddress(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	a, b := v.client("192.0.2.1"), v.client("198.51.100.7")
	a.signIn(t, "demo", v.demoPass)
	b.signIn(t, "demo", v.demoPass)
	unseal := func(c *client, pass string) *resp {
		t.Helper()
		return c.do(t, http.MethodPost, "/system/unseal", map[string]string{"passphrase": pass})
	}
	const wrong = "this is not the passphrase"
	for range 2 {
		if r := unseal(a, wrong); r.Code != 422 {
			t.Fatalf("wrong passphrase: %d", r.Code)
		}
	}
	if r := unseal(b, wrong); r.Code != 422 {
		t.Fatal(r.Code)
	}
	r := unseal(b, v.passphrase)
	if r.Code != 429 || r.Header().Get("Retry-After") != "60" {
		t.Fatalf("three failures on the instance: %d %q", r.Code, r.Header().Get("Retry-After"))
	}
	v.clk.Advance(61 * time.Second)
	if r := unseal(b, v.passphrase); r.Code != 200 {
		t.Fatalf("after the wait: %d %s", r.Code, r.Body.String())
	}
	if r := b.do(t, http.MethodPost, "/system/seal", nil); r.Code != 200 {
		t.Fatal(r.Code)
	}
	// a guessed twice: its third failure locks a, not the instance.
	if r := unseal(a, wrong); r.Code != 422 {
		t.Fatal(r.Code)
	}
	if r := unseal(a, v.passphrase); r.Code != 429 {
		t.Errorf("a after its third failure: %d", r.Code)
	}
	if r := unseal(b, v.passphrase); r.Code != 200 {
		t.Errorf("b must not suffer from a: %d %s", r.Code, r.Body.String())
	}
	got := v.audit(t, v.ia)
	// Only what happened over the API: init unsealed once itself.
	got = got[slices.Index(got, "user.login/success"):]
	if count(got, "system.unseal/failure") != 4 || count(got, "system.unseal/denied") != 2 || count(got, "system.unseal/success") != 2 {
		t.Errorf("audit: %v", got)
	}
}

// TestTwoStepSignIn: the pending session of /auth/login lasts 5 minutes and
// is good for /auth/totp only; the second factor gives a new session ID;
// TOTP failures count with password failures; the device cookie comes only
// with a complete sign-in.
func TestTwoStepSignIn(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.user(t, "alice", false, authz.Binding{Role: authz.Viewer})
	c := v.client("192.0.2.1")
	v.clk.Advance(30 * time.Second)
	r := c.do(t, http.MethodPost, "/auth/login", map[string]string{"username": "alice", "password": testPassword})
	if r.Code != 200 || r.body["second_factor_required"] != true || c.cookies[auth.DeviceCookieName] != nil {
		t.Fatalf("login: %d %s, device cookie %v", r.Code, r.Body.String(), c.cookies[auth.DeviceCookieName])
	}
	pending := c.cookies[auth.CookieName].Value
	for _, path := range []string{"/auth/session", "/system/status", "/cas"} {
		if r := c.do(t, http.MethodGet, path, nil); r.Code != 401 {
			t.Errorf("%s with the pending session: %d", path, r.Code)
		}
	}
	if r := c.do(t, http.MethodPost, "/auth/totp", map[string]string{"code": v.code("alice")}); r.Code != 200 {
		t.Fatalf("totp: %d %s", r.Code, r.Body.String())
	}
	full := c.cookies[auth.CookieName].Value
	if full == pending || c.cookies[auth.DeviceCookieName] == nil || c.cookies[auth.DeviceCookieName].MaxAge != int(auth.DeviceCookieTTL.Seconds()) {
		t.Errorf("new session ID %v, device cookie %+v", full != pending, c.cookies[auth.DeviceCookieName])
	}
	old := v.client("192.0.2.1")
	old.cookies[auth.CookieName] = &http.Cookie{Name: auth.CookieName, Value: pending, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
	if r := old.do(t, http.MethodPost, "/auth/totp", map[string]string{"code": v.code("alice")}); r.Code != 401 {
		t.Errorf("the pending session after the second factor: %d", r.Code)
	}

	// 5 minutes for the second factor.
	late := v.client("192.0.2.2")
	v.clk.Advance(30 * time.Second)
	late.do(t, http.MethodPost, "/auth/login", map[string]string{"username": "alice", "password": testPassword})
	v.clk.Advance(auth.PendingTTL)
	if r := late.do(t, http.MethodPost, "/auth/totp", map[string]string{"code": v.code("alice")}); r.Code != 401 {
		t.Errorf("second factor after 5 minutes: %d", r.Code)
	}

	// Wrong passwords and wrong codes share the lockout.
	for i := range auth.LockAfter - 1 {
		s := v.client(fmt.Sprintf("203.0.113.%d", i+1))
		if r := s.do(t, http.MethodPost, "/auth/login", map[string]string{"username": "alice", "password": "wrong password, long enough"}); r.Code != 401 {
			t.Fatalf("wrong password %d: %d", i, r.Code)
		}
	}
	s := v.client("203.0.113.99")
	s.do(t, http.MethodPost, "/auth/login", map[string]string{"username": "alice", "password": testPassword})
	// A wrong code with a valid pending session: 422 "type it again", not 401.
	if r := s.do(t, http.MethodPost, "/auth/totp", map[string]string{"code": "000000"}); r.Code != 422 || r.problemType() != "wrong-secret" {
		t.Fatalf("wrong code: %d %s", r.Code, r.problemType())
	}
	if r := v.client("203.0.113.100").do(t, http.MethodPost, "/auth/login", map[string]string{"username": "alice", "password": testPassword}); r.Code != 429 || r.Header().Get("Retry-After") == "" {
		t.Errorf("after %d password failures and one wrong code: %d", auth.LockAfter-1, r.Code)
	}
	// The browser that signed in before is still let in.
	v.clk.Advance(30 * time.Second)
	if r := c.do(t, http.MethodPost, "/auth/login", map[string]string{"username": "alice", "password": testPassword}); r.Code != 200 {
		t.Errorf("known device while locked: %d %s", r.Code, r.Body.String())
	}
}

// TestBodiesAreJSONOnly: writes need application/json (415 otherwise), take
// no unknown fields and no trailing data (400), and have a size limit (413).
func TestBodiesAreJSONOnly(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.unseal(t)
	c := v.client("192.0.2.1")
	login := `{"username":"demo","password":"x"}`
	for ct, want := range map[string]int{"": 415, "text/plain": 415, "application/x-www-form-urlencoded": 415, "application/json; charset=utf-8": 401} {
		if r := c.do(t, http.MethodPost, "/auth/login", login, "Content-Type", ct); r.Code != want {
			t.Errorf("login with %q: %d, want %d", ct, r.Code, want)
		}
	}
	c.signIn(t, "demo", v.demoPass)
	issue := `{"ca_id":"` + v.caIDs["issuing"] + `","preset":"server","sans":{"dns":["a.homelab.lan"]},"key":{"algorithm":"ecdsa-p256"}}`
	if r := c.do(t, http.MethodPost, "/certificates", issue, "Content-Type", "text/plain"); r.Code != 415 {
		t.Errorf("issue as text/plain: %d", r.Code)
	}
	for body, field := range map[string]string{
		strings.Replace(issue, `"preset"`, `"presett"`, 1): "/presett",
		issue + ` {}`:   "",
		`{"ca_id": 5}`:  "/ca_id",
		`{"ca_id": "x"`: "",
		``:              "",
	} {
		r := c.do(t, http.MethodPost, "/certificates", body, "Content-Type", "application/json")
		errs, _ := r.body["errors"].([]any)
		got := ""
		if len(errs) > 0 {
			got, _ = errs[0].(map[string]any)["field"].(string)
		}
		if r.Code != 400 || got != field {
			t.Errorf("%q: %d field %q, want 400 %q", body, r.Code, got, field)
		}
	}
	big := `{"ca_id":"` + strings.Repeat("a", MaxBody) + `"}`
	if r := c.do(t, http.MethodPost, "/certificates", big, "Content-Type", "application/json"); r.Code != 413 || r.problemType() != "too-large" {
		t.Errorf("too large: %d %s", r.Code, r.problemType())
	}
}

// TestSearchIsLiteral: % and _ are ordinary characters; at most 100 per page.
func TestSearchIsLiteral(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.unseal(t)
	c := v.client("192.0.2.1")
	c.signIn(t, "demo", v.demoPass)
	for _, n := range []string{"nas", "web", "mail"} {
		v.clk.Advance(time.Second)
		if r := c.do(t, http.MethodPost, "/certificates", map[string]any{"ca_id": v.caIDs["issuing"], "preset": "server", "sans": map[string]any{"dns": []string{n + ".homelab.lan"}}, "key": map[string]string{"algorithm": "ecdsa-p256"}}); r.Code != 201 {
			t.Fatal(r.Body.String())
		}
	}
	items := func(query string) int {
		t.Helper()
		r := c.do(t, http.MethodGet, "/certificates?"+query, nil)
		if r.Code != 200 {
			t.Fatalf("%s: %d %s", query, r.Code, r.Body.String())
		}
		list, _ := r.body["items"].([]any)
		return len(list)
	}
	for query, want := range map[string]int{"q=%25": 0, "q=_": 0, "q=n_s": 0, "q=%25.lan": 0, "q=NAS": 1, "q=homelab.lan": 3, "limit=100": 3, "limit=2": 2} {
		if got := items(query); got != want {
			t.Errorf("%s: %d, want %d", query, got, want)
		}
	}
	for _, query := range []string{"limit=0", "limit=101", "limit=x", "status=bogus", "expires_before=tomorrow", "cursor=a%25b"} {
		if r := c.do(t, http.MethodGet, "/certificates?"+query, nil); r.Code != 400 {
			t.Errorf("%s: %d", query, r.Code)
		}
	}
	r := c.do(t, http.MethodGet, "/certificates?limit=2", nil)
	next, _ := r.body["next_cursor"].(string)
	if items("limit=2&cursor="+next) != 1 {
		t.Error("second page")
	}
}

// TestCSRFAndCrossOrigin: a change with a session needs its token; a
// cross-origin browser request is refused before anything else.
func TestCSRFAndCrossOrigin(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	c := v.client("192.0.2.1")
	c.signIn(t, "demo", v.demoPass)
	if r := c.do(t, http.MethodPost, "/system/seal", nil, auth.CSRFHeader, ""); r.Code != 403 || !strings.Contains(r.Body.String(), "CSRF") {
		t.Errorf("without the token: %d %s", r.Code, r.Body.String())
	}
	if r := c.do(t, http.MethodPost, "/system/seal", nil, auth.CSRFHeader, "wrong"); r.Code != 403 {
		t.Errorf("wrong token: %d", r.Code)
	}
	if r := c.do(t, http.MethodPost, "/system/seal", nil, "Sec-Fetch-Site", "cross-site"); r.Code != 403 || r.Header().Get(requestIDHeader) == "" {
		t.Errorf("cross-site: %d", r.Code)
	}
	if r := c.do(t, http.MethodPost, "/auth/login", map[string]string{"username": "demo", "password": v.demoPass}, "Sec-Fetch-Site", "cross-site"); r.Code != 403 {
		t.Errorf("cross-site login: %d", r.Code)
	}
	if r := c.do(t, http.MethodGet, "/cas", nil, auth.CSRFHeader, ""); r.Code != 200 {
		t.Errorf("a read needs no token: %d", r.Code)
	}
	if r := c.do(t, http.MethodPost, "/system/seal", nil); r.Code != 200 {
		t.Errorf("with the token: %d", r.Code)
	}
}

// TestPassiveRoutesDontKeepTheSession: status and session polling don't move
// the idle timeout – the server decides by the route.
func TestPassiveRoutesDontKeepTheSession(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	c := v.client("192.0.2.1")
	c.signIn(t, "demo", v.demoPass)
	v.clk.Advance(20 * time.Minute)
	for _, path := range []string{"/system/status", "/auth/session"} {
		if r := c.do(t, http.MethodGet, path, nil, "X-Activity", "1"); r.Code != 200 {
			t.Fatalf("%s: %d", path, r.Code)
		}
	}
	v.clk.Advance(11 * time.Minute)
	if r := c.do(t, http.MethodGet, "/auth/session", nil); r.Code != 401 {
		t.Errorf("31 minutes of polling only: %d", r.Code)
	}
	c.signIn(t, "demo", v.demoPass)
	v.clk.Advance(20 * time.Minute)
	if r := c.do(t, http.MethodGet, "/cas", nil); r.Code != 200 {
		t.Fatal(r.Code)
	}
	v.clk.Advance(20 * time.Minute)
	if r := c.do(t, http.MethodGet, "/auth/session", nil); r.Code != 200 {
		t.Errorf("a real request keeps the session: %d", r.Code)
	}
}

// TestKeyDownloadOverTheAPI: an attachment, no-store, audited; sealed is 503.
func TestKeyDownloadOverTheAPI(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.unseal(t)
	c := v.client("192.0.2.1")
	c.signIn(t, "demo", v.demoPass)
	r := c.do(t, http.MethodPost, "/certificates", map[string]any{"ca_id": v.caIDs["issuing"], "preset": "server", "sans": map[string]any{"dns": []string{"nas.homelab.lan"}}, "key": map[string]string{"algorithm": "ecdsa-p256"}})
	id, _ := r.body["id"].(string)
	r = c.do(t, http.MethodPost, "/certificates/"+id+"/export", map[string]string{"format": "pkcs8-pem"})
	if r.Code != 200 || r.Header().Get("Content-Type") != "application/x-pem-file" || r.Header().Get("Cache-Control") != "no-store" ||
		r.Header().Get("Content-Disposition") != `attachment; filename="nas.homelab.lan.key.pem"` || !strings.HasPrefix(r.Body.String(), "-----BEGIN PRIVATE KEY-----") {
		t.Fatalf("export: %d %v\n%s", r.Code, r.Header(), r.Body.String())
	}
	if got := v.audit(t, v.ta); !slices.Contains(got, "key.download/success") {
		t.Errorf("tenant audit: %v", got)
	}
	if err := v.ring.Seal(t.Context(), console); err != nil {
		t.Fatal(err)
	}
	if r := c.do(t, http.MethodPost, "/certificates/"+id+"/export", map[string]string{"format": "pkcs8-pem"}); r.Code != 503 || r.problemType() != "sealed" {
		t.Errorf("sealed: %d %s", r.Code, r.Body.String())
	}
}

// TestChainsLeaveOutTheRoot (owner 2026-10-17): chain = the intermediates up
// to just below the root, fullchain = certificate + intermediates, like
// certbot. The root comes from GET /cas/{id}/certificate; with it as trust
// anchor and fullchain as the untrusted part, OpenSSL verifies the server.
func TestChainsLeaveOutTheRoot(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.unseal(t)
	c := v.client("192.0.2.1")
	c.signIn(t, "demo", v.demoPass)
	r := c.do(t, http.MethodPost, "/certificates", map[string]any{"ca_id": v.caIDs["issuing"], "preset": "server", "sans": map[string]any{"dns": []string{"nas.homelab.lan"}}, "key": map[string]string{"algorithm": "ecdsa-p256"}})
	id, _ := r.body["id"].(string)
	certs := func(path string) []*x509.Certificate {
		t.Helper()
		r := c.do(t, http.MethodGet, path, nil)
		if r.Code != 200 {
			t.Fatalf("%s: %d", path, r.Code)
		}
		var out []*x509.Certificate
		rest := r.Body.Bytes()
		for {
			var b *pem.Block
			if b, rest = pem.Decode(rest); b == nil {
				break
			}
			cert, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, cert)
		}
		return out
	}
	full := certs("/certificates/" + id + "/download/fullchain")
	chain := certs("/certificates/" + id + "/download/chain")
	root := certs("/cas/" + v.caIDs["root"] + "/certificate")
	if len(full) != 2 || full[0].Subject.CommonName != "nas.homelab.lan" || !strings.Contains(full[1].Subject.CommonName, "Issuing") {
		t.Fatalf("fullchain: %d certificates", len(full))
	}
	if len(chain) != 1 || !chain[0].Equal(full[1]) {
		t.Errorf("chain: %d certificates", len(chain))
	}
	for _, cert := range append(full, chain...) {
		if cert.Equal(root[0]) {
			t.Error("the root is in a chain")
		}
	}

	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	rootFile := write("root.pem", pemCerts(root[0].Raw))
	fullFile := write("fullchain.pem", c.do(t, http.MethodGet, "/certificates/"+id+"/download/fullchain", nil).Body.Bytes())
	out, err := exec.CommandContext(t.Context(), testutil.OpenSSL(t), "verify", "-x509_strict", "-purpose", "sslserver", "-CAfile", rootFile, "-untrusted", fullFile, fullFile).CombinedOutput() // #nosec G204 -- test binary and temp files
	if err != nil || !strings.Contains(string(out), ": OK") {
		t.Errorf("openssl verify: %v\n%s", err, out)
	}
}

// TestUncleanPathsAreNotFound: "//" or "/./" under /api/v1/ is a 404 problem,
// not the mux's redirect in text/html (owner 2026-10-17).
func TestUncleanPathsAreNotFound(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	c := v.client("192.0.2.1")
	for _, p := range []string{"/certificates//download/fullchain", "/cas/./x", "/system//status", "/"} {
		if r := c.do(t, http.MethodGet, p, nil); r.Code != 404 || r.Header().Get("Content-Type") != "application/problem+json" {
			t.Errorf("%s: %d %s", p, r.Code, r.Header().Get("Content-Type"))
		}
	}
}

// TestRootIssuesNoLeavesOverTheAPI: issuing from a root is a policy refusal
// (422) with the engine's reason (owner 2026-10-18).
func TestRootIssuesNoLeavesOverTheAPI(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.unseal(t)
	c := v.client("192.0.2.1")
	c.signIn(t, "demo", v.demoPass)
	r := c.do(t, http.MethodPost, "/certificates", map[string]any{"ca_id": v.caIDs["root"], "preset": "server", "sans": map[string]any{"dns": []string{"leaf-from-root.homelab.lan"}}, "key": map[string]string{"algorithm": "ecdsa-p256"}})
	if r.Code != 422 || r.problemType() != "policy-violation" || !strings.Contains(r.Body.String(), "a root CA only signs intermediate CAs and CRLs") {
		t.Errorf("issue from the root: %d %s", r.Code, r.Body.String())
	}
}

// TestExportFormatsAndKeyDeletion (step 18): PKCS#12 that OpenSSL opens with
// the password, a combined PEM, and "delete the key after the download" –
// afterwards the key is gone (409) and the audit log says so.
func TestExportFormatsAndKeyDeletion(t *testing.T) {
	t.Parallel()
	bin := testutil.OpenSSL(t)
	v := newEnv(t)
	v.unseal(t)
	c := v.client("192.0.2.1")
	c.signIn(t, "demo", v.demoPass)
	r := c.do(t, http.MethodPost, "/certificates", map[string]any{"ca_id": v.caIDs["issuing"], "preset": "server", "sans": map[string]any{"dns": []string{"nas.homelab.lan"}}, "key": map[string]string{"algorithm": "ecdsa-p256"}})
	id, _ := r.body["id"].(string)
	export := func(body map[string]any) *resp {
		t.Helper()
		return c.do(t, http.MethodPost, "/certificates/"+id+"/export", body)
	}
	if rs := export(map[string]any{"format": "pkcs12", "password": "short"}); rs.Code != 400 {
		t.Errorf("short PKCS#12 password: %d", rs.Code)
	}
	if rp := export(map[string]any{"format": "pkcs8-pem", "password": "a password that is not used"}); rp.Code != 400 {
		t.Errorf("password for PEM: %d", rp.Code)
	}
	r = export(map[string]any{"format": "combined-pem"})
	if r.Code != 200 || strings.Count(r.Body.String(), "BEGIN CERTIFICATE") != 2 || !strings.Contains(r.Body.String(), "BEGIN PRIVATE KEY") {
		t.Errorf("combined PEM: %d\n%s", r.Code, r.Body.String())
	}
	password := "a password for the p12 file"
	r = export(map[string]any{"format": "pkcs12", "password": password, "delete_key_after_download": true})
	if r.Code != 200 || r.Header().Get("Content-Type") != "application/x-pkcs12" || r.Header().Get("X-Key-Deleted") != "true" ||
		r.Header().Get("Content-Disposition") != `attachment; filename="nas.homelab.lan.p12"` {
		t.Fatalf("pkcs12: %d %v", r.Code, r.Header())
	}
	dir := t.TempDir()
	p12, pass := filepath.Join(dir, "nas.p12"), filepath.Join(dir, "pass")
	if err := os.WriteFile(p12, r.Body.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pass, []byte(password), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(t.Context(), bin, "pkcs12", "-in", p12, "-passin", "file:"+pass, "-nodes").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "BEGIN PRIVATE KEY") || !strings.Contains(string(out), "subject=CN=nas.homelab.lan") {
		t.Errorf("openssl pkcs12: %v\n%s", err, out)
	}
	if r := export(map[string]any{"format": "pkcs8-pem"}); r.Code != 409 || !strings.Contains(r.Body.String(), "deleted") {
		t.Errorf("export after the deletion: %d %s", r.Code, r.Body.String())
	}
	if r := c.do(t, http.MethodGet, "/certificates/"+id, nil); r.Code != 200 {
		t.Errorf("the certificate stays: %d", r.Code)
	}
	v.deliver(t)
	if got := v.audit(t, v.ta); !slices.Contains(got, "key.destroy/success") {
		t.Errorf("tenant audit: %v", got)
	}
}
