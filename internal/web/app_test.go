package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/auth"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// TestSignInUnsealAndPRG: without a session to the sign-in page and back;
// every POST answers 303 (Post/Redirect/Get); a sealed server sends the
// instance admin to /unseal, whose form has no user name field and
// autocomplete off (owner 2026-10-17).
func TestSignInUnsealAndPRG(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	b := v.browser("192.0.2.1")
	if r := b.get(t, "/certificates?status=valid"); r.Code != http.StatusSeeOther || r.location() != "/login?next=%2Fcertificates%3Fstatus%3Dvalid" {
		t.Fatalf("no session: %d %q", r.Code, r.location())
	}
	login := b.get(t, "/login?next=%2Fcertificates")
	for _, leak := range []string{"DEMO", "sealed", "Sealed", "version", "demo"} {
		if strings.Contains(login.html(), leak) {
			t.Errorf("the sign-in page tells %q", leak)
		}
	}
	v.Clock.Advance(30 * time.Second)
	r := b.post(t, "/login", url.Values{"username": {"demo"}, "password": {v.DemoPassword}, "next": {"/certificates"}})
	if r.Code != http.StatusSeeOther || r.location() != "/login/code?next=%2Fcertificates" || b.cookies[auth.DeviceCookieName] != "" {
		t.Fatalf("password: %d %q", r.Code, r.location())
	}
	if rr := b.post(t, "/login/code", url.Values{"code": {"000000"}, "next": {"/certificates"}}); rr.Code != http.StatusSeeOther || rr.location() != "/login/code?next=%2Fcertificates" {
		t.Errorf("wrong code: %d %q", rr.Code, rr.location())
	}
	if msgs := messages(b.get(t, "/login/code?next=%2Fcertificates").html()); len(msgs) != 1 || !strings.Contains(msgs[0], "Wrong or already used code") {
		t.Errorf("wrong code message: %v", msgs)
	}
	r = b.post(t, "/login/code", url.Values{"code": {v.Code("demo")}, "next": {"/certificates"}})
	if r.Code != http.StatusSeeOther || r.location() != "/unseal?next=%2Fcertificates" || b.cookies[auth.DeviceCookieName] == "" {
		t.Fatalf("code while sealed: %d %q", r.Code, r.location())
	}

	unseal := b.get(t, "/unseal?next=%2Fcertificates").html()
	form := regexp.MustCompile(`(?s)<form class="form" action="/unseal" method="post" autocomplete="off">.*?</form>`).FindString(unseal)
	if form == "" || !strings.Contains(form, `type="password" name="passphrase" autocomplete="off"`) || strings.Contains(form, "username") || strings.Contains(form, `type="text"`) {
		t.Errorf("unseal form:\n%s", form)
	}
	token := b.csrf(t)
	if r := b.post(t, "/unseal", url.Values{"passphrase": {"not the passphrase"}, "next": {"/certificates"}, "csrf_token": {token}}); r.Code != http.StatusSeeOther || r.location() != "/unseal?next=%2Fcertificates" {
		t.Errorf("wrong passphrase: %d %q", r.Code, r.location())
	}
	if !strings.Contains(b.get(t, "/unseal?next=%2Fcertificates").html(), "Wrong passphrase.") {
		t.Error("no message after the wrong passphrase")
	}
	if r := b.post(t, "/unseal", url.Values{"passphrase": {v.Passphrase}, "next": {"/certificates"}, "csrf_token": {token}}); r.Code != http.StatusSeeOther || r.location() != "/certificates" || v.Ring.Status().Sealed {
		t.Fatalf("unseal: %d %q", r.Code, r.location())
	}
	if !strings.Contains(b.get(t, "/certificates").html(), "Unsealed – signing and CRL renewal are on.") {
		t.Error("no message after the unseal")
	}

	// Seal and sign out are POST forms with the token; each ends in 303.
	home := b.get(t, "/").html()
	for _, f := range []string{`<form action="/seal" method="post"><input type="hidden" name="csrf_token" value="` + token,
		`<form action="/logout" method="post"><input type="hidden" name="csrf_token" value="` + token} {
		if !strings.Contains(home, f) {
			t.Errorf("user menu lacks %s", f)
		}
	}
	if r := b.post(t, "/seal", url.Values{"csrf_token": {token}}); r.Code != http.StatusSeeOther || r.location() != "/" || !v.Ring.Status().Sealed {
		t.Errorf("seal: %d %q", r.Code, r.location())
	}
	if r := b.post(t, "/logout", url.Values{"csrf_token": {token}}); r.Code != http.StatusSeeOther || r.location() != "/login" {
		t.Errorf("logout: %d %q", r.Code, r.location())
	}
	if r := b.get(t, "/"); r.Code != http.StatusSeeOther {
		t.Errorf("after sign-out: %d", r.Code)
	}
}

// TestSignInFailureLooksTheSame: an invented name and a real one that
// strangers locked get the same message (owner 2026-10-17).
func TestSignInFailureLooksTheSame(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.User(t, "alice", false, authz.Binding{Role: authz.Viewer})
	for i := range auth.LockAfter {
		_, _ = v.Auth.Login(t.Context(), "alice", "wrong password, long enough", fmt.Sprintf("203.0.113.%d", i+1))
	}
	answer := func(ip, name, password string) []string {
		b := v.browser(ip)
		r := b.post(t, "/login", url.Values{"username": {name}, "password": {password}})
		if r.Code != http.StatusSeeOther || r.location() != "/login" {
			t.Fatalf("%s: %d %q", name, r.Code, r.location())
		}
		return messages(b.get(t, "/login").html())
	}
	locked := answer("198.51.100.1", "alice", testinstance.Password)
	invented := answer("198.51.100.2", "nobody-by-this-name", testinstance.Password)
	wrong := answer("198.51.100.3", "demo", "wrong password, long enough")
	if len(locked) != 1 || !slices.Equal(locked, invented) || !slices.Equal(locked, wrong) || strings.Contains(locked[0], "minute") && strings.ContainsAny(locked[0], "0123456789") {
		t.Errorf("locked %q\ninvented %q\nwrong %q", locked, invented, wrong)
	}
}

// TestNextIsALocalPathOnly: exactly the owner's cases, then some more.
func TestNextIsALocalPathOnly(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{
		"//evil.example", `/\evil.example`, "/%2F%2Fevil.example", "https://evil.example", "javascript:alert(1)",
		"/ok\nx", "/ok\rSet-Cookie: x=1", "/ok\x00", "/ok\x7f", "/%0d%0aSet-Cookie:x", "/%5Cevil.example", "\t/x",
		"evil.example", "", "/login", "/login/code?next=//evil.example", "///evil.example", "/./%2F/evil", "/a/..//evil", "/a/%2E%2E/x", "/x/.",
	} {
		if got := safeNext(bad); got != "/" {
			t.Errorf("safeNext(%q) = %q, want /", bad, got)
		}
	}
	for _, good := range []string{"/certificates?status=valid&q=nas", "/authorities/ca_01abc", "/", "/certificates/crt_1/chain"} {
		if got := safeNext(good); got != good {
			t.Errorf("safeNext(%q) = %q", good, got)
		}
	}
	// And through the sign-in: the code step goes home.
	v := newUIEnv(t)
	v.Unseal(t)
	b := v.browser("192.0.2.1")
	v.Clock.Advance(30 * time.Second)
	b.post(t, "/login", url.Values{"username": {"demo"}, "password": {v.DemoPassword}, "next": {"//evil.example"}})
	if r := b.post(t, "/login/code", url.Values{"code": {v.Code("demo")}, "next": {"/%2F%2Fevil.example"}}); r.location() != "/" {
		t.Errorf("after the code: %q", r.location())
	}
}

func testCSRWith(t *testing.T, cn string, dns []string, ips []string) (pemText string, der []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: dns}
	for _, ip := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	der, err = x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), der
}

// TestIssueWithACSR: the CSR's names fill the form; what the form says is
// issued; the answer is 303 to the new certificate; uploads take PEM and
// DER; a broken CSR or a bad signature is a message at the field.
func TestIssueWithACSR(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.Unseal(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	token := b.csrf(t)
	csrPEM, csrDER := testCSRWith(t, "nas.homelab.lan", []string{"nas.homelab.lan", "files.homelab.lan"}, []string{"10.0.0.5"})
	base := url.Values{"csrf_token": {token}, "preset": {"server"}, "ca": {v.CAIDs["issuing"]}, "keymode": {"csr"}, "alg": {"ecdsa-p256"}, "days": {"90"}}
	step := func(from int, goTo string, extra url.Values) url.Values {
		f := url.Values{}
		for k, vs := range base {
			f[k] = vs
		}
		f.Set("from", fmt.Sprint(from))
		f.Set("go", goTo)
		for k, vs := range extra {
			f[k] = vs
		}
		return f
	}

	// Paste: the names step comes filled from the CSR.
	r := b.post(t, "/certificates/new", step(2, "next", url.Values{"csr": {csrPEM}}))
	html := r.html()
	if r.Code != http.StatusOK || !strings.Contains(html, `aria-current="step">Names`) || !strings.Contains(html, "nas.homelab.lan\nfiles.homelab.lan</textarea>") ||
		!strings.Contains(html, ">10.0.0.5</textarea>") || !strings.Contains(html, `name="cn" value="nas.homelab.lan"`) {
		t.Fatalf("prefill: %d\n%s", r.Code, html)
	}
	prefilled := regexp.MustCompile(`name="prefilled" value="([0-9a-f]+)"`).FindStringSubmatch(html)
	if prefilled == nil {
		t.Fatal("no prefill mark")
	}

	// Upload as DER and as PEM: the same prefill.
	for name, data := range map[string][]byte{"nas.der": csrDER, "nas.csr": []byte(csrPEM)} {
		rr := b.postFile(t, "/certificates/new", step(2, "next", nil), "csrfile", name, data)
		if rr.Code != http.StatusOK || !strings.Contains(rr.html(), "nas.homelab.lan\nfiles.homelab.lan</textarea>") {
			t.Errorf("upload %s: %d", name, rr.Code)
		}
	}
	// Broken CSR and bad signature: a message at the field, no error page.
	broken := strings.Replace(csrPEM, "MI", "XX", 1)
	tampered := []byte(strings.Clone(string(csrDER)))
	tampered[len(tampered)-5] ^= 0x55
	for name, extra := range map[string]url.Values{
		"broken":   {"csr": {broken}},
		"not PEM":  {"csr": {"hello"}},
		"bad sign": {"csr": {string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: tampered}))}},
	} {
		rr := b.post(t, "/certificates/new", step(2, "next", extra))
		if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.html(), `<div class="err" id="csr-err">`) {
			t.Errorf("%s: %d", name, rr.Code)
		}
	}
	if rr := b.postFile(t, "/certificates/new", step(2, "next", nil), "csrfile", "x.der", []byte("not a request")); rr.Code != http.StatusUnprocessableEntity ||
		!strings.Contains(rr.html(), "neither a PEM nor a DER certificate request") {
		t.Errorf("bad upload: %d", rr.Code)
	}

	// The user changes the names: the form wins over the CSR.
	names := url.Values{"csr": {csrPEM}, "prefilled": {prefilled[1]}, "cn": {"web.homelab.lan"}, "dns": {"web.homelab.lan"}, "ip": {""}}
	if rr := b.post(t, "/certificates/new", step(3, "next", names)); rr.Code != http.StatusOK || !strings.Contains(rr.html(), `aria-current="step">Review`) {
		t.Fatalf("review: %d", rr.Code)
	}
	r = b.post(t, "/certificates/new", step(4, "issue", names))
	if r.Code != http.StatusSeeOther || !regexp.MustCompile(`^/certificates/crt_[0-9a-z]+$`).MatchString(r.location()) {
		t.Fatalf("issue: %d %q\n%s", r.Code, r.location(), r.html())
	}
	detail := b.get(t, r.location()).html()
	if !strings.Contains(detail, "Certificate issued, serial number") || !strings.Contains(detail, "web.homelab.lan") {
		t.Error("detail after issuing")
	}
	info, err := v.Engine.Certificate(t.Context(), testinstance.Console, strings.TrimPrefix(r.location(), "/certificates/"))
	if err != nil || !slices.Equal(info.DNSNames, []string{"web.homelab.lan"}) || len(info.IPs) != 0 {
		t.Errorf("issued names %v %v %v – the CSR's names must not get in", info.DNSNames, info.IPs, err)
	}
}

// TestKeyDownloadNeedsAFreshCode: without a fresh second factor the key
// download goes to /step-up and back to the certificate – it doesn't start
// by itself; afterwards the download is the file itself.
func TestKeyDownloadNeedsAFreshCode(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.Unseal(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	issued, err := v.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}, Who: testinstance.Console})
	if err != nil {
		t.Fatal(err)
	}
	detail := "/certificates/" + issued.ID
	page := b.get(t, detail).html()
	if !strings.Contains(page, `href="`+detail+`/export"`) || !strings.Contains(page, "Download fullchain") {
		t.Fatalf("detail actions:\n%s", page)
	}
	token := b.csrf(t)
	v.Clock.Advance(authz.StepUpWindow + time.Second)
	r := b.post(t, detail+"/key", url.Values{"csrf_token": {token}})
	if r.Code != http.StatusSeeOther || r.location() != "/step-up?next=%2Fcertificates%2F"+issued.ID {
		t.Fatalf("without a fresh code: %d %q", r.Code, r.location())
	}
	v.Clock.Advance(30 * time.Second)
	if rr := b.post(t, "/step-up", url.Values{"csrf_token": {token}, "code": {v.Code("demo")}, "next": {detail}}); rr.Code != http.StatusSeeOther || rr.location() != detail {
		t.Fatalf("step-up: %d %q", rr.Code, rr.location())
	}
	r = b.post(t, detail+"/key", url.Values{"csrf_token": {token}})
	if r.Code != http.StatusOK || r.Header().Get("Content-Type") != "application/x-pem-file" || r.Header().Get("Cache-Control") != "no-store" ||
		r.Header().Get("Content-Disposition") != `attachment; filename="nas.homelab.lan.key.pem"` || !strings.HasPrefix(r.html(), "-----BEGIN PRIVATE KEY-----") {
		t.Errorf("download: %d %v", r.Code, r.Header())
	}
	full := b.get(t, detail+"/download/fullchain")
	if full.Code != http.StatusOK || strings.Count(full.html(), "BEGIN CERTIFICATE") != 2 {
		t.Errorf("fullchain: %d, %d certificates", full.Code, strings.Count(full.html(), "BEGIN CERTIFICATE"))
	}
}

// TestFormsNeedTheToken: a POST without the session's CSRF token is refused.
func TestFormsNeedTheToken(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	for _, path := range []string{"/logout", "/seal", "/unseal", "/admin/appearance", "/certificates/new"} {
		if r := b.post(t, path, url.Values{"csrf_token": {"wrong"}}); r.Code != http.StatusForbidden {
			t.Errorf("%s with a wrong token: %d", path, r.Code)
		}
	}
	if r := b.get(t, "/"); r.Code != http.StatusOK {
		t.Error("the session must still be there")
	}
}

// TestRolesShapeThePages: no read access is 404; read access without the
// role offers no command, and the server refuses it anyway.
func TestRolesShapeThePages(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.Unseal(t)
	v.User(t, "viewer", false, authz.Binding{Role: authz.Viewer})
	v.User(t, "rootview", false, authz.Binding{CA: "root", Role: authz.Viewer})
	issued, err := v.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}, Who: testinstance.Console})
	if err != nil {
		t.Fatal(err)
	}
	rv := v.browser("192.0.2.2")
	rv.signIn(t, "rootview", testinstance.Password)
	for _, path := range []string{"/authorities/" + v.CAIDs["issuing"], "/certificates/" + issued.ID, "/certificates/" + issued.ID + "/download/pem"} {
		if r := rv.get(t, path); r.Code != http.StatusNotFound {
			t.Errorf("%s without read access: %d", path, r.Code)
		}
	}
	if r := rv.get(t, "/authorities/"+v.CAIDs["root"]); r.Code != http.StatusOK || strings.Contains(r.html(), `href="/certificates/new?ca=`) {
		t.Errorf("root for its viewer: %d", r.Code)
	}
	vw := v.browser("192.0.2.3")
	vw.signIn(t, "viewer", testinstance.Password)
	page := vw.get(t, "/certificates/"+issued.ID).html()
	if strings.Contains(page, "Download private key") || !strings.Contains(page, "Download fullchain") {
		t.Error("a viewer must see downloads but no key download")
	}
	if strings.Contains(vw.get(t, "/certificates").html(), "New certificate") || strings.Contains(vw.get(t, "/").html(), "Seal now") {
		t.Error("a viewer must not be offered issuing or sealing")
	}
	token := vw.csrf(t)
	if r := vw.post(t, "/certificates/"+issued.ID+"/key", url.Values{"csrf_token": {token}}); r.Code != http.StatusForbidden {
		t.Errorf("key download as a viewer: %d", r.Code)
	}
	if r := vw.get(t, "/certificates/new"); r.Code != http.StatusForbidden {
		t.Errorf("issue page as a viewer: %d", r.Code)
	}
	if r := vw.get(t, "/unseal"); r.Code != http.StatusForbidden {
		t.Errorf("unseal page as a viewer: %d", r.Code)
	}
}

// TestDashboardShowsRealNumbers: counts and "needs attention".
func TestDashboardShowsRealNumbers(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.Unseal(t)
	for _, n := range []string{"a", "b"} {
		if _, err := v.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{n + ".homelab.lan"}, Who: testinstance.Console}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := v.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{"soon.homelab.lan"}, ValidityDays: 10, Who: testinstance.Console}); err != nil {
		t.Fatal(err)
	}
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	html := b.get(t, "/").html()
	for _, want := range []string{`>3</`, "Needs attention", "Nothing needs attention", "soon.homelab.lan", "DEMO instance"} {
		if !strings.Contains(html, want) {
			t.Errorf("dashboard lacks %q", want)
		}
	}
	// Four days later the 7-day CRL of the intermediate needs attention.
	v.Clock.Advance(4 * 24 * time.Hour)
	if err := v.Ring.Seal(t.Context(), testinstance.Console); err != nil {
		t.Fatal(err)
	}
	b2 := v.browser("192.0.2.9")
	b2.signIn(t, "demo", v.DemoPassword)
	if html := b2.get(t, "/").html(); !strings.Contains(html, "CRL of issuing/1") || !strings.Contains(html, "Signing is off") {
		t.Error("CRL attention or the sealed notice missing")
	}
}

var (
	realOnce sync.Once
	realHTML map[string]string
)

// realPages renders every page of the real UI once – sign-in pages, sealed
// and unsealed pages, each wizard step and an error state – for the HTML
// rules of server_test.go.
func realPages(t *testing.T) map[string]string {
	t.Helper()
	realOnce.Do(func() {
		out := map[string]string{}
		v := newUIEnv(t)
		anon := v.browser("192.0.2.50")
		out["real /login"] = anon.get(t, "/login").html()
		anon.cookies[auth.CookieName] = "pending"
		out["real /login/code"] = anon.get(t, "/login/code").html()
		b := v.browser("192.0.2.1")
		b.signIn(t, "demo", v.DemoPassword)
		out["real /unseal"] = b.get(t, "/unseal").html()
		v.Unseal(t)
		issued, err := v.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{"nas.homelab.lan"}, Who: testinstance.Console})
		if err != nil {
			t.Fatal(err)
		}
		issuingCA := "issuing"
		dom, err := v.Engine.CreateDomain(t.Context(), ca.DomainRequest{Name: "homelab.lan", DomainSettings: ca.DomainSettings{CA: &issuingCA}, Who: testinstance.Console})
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{
			"/domains", "/domains/new", "/domains/" + dom.ID,
			"/", "/certificates", "/certificates?status=expiring&q=nas", "/certificates/" + issued.ID,
			"/certificates/" + issued.ID + "/extensions", "/certificates/" + issued.ID + "/chain", "/certificates/new",
			"/authorities", "/authorities/" + v.CAIDs["issuing"], "/authorities/" + v.CAIDs["root"],
			"/admin/appearance", "/design", "/step-up?next=%2F", "/certificates/crt_none",
			"/certificates/" + issued.ID + "/revoke", "/certificates/" + issued.ID + "/renew", "/certificates/" + issued.ID + "/export",
			"/authorities/new", "/authorities/import", "/authorities/" + v.CAIDs["issuing"] + "/manage", "/authorities/" + v.CAIDs["root"] + "/manage",
			"/presets", "/presets/server", "/admin/users", "/admin/users/new", "/admin/users/" + v.UserID(t, "demo"), "/admin/settings",
			"/admin/audit", "/admin/audit?scope=instance", "/admin/import", "/account",
		} {
			out["real "+p] = b.get(t, p).html()
		}
		token := b.csrf(t)
		csrPEM, _ := testCSRWith(t, "web.homelab.lan", []string{"web.homelab.lan"}, nil)
		form := func(from int, extra url.Values) url.Values {
			f := url.Values{"csrf_token": {token}, "from": {fmt.Sprint(from)}, "go": {"next"}, "preset": {"server"}, "ca": {v.CAIDs["issuing"]},
				"keymode": {"csr"}, "alg": {"ecdsa-p256"}, "days": {"90"}, "csr": {csrPEM}, "cn": {"web.homelab.lan"}, "dns": {"web.homelab.lan"}}
			for k, vs := range extra {
				f[k] = vs
			}
			return f
		}
		out["real wizard key"] = b.post(t, "/certificates/new", form(1, nil)).html()
		out["real wizard names"] = b.post(t, "/certificates/new", form(2, nil)).html()
		out["real wizard review"] = b.post(t, "/certificates/new", form(3, nil)).html()
		out["real wizard error"] = b.post(t, "/certificates/new", form(2, url.Values{"csr": {"hello"}})).html()
		out["real wizard refused"] = b.post(t, "/certificates/new", form(4, url.Values{"go": {"issue"}, "dns": {"*.lan"}})).html()
		out["real new user"] = b.post(t, "/admin/users/new", url.Values{"csrf_token": {token}, "username": {"carol"}, "password": {"a long password for the new colleague"}, "role": {"viewer"}}).html()
		out["real new token"] = b.post(t, "/account/tokens", url.Values{"csrf_token": {token}, "name": {"ci"}, "role": {"viewer"}, "days": {"30"}}).html()
		out["real new codes"] = b.post(t, "/account/recovery-codes", url.Values{"csrf_token": {token}, "password": {v.DemoPassword}}).html()
		for page, want := range map[string]string{
			"real wizard refused": "the policy refused the request", "real wizard error": `id="csr-err"`,
			"real wizard names": `aria-current="step">Names`, "real /certificates/crt_none": "There is no such object",
			"real /unseal": "Sealed since", "real /login/code": `autocomplete="one-time-code"`,
			"real new user": "otpauth://", "real new token": "mop_", "real new codes": "Shown only now", "real /admin/audit?scope=instance": "user.login",
			"real /account": "API tokens", "real /presets/server": "serverAuth",
		} {
			if !strings.Contains(out[page], want) {
				t.Errorf("%s lacks %q", page, want)
			}
		}
		realHTML = out
	})
	if realHTML == nil {
		t.Fatal("the real pages could not be rendered")
	}
	return realHTML
}

// TestIssueKeepsTheFormNames: the final "issue" checks every step again, but
// never fills the names from the CSR again – also when the prefill mark is
// missing or changed, the form's names are issued.
func TestIssueKeepsTheFormNames(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.Unseal(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	csrPEM, _ := testCSRWith(t, "nas.homelab.lan", []string{"nas.homelab.lan"}, nil)
	r := b.post(t, "/certificates/new", url.Values{
		"csrf_token": {b.csrf(t)}, "from": {"4"}, "go": {"issue"}, "preset": {"server"}, "ca": {v.CAIDs["issuing"]},
		"keymode": {"csr"}, "alg": {"ecdsa-p256"}, "days": {"30"}, "csr": {csrPEM}, "prefilled": {""},
		"cn": {"other.homelab.lan"}, "dns": {"other.homelab.lan"},
	})
	if r.Code != http.StatusSeeOther {
		t.Fatalf("issue: %d\n%s", r.Code, r.html())
	}
	info, err := v.Engine.Certificate(t.Context(), testinstance.Console, strings.TrimPrefix(r.location(), "/certificates/"))
	if err != nil || !slices.Equal(info.DNSNames, []string{"other.homelab.lan"}) || info.CommonName != "other.homelab.lan" {
		t.Errorf("issued %v %q %v", info.DNSNames, info.CommonName, err)
	}
}

// TestWizardOffersNoRoot: the issue wizard lists only intermediates; a root
// sent anyway is refused at the first step (owner 2026-10-18).
func TestWizardOffersNoRoot(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.Unseal(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	page := b.get(t, "/certificates/new").html()
	if strings.Contains(page, `value="`+v.CAIDs["root"]+`"`) || !strings.Contains(page, `value="`+v.CAIDs["issuing"]+`"`) {
		t.Error("the wizard must offer the intermediate, not the root")
	}
	r := b.post(t, "/certificates/new", url.Values{"csrf_token": {b.csrf(t)}, "from": {"1"}, "go": {"next"}, "preset": {"server"}, "ca": {v.CAIDs["root"]}})
	if r.Code != http.StatusUnprocessableEntity || !strings.Contains(r.html(), "Choose a CA where you may issue.") {
		t.Errorf("root sent anyway: %d", r.Code)
	}
	if strings.Contains(b.get(t, "/authorities/"+v.CAIDs["root"]).html(), `href="/certificates/new?ca=`) {
		t.Error("the root's page must not offer issuing")
	}
}

// TestIssueOnlyOfferedToIssuers: "Issue certificate" appears in the menu and
// on the dashboard only for users who may issue at one CA at least.
func TestIssueOnlyOfferedToIssuers(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.User(t, "viewer", false, authz.Binding{Role: authz.Viewer})
	v.User(t, "op", false, authz.Binding{CA: "issuing", Role: authz.Operator})
	v.User(t, "rootop", false, authz.Binding{CA: "root", Role: authz.Operator}) // a root issues nothing
	for name, want := range map[string]bool{"viewer": false, "op": true, "rootop": false} {
		b := v.browser("192.0.2.1")
		b.signIn(t, name, testinstance.Password)
		html := b.get(t, "/").html()
		if got := strings.Contains(html, `href="/certificates/new"`); got != want {
			t.Errorf("%s: issue offered %v, want %v", name, got, want)
		}
	}
}

// TestAuditHasTheAddress: the process log keeps no client address (decision
// 2 of step 14) because the audit log has it for every sign-in event – both
// factors, success and failure, step-up and unseal (owner 2026-10-18).
func TestAuditHasTheAddress(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	const ip = "198.51.100.23"
	b := v.browser(ip)
	b.post(t, "/login", url.Values{"username": {"demo"}, "password": {"wrong password, long enough"}})
	b.post(t, "/login", url.Values{"username": {"nobody-by-this-name"}, "password": {"wrong password, long enough"}})
	v.Clock.Advance(30 * time.Second)
	b.post(t, "/login", url.Values{"username": {"demo"}, "password": {v.DemoPassword}})
	b.post(t, "/login/code", url.Values{"code": {"000000"}})
	b.post(t, "/login/code", url.Values{"code": {v.Code("demo")}})
	token := b.csrf(t)
	b.post(t, "/step-up", url.Values{"csrf_token": {token}, "code": {"000000"}})
	v.Clock.Advance(30 * time.Second)
	b.post(t, "/step-up", url.Values{"csrf_token": {token}, "code": {v.Code("demo")}})
	b.post(t, "/unseal", url.Values{"csrf_token": {token}, "passphrase": {"not the passphrase"}})
	b.post(t, "/unseal", url.Values{"csrf_token": {token}, "passphrase": {v.Passphrase}})
	got := testinstance.AuditIPs(t, v.InstanceAudit)
	for _, want := range []string{
		"user.login/failure " + ip, // wrong password, and the unknown name
		"user.login/success " + ip, // after the second factor
		"user.step_up/failure " + ip, "user.step_up/success " + ip,
		"system.unseal/failure " + ip, "system.unseal/success " + ip,
	} {
		if !slices.Contains(got, want) {
			t.Errorf("audit lacks %q:\n%s", want, strings.Join(got, "\n"))
		}
	}
	// Wrong password, unknown name and wrong code: three failed sign-ins.
	if n := len(slices.DeleteFunc(slices.Clone(got), func(s string) bool { return s != "user.login/failure "+ip })); n != 3 {
		t.Errorf("failed sign-ins with the address: %d\n%s", n, strings.Join(got, "\n"))
	}
}

// TestAuthorityListIsReadable: a root counts the intermediates it signed, has
// no maximum validity for leaves, and key storage has a readable label.
func TestAuthorityListIsReadable(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	html := b.get(t, "/authorities").html()
	for _, want := range []string{">Signed</th>", "1 intermediate CA", "0 certificates", "–", "Encrypted on this server"} {
		if !strings.Contains(html, want) {
			t.Errorf("CA list lacks %q", want)
		}
	}
	if strings.Contains(html, "online_encrypted") {
		t.Error("raw key mode shown")
	}
	root := b.get(t, "/authorities/"+v.CAIDs["root"]).html()
	if strings.Contains(root, "Maximum validity") || !strings.Contains(root, "Signed here: issuing.") {
		t.Error("root detail")
	}
}
