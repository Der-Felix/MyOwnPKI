package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

func TestDirectoryNonceAndProxy(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	dreq, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, v.ts.URL+"/acme/directory", nil)
	resp, err := http.DefaultClient.Do(dreq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Replay-Nonce") == "" || !strings.Contains(resp.Header.Get("Link"), testBase+"/directory") {
		t.Errorf("directory: %d %v", resp.StatusCode, resp.Header)
	}
	// Not through the proxy: 403 before anything is read.
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/acme/directory", nil)
	req.RemoteAddr = "203.0.113.7:4242"
	v.s.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "reverse proxy") {
		t.Errorf("untrusted peer: %d %s", rec.Code, rec.Body)
	}
	// X-Forwarded-For counts only from a trusted proxy: the last untrusted hop.
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/acme/directory", nil)
	req.RemoteAddr = "127.0.0.1:4242"
	req.Header.Set("X-Forwarded-For", "198.51.100.1, 203.0.113.9, 127.0.0.1")
	if got := v.s.clientIP(req, netipMust("127.0.0.1")); got != "203.0.113.9" {
		t.Errorf("client IP %q", got)
	}
}

func TestHTTP01ToCertificate(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	if a := c.register(); a.code != http.StatusCreated || a.json["status"] != "valid" || c.kid == "" {
		t.Fatalf("register: %d %s", a.code, a.body)
	}
	// The same key again: the existing account.
	if a := c.register(); a.code != http.StatusOK {
		t.Errorf("register again: %d", a.code)
	}
	order := c.order("nas.homelab.lan", "192.0.2.11")
	if order.code != http.StatusCreated || order.json["status"] != "pending" {
		t.Fatalf("order: %d %s", order.code, order.body)
	}
	orderURL := order.header.Get("Location")
	c.solve(order, "http-01")
	if o := c.post(orderURL, nil); o.json["status"] != "ready" {
		t.Fatalf("order after the challenges: %s", o.body)
	}
	certKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fin := c.finalize(order, csrFor(t, certKey, "nas.homelab.lan", []string{"nas.homelab.lan"}, []net.IP{net.ParseIP("192.0.2.11")}))
	if fin.code != http.StatusOK || fin.json["status"] != "valid" {
		t.Fatalf("finalize: %d %s", fin.code, fin.body)
	}
	certURL, _ := fin.json["certificate"].(string)
	got := c.post(certURL, nil)
	if got.code != 200 || got.header.Get("Content-Type") != "application/pem-certificate-chain" {
		t.Fatalf("certificate: %d %s", got.code, got.body)
	}
	var certs []*x509.Certificate
	rest := got.body
	for {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		cert, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, cert)
	}
	if len(certs) != 2 || !slices.Equal(certs[0].DNSNames, []string{"nas.homelab.lan"}) || len(certs[0].IPAddresses) != 1 {
		t.Fatalf("chain: %d certificates, names %v %v", len(certs), certs[0].DNSNames, certs[0].IPAddresses)
	}
	if d := certs[0].NotAfter.Sub(certs[0].NotBefore).Hours() / 24; d < 89 || d > 91 {
		t.Errorf("validity %.1f days, want 90", d)
	}
	// Another account doesn't get the certificate or the order.
	other := v.client(t)
	other.register()
	if a := other.post(certURL, nil); a.code != http.StatusNotFound {
		t.Errorf("other account, certificate: %d", a.code)
	}
	if a := other.post(orderURL, nil); a.code != http.StatusNotFound {
		t.Errorf("other account, order: %d", a.code)
	}
	// A second order for the same names reuses the valid authorizations.
	again := c.order("nas.homelab.lan")
	if again.json["status"] != "ready" {
		t.Errorf("reuse: %s", again.body)
	}
	v.Deliver(t)
	audit := strings.Join(testinstance.Audit(t, v.TenantAudit), " ")
	for _, want := range []string{"acme.account.create/success", "acme.order.create/success", "acme.challenge.validate/success", "certificate.issue/success"} {
		if !strings.Contains(audit, want) {
			t.Errorf("audit lacks %s: %s", want, audit)
		}
	}
}

func TestDNS01Wildcard(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	c.register()
	order := c.order("*.homelab.lan")
	if order.code != http.StatusCreated {
		t.Fatalf("order: %d %s", order.code, order.body)
	}
	az := c.post(strs(order.json["authorizations"])[0], nil)
	if az.json["wildcard"] != true || len(list(az.json["challenges"])) != 1 {
		t.Fatalf("wildcard authorization offers only dns-01: %s", az.body)
	}
	c.solve(order, "dns-01")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fin := c.finalize(order, csrFor(t, key, "", []string{"*.homelab.lan"}, nil))
	if fin.json["status"] != "valid" {
		t.Fatalf("finalize: %d %s", fin.code, fin.body)
	}
}

func TestFailedChallengeAndPolicy(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	c.register()
	// A name that resolves to loopback is never a validation target.
	v.addrFor["loop.homelab.lan"] = netipMust("127.0.0.1")
	order := c.order("loop.homelab.lan")
	az := strs(order.json["authorizations"])[0]
	a := c.post(az, nil)
	var chURL string
	for _, x := range list(a.json["challenges"]) {
		if ch, _ := x.(map[string]any); ch["type"] == "http-01" {
			chURL, _ = ch["url"].(string)
		}
	}
	c.post(chURL, map[string]any{})
	res := c.waitAuthz(az, "invalid")
	if !strings.Contains(string(res.body), "never a validation target") {
		t.Errorf("loopback: %s", res.body)
	}
	if o := c.post(order.header.Get("Location"), nil); o.json["status"] != "invalid" {
		t.Errorf("order after a failed challenge: %s", o.body)
	}
	// Wrong content.
	order = c.order("web.homelab.lan")
	az = strs(order.json["authorizations"])[0]
	a = c.post(az, nil)
	for _, x := range list(a.json["challenges"]) {
		if ch, _ := x.(map[string]any); ch["type"] == "http-01" {
			chURL, _ = ch["url"].(string)
			tok, _ := ch["token"].(string)
			v.chall.set(tok, "not the key authorization")
		}
	}
	c.post(chURL, map[string]any{})
	if res = c.waitAuthz(az, "invalid"); !strings.Contains(string(res.body), "incorrectResponse") {
		t.Errorf("wrong content: %s", res.body)
	}
	// Names without a domain, outside IP ranges, wildcard with http only.
	for _, name := range []string{"nas.elsewhere.example", "198.51.100.1"} {
		if r := c.order(name); r.code != http.StatusBadRequest || r.problem() != "rejectedIdentifier" {
			t.Errorf("%s: %d %s", name, r.code, r.body)
		}
	}
	if r := c.order("bad_name.homelab.lan"); r.code != http.StatusBadRequest {
		t.Errorf("bad name: %d %s", r.code, r.body)
	}
	if r := c.post(testBase+"/new-order", map[string]any{"identifiers": []map[string]string{{"type": "email", "value": "a@b"}}}); r.problem() != "unsupportedIdentifier" {
		t.Errorf("email identifier: %s", r.body)
	}
}

func TestApprovalLevels(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalAccount)
	c := v.client(t)
	c.register()
	if r := c.order("nas.homelab.lan"); r.code != http.StatusForbidden || r.problem() != "unauthorized" || !strings.Contains(string(r.body), "waits for approval") {
		t.Errorf("unapproved account: %d %s", r.code, r.body)
	}
	if err := v.s.ApproveAccount(t.Context(), strings.TrimPrefix(c.kid, testBase+"/account/"), testinstance.Console); err != nil {
		t.Fatal(err)
	}
	if r := c.order("nas.homelab.lan"); r.code != http.StatusCreated {
		t.Errorf("approved account: %d %s", r.code, r.body)
	}

	nv := newEnv(t, ca.ApprovalNewName)
	nc := nv.client(t)
	nc.register()
	if r := nc.order("new.homelab.lan"); r.code != http.StatusForbidden || !strings.Contains(string(r.body), "waits for approval") {
		t.Errorf("new name: %d %s", r.code, r.body)
	}
	if err := nv.s.DecideName(t.Context(), "dns:new.homelab.lan", true, testinstance.Console); err != nil {
		t.Fatal(err)
	}
	if r := nc.order("new.homelab.lan"); r.code != http.StatusCreated {
		t.Errorf("approved name: %d %s", r.code, r.body)
	}
}

func TestFinalizeWhileSealed(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	c.register()
	order := c.order("nas.homelab.lan")
	c.solve(order, "http-01")
	if err := v.Ring.Seal(t.Context(), testinstance.Console); err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fin := c.finalize(order, csrFor(t, key, "nas.homelab.lan", []string{"nas.homelab.lan"}, nil))
	if fin.code != http.StatusOK || fin.json["status"] != "processing" || fin.header.Get("Retry-After") == "" {
		t.Fatalf("sealed finalize: %d %v %s", fin.code, fin.header, fin.body)
	}
	if n, err := v.s.Waiting(t.Context()); err != nil || n != 1 {
		t.Errorf("waiting: %d %v", n, err)
	}
	v.Unseal(t)
	if err := v.s.ProcessPending(t.Context()); err != nil {
		t.Fatal(err)
	}
	if o := c.post(order.header.Get("Location"), nil); o.json["status"] != "valid" || o.json["certificate"] == nil {
		t.Errorf("after the unseal: %s", o.body)
	}
	// Finalize again: the order as it is, still one certificate.
	if again := c.finalize(order, csrFor(t, key, "", []string{"nas.homelab.lan"}, nil)); again.json["status"] != "valid" {
		t.Errorf("finalize again: %s", again.body)
	}
}

func TestBadCSRs(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	c.register()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, csr := range map[string][]byte{
		"an extra name":   csrFor(t, key, "", []string{"nas.homelab.lan", "evil.homelab.lan"}, nil),
		"a missing name":  csrFor(t, key, "", []string{"web.homelab.lan"}, nil),
		"a foreign CN":    csrFor(t, key, "evil.example", []string{"nas.homelab.lan", "web.homelab.lan"}, nil),
		"the account key": csrFor(t, c.key, "", []string{"nas.homelab.lan", "web.homelab.lan"}, nil),
		"garbage":         []byte("not a CSR"),
	} {
		order := c.order("nas.homelab.lan", "web.homelab.lan")
		c.solve(order, "http-01")
		if fin := c.finalize(order, csr); fin.problem() != "badCSR" {
			t.Errorf("%s: %d %s", name, fin.code, fin.body)
			continue
		}
		if o := c.post(order.header.Get("Location"), nil); o.json["status"] != "invalid" {
			t.Errorf("%s: order %s", name, o.body)
		}
	}
	// Finalize before the challenges: orderNotReady.
	order := c.order("db.homelab.lan")
	if fin := c.finalize(order, csrFor(t, key, "", []string{"db.homelab.lan"}, nil)); fin.code != http.StatusForbidden || fin.problem() != "orderNotReady" {
		t.Errorf("not ready: %d %s", fin.code, fin.body)
	}
}

func TestRequestRules(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	c.register()
	url := testBase + "/new-order"
	payload := map[string]any{"identifiers": []map[string]string{{"type": "dns", "value": "nas.homelab.lan"}}}
	// A nonce works once.
	body := c.jws(url, payload, false)
	if a := c.postRaw(url, body); a.code != http.StatusCreated {
		t.Fatalf("first: %d %s", a.code, a.body)
	}
	if a := c.postRaw(url, body); a.problem() != "badNonce" {
		t.Errorf("replayed nonce: %s", a.body)
	}
	// The signed URL must be the requested one.
	if a := c.postRaw(url, c.jws(testBase+"/new-account", payload, false)); a.code != http.StatusUnauthorized {
		t.Errorf("other URL: %d %s", a.code, a.body)
	}
	// An account request with jwk instead of kid.
	if a := c.postRaw(url, c.jws(url, payload, true)); a.problem() != "malformed" {
		t.Errorf("jwk on newOrder: %s", a.body)
	}
	// Unknown account, other key.
	other := v.client(t)
	other.kid = c.kid
	if a := other.post(url, payload); a.code != http.StatusUnauthorized {
		t.Errorf("kid of another key: %d %s", a.code, a.body)
	}
	other.kid = testBase + "/account/acc_doesnotexist"
	if a := other.post(url, payload); a.problem() != "accountDoesNotExist" {
		t.Errorf("unknown kid: %s", a.body)
	}
	// Wrong content type.
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, c.local(url), strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("content type: %d", resp.StatusCode)
	}
	// onlyReturnExisting for an unknown key.
	n := v.client(t)
	nurl := testBase + "/new-account"
	if a := n.postRaw(nurl, n.jws(nurl, map[string]any{"onlyReturnExisting": true}, true)); a.problem() != "accountDoesNotExist" {
		t.Errorf("onlyReturnExisting: %s", a.body)
	}
	// Contacts other than mailto:
	if a := n.postRaw(nurl, n.jws(nurl, map[string]any{"contact": []string{"tel:+49"}}, true)); a.problem() != "unsupportedContact" {
		t.Errorf("tel contact: %s", a.body)
	}
}

func TestAccountKeyChangeAndDeactivation(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	c.register()
	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nk := v.client(t)
	nk.key = newKey
	nkj, _ := joseKeyFor(&newKey.PublicKey)
	url := testBase + "/key-change"
	inner := signedBody(t, newKey, map[string]any{"alg": "ES256", "url": url, "jwk": rawJSON(nkj)}, map[string]any{"account": c.kid, "oldKey": rawJSON(c.jwk)})
	if a := c.post(url, rawBytes(inner)); a.code != http.StatusOK {
		t.Fatalf("key change: %d %s", a.code, a.body)
	}
	// The old key no longer works, the new one does.
	if a := c.order("nas.homelab.lan"); a.code != http.StatusUnauthorized {
		t.Errorf("old key after the change: %d %s", a.code, a.body)
	}
	c.key, c.jwk = newKey, nkj
	if a := c.order("nas.homelab.lan"); a.code != http.StatusCreated {
		t.Errorf("new key: %d %s", a.code, a.body)
	}
	// Deactivate: no further requests.
	if a := c.post(c.kid, map[string]string{"status": "deactivated"}); a.code != 200 || a.json["status"] != "deactivated" {
		t.Fatalf("deactivate: %d %s", a.code, a.body)
	}
	if a := c.order("nas.homelab.lan"); a.code != http.StatusUnauthorized {
		t.Errorf("deactivated account orders: %d %s", a.code, a.body)
	}
}
