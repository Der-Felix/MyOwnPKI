package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/acme/jose"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
)

// problemOf decodes a problem document.
func problemOf(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("not JSON: %v: %s", err, rec.Body)
	}
	return m
}

// TestJoseFailMapsEveryClass: each error class of the JWS reader has its
// ACME problem type and status (RFC 8555 §6.2, §6.7).
func TestJoseFailMapsEveryClass(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	for name, tc := range map[string]struct {
		err     error
		status  int
		problem string
	}{
		"algorithm":         {jose.ErrBadAlgorithm, http.StatusBadRequest, "badSignatureAlgorithm"},
		"algorithm wrapped": {fmt.Errorf("%w: %q", jose.ErrBadAlgorithm, "none"), http.StatusBadRequest, "badSignatureAlgorithm"},
		"public key":        {jose.ErrBadKey, http.StatusBadRequest, "badPublicKey"},
		"key wrapped":       {fmt.Errorf("%w: RSA of 1024 bits", jose.ErrBadKey), http.StatusBadRequest, "badPublicKey"},
		"signature":         {jose.ErrBadSignature, http.StatusUnauthorized, "unauthorized"},
		"malformed":         {jose.ErrMalformed, http.StatusBadRequest, "malformed"},
		"malformed wrapped": {fmt.Errorf("%w: no nonce", jose.ErrMalformed), http.StatusBadRequest, "malformed"},
		"another error":     {errors.New("something else"), http.StatusBadRequest, "malformed"},
	} {
		rec := httptest.NewRecorder()
		v.s.joseFail(rec, tc.err)
		p := problemOf(t, rec)
		if rec.Code != tc.status || p["type"] != "urn:ietf:params:acme:error:"+tc.problem || rec.Header().Get("Content-Type") != "application/problem+json" {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
		if tc.problem == "badSignatureAlgorithm" {
			if algs, _ := p["algorithms"].([]any); len(algs) != 4 {
				t.Errorf("%s: the answer does not list the algorithms: %s", name, rec.Body)
			}
		}
	}
}

// TestFailMapsErrors: how a handler's error reaches the client – a problem
// as it is, rate limits and the sealed state with Retry-After, a policy
// refusal as rejectedIdentifier, and anything else as serverInternal without
// its text (the text is logged).
func TestFailMapsErrors(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	var logs lockedBuffer
	v.s.log = slog.New(slog.NewTextHandler(&logs, nil))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/acme/new-order", nil)
	for name, tc := range map[string]struct {
		err        error
		status     int
		problem    string
		retryAfter string
		hide       string // text that must not reach the client
	}{
		"a problem":                 {problemErr(http.StatusConflict, "malformed", "no"), http.StatusConflict, "malformed", "", ""},
		"a problem, wrapped":        {fmt.Errorf("outer: %w", problemErr(http.StatusBadRequest, "badCSR", "x")), http.StatusBadRequest, "badCSR", "", ""},
		"rate limit":                {problemErr(http.StatusTooManyRequests, "rateLimited", "slow down"), http.StatusTooManyRequests, "rateLimited", "30", ""},
		"rate limit with its wait":  {rateLimited(90*time.Second, "too many"), http.StatusTooManyRequests, "rateLimited", "90", ""},
		"rate limit under a second": {rateLimited(time.Millisecond, "too many"), http.StatusTooManyRequests, "rateLimited", "1", ""},
		"unavailable":               {problemErr(http.StatusServiceUnavailable, "serverInternal", "sealed"), http.StatusServiceUnavailable, "serverInternal", "30", ""},
		"a policy refusal":          {&ca.DeniedError{Reasons: []string{"name not allowed", "key too small"}}, http.StatusForbidden, "rejectedIdentifier", "", ""},
		"something else":            {errors.New("database is locked: SECRET-SQL"), http.StatusInternalServerError, "serverInternal", "", "SECRET-SQL"},
	} {
		rec := httptest.NewRecorder()
		v.s.fail(rec, req, tc.err)
		p := problemOf(t, rec)
		if rec.Code != tc.status || p["type"] != "urn:ietf:params:acme:error:"+tc.problem || rec.Header().Get("Retry-After") != tc.retryAfter {
			t.Errorf("%s: %d %v %s", name, rec.Code, rec.Header(), rec.Body)
		}
		if tc.hide != "" {
			if strings.Contains(rec.Body.String(), tc.hide) {
				t.Errorf("%s: the error text reached the client: %s", name, rec.Body)
			}
			if !strings.Contains(logs.String(), tc.hide) {
				t.Errorf("%s: the error text is not in the log: %s", name, logs.String())
			}
		}
	}
	rec := httptest.NewRecorder()
	v.s.fail(rec, req, &ca.DeniedError{Reasons: []string{"name not allowed", "key too small"}})
	if d, _ := problemOf(t, rec)["detail"].(string); d != "name not allowed; key too small" {
		t.Errorf("reasons: %q", d)
	}
}

// TestReadRefusals: the request rules of read that a client can break before
// any resource is looked at.
func TestReadRefusals(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	c.register()
	orderURL := testBase + "/new-order"
	send := func(contentType string, body []byte) *answer {
		t.Helper()
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, c.local(orderURL), bytes.NewReader(body))
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		a := &answer{code: resp.StatusCode, header: resp.Header}
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		a.body = buf.Bytes()
		_ = json.Unmarshal(a.body, &a.json)
		return a
	}
	good := c.jws(orderURL, map[string]any{"identifiers": []map[string]string{{"type": "dns", "value": "nas.homelab.lan"}}}, false)
	for name, tc := range map[string]struct {
		contentType string
		body        []byte
		code        int
		problem     string
	}{
		"no content type":           {"", good, http.StatusUnsupportedMediaType, "malformed"},
		"plain JSON":                {"application/json", good, http.StatusUnsupportedMediaType, "malformed"},
		"JOSE with a parameter":     {"application/jose+json; charset=utf-8", good, http.StatusCreated, ""},
		"a body over 64 KiB":        {"application/jose+json", bytes.Repeat([]byte("x"), maxBody+1), http.StatusRequestEntityTooLarge, "malformed"},
		"an empty body":             {"application/jose+json", nil, http.StatusBadRequest, "malformed"},
		"no JSON":                   {"application/jose+json", []byte("nope"), http.StatusBadRequest, "malformed"},
		"a JSON list":               {"application/jose+json", []byte("[]"), http.StatusBadRequest, "malformed"},
		"the compact serialization": {"application/jose+json", []byte("a.b.c"), http.StatusBadRequest, "malformed"},
		"the general serialization": {"application/jose+json", []byte(`{"signatures":[]}`), http.StatusBadRequest, "malformed"},
		"an unprotected header":     {"application/jose+json", []byte(`{"protected":"e30","payload":"","signature":"AA","header":{}}`), http.StatusBadRequest, "malformed"},
	} {
		if a := send(tc.contentType, tc.body); a.code != tc.code || a.problem() != tc.problem {
			t.Errorf("%s: %d %s", name, a.code, a.body)
		}
	}

	// A kid that is no account URL of this server.
	for name, kid := range map[string]string{
		"another server":     "https://other.example/acme/account/acc_x",
		"no id":              testBase + "/account/",
		"a path below":       c.kid + "/orders",
		"the directory":      testBase + "/directory",
		"a relative URL":     "/acme/account/acc_x",
		"an unknown account": testBase + "/account/acc_doesnotexist",
	} {
		cl := v.client(t)
		cl.kid = kid
		if a := cl.post(orderURL, map[string]any{"identifiers": []map[string]string{{"type": "dns", "value": "nas.homelab.lan"}}}); a.code != http.StatusBadRequest || a.problem() != "accountDoesNotExist" {
			t.Errorf("kid %s: %d %s", name, a.code, a.body)
		}
	}

	// A peer address that does not parse is no peer.
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/acme/directory", nil)
	req.RemoteAddr = "not an address"
	v.s.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || rec.Header().Get("Replay-Nonce") != "" {
		t.Errorf("a peer without an address: %d %v", rec.Code, rec.Header())
	}
}

// TestNewNonceAndLimits: new-nonce answers GET and HEAD (RFC 8555 §7.2) with
// a fresh nonce each time; the limits fall back to the defaults.
func TestNewNonceAndLimits(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	seen := map[string]bool{}
	for method, code := range map[string]int{http.MethodGet: http.StatusNoContent, http.MethodHead: http.StatusOK} {
		for range 2 {
			req, _ := http.NewRequestWithContext(t.Context(), method, v.ts.URL+"/acme/new-nonce", http.NoBody)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			n := resp.Header.Get("Replay-Nonce")
			if resp.StatusCode != code || n == "" || seen[n] || resp.Header.Get("Cache-Control") != "no-store" {
				t.Errorf("%s: %d nonce %q (seen: %v) %v", method, resp.StatusCode, n, seen[n], resp.Header)
			}
			seen[n] = true
		}
	}

	if got := v.s.limitsNow(t.Context()); got != DefaultLimits {
		t.Errorf("without settings: %+v", got)
	}
	v.s.opt.Limits = func(context.Context) (Limits, error) {
		return Limits{OrdersPerAccount: 7, FailedPerName: 8, AccountsPerIP: 9}, nil
	}
	if got := v.s.limitsNow(t.Context()); got != (Limits{7, 8, 9}) {
		t.Errorf("the tenant's settings: %+v", got)
	}
	var logs lockedBuffer
	v.s.log = slog.New(slog.NewTextHandler(&logs, nil))
	v.s.opt.Limits = func(context.Context) (Limits, error) { return Limits{}, errors.New("settings unreadable") }
	if got := v.s.limitsNow(t.Context()); got != DefaultLimits || !strings.Contains(logs.String(), "settings unreadable") {
		t.Errorf("unreadable settings: %+v, log %q", got, logs.String())
	}

	// No randomness, no nonce – and no crash.
	bad, err := New(Options{Engine: v.s.engine, BaseURL: testBase, TrustedProxies: "127.0.0.1", Clock: v.s.clk, Rand: iotest.ErrReader(errors.New("no entropy"))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bad.Close)
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/acme/directory", nil)
	req.RemoteAddr = "127.0.0.1:1"
	bad.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Replay-Nonce") != "" {
		t.Errorf("without entropy: %d %v", rec.Code, rec.Header())
	}
}

// TestNonceStore (RFC 8555 §6.5): a nonce works once, for an hour, and the
// store never holds more than maxNonces.
func TestNonceStore(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

	t.Run("once", func(t *testing.T) {
		t.Parallel()
		n := newNonceStore(clock.NewFake(start), rand.Reader)
		a, err := n.New()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := n.New()
		if a == b || a == "" {
			t.Fatalf("nonces %q %q", a, b)
		}
		if !n.Use(a) || n.Use(a) {
			t.Error("a nonce must work exactly once")
		}
		if n.Use("") || n.Use("never-issued") || n.Use(b+"x") {
			t.Error("an unknown nonce was accepted")
		}
		if !n.Use(b) {
			t.Error("another nonce is not touched by the use of the first")
		}
	})

	t.Run("expiry", func(t *testing.T) {
		t.Parallel()
		clk := clock.NewFake(start)
		n := newNonceStore(clk, rand.Reader)
		fresh, _ := n.New()
		stale, _ := n.New()
		clk.Advance(nonceTimeout - time.Second)
		if !n.Use(fresh) {
			t.Error("a nonce one second before its end was refused")
		}
		clk.Advance(time.Second)
		if n.Use(stale) {
			t.Error("a nonce at its expiry was accepted")
		}
		if _, still := n.byVal[stale]; still {
			t.Error("an expired nonce stays in the store after its use")
		}
	})

	t.Run("cap", func(t *testing.T) {
		t.Parallel()
		n := newNonceStore(clock.NewFake(start), rand.Reader)
		var all []string
		for range maxNonces + 50 {
			v, err := n.New()
			if err != nil {
				t.Fatal(err)
			}
			all = append(all, v)
		}
		if len(n.byVal) != maxNonces {
			t.Errorf("%d nonces held, want %d", len(n.byVal), maxNonces)
		}
		for _, old := range all[:50] {
			if n.Use(old) {
				t.Fatal("an evicted nonce was accepted: the oldest go first")
			}
		}
		if !n.Use(all[len(all)-1]) || !n.Use(all[50]) {
			t.Error("the newest nonces must survive")
		}
	})

	t.Run("used ones do not pile up", func(t *testing.T) {
		t.Parallel()
		n := newNonceStore(clock.NewFake(start), rand.Reader)
		for range 2*maxNonces + 10 {
			v, err := n.New()
			if err != nil {
				t.Fatal(err)
			}
			if !n.Use(v) {
				t.Fatal("a fresh nonce was refused")
			}
		}
		if len(n.byVal) != 0 || len(n.order) > 2*maxNonces {
			t.Errorf("after %d used nonces: %d held, %d in the order list", 2*maxNonces+10, len(n.byVal), len(n.order))
		}
	})

	t.Run("no randomness", func(t *testing.T) {
		t.Parallel()
		n := newNonceStore(clock.NewFake(start), iotest.ErrReader(errors.New("no entropy")))
		if v, err := n.New(); err == nil || v != "" || len(n.byVal) != 0 {
			t.Errorf("%q %v %d", v, err, len(n.byVal))
		}
	})
}

// TestCertIdentifiers: the names of a certificate as ACME identifiers, and
// the certificates no authorization can cover.
func TestCertIdentifiers(t *testing.T) {
	t.Parallel()
	ip4 := net.ParseIP("192.0.2.10")
	mapped := net.ParseIP("::ffff:192.0.2.11")
	ip6 := net.ParseIP("2001:db8::1")
	for name, tc := range map[string]struct {
		cert *x509.Certificate
		want []identifier
		fail string
	}{
		"dns names, lower cased": {&x509.Certificate{DNSNames: []string{"NAS.homelab.lan", "*.Homelab.lan"}}, []identifier{{"dns", "nas.homelab.lan"}, {"dns", "*.homelab.lan"}}, ""},
		"IPv4, mapped and IPv6":  {&x509.Certificate{IPAddresses: []net.IP{ip4, mapped, ip6}}, []identifier{{"ip", "192.0.2.10"}, {"ip", "192.0.2.11"}, {"ip", "2001:db8::1"}}, ""},
		"both kinds":             {&x509.Certificate{DNSNames: []string{"a.homelab.lan"}, IPAddresses: []net.IP{ip4}}, []identifier{{"dns", "a.homelab.lan"}, {"ip", "192.0.2.10"}}, ""},
		"no names":               {&x509.Certificate{}, nil, "names no ACME authorization covers"},
		"only an e-mail address": {&x509.Certificate{EmailAddresses: []string{"a@x.example"}}, nil, "names no ACME authorization covers"},
		"a name and an e-mail": {&x509.Certificate{DNSNames: []string{"a.homelab.lan"}, EmailAddresses: []string{"a@x.example"}}, nil,
			"names no ACME authorization covers"},
		"a name and a URI": {&x509.Certificate{DNSNames: []string{"a.homelab.lan"}, URIs: []*url.URL{{Scheme: "spiffe", Host: "x"}}}, nil,
			"names no ACME authorization covers"},
		"an address of 3 bytes": {&x509.Certificate{DNSNames: []string{"a.homelab.lan"}, IPAddresses: []net.IP{{1, 2, 3}}}, nil, "IP address no ACME authorization covers"},
	} {
		got, err := certIdentifiers(tc.cert)
		if tc.fail != "" {
			var ae *acmeError
			if !errors.As(err, &ae) || ae.status != http.StatusForbidden || ae.typ != "unauthorized" || !strings.Contains(ae.detail, tc.fail) || got != nil {
				t.Errorf("%s: %v %v", name, got, err)
			}
			continue
		}
		if err != nil || fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%s: %v %v, want %v", name, got, err, tc.want)
		}
	}
}

// issueNames orders names (DNS names and IPs), solves them and returns the
// certificate's DER.
func (c *client) issueNames(names ...string) []byte {
	c.t.Helper()
	order := c.order(names...)
	c.solve(order, "http-01")
	var dns []string
	var ips []net.IP
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, n)
		}
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	fin := c.finalize(order, csrFor(c.t, key, "", dns, ips))
	if fin.json["status"] != "valid" {
		c.t.Fatalf("finalize: %d %s", fin.code, fin.body)
	}
	got := c.post(field(fin.json, "certificate"), nil)
	block, _ := pem.Decode(got.body) // the first block is the certificate itself
	if block == nil {
		c.t.Fatalf("certificate: %s", got.body)
	}
	return block.Bytes
}

// TestRevokeNeedsEveryName: an account that does not own a certificate may
// revoke it only when it holds a valid authorization for every name in it,
// DNS names and IPs alike, and only while those authorizations last.
func TestRevokeNeedsEveryName(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	owner := v.client(t)
	owner.register()
	stranger := v.client(t)
	stranger.register()
	url := testBase + "/revoke-cert"
	der := owner.issueNames("a.homelab.lan", "b.homelab.lan", "192.0.2.10")

	refused := func(what string) {
		t.Helper()
		a := stranger.post(url, revokePayload(der, -1))
		if a.code != http.StatusForbidden || a.problem() != "unauthorized" || !strings.Contains(field(a.json, "detail"), what) {
			t.Fatalf("want a refusal naming %s: %d %s", what, a.code, a.body)
		}
		if _, revoked := v.revocation(t, der); revoked {
			t.Fatal("the certificate is revoked")
		}
	}
	refused(`dns "a.homelab.lan"`)
	stranger.solve(stranger.order("a.homelab.lan"), "http-01")
	refused(`dns "b.homelab.lan"`)
	stranger.solve(stranger.order("b.homelab.lan"), "http-01")
	refused(`ip "192.0.2.10"`)

	// With all three authorizations: allowed – unless they ran out.
	stranger.solve(stranger.order("192.0.2.10"), "http-01")
	v.expire(ValidAuthzLifetime+time.Hour, owner, stranger)
	refused("no valid authorization")
	stranger.solve(stranger.order("a.homelab.lan", "b.homelab.lan", "192.0.2.10"), "http-01")
	if a := stranger.post(url, revokePayload(der, 5)); a.code != http.StatusOK {
		t.Fatalf("revoke with all names: %d %s", a.code, a.body)
	}
	if r, ok := v.revocation(t, der); !ok || r != ca.ReasonCessationOfOperation {
		t.Errorf("revocation: %q %v", r, ok)
	}
}
