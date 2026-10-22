package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/acme/jose"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

const testBase = "https://acme.homelab.test/acme"

// env is an initialized instance with a domain, the ACME server and the
// network edges of the validator replaced: names resolve to 192.0.2.10, and
// port 80 of that address is a local challenge server.
type env struct {
	*testinstance.Instance
	s       *Server
	ts      *httptest.Server // the ACME handler (plain HTTP, the "proxy" side)
	chall   *challengeServer
	txt     map[string][]string
	txtMu   sync.Mutex
	addrFor map[string]netip.Addr
}

type challengeServer struct {
	mu       sync.Mutex
	files    map[string]string           // token -> body
	handlers map[string]http.HandlerFunc // token -> own answer (redirect tests)
	srv      *httptest.Server            // 192.0.2.10:80 and 192.0.2.11:80
	tls      *httptest.Server            // 192.0.2.10:443
	banner   net.Listener                // 192.0.2.12:80, not HTTP
}

func (c *challengeServer) set(token, body string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.files[token] = body
}

func newEnv(t *testing.T, approval string) *env {
	t.Helper()
	inst := testinstance.New(t, testinstance.Options{})
	inst.Unseal(t)
	return newEnvOn(t, inst, approval)
}

// newEnvOn sets up the domain, the ACME server and the network edges on an
// unsealed instance.
func newEnvOn(t *testing.T, inst *testinstance.Instance, approval string) *env {
	t.Helper()
	ctx := t.Context()
	issuing := "issuing"
	wild := true
	if _, err := inst.Engine.CreateDomain(ctx, ca.DomainRequest{Name: "homelab.lan", DomainSettings: ca.DomainSettings{
		CA: &issuing, Approval: &approval, Wildcards: &wild, IPRanges: []string{"192.0.2.0/24"},
	}, Who: testinstance.Console}); err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{Engine: inst.Engine, BaseURL: testBase, TrustedProxies: "127.0.0.1, ::1", Clock: inst.Clock})
	if err != nil {
		t.Fatal(err)
	}
	v := &env{Instance: inst, s: s, txt: map[string][]string{}, addrFor: map[string]netip.Addr{}}
	v.chall = &challengeServer{files: map[string]string{}, handlers: map[string]http.HandlerFunc{}}
	serve := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
		v.chall.mu.Lock()
		body, ok := v.chall.files[token]
		h := v.chall.handlers[token]
		v.chall.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, body)
	})
	v.chall.srv = httptest.NewServer(serve)
	t.Cleanup(v.chall.srv.Close)
	v.chall.tls = httptest.NewTLSServer(serve)
	t.Cleanup(v.chall.tls.Close)
	banner, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	v.chall.banner = banner
	t.Cleanup(func() { _ = banner.Close() })
	go func() {
		for {
			conn, aerr := banner.Accept()
			if aerr != nil {
				return
			}
			_, _ = io.WriteString(conn, "SSH-2.0-SECRET-BANNER-4711\r\n")
			_ = conn.Close()
		}
	}()
	target := v.chall.srv.Listener.Addr().String()
	s.valid.lookupIP = func(_ context.Context, host string) ([]netip.Addr, error) {
		if a, ok := v.addrFor[host]; ok {
			return []netip.Addr{a}, nil
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
	}
	s.valid.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Only checked addresses reach the test targets.
		var d net.Dialer
		switch addr {
		case "192.0.2.10:80", "192.0.2.11:80":
			return d.DialContext(ctx, network, target)
		case "192.0.2.10:443":
			return d.DialContext(ctx, network, v.chall.tls.Listener.Addr().String())
		case "192.0.2.12:80":
			return d.DialContext(ctx, network, v.chall.banner.Addr().String())
		}
		// Like a real dialer, the error names the address.
		return nil, &net.OpError{Op: "dial", Net: network, Addr: net.TCPAddrFromAddrPort(netip.MustParseAddrPort(addr)), Err: io.ErrUnexpectedEOF}
	}
	s.valid.lookupTXT = func(_ context.Context, name string) ([]string, error) {
		v.txtMu.Lock()
		defer v.txtMu.Unlock()
		if r, ok := v.txt[name]; ok {
			return r, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	v.ts = httptest.NewServer(s)
	t.Cleanup(func() {
		v.ts.Close()
		s.Close()
	})
	return v
}

// client is a minimal ACME client: an ES256 account key and the protocol
// steps the tests need.
type client struct {
	t     *testing.T
	v     *env
	key   *ecdsa.PrivateKey
	jwk   string
	kid   string
	nonce string
}

func (v *env) client(t *testing.T) *client {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jk, err := jose.KeyFor(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return &client{t: t, v: v, key: k, jwk: string(jk.Canonical())}
}

// local turns a URL of the base into one of the test server.
func (c *client) local(u string) string {
	return c.v.ts.URL + "/acme" + strings.TrimPrefix(u, testBase)
}

func (c *client) thumbprint() string {
	k, _ := jose.KeyFor(&c.key.PublicKey)
	return k.Thumbprint()
}

func (c *client) getNonce() string {
	c.t.Helper()
	if c.nonce != "" {
		n := c.nonce
		c.nonce = ""
		return n
	}
	req, _ := http.NewRequestWithContext(c.t.Context(), http.MethodHead, c.local(testBase+"/new-nonce"), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.Header.Get("Replay-Nonce")
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func signES256(t *testing.T, key *ecdsa.PrivateKey, input []byte) []byte {
	t.Helper()
	h := sha256.Sum256(input)
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}

// jws signs payload for url; useJWK sends the key instead of the kid.
func (c *client) jws(url string, payload any, useJWK bool) []byte {
	c.t.Helper()
	hdr := map[string]any{"alg": "ES256", "nonce": c.getNonce(), "url": url}
	if useJWK || c.kid == "" {
		hdr["jwk"] = json.RawMessage(c.jwk)
	} else {
		hdr["kid"] = c.kid
	}
	return signedBody(c.t, c.key, hdr, payload)
}

func signedBody(t *testing.T, key *ecdsa.PrivateKey, hdr map[string]any, payload any) []byte {
	t.Helper()
	h, _ := json.Marshal(hdr)
	var p []byte
	switch v := payload.(type) {
	case nil:
	case []byte:
		p = v
	case rawBytes:
		p = v
	default:
		p, _ = json.Marshal(v)
	}
	ph, pl := b64(h), b64(p)
	sig := signES256(t, key, []byte(ph+"."+pl))
	body, _ := json.Marshal(map[string]string{"protected": ph, "payload": pl, "signature": b64(sig)})
	return body
}

type answer struct {
	code   int
	header http.Header
	body   []byte
	json   map[string]any
}

func (a *answer) problem() string {
	t, _ := a.json["type"].(string)
	return strings.TrimPrefix(t, "urn:ietf:params:acme:error:")
}

// post sends a signed request to a base URL.
func (c *client) post(url string, payload any) *answer {
	c.t.Helper()
	return c.postRaw(url, c.jws(url, payload, false))
}

func (c *client) postRaw(url string, body []byte) *answer {
	c.t.Helper()
	req, _ := http.NewRequestWithContext(c.t.Context(), http.MethodPost, c.local(url), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/jose+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	c.nonce = resp.Header.Get("Replay-Nonce")
	a := &answer{code: resp.StatusCode, header: resp.Header, body: data}
	_ = json.Unmarshal(data, &a.json)
	return a
}

func (c *client) register() *answer {
	c.t.Helper()
	url := testBase + "/new-account"
	a := c.postRaw(url, c.jws(url, map[string]any{"termsOfServiceAgreed": true, "contact": []string{"mailto:admin@homelab.lan"}}, true))
	if a.code == http.StatusCreated || a.code == http.StatusOK {
		c.kid = a.header.Get("Location")
	}
	return a
}

func (c *client) order(names ...string) *answer {
	c.t.Helper()
	var ids []map[string]string
	for _, n := range names {
		typ := "dns"
		if _, err := netip.ParseAddr(n); err == nil {
			typ = "ip"
		}
		ids = append(ids, map[string]string{"type": typ, "value": n})
	}
	return c.post(testBase+"/new-order", map[string]any{"identifiers": ids})
}

func strs(v any) []string {
	var out []string
	l, _ := v.([]any)
	for _, x := range l {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

// solve answers every authorization of an order with the challenge type and
// waits until each is valid (or the test fails).
func (c *client) solve(order *answer, typ string) {
	c.t.Helper()
	for _, az := range strs(order.json["authorizations"]) {
		a := c.post(az, nil)
		if a.code != http.StatusOK {
			c.t.Fatalf("authz: %d %s", a.code, a.body)
		}
		if a.json["status"] == "valid" {
			continue
		}
		id, _ := a.json["identifier"].(map[string]any)
		value, _ := id["value"].(string)
		var chURL, token string
		chs, _ := a.json["challenges"].([]any)
		for _, x := range chs {
			ch, _ := x.(map[string]any)
			if ch["type"] == typ {
				chURL, _ = ch["url"].(string)
				token, _ = ch["token"].(string)
			}
		}
		if chURL == "" {
			c.t.Fatalf("no %s challenge for %s: %s", typ, value, a.body)
		}
		keyAuth := token + "." + c.thumbprint()
		switch typ {
		case "http-01":
			c.v.chall.set(token, keyAuth)
		case "dns-01":
			sum := sha256.Sum256([]byte(keyAuth))
			c.v.txtMu.Lock()
			c.v.txt["_acme-challenge."+value] = []string{"unrelated", b64(sum[:])}
			c.v.txtMu.Unlock()
		}
		if r := c.post(chURL, map[string]any{}); r.code != http.StatusOK {
			c.t.Fatalf("challenge: %d %s", r.code, r.body)
		}
		c.waitAuthz(az, "valid")
	}
}

func (c *client) waitAuthz(url, want string) *answer {
	c.t.Helper()
	var a *answer
	for range 200 {
		a = c.post(url, nil)
		if s, _ := a.json["status"].(string); s != "pending" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if a.json["status"] != want {
		c.t.Fatalf("authorization %s, want %s: %s", a.json["status"], want, a.body)
	}
	return a
}

func csrFor(t *testing.T, key crypto.Signer, cn string, dns []string, ips []net.IP) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, DNSNames: dns, IPAddresses: ips}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (c *client) finalize(order *answer, csr []byte) *answer {
	c.t.Helper()
	fin, _ := order.json["finalize"].(string)
	return c.post(fin, map[string]string{"csr": b64(csr)})
}

func netipMust(s string) netip.Addr { return netip.MustParseAddr(s) }

// joseKeyFor is the canonical JWK of a public key.
func joseKeyFor(pub *ecdsa.PublicKey) (string, error) {
	k, err := jose.KeyFor(pub)
	if err != nil {
		return "", err
	}
	return string(k.Canonical()), nil
}

func rawJSON(s string) json.RawMessage { return json.RawMessage(s) }

// rawBytes is a payload sent as it is (the inner JWS of a key change).
type rawBytes []byte

func (r rawBytes) MarshalJSON() ([]byte, error) { return r, nil }

// list is a JSON array, or nil.
func list(v any) []any {
	l, _ := v.([]any)
	return l
}
