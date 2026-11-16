package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// field is a string member of a JSON object, or "".
func field(m map[string]any, name string) string {
	s, _ := m[name].(string)
	return s
}

// expire moves the clock on and forgets the nonces the clients hold: the
// server keeps a nonce for an hour only.
func (v *env) expire(d time.Duration, clients ...*client) {
	v.Clock.Advance(d)
	for _, c := range clients {
		c.nonce = ""
	}
}

// challengeOf is the URL and token of an authorization's challenge of a type.
func (c *client) challengeOf(authzURL, typ string) (chURL, token string) {
	c.t.Helper()
	a := c.post(authzURL, nil)
	for _, x := range list(a.json["challenges"]) {
		ch, _ := x.(map[string]any)
		if ch["type"] == typ {
			chURL, _ = ch["url"].(string)
			token, _ = ch["token"].(string)
		}
	}
	if chURL == "" {
		c.t.Fatalf("no %s challenge in %s", typ, a.body)
	}
	return chURL, token
}

// TestChallengeBranches: what the challenge endpoint does when the request is
// not the plain "start a pending challenge of my own": other accounts, unknown
// ids, an authorization that is not pending any more, a challenge that runs or
// has run.
func TestChallengeBranches(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	c.register()
	other := v.client(t)
	other.register()

	order := c.order("nas.homelab.lan")
	az := strs(order.json["authorizations"])[0]
	chURL, token := c.challengeOf(az, "http-01")

	// POST-as-GET: the challenge as it is, with a link up to the authorization.
	a := c.post(chURL, nil)
	if a.code != http.StatusOK || a.json["status"] != "pending" || a.json["token"] != token || !strings.Contains(strings.Join(a.header.Values("Link"), " "), `<`+az+`>;rel="up"`) {
		t.Errorf("read: %d %v %s", a.code, a.header, a.body)
	}
	// Another account's challenge and an unknown one do not exist.
	if r := other.post(chURL, nil); r.code != http.StatusNotFound || r.problem() != "malformed" {
		t.Errorf("foreign challenge: %d %s", r.code, r.body)
	}
	if r := other.post(chURL, map[string]any{}); r.code != http.StatusNotFound {
		t.Errorf("starting a foreign challenge: %d %s", r.code, r.body)
	}
	if r := c.post(testBase+"/challenge/ch_doesnotexist", nil); r.code != http.StatusNotFound || r.problem() != "malformed" {
		t.Errorf("unknown challenge: %d %s", r.code, r.body)
	}
	if got := c.post(chURL, nil).json["status"]; got != "pending" {
		t.Errorf("a refused request started the challenge: %v", got)
	}

	// A deactivated authorization can't be started: the answer is the
	// challenge as it is, and nothing is validated.
	if r := c.post(az, map[string]string{"status": "deactivated"}); r.code != http.StatusOK || r.json["status"] != "deactivated" {
		t.Fatalf("deactivate authz: %d %s", r.code, r.body)
	}
	if r := c.post(chURL, map[string]any{}); r.code != http.StatusOK || r.json["status"] != "pending" || r.header.Get("Retry-After") != "" {
		t.Errorf("start on a deactivated authorization: %d %v %s", r.code, r.header, r.body)
	}

	// An expired one can't either.
	second := c.order("web.homelab.lan")
	az2 := strs(second.json["authorizations"])[0]
	chURL2, _ := c.challengeOf(az2, "http-01")
	v.expire(25*time.Hour, c, other)
	if r := c.post(az2, nil); r.json["status"] != "expired" {
		t.Errorf("authorization after 25 hours: %s", r.body)
	}
	if r := c.post(chURL2, map[string]any{}); r.code != http.StatusOK || r.json["status"] != "pending" {
		t.Errorf("start on an expired authorization: %d %s", r.code, r.body)
	}
	if n := auditCount(t, v, ActionChallenge); n != 0 {
		t.Errorf("%d validations ran, want none", n)
	}
}

// TestChallengeRunsOnce: a second start while the check runs does not start a
// second check; after it has finished a repeated start changes nothing.
func TestChallengeRunsOnce(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	c.register()

	dialed, release := make(chan struct{}, 8), make(chan struct{})
	var dials atomic.Int32
	realDial := v.s.valid.dial
	v.s.SetNetwork(func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		dialed <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return realDial(ctx, network, addr)
	}, v.s.valid.lookupIP)

	order := c.order("nas.homelab.lan")
	az := strs(order.json["authorizations"])[0]
	chURL, token := c.challengeOf(az, "http-01")
	v.chall.set(token, token+"."+c.thumbprint())

	first := c.post(chURL, map[string]any{})
	if first.code != http.StatusOK || first.json["status"] != "processing" || first.header.Get("Retry-After") != "2" {
		t.Fatalf("start: %d %v %s", first.code, first.header, first.body)
	}
	<-dialed
	again := c.post(chURL, map[string]any{})
	if again.code != http.StatusOK || again.json["status"] != "processing" || again.header.Get("Retry-After") != "2" {
		t.Errorf("start while it runs: %d %v %s", again.code, again.header, again.body)
	}
	close(release)
	c.waitAuthz(az, "valid")
	if n := dials.Load(); n != 1 {
		t.Errorf("the target was contacted %d times, want once", n)
	}

	// Finished and valid: another start is the challenge as it is.
	done := c.post(chURL, map[string]any{})
	if done.code != http.StatusOK || done.json["status"] != "valid" || done.header.Get("Retry-After") != "" || done.json["validated"] == nil {
		t.Errorf("start on a valid challenge: %d %v %s", done.code, done.header, done.body)
	}
	if n := auditCount(t, v, ActionChallenge); n != 1 {
		t.Errorf("%d validation entries, want 1", n)
	}
}

// TestAuthzBranches (RFC 8555 §7.5.2): deactivating an authorization, and
// what is not allowed on it.
func TestAuthzBranches(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	c.register()
	other := v.client(t)
	other.register()
	order := c.order("nas.homelab.lan", "web.homelab.lan")
	azs := strs(order.json["authorizations"])
	if len(azs) != 2 {
		t.Fatalf("authorizations: %s", order.body)
	}

	if r := other.post(azs[0], nil); r.code != http.StatusNotFound || r.problem() != "malformed" {
		t.Errorf("foreign authorization: %d %s", r.code, r.body)
	}
	if r := other.post(azs[0], map[string]string{"status": "deactivated"}); r.code != http.StatusNotFound {
		t.Errorf("deactivating a foreign authorization: %d %s", r.code, r.body)
	}
	if r := c.post(testBase+"/authz/az_doesnotexist", nil); r.code != http.StatusNotFound {
		t.Errorf("unknown authorization: %d %s", r.code, r.body)
	}
	for name, payload := range map[string]any{
		"status valid":     map[string]string{"status": "valid"},
		"no status":        map[string]any{"x": 1},
		"payload no JSON":  rawBytes("nope"),
		"status is number": map[string]any{"status": 1},
	} {
		if r := c.post(azs[0], payload); r.code != http.StatusBadRequest || r.problem() != "malformed" {
			t.Errorf("%s: %d %s", name, r.code, r.body)
		}
	}
	if r := c.post(azs[0], nil); r.json["status"] != "pending" {
		t.Errorf("after the refusals: %s", r.body)
	}

	r := c.post(azs[0], map[string]string{"status": "deactivated"})
	if r.code != http.StatusOK || r.json["status"] != "deactivated" || len(list(r.json["challenges"])) == 0 {
		t.Fatalf("deactivate: %d %s", r.code, r.body)
	}
	if n := auditCount(t, v, ActionAuthzDeactivate); n != 1 {
		t.Errorf("%d authz.deactivate entries, want 1", n)
	}
	// The order that needs it can't become ready any more.
	o := c.post(order.header.Get("Location"), nil)
	if o.json["status"] != "invalid" {
		t.Fatalf("order after the deactivation: %s", o.body)
	}
	if e, _ := o.json["error"].(map[string]any); !strings.Contains(field(e, "detail"), "is deactivated") {
		t.Errorf("order error: %s", o.body)
	}
	// A new order for the same name gets a new authorization.
	again := c.order("nas.homelab.lan")
	if strs(again.json["authorizations"])[0] == azs[0] {
		t.Errorf("a deactivated authorization was reused: %s", again.body)
	}
}

// readyOrder orders names, solves them and returns the order, ready to be
// finalized.
func (c *client) readyOrder(names ...string) *answer {
	c.t.Helper()
	o := c.order(names...)
	if o.code != http.StatusCreated {
		c.t.Fatalf("order: %d %s", o.code, o.body)
	}
	c.solve(o, "http-01")
	return o
}

// TestFinalizeBranches: the states an order can be in when the client
// finalizes (RFC 8555 §7.4) and what is wrong with the request.
func TestFinalizeBranches(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	c.register()
	other := v.client(t)
	other.register()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr := func(names ...string) []byte { return csrFor(t, key, "", names, nil) }
	state := func(o *answer) *answer { return c.post(o.header.Get("Location"), nil) }

	// Another account's order and an unknown one.
	own := c.readyOrder("own.homelab.lan")
	if r := other.finalize(own, csr("own.homelab.lan")); r.code != http.StatusNotFound || r.problem() != "malformed" {
		t.Errorf("foreign order: %d %s", r.code, r.body)
	}
	if r := c.post(testBase+"/order/ord_doesnotexist/finalize", map[string]string{"csr": b64(csr("own.homelab.lan"))}); r.code != http.StatusNotFound {
		t.Errorf("unknown order: %d %s", r.code, r.body)
	}

	// A request that is wrong before the CSR is looked at: the order stays ready.
	for name, payload := range map[string]any{
		"no payload":         nil,
		"payload is no JSON": rawBytes("nope"),
		"csr is a number":    map[string]any{"csr": 1},
		"csr with padding":   map[string]string{"csr": b64(csr("own.homelab.lan")) + "=="},
		"csr is base64 std":  map[string]string{"csr": "+/+/"},
	} {
		r := c.post(field(own.json, "finalize"), payload)
		if r.code != http.StatusBadRequest || (r.problem() != "badCSR" && r.problem() != "malformed") {
			t.Errorf("%s: %d %s", name, r.code, r.body)
		}
		if s := state(own).json["status"]; s != "ready" {
			t.Errorf("%s: the order is %v, want ready", name, s)
		}
	}

	// A CSR that is wrong in itself ends the order.
	good := csr("bad.homelab.lan")
	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-1] ^= 0xff
	withEmail, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{}, DNSNames: []string{"bad.homelab.lan"}, EmailAddresses: []string{"a@x.example"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	withURI, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"bad.homelab.lan"}, URIs: []*url.URL{{Scheme: "https", Host: "x.example"}}}, key)
	if err != nil {
		t.Fatal(err)
	}
	withIP, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"bad.homelab.lan"}, IPAddresses: []net.IP{net.ParseIP("192.0.2.10")}}, key)
	if err != nil {
		t.Fatal(err)
	}
	for name, der := range map[string][]byte{
		"signature does not verify": tampered,
		"not a CSR":                 []byte("this is not DER"),
		"an empty csr":              {},
		"an e-mail address":         withEmail,
		"a URI":                     withURI,
		"an extra IP":               withIP,
	} {
		o := c.readyOrder("bad.homelab.lan")
		if r := c.finalize(o, der); r.code != http.StatusBadRequest || r.problem() != "badCSR" {
			t.Errorf("%s: %d %s", name, r.code, r.body)
		}
		got := state(o)
		if got.json["status"] != "invalid" {
			t.Errorf("%s: the order is %v", name, got.json["status"])
		}
		if e, _ := got.json["error"].(map[string]any); e == nil || !strings.HasSuffix(field(e, "type"), ":badCSR") {
			t.Errorf("%s: order error %v", name, got.json["error"])
		}
		// An invalid order can't be finalized again.
		if r := c.finalize(o, good); r.code != http.StatusForbidden || r.problem() != "orderNotReady" {
			t.Errorf("%s: finalize again: %d %s", name, r.code, r.body)
		}
	}

	// An invalid order (an authorization was deactivated) is not ready.
	dead := c.order("dead.homelab.lan")
	c.post(strs(dead.json["authorizations"])[0], map[string]string{"status": "deactivated"})
	if r := c.finalize(dead, csr("dead.homelab.lan")); r.code != http.StatusForbidden || r.problem() != "orderNotReady" || !strings.Contains(string(r.body), "invalid") {
		t.Errorf("invalid order: %d %s", r.code, r.body)
	}

	// An expired order: ready one moment, invalid after its 24 hours.
	late := c.readyOrder("late.homelab.lan")
	v.expire(25*time.Hour, c, other)
	if r := c.finalize(late, csr("late.homelab.lan")); r.code != http.StatusForbidden || r.problem() != "orderNotReady" {
		t.Errorf("expired order: %d %s", r.code, r.body)
	}
	got := state(late)
	if e, _ := got.json["error"].(map[string]any); got.json["status"] != "invalid" || e == nil || !strings.Contains(field(e, "detail"), "the order expired") {
		t.Errorf("expired order state: %s", got.body)
	}
	if _, ok := got.json["certificate"]; ok {
		t.Errorf("an expired order has a certificate: %s", got.body)
	}

	// Names in capitals are the same names (the CSR need not be lower case).
	caps := c.readyOrder("caps.homelab.lan")
	if r := c.finalize(caps, csr("CAPS.Homelab.LAN")); r.code != http.StatusOK || r.json["status"] != "valid" || r.json["certificate"] == nil {
		t.Errorf("CSR with capitals: %d %s", r.code, r.body)
	}
	// Finalize again is the order as it is.
	if r := c.finalize(caps, []byte("garbage")); r.code != http.StatusOK || r.json["status"] != "valid" {
		t.Errorf("finalize a valid order again: %d %s", r.code, r.body)
	}
}

// TestFinalizeProcessing: an order that waits for the unseal is "processing"
// and answers the same to every further finalize, whatever it carries.
func TestFinalizeProcessing(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	c.register()
	order := c.readyOrder("wait.homelab.lan")
	if err := v.Ring.Seal(t.Context(), testinstance.Console); err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if r := c.finalize(order, csrFor(t, key, "", []string{"wait.homelab.lan"}, nil)); r.json["status"] != "processing" {
		t.Fatalf("sealed finalize: %d %s", r.code, r.body)
	}
	for name, payload := range map[string]any{"another CSR": map[string]string{"csr": b64(csrFor(t, key, "", []string{"other.homelab.lan"}, nil))}, "garbage": rawBytes("nope"), "nothing": nil} {
		r := c.post(field(order.json, "finalize"), payload)
		if r.code != http.StatusOK || r.json["status"] != "processing" || r.header.Get("Retry-After") != "30" || r.header.Get("Location") != order.header.Get("Location") {
			t.Errorf("%s while processing: %d %v %s", name, r.code, r.header, r.body)
		}
	}
	if r := c.post(order.header.Get("Location"), nil); r.json["status"] != "processing" || r.header.Get("Retry-After") != "30" {
		t.Errorf("order while processing: %v %s", r.header, r.body)
	}
	if n, err := v.s.Waiting(t.Context()); err != nil || n != 1 {
		t.Errorf("waiting: %d %v", n, err)
	}
}
