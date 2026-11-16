package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
)

// FuzzACMEPayload is the handler-level target (PHASE3 section 18.2, step 88,
// tier 2): a real server with a real database, a valid account, a valid
// nonce and a correctly signed JWS around the fuzzed payload. The handler is
// called in process (no socket), because the rate is what decides whether
// the target stays.
//
// Setup, once per fuzz worker process: three accounts. "A" owns an order
// that waits for its CSR and a certificate; the requests of the target are
// signed by A, except the two that change the account itself (account and
// key-change), which are signed by "C", and the account creations, which are
// signed by fresh keys of a pool of 64 (after that the key has its account
// already and the handler answers with it). "V" is the victim: an account
// with a certificate, a ready order and a pending order, whose rows must not
// change whatever A or C send. The rows a request may change on its own
// account are put back after it: C's key, status and contacts, A's order.
//
// Invariants, for every input: no panic; no status 5xx; every 4xx is an
// application/problem+json document with a type from the ACME namespace and
// a short detail; every 2xx body that claims JSON is JSON; no row of V
// changes (account, orders, authorizations, challenges, certificate,
// revocation); the answer takes less than 2 seconds.
//
// The number of rows is capped: a new order is not sent any more after
// maxFuzzOrders accepted ones (the rest of that run exercises the other
// endpoints), because every accepted order adds rows to the database.
func FuzzACMEPayload(f *testing.F) {
	fz := newPayloadFuzz(f)
	for _, s := range fz.seeds(f) {
		f.Add(s.endpoint, s.payload)
	}
	f.Fuzz(func(t *testing.T, endpoint byte, payload []byte) {
		fz.run(t, endpoint, payload)
	})
}

const maxFuzzOrders = 2000

// The endpoints of the target; the byte of the fuzz input picks one by its
// remainder. For finalize and account the next bit of the byte picks the
// victim's resource instead of the sender's own (it must be refused).
const (
	epNewAccount = iota
	epNewOrder
	epFinalize
	epRevoke
	epKeyChange
	epAccount
	epCount
)

type payloadFuzz struct {
	v    *env
	a, c *client // senders: A (orders, revocations), C (account changes)
	pool []*ecdsa.PrivateKey
	next int // the next key of the pool

	aOrder, vOrder string // paths of A's order that waits for its CSR and of V's ready order
	aID, vID, cID  string // account IDs
	vOrderID       string
	orders         int    // accepted new orders
	aCert          []byte // A's certificate
	victimCert     []byte // V's certificate

	cRow accountRow // C as it was made
}

type accountRow struct{ thumb, jwk, status, contact, updated string }

type fuzzSeed struct {
	endpoint byte
	payload  []byte
}

func newPayloadFuzz(f *testing.F) *payloadFuzz {
	f.Helper()
	v := newEnv(f, ca.ApprovalOpen)
	// The limits are the tenant's; a fuzz run is one address and many requests.
	v.s.opt.Limits = func(context.Context) (Limits, error) {
		return Limits{OrdersPerAccount: 1 << 30, FailedPerName: 1 << 30, AccountsPerIP: 1 << 30}, nil
	}
	fz := &payloadFuzz{v: v}
	fz.a, fz.c = v.client(f), v.client(f)
	victim := v.client(f)
	for _, c := range []*client{fz.a, fz.c, victim} {
		if r := c.register(); r.code != http.StatusCreated {
			f.Fatalf("register: %d %s", r.code, r.body)
		}
	}
	fz.aID, fz.cID, fz.vID = idOf(fz.a.kid), idOf(fz.c.kid), idOf(victim.kid)
	for range 64 {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			f.Fatal(err)
		}
		fz.pool = append(fz.pool, k)
	}

	// A: a certificate (a seed revokes it) and an order that waits for its CSR.
	fz.aCert, _ = fz.a.issue("a-cert.homelab.lan")
	o := fz.a.order("a-order.homelab.lan")
	fz.a.solve(o, "http-01")
	fz.aOrder = pathOf(o.header.Get("Location"))
	if r := fz.a.post(o.header.Get("Location"), nil); r.json["status"] != "ready" {
		f.Fatalf("A's order: %s", r.body)
	}
	// V: a certificate, a ready order and a pending one.
	fz.victimCert, _ = victim.issue("v-cert.homelab.lan")
	ready := victim.order("v-ready.homelab.lan")
	victim.solve(ready, "http-01")
	fz.vOrder = pathOf(ready.header.Get("Location"))
	fz.vOrderID = idOf(fz.vOrder)
	if r := victim.post(ready.header.Get("Location"), nil); r.json["status"] != "ready" {
		f.Fatalf("V's order: %s", r.body)
	}
	if r := victim.order("v-pending.homelab.lan"); r.code != http.StatusCreated {
		f.Fatalf("V's pending order: %s", r.body)
	}
	fz.cRow = fz.readAccount(f.Context(), f, fz.cID)
	return fz
}

// idOf is the last path segment of a URL or path.
func idOf(u string) string { return u[strings.LastIndex(u, "/")+1:] }

// pathOf turns a URL of the base into its path after the base.
func pathOf(u string) string { return strings.TrimPrefix(u, testBase) }

func (fz *payloadFuzz) readAccount(ctx context.Context, tb testing.TB, id string) accountRow {
	tb.Helper()
	var r accountRow
	err := fz.v.PKIDB.Read.QueryRowContext(ctx, `SELECT key_thumbprint, jwk, status, contact, updated_at FROM acme_accounts WHERE id = ?`, id).
		Scan(&r.thumb, &r.jwk, &r.status, &r.contact, &r.updated)
	if err != nil {
		tb.Fatal(err)
	}
	return r
}

// seeds: one request of every endpoint that works, and the shapes next to it
// that must be refused.
func (fz *payloadFuzz) seeds(tb testing.TB) []fuzzSeed {
	tb.Helper()
	js := func(v any) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			tb.Fatal(err)
		}
		return b
	}
	ids := func(typ string, values ...string) map[string]any {
		var l []map[string]string
		for _, v := range values {
			l = append(l, map[string]string{"type": typ, "value": v})
		}
		return map[string]any{"identifiers": l}
	}
	var out []fuzzSeed
	add := func(ep int, payload []byte) { out = append(out, fuzzSeed{byte(ep), payload}) } // #nosec G115 -- ep is below 2*epCount

	// new-account
	add(epNewAccount, js(map[string]any{"termsOfServiceAgreed": true, "contact": []string{"mailto:fuzz@homelab.lan"}}))
	add(epNewAccount, js(map[string]any{"onlyReturnExisting": true}))
	add(epNewAccount, js(map[string]any{"contact": []string{"tel:+49", "mailto:a b@example.com"}}))
	add(epNewAccount, js(map[string]any{"externalAccountBinding": map[string]any{"protected": "e30", "payload": "e30", "signature": "AA"}}))
	add(epNewAccount, []byte(`{}`))
	// new-order
	add(epNewOrder, js(ids("dns", "fuzz.homelab.lan")))
	add(epNewOrder, js(ids("dns", "a.homelab.lan", "*.homelab.lan", "A.HOMELAB.LAN")))
	add(epNewOrder, js(ids("ip", "192.0.2.5")))
	add(epNewOrder, js(ids("dns", "outside.example.org")))
	add(epNewOrder, js(ids("dns", strings.Repeat("a", 64)+".homelab.lan")))
	add(epNewOrder, js(ids("email", "a@homelab.lan")))
	add(epNewOrder, js(map[string]any{"identifiers": []string{}}))
	add(epNewOrder, js(map[string]any{"identifiers": ids("dns", "x.homelab.lan")["identifiers"], "notBefore": "2030-01-01T00:00:00Z"}))
	add(epNewOrder, js(map[string]any{"identifiers": ids("dns", "x.homelab.lan")["identifiers"], "replaces": "AQID.AQ"}))
	add(epNewOrder, []byte(`{"identifiers":[{"type":"dns","value":"x.homelab.lan","value":"y.homelab.lan"}]}`))
	many := make([]string, 101)
	for i := range many {
		many[i] = fmt.Sprintf("n%d.homelab.lan", i)
	}
	add(epNewOrder, js(ids("dns", many...)))
	// finalize: a CSR for A's order, the same for V's (foreign: +epCount), garbage
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	good := b64(csrFor(tb, key, "a-order.homelab.lan", []string{"a-order.homelab.lan"}, nil))
	other := b64(csrFor(tb, key, "v-ready.homelab.lan", []string{"v-ready.homelab.lan"}, nil))
	add(epFinalize, js(map[string]string{"csr": good}))
	add(epFinalize, js(map[string]string{"csr": other}))
	add(epFinalize+epCount, js(map[string]string{"csr": other}))
	add(epFinalize, js(map[string]string{"csr": "AA"}))
	add(epFinalize, js(map[string]string{"csr": ""}))
	add(epFinalize, []byte(`{"csr":1}`))
	// revoke-cert: A's own certificate, V's, a bad reason, garbage
	add(epRevoke, js(map[string]any{"certificate": b64(fz.victimCert), "reason": 1}))
	add(epRevoke, js(map[string]any{"certificate": b64(fz.victimCert), "reason": 99}))
	add(epRevoke, js(map[string]any{"certificate": "AA"}))
	add(epRevoke, []byte(`{"certificate":null}`))
	add(epRevoke, js(map[string]any{"certificate": b64(fz.aCert), "reason": 0}))
	// key-change: an inner JWS signed by a new key, and the shapes around it
	fz.keyChangeSeeds(tb, add)
	// account
	add(epAccount, js(map[string]any{"contact": []string{"mailto:changed@homelab.lan"}}))
	add(epAccount, js(map[string]any{"contact": []string{}}))
	add(epAccount, js(map[string]any{"status": "deactivated"}))
	add(epAccount, js(map[string]any{"status": "valid"}))
	add(epAccount+epCount, js(map[string]any{"status": "deactivated"}))
	add(epAccount+epCount, js(map[string]any{"contact": []string{"mailto:evil@example.com"}}))
	add(epAccount, nil)
	// shapes that fit every endpoint
	for ep := range epCount {
		for _, p := range []string{``, `null`, `[]`, `"x"`, `0`, `{`, `{"a":{"a":{"a":{"a":{}}}}}`, "\xff\xfe", strings.Repeat("[", 5000)} {
			add(ep, []byte(p))
		}
	}
	return out
}

// keyChangeSeeds adds the key change of account C to a new key: the valid
// request and the refusals next to it.
func (fz *payloadFuzz) keyChangeSeeds(tb testing.TB, add func(int, []byte)) {
	tb.Helper()
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	nk := fz.c.withKey(tb, newKey)
	url := testBase + "/key-change"
	inner := func(account, oldKey string, key *ecdsa.PrivateKey, jwk string, hdrURL string) []byte {
		hdr := map[string]any{"alg": "ES256", "url": hdrURL, "jwk": json.RawMessage(jwk)}
		payload := map[string]any{"account": account, "oldKey": json.RawMessage(oldKey)}
		return signedBody(tb, key, hdr, payload)
	}
	add(epKeyChange, inner(fz.c.kid, fz.c.jwk, newKey, nk.jwk, url))
	add(epKeyChange, inner(fz.c.kid, fz.c.jwk, newKey, nk.jwk, url+"-other"))                                                // another URL
	add(epKeyChange, inner(fz.c.kid, nk.jwk, newKey, nk.jwk, url))                                                           // oldKey is the new key
	add(epKeyChange, inner(fz.a.kid, fz.c.jwk, newKey, nk.jwk, url))                                                         // another account
	add(epKeyChange, inner(fz.c.kid, fz.c.jwk, newKey, fz.a.jwk, url))                                                       // new key already has an account
	add(epKeyChange, inner(fz.c.kid, fz.c.jwk, fz.c.key, nk.jwk, url))                                                       // signed by the wrong key
	add(epKeyChange, bytes.Replace(inner(fz.c.kid, fz.c.jwk, newKey, nk.jwk, url), []byte(`"payload"`), []byte(`"pay"`), 1)) // broken
}

// withKey is a client of the same server that signs with key.
func (c *client) withKey(tb testing.TB, key *ecdsa.PrivateKey) *client {
	tb.Helper()
	jk, err := joseKeyFor(&key.PublicKey)
	if err != nil {
		tb.Fatal(err)
	}
	return &client{t: tb, v: c.v, key: key, jwk: jk}
}

// run is one input of the target.
func (fz *payloadFuzz) run(t *testing.T, endpoint byte, payload []byte) {
	t.Helper()
	ctx := t.Context()
	kind := int(endpoint) % epCount
	foreign := int(endpoint)/epCount%2 == 1
	if kind == epNewOrder && fz.orders >= maxFuzzOrders {
		return
	}

	var path string
	var signer *client
	byJWK := false
	switch kind {
	case epNewAccount:
		path, byJWK = "/new-account", true
		k := fz.pool[fz.next%len(fz.pool)]
		fz.next++
		signer = fz.c.withKey(t, k)
	case epNewOrder:
		path, signer = "/new-order", fz.a
	case epFinalize:
		path, signer = fz.aOrder+"/finalize", fz.a
		if foreign {
			path = fz.vOrder + "/finalize"
		}
		fz.resetOrder(ctx, t, idOf(fz.aOrder))
	case epRevoke:
		path, signer = "/revoke-cert", fz.a
	case epKeyChange:
		path, signer = "/key-change", fz.c
	case epAccount:
		path, signer = "/account/"+fz.cID, fz.c
		if foreign {
			path = "/account/" + fz.vID
		}
	}

	before := fz.victimDigest(ctx, t)
	nonce, err := fz.v.s.nonces.New()
	if err != nil {
		t.Fatal(err)
	}
	hdr := map[string]any{"alg": "ES256", "nonce": nonce, "url": testBase + path}
	if byJWK {
		hdr["jwk"] = json.RawMessage(signer.jwk)
	} else {
		hdr["kid"] = signer.kid
	}
	body := signedBody(t, signer.key, hdr, payload)
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/acme"+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/jose+json")
	req.RemoteAddr = "127.0.0.1:4321"

	start := time.Now()
	rec := httptest.NewRecorder()
	fz.v.s.ServeHTTP(rec, req)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("endpoint %d took %v", kind, d)
	}
	res := rec.Result()
	defer func() { _ = res.Body.Close() }()
	answer := rec.Body.Bytes()

	switch {
	case res.StatusCode >= 500:
		t.Fatalf("endpoint %d answered %d: %.300s", kind, res.StatusCode, answer)
	case res.StatusCode >= 400:
		ct := res.Header.Get("Content-Type")
		var p struct {
			Type   string `json:"type"`
			Detail string `json:"detail"`
			Status int    `json:"status"`
		}
		if !strings.HasPrefix(ct, "application/problem+json") || json.Unmarshal(answer, &p) != nil ||
			!strings.HasPrefix(p.Type, "urn:ietf:params:acme:error:") || p.Status != res.StatusCode {
			t.Fatalf("endpoint %d: a %d without a problem document (%q): %.300s", kind, res.StatusCode, ct, answer)
		}
		if len(p.Detail) > fuzzMaxDetail {
			t.Fatalf("endpoint %d: a detail of %d bytes echoes the request: %.200s", kind, len(p.Detail), p.Detail)
		}
	case strings.HasPrefix(res.Header.Get("Content-Type"), "application/json"):
		if !json.Valid(answer) {
			t.Fatalf("endpoint %d: an answer that claims JSON and is not: %.300s", kind, answer)
		}
	}
	if kind == epNewOrder && res.StatusCode == http.StatusCreated {
		fz.orders++
	}

	// Put back what a request may change on its own account.
	switch kind {
	case epKeyChange, epAccount:
		fz.restoreC(ctx, t)
	}
	if after := fz.victimDigest(ctx, t); after != before {
		t.Fatalf("endpoint %d (foreign=%v, status %d) changed rows of another account: %.300s", kind, foreign, res.StatusCode, answer)
	}
}

// resetOrder makes A's order wait for its CSR again.
func (fz *payloadFuzz) resetOrder(ctx context.Context, t *testing.T, id string) {
	t.Helper()
	if _, err := fz.v.PKIDB.Write.ExecContext(ctx, `UPDATE acme_orders SET status = 'ready', csr_der = NULL, certificate_id = NULL, error = NULL WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}
}

// restoreC puts C's key, status and contacts back.
func (fz *payloadFuzz) restoreC(ctx context.Context, t *testing.T) {
	t.Helper()
	r := fz.cRow
	if _, err := fz.v.PKIDB.Write.ExecContext(ctx, `UPDATE acme_accounts SET key_thumbprint = ?, jwk = ?, status = ?, contact = ?, updated_at = ? WHERE id = ?`,
		r.thumb, r.jwk, r.status, r.contact, r.updated, fz.cID); err != nil {
		t.Fatal(err)
	}
}

// victimDigest is a hash over every row that belongs to V.
func (fz *payloadFuzz) victimDigest(ctx context.Context, t *testing.T) string {
	t.Helper()
	h := sha256.New()
	db := fz.v.PKIDB.Read
	for _, q := range []string{
		`SELECT * FROM acme_accounts WHERE id = ?`,
		`SELECT * FROM acme_orders WHERE account_id = ? ORDER BY id`,
		`SELECT * FROM acme_authzs WHERE account_id = ? ORDER BY id`,
		`SELECT ch.* FROM acme_challenges ch JOIN acme_authzs a ON a.id = ch.authz_id WHERE a.account_id = ? ORDER BY ch.id`,
		`SELECT * FROM acme_order_authzs WHERE order_id IN (SELECT id FROM acme_orders WHERE account_id = ?) ORDER BY order_id, authz_id`,
		`SELECT * FROM certificates WHERE id IN (SELECT certificate_id FROM acme_orders WHERE account_id = ?) ORDER BY id`,
		`SELECT * FROM revocations WHERE certificate_id IN (SELECT certificate_id FROM acme_orders WHERE account_id = ?) ORDER BY certificate_id`,
	} {
		rows, err := db.QueryContext(ctx, q, fz.vID)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(h, "\n%s\n", q)
		hashRows(t, h, rows)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func hashRows(t *testing.T, h interface{ Write([]byte) (int, error) }, rows *sql.Rows) {
	t.Helper()
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		for _, v := range vals {
			switch x := v.(type) {
			case []byte:
				fmt.Fprintf(h, "b%d:", len(x))
				_, _ = h.Write(x)
			default:
				fmt.Fprintf(h, "%T:%v", x, x)
			}
			_, _ = h.Write([]byte{0})
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

// TestWrongJWSURLIsNotEchoedInFull: the refusal for a JWS whose "url" is not
// the request's URL is sent before any signature is checked, so it is open
// to everybody; it names the start of the URL, not all 64 KiB of it (the
// same class as TestRefusalsDoNotEchoTheRequest in the jose package).
func TestWrongJWSURLIsNotEchoedInFull(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	url := testBase + "/new-account"
	body := c.jws(url+"/"+strings.Repeat("x", 20000), map[string]any{"termsOfServiceAgreed": true}, true)
	a := c.postRaw(url, body)
	if a.code != http.StatusUnauthorized || a.problem() != "unauthorized" {
		t.Fatalf("%d %s", a.code, a.body)
	}
	if len(a.body) > 1000 {
		t.Errorf("the refusal has %d bytes", len(a.body))
	}
}
