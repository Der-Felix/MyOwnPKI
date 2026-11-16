package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// auditCount is the number of entries of an action in the tenant's audit
// log (the outbox is delivered first).
func auditCount(t *testing.T, v *env, action string) int {
	t.Helper()
	v.Deliver(t)
	n := 0
	for _, line := range testinstance.Audit(t, v.TenantAudit) {
		if strings.HasPrefix(line, action+"/") {
			n++
		}
	}
	return n
}

// accountRow is the stored account behind the client's kid.
func (c *client) accountRow() pkidb.AcmeAccount {
	c.t.Helper()
	a, err := pkidb.New(c.v.Engine.PKI).GetACMEAccount(c.t.Context(), c.kid[strings.LastIndex(c.kid, "/")+1:])
	if err != nil {
		c.t.Fatal(err)
	}
	return a
}

func contactsOf(a *answer) []string { return strs(a.json["contact"]) }

// TestNewAccountBranches: what newAccount refuses and what it accepts
// (RFC 8555 §7.3): the contact rules, terms, onlyReturnExisting, a payload
// that is no JSON, a request signed with a kid.
func TestNewAccountBranches(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	v.s.opt.Limits = func(context.Context) (Limits, error) {
		return Limits{AccountsPerIP: 1000, OrdersPerAccount: 1000, FailedPerName: 1000}, nil
	} // one address makes all of them
	url := testBase + "/new-account"
	long := "mailto:" + strings.Repeat("a", 250) + "@x.example"
	for name, tc := range map[string]struct {
		payload any
		code    int
		problem string
	}{
		"plain address":               {map[string]any{"contact": []string{"mailto:admin@homelab.lan"}}, http.StatusCreated, ""},
		"no contact at all":           {map[string]any{}, http.StatusCreated, ""},
		"terms not agreed":            {map[string]any{"termsOfServiceAgreed": false}, http.StatusCreated, ""}, // the server publishes no terms
		"five contacts":               {map[string]any{"contact": []string{"mailto:a@x.example", "mailto:b@x.example", "mailto:c@x.example", "mailto:d@x.example", "mailto:e@x.example"}}, http.StatusCreated, ""},
		"six contacts":                {map[string]any{"contact": []string{"mailto:a@x.example", "mailto:b@x.example", "mailto:c@x.example", "mailto:d@x.example", "mailto:e@x.example", "mailto:f@x.example"}}, http.StatusBadRequest, "invalidContact"},
		"telephone":                   {map[string]any{"contact": []string{"tel:+4930123"}}, http.StatusBadRequest, "unsupportedContact"},
		"https URL":                   {map[string]any{"contact": []string{"https://example.com/me"}}, http.StatusBadRequest, "unsupportedContact"},
		"a second contact is a tel":   {map[string]any{"contact": []string{"mailto:a@x.example", "tel:1"}}, http.StatusBadRequest, "unsupportedContact"},
		"hfields in the address":      {map[string]any{"contact": []string{"mailto:a@x.example?subject=hi"}}, http.StatusBadRequest, "invalidContact"},
		"several addresses in one":    {map[string]any{"contact": []string{"mailto:a@x.example,b@x.example"}}, http.StatusBadRequest, "invalidContact"},
		"angle brackets":              {map[string]any{"contact": []string{"mailto:<a@x.example>"}}, http.StatusBadRequest, "invalidContact"},
		"a display name":              {map[string]any{"contact": []string{"mailto:Admin <a@x.example>"}}, http.StatusBadRequest, "invalidContact"},
		"a space":                     {map[string]any{"contact": []string{"mailto:a b@x.example"}}, http.StatusBadRequest, "invalidContact"},
		"empty address":               {map[string]any{"contact": []string{"mailto:"}}, http.StatusBadRequest, "invalidContact"},
		"no at sign":                  {map[string]any{"contact": []string{"mailto:admin"}}, http.StatusBadRequest, "invalidContact"},
		"longer than 254":             {map[string]any{"contact": []string{long}}, http.StatusBadRequest, "invalidContact"},
		"contact is no list":          {map[string]any{"contact": "mailto:a@x.example"}, http.StatusBadRequest, "malformed"},
		"payload is a list":           {[]string{"x"}, http.StatusBadRequest, "malformed"},
		"payload is no JSON":          {rawBytes("not json"), http.StatusBadRequest, "malformed"},
		"no payload":                  {nil, http.StatusBadRequest, "malformed"},
		"onlyReturnExisting, unknown": {map[string]any{"onlyReturnExisting": true}, http.StatusBadRequest, "accountDoesNotExist"},
		"EAB is no object":            {map[string]any{"externalAccountBinding": "x"}, http.StatusBadRequest, "malformed"},
		"EAB of an unknown key":       {map[string]any{"externalAccountBinding": map[string]string{"protected": "e30", "payload": "e30", "signature": "AA"}}, http.StatusBadRequest, "malformed"},
		"EAB null is no EAB":          {map[string]any{"externalAccountBinding": nil}, http.StatusCreated, ""},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c := v.client(t)
			a := c.postRaw(url, c.jws(url, tc.payload, true))
			if a.code != tc.code || a.problem() != tc.problem {
				t.Fatalf("%d %q, want %d %q: %s", a.code, a.problem(), tc.code, tc.problem, a.body)
			}
			if a.code == http.StatusCreated {
				if a.header.Get("Location") == "" || a.json["status"] != "valid" || a.json["orders"] == nil {
					t.Errorf("incomplete account: %v %s", a.header, a.body)
				}
				return
			}
			// A refusal creates nothing: the key has no account.
			c.nonce = "" // the answer's nonce is fine, but start clean
			if again := c.postRaw(url, c.jws(url, map[string]any{"onlyReturnExisting": true}, true)); again.problem() != "accountDoesNotExist" {
				t.Errorf("an account was created by the refused request: %d %s", again.code, again.body)
			}
		})
	}
}

// TestNewAccountExistingKey: a key that has an account gets that account
// (RFC 8555 §7.3.1) – with onlyReturnExisting and without – and no second
// account or audit entry; a kid in newAccount is malformed.
func TestNewAccountExistingKey(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	first := c.register()
	if first.code != http.StatusCreated {
		t.Fatalf("register: %d %s", first.code, first.body)
	}
	url := testBase + "/new-account"
	for name, payload := range map[string]any{
		"onlyReturnExisting": map[string]any{"onlyReturnExisting": true},
		"registering again":  map[string]any{"contact": []string{"mailto:other@homelab.lan"}, "termsOfServiceAgreed": true},
	} {
		a := c.postRaw(url, c.jws(url, payload, true))
		if a.code != http.StatusOK || a.header.Get("Location") != c.kid {
			t.Errorf("%s: %d %v %s", name, a.code, a.header, a.body)
		}
		if !slices.Equal(contactsOf(a), []string{"mailto:admin@homelab.lan"}) {
			t.Errorf("%s: the contacts changed: %s", name, a.body)
		}
	}
	if n := auditCount(t, v, ActionAccountCreate); n != 1 {
		t.Errorf("%d account.create entries, want 1", n)
	}
	// "kid" belongs to resources of an account, not to newAccount.
	if a := c.postRaw(url, c.jws(url, map[string]any{}, false)); a.code != http.StatusBadRequest || a.problem() != "malformed" {
		t.Errorf("kid on newAccount: %d %s", a.code, a.body)
	}
}

// TestNewAccountEABFailures: an account that brings an external binding that
// does not hold gets no account and the key is not spent, so the right
// request works afterwards; sealed, the MAC key can't be read.
func TestNewAccountEABFailures(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalAccount)
	who := testinstance.Console
	key, err := v.s.CreateEABKey(t.Context(), "nas", 7, who)
	if err != nil {
		t.Fatal(err)
	}
	wrong := b64(make([]byte, 32))

	other := v.client(t)
	if a := other.registerEAB("eab_unknown", wrong); a.code != http.StatusUnauthorized || !strings.Contains(string(a.body), "unknown EAB key") {
		t.Errorf("unknown kid: %d %s", a.code, a.body)
	}
	if a := other.registerEAB(key.KID, wrong); a.code != http.StatusUnauthorized {
		t.Errorf("wrong MAC: %d %s", a.code, a.body)
	}
	// A failed binding spends nothing: the right MAC works for the same key.
	c := v.client(t)
	if a := c.registerEAB(key.KID, key.HMAC); a.code != http.StatusCreated {
		t.Fatalf("right MAC after wrong ones: %d %s", a.code, a.body)
	}
	if row := c.accountRow(); !row.ApprovedAt.Valid || row.ApprovedBy.String != "eab:"+key.KID {
		t.Errorf("an EAB account is approved by its key: %+v", row)
	}

	// Sealed: the MAC key is encrypted by the key ring.
	second, err := v.s.CreateEABKey(t.Context(), "web", 7, who)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Ring.Seal(t.Context(), who); err != nil {
		t.Fatal(err)
	}
	if a := v.client(t).registerEAB(second.KID, second.HMAC); a.code != http.StatusServiceUnavailable || a.problem() != "serverInternal" || a.header.Get("Retry-After") == "" {
		t.Errorf("sealed: %d %v %s", a.code, a.header, a.body)
	}
}

// TestAccountUpdate: the contact list of an account (RFC 8555 §7.3.2) –
// replace, clear, leave alone, refuse – and the refusals that leave the row
// as it was.
func TestAccountUpdate(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	c.register()
	updates := 0

	// POST-as-GET reads.
	if a := c.post(c.kid, nil); a.code != http.StatusOK || a.json["status"] != "valid" || !slices.Equal(contactsOf(a), []string{"mailto:admin@homelab.lan"}) {
		t.Fatalf("read: %d %s", a.code, a.body)
	}
	// Replace.
	if a := c.post(c.kid, map[string]any{"contact": []string{"mailto:new@homelab.lan", "mailto:second@homelab.lan"}}); a.code != http.StatusOK || len(contactsOf(a)) != 2 {
		t.Fatalf("replace: %d %s", a.code, a.body)
	}
	updates++
	if got := c.accountRow().Contact; !strings.Contains(got, "new@homelab.lan") || !strings.Contains(got, "second@homelab.lan") {
		t.Errorf("stored contacts: %s", got)
	}
	// An empty list clears.
	if a := c.post(c.kid, map[string]any{"contact": []string{}}); a.code != http.StatusOK || len(contactsOf(a)) != 0 || a.json["contact"] == nil {
		t.Fatalf("clear: %d %s", a.code, a.body)
	}
	updates++
	// A payload without contact and status changes nothing and writes no entry.
	before := c.accountRow()
	if a := c.post(c.kid, map[string]any{"unrelated": 1}); a.code != http.StatusOK || a.json["status"] != "valid" {
		t.Fatalf("no-op: %d %s", a.code, a.body)
	}
	if after := c.accountRow(); after != before {
		t.Errorf("a no-op update changed the row: %+v -> %+v", before, after)
	}

	// Refusals leave the account as it is.
	if a := c.post(c.kid, map[string]any{"contact": []string{"mailto:keep@homelab.lan"}}); a.code != http.StatusOK {
		t.Fatalf("set: %d %s", a.code, a.body)
	}
	updates++
	for name, tc := range map[string]struct {
		payload any
		code    int
		problem string
	}{
		"telephone":              {map[string]any{"contact": []string{"tel:1"}}, http.StatusBadRequest, "unsupportedContact"},
		"six contacts":           {map[string]any{"contact": []string{"mailto:a@x.example", "mailto:b@x.example", "mailto:c@x.example", "mailto:d@x.example", "mailto:e@x.example", "mailto:f@x.example"}}, http.StatusBadRequest, "invalidContact"},
		"status valid":           {map[string]any{"status": "valid"}, http.StatusBadRequest, "malformed"},
		"status revoked":         {map[string]any{"status": "revoked"}, http.StatusBadRequest, "malformed"},
		"status beats contact":   {map[string]any{"status": "pending", "contact": []string{"mailto:x@x.example"}}, http.StatusBadRequest, "malformed"},
		"contact is no list":     {map[string]any{"contact": "mailto:x@x.example"}, http.StatusBadRequest, "malformed"},
		"payload is no JSON":     {rawBytes("nope"), http.StatusBadRequest, "malformed"},
		"payload is a JSON list": {rawBytes("[1]"), http.StatusBadRequest, "malformed"},
	} {
		if a := c.post(c.kid, tc.payload); a.code != tc.code || a.problem() != tc.problem {
			t.Errorf("%s: %d %s", name, a.code, a.body)
		}
	}
	if got := c.accountRow(); got.Contact != `["mailto:keep@homelab.lan"]` || got.Status != "valid" {
		t.Errorf("after the refusals: %+v", got)
	}

	// Another account's URL: an account changes only itself.
	other := v.client(t)
	other.register()
	if a := other.postRaw(c.kid, other.jws(c.kid, map[string]any{"contact": []string{"mailto:evil@x.example"}}, false)); a.code != http.StatusUnauthorized || a.problem() != "unauthorized" {
		t.Errorf("foreign account URL: %d %s", a.code, a.body)
	}
	if a := other.postRaw(c.kid, other.jws(c.kid, nil, false)); a.code != http.StatusUnauthorized {
		t.Errorf("reading a foreign account: %d %s", a.code, a.body)
	}
	if got := c.accountRow().Contact; got != `["mailto:keep@homelab.lan"]` {
		t.Errorf("a foreign request changed the contacts: %s", got)
	}
	if n := auditCount(t, v, ActionAccountUpdate); n != updates {
		t.Errorf("%d account.update entries, want %d", n, updates)
	}
}

// TestAccountDeactivation (RFC 8555 §7.3.6): the account ends, its
// authorizations with it, nothing it signed works any more, a deactivation
// is final, and the key does not bring it back.
func TestAccountDeactivation(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	c.register()
	bystander := v.client(t)
	bystander.register()
	order := c.order("nas.homelab.lan")
	c.solve(order, "http-01")
	theirs := bystander.order("web.homelab.lan")
	pendingAuthz := strs(theirs.json["authorizations"])[0]

	// Status beats contact in one payload: it is a deactivation, the contacts stay.
	a := c.post(c.kid, map[string]any{"status": "deactivated", "contact": []string{"mailto:changed@homelab.lan"}})
	if a.code != http.StatusOK || a.json["status"] != "deactivated" {
		t.Fatalf("deactivate: %d %s", a.code, a.body)
	}
	if row := c.accountRow(); row.Contact != `["mailto:admin@homelab.lan"]` || row.Status != "deactivated" {
		t.Errorf("row after the deactivation: %+v", row)
	}
	q := pkidb.New(v.Engine.PKI)
	for _, az := range strs(order.json["authorizations"]) {
		row, err := q.GetACMEAuthz(t.Context(), az[strings.LastIndex(az, "/")+1:])
		if err != nil || row.Status != "deactivated" {
			t.Errorf("authorization of the account after the deactivation: %v %+v", err, row)
		}
	}
	if row, err := q.GetACMEAuthz(t.Context(), pendingAuthz[strings.LastIndex(pendingAuthz, "/")+1:]); err != nil || row.Status != "pending" {
		t.Errorf("another account's authorization changed: %v %+v", err, row)
	}

	// Everything the account signs is refused now.
	for name, got := range map[string]*answer{
		"read":     c.post(c.kid, nil),
		"update":   c.post(c.kid, map[string]any{"contact": []string{"mailto:a@x.example"}}),
		"again":    c.post(c.kid, map[string]string{"status": "deactivated"}),
		"order":    c.order("db.homelab.lan"),
		"orders":   c.post(c.kid+"/orders", nil),
		"authz":    c.post(strs(order.json["authorizations"])[0], nil),
		"finalize": c.finalize(order, csrFor(t, c.key, "", []string{"nas.homelab.lan"}, nil)),
	} {
		if got.code != http.StatusUnauthorized || got.problem() != "unauthorized" || !strings.Contains(string(got.body), "deactivated") {
			t.Errorf("%s: %d %s", name, got.code, got.body)
		}
	}
	// The key alone does not revive it: newAccount hands back the dead account.
	url := testBase + "/new-account"
	if r := c.postRaw(url, c.jws(url, map[string]any{"termsOfServiceAgreed": true}, true)); r.code != http.StatusOK || r.json["status"] != "deactivated" {
		t.Errorf("registering with the key of a deactivated account: %d %s", r.code, r.body)
	}
	if n := auditCount(t, v, ActionAccountDeactivate); n != 1 {
		t.Errorf("%d account.deactivate entries, want 1", n)
	}
	if n := auditCount(t, v, ActionAccountCreate); n != 2 {
		t.Errorf("%d account.create entries, want 2 (no third)", n)
	}
	// The other account is not touched.
	if got := bystander.post(bystander.kid, nil); got.code != http.StatusOK || got.json["status"] != "valid" {
		t.Errorf("bystander: %d %s", got.code, got.body)
	}
}

// keyChangeBody is the outer payload of a key change: the inner JWS signed
// with newKey, naming the account and the old key unless mutate changes it.
func (c *client) keyChangeBody(newKey *ecdsa.PrivateKey, mutate func(hdr, body map[string]any)) rawBytes {
	c.t.Helper()
	nkj, err := joseKeyFor(&newKey.PublicKey)
	if err != nil {
		c.t.Fatal(err)
	}
	hdr := map[string]any{"alg": "ES256", "url": testBase + "/key-change", "jwk": rawJSON(nkj)}
	body := map[string]any{"account": c.kid, "oldKey": rawJSON(c.jwk)}
	if mutate != nil {
		mutate(hdr, body)
	}
	return rawBytes(signedBody(c.t, newKey, hdr, body))
}

// TestKeyChangeRefusals (RFC 8555 §7.3.5): every refusal leaves the old key
// in force and writes no key-change entry; the one that works changes the
// key and the audit log says from which to which.
func TestKeyChangeRefusals(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	c.register()
	victim := v.client(t)
	victim.register()
	taken := v.client(t) // a key that has an account already
	taken.register()
	url := testBase + "/key-change"
	fresh := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	stranger := fresh()
	wrongOld, _ := joseKeyFor(&stranger.PublicKey)
	thumb := c.accountRow().KeyThumbprint

	for name, tc := range map[string]struct {
		body    func() rawBytes
		code    int
		problem string
		detail  string
	}{
		"the new key has an account": {func() rawBytes { return c.keyChangeBody(taken.key, nil) }, http.StatusConflict, "malformed", "another account already"},
		"the new key is the old key": {func() rawBytes { return c.keyChangeBody(c.key, nil) }, http.StatusConflict, "malformed", "another account already"},
		"the old key is wrong": {func() rawBytes {
			return c.keyChangeBody(fresh(), func(_, b map[string]any) { b["oldKey"] = rawJSON(wrongOld) })
		}, http.StatusBadRequest, "malformed", "oldKey"},
		"the old key is no key": {func() rawBytes {
			return c.keyChangeBody(fresh(), func(_, b map[string]any) { b["oldKey"] = "nope" })
		}, http.StatusBadRequest, "malformed", "oldKey"},
		"the old key is missing": {func() rawBytes {
			return c.keyChangeBody(fresh(), func(_, b map[string]any) { delete(b, "oldKey") })
		}, http.StatusBadRequest, "malformed", "oldKey"},
		"another account": {func() rawBytes {
			return c.keyChangeBody(fresh(), func(_, b map[string]any) { b["account"] = victim.kid })
		}, http.StatusBadRequest, "malformed", "account must be"},
		"no account": {func() rawBytes {
			return c.keyChangeBody(fresh(), func(_, b map[string]any) { delete(b, "account") })
		}, http.StatusBadRequest, "malformed", "account must be"},
		"the inner URL is another": {func() rawBytes {
			return c.keyChangeBody(fresh(), func(h, _ map[string]any) { h["url"] = testBase + "/new-order" })
		}, http.StatusBadRequest, "malformed", "same url"},
		"the inner JWS has a nonce": {func() rawBytes {
			return c.keyChangeBody(fresh(), func(h, _ map[string]any) { h["nonce"] = "abc" })
		}, http.StatusBadRequest, "malformed", ""},
		"the inner JWS has a kid": {func() rawBytes {
			return c.keyChangeBody(fresh(), func(h, _ map[string]any) { delete(h, "jwk"); h["kid"] = c.kid })
		}, http.StatusBadRequest, "malformed", "kid"},
		"the inner algorithm is none": {func() rawBytes {
			return c.keyChangeBody(fresh(), func(h, _ map[string]any) { h["alg"] = "none" })
		}, http.StatusBadRequest, "badSignatureAlgorithm", ""},
		"the inner algorithm does not fit the key": {func() rawBytes {
			return c.keyChangeBody(fresh(), func(h, _ map[string]any) { h["alg"] = "ES384" })
		}, http.StatusBadRequest, "badSignatureAlgorithm", ""},
		"the inner signature is of another key": {func() rawBytes {
			// The inner JWK names one key, another one signs.
			k := fresh()
			kj, _ := joseKeyFor(&k.PublicKey)
			hdr := map[string]any{"alg": "ES256", "url": url, "jwk": rawJSON(kj)}
			return rawBytes(signedBody(t, stranger, hdr, map[string]any{"account": c.kid, "oldKey": rawJSON(c.jwk)}))
		}, http.StatusUnauthorized, "unauthorized", ""},
		"the inner payload is no JSON": {func() rawBytes {
			k := fresh()
			kj, _ := joseKeyFor(&k.PublicKey)
			return rawBytes(signedBody(t, k, map[string]any{"alg": "ES256", "url": url, "jwk": rawJSON(kj)}, rawBytes("nope")))
		}, http.StatusBadRequest, "malformed", "inner payload"},
		"the payload is no JWS":   {func() rawBytes { return rawBytes(`{"x":1}`) }, http.StatusBadRequest, "malformed", ""},
		"the payload is empty":    {func() rawBytes { return nil }, http.StatusBadRequest, "malformed", ""},
		"the payload is a string": {func() rawBytes { return rawBytes(`"abc"`) }, http.StatusBadRequest, "malformed", ""},
	} {
		a := c.post(url, tc.body())
		if a.code != tc.code || a.problem() != tc.problem || !strings.Contains(string(a.body), tc.detail) {
			t.Errorf("%s: %d %s", name, a.code, a.body)
		}
		if tc.code == http.StatusConflict && a.header.Get("Location") == "" {
			t.Errorf("%s: no Location of the account that holds the key", name)
		}
	}
	if got := c.accountRow().KeyThumbprint; got != thumb {
		t.Errorf("a refused key change changed the key: %s -> %s", thumb, got)
	}
	if a := c.order("nas.homelab.lan"); a.code != http.StatusCreated {
		t.Errorf("the old key after the refusals: %d %s", a.code, a.body)
	}
	if n := auditCount(t, v, ActionAccountKeyChange); n != 0 {
		t.Errorf("%d key-change entries after refusals only", n)
	}

	// And the change that is allowed.
	newKey := fresh()
	if a := c.post(url, c.keyChangeBody(newKey, nil)); a.code != http.StatusOK {
		t.Fatalf("key change: %d %s", a.code, a.body)
	}
	if got := c.accountRow().KeyThumbprint; got == thumb {
		t.Error("the key did not change")
	}
	v.Deliver(t)
	rows, err := v.TenantAudit.Read.QueryContext(t.Context(), `SELECT details_json FROM audit_entries WHERE action = ?`, ActionAccountKeyChange)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var details []string
	for rows.Next() {
		var d string
		if serr := rows.Scan(&d); serr != nil {
			t.Fatal(serr)
		}
		details = append(details, d)
	}
	if rerr := rows.Err(); rerr != nil {
		t.Fatal(rerr)
	}
	if len(details) != 1 {
		t.Fatalf("%d key-change entries, want 1", len(details))
	}
	var d map[string]any
	if err := json.Unmarshal([]byte(details[0]), &d); err != nil || d["old_thumbprint"] != thumb || d["new_thumbprint"] == thumb || d["new_thumbprint"] == "" {
		t.Errorf("key-change details: %v %v", err, details[0])
	}
	// The account has the new key now; a request signed with the old one fails.
	if a := c.post(url, c.keyChangeBody(taken.key, nil)); a.code != http.StatusUnauthorized {
		t.Errorf("signing with the old key after the change: %d %s", a.code, a.body)
	}
}

// TestAccountOrders (RFC 8555 §7.1.2.1): the list of an account – newest
// first, only its own, an empty list as [] – and the refusal of another
// account's list.
func TestAccountOrders(t *testing.T) {
	t.Parallel()
	v := newEnv(t, ca.ApprovalOpen)
	c := v.client(t)
	c.register()
	other := v.client(t)
	other.register()
	list := func(cl *client) []string {
		t.Helper()
		a := cl.post(cl.kid+"/orders", nil)
		if a.code != http.StatusOK {
			t.Fatalf("orders: %d %s", a.code, a.body)
		}
		if a.json["orders"] == nil {
			t.Fatalf("no orders member: %s", a.body)
		}
		return strs(a.json["orders"])
	}
	if got := list(c); len(got) != 0 {
		t.Fatalf("a new account has orders: %v", got)
	}
	var mine []string
	for _, name := range []string{"a.homelab.lan", "b.homelab.lan", "c.homelab.lan"} {
		o := c.order(name)
		if o.code != http.StatusCreated {
			t.Fatalf("order: %d %s", o.code, o.body)
		}
		mine = append(mine, o.header.Get("Location"))
		v.Clock.Advance(time.Minute) // created_at has a resolution of a second
	}
	theirs := other.order("d.homelab.lan").header.Get("Location")
	slices.Reverse(mine)
	if got := list(c); !slices.Equal(got, mine) {
		t.Errorf("own orders, newest first: %v, want %v", got, mine)
	}
	if got := list(other); !slices.Equal(got, []string{theirs}) {
		t.Errorf("the other account's orders: %v, want %v", got, theirs)
	}
	// Reading another account's list, with or without a body.
	for name, payload := range map[string]any{"POST-as-GET": nil, "with a body": map[string]any{}} {
		if a := other.postRaw(c.kid+"/orders", other.jws(c.kid+"/orders", payload, false)); a.code != http.StatusUnauthorized || a.problem() != "unauthorized" {
			t.Errorf("%s: another account's list: %d %s", name, a.code, a.body)
		}
	}
	// A kid that is not the account's URL for this path is unauthorized too.
	if a := c.postRaw(other.kid+"/orders", c.jws(other.kid+"/orders", nil, false)); a.code != http.StatusUnauthorized {
		t.Errorf("own signature, other path: %d %s", a.code, a.body)
	}
}
