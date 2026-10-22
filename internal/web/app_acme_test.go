package web

import (
	"database/sql"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// TestACMEApprovalPages (PHASE2 step 13): the dashboard counts what waits,
// an admin approves accounts and names and creates an EAB key that is
// shown once; a viewer sees the queues without the forms.
func TestACMEApprovalPages(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.Unseal(t)
	ctx := t.Context()
	q := pkidb.New(v.Engine.PKI)
	if err := q.InsertACMEAccount(ctx, pkidb.InsertACMEAccountParams{
		ID: "acct_waiting", KeyThumbprint: "tp-waiting", Jwk: `{}`, Status: "valid", Contact: `["mailto:nas@homelab.example"]`,
		CreatedAt: "2026-10-22T08:00:00Z", CreatedIp: "192.0.2.10", UpdatedAt: "2026-10-22T08:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := q.RequestACMEName(ctx, pkidb.RequestACMENameParams{Name: "dns:nas.homelab.example", RequestedBy: "acct_waiting", RequestedAt: "2026-10-22T08:01:00Z"}); err != nil {
		t.Fatal(err)
	}

	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	token := b.csrf(t)
	home := b.get(t, "/").html()
	for _, want := range []string{"1 ACME account(s) wait for approval.", "1 new name(s) wait for approval.", `href="/acme/accounts"`, `href="/acme/names"`} {
		if !strings.Contains(home, want) {
			t.Errorf("dashboard lacks %q", want)
		}
	}

	// Accounts: waiting, approved after the form.
	if page := b.get(t, "/acme/accounts").html(); !strings.Contains(page, "acct_waiting") || !strings.Contains(page, "nas@homelab.example") || !strings.Contains(page, "Approve account") {
		t.Errorf("accounts page: %s", page)
	}
	if page := b.get(t, "/acme/accounts/acct_waiting").html(); !strings.Contains(page, "tp-waiting") || !strings.Contains(page, "no – waiting") {
		t.Errorf("account page: %s", page)
	}
	if r := b.get(t, "/acme/accounts/acct_none"); r.Code != http.StatusNotFound {
		t.Errorf("unknown account: %d", r.Code)
	}
	r := b.post(t, "/acme/accounts/approve", url.Values{"csrf_token": {token}, "id": {"acct_waiting"}})
	if r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, "/acme/accounts"), "approved") {
		t.Fatalf("approve: %d", r.Code)
	}
	if a, err := q.GetACMEAccount(ctx, "acct_waiting"); err != nil || !a.ApprovedAt.Valid || a.ApprovedBy.String != "demo" {
		t.Errorf("account after approval: %v %+v", err, a)
	}
	if b.post(t, "/acme/accounts/approve", url.Values{"csrf_token": {token}, "id": {"acct_waiting"}}); !strings.Contains(flashOf(t, b, "/acme/accounts"), "approved already") {
		t.Error("approving twice is not refused")
	}

	// Names: decide, approve in advance, refuse garbage.
	r = b.post(t, "/acme/names/decide", url.Values{"csrf_token": {token}, "name": {"dns:nas.homelab.example"}, "decision": {"refuse"}})
	if r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, "/acme/names"), "refused") {
		t.Errorf("refuse name: %d", r.Code)
	}
	b.post(t, "/acme/names/decide", url.Values{"csrf_token": {token}, "name": {"dns:new.homelab.example"}, "decision": {"approve"}})
	if n, err := q.GetACMEName(ctx, "dns:new.homelab.example"); err != nil || n.Status != "approved" {
		t.Errorf("approve in advance: %v %+v", err, n)
	}
	b.post(t, "/acme/names/decide", url.Values{"csrf_token": {token}, "name": {"<b>nas</b>"}, "decision": {"approve"}})
	if msg := flashOf(t, b, "/acme/names"); !strings.Contains(msg, "is not dns:") || strings.Contains(msg, "<b>") {
		t.Errorf("garbage name: %q", msg)
	}
	if home = b.get(t, "/").html(); strings.Contains(home, "wait for approval") {
		t.Error("the dashboard still counts after the decisions")
	}

	// EAB: shown once, never again.
	r = b.post(t, "/acme/eab", url.Values{"csrf_token": {token}, "label": {"nas.homelab.example"}, "days": {"7"}})
	created := r.html()
	var mac string
	if m := regexp.MustCompile(`MAC key \(base64url\)</dt><dd[^>]*>([A-Za-z0-9_-]{43})<`).FindStringSubmatch(created); m != nil {
		mac = m[1]
	}
	if r.Code != http.StatusOK || r.Header().Get("Cache-Control") != "no-store" || mac == "" || !strings.Contains(created, "--eab-hmac-key "+mac) ||
		!strings.Contains(created, "https://pki.homelab.test/acme/directory") {
		t.Fatalf("new EAB key: %d %q %s", r.Code, r.Header().Get("Cache-Control"), created)
	}
	if list := b.get(t, "/acme/eab").html(); strings.Contains(list, mac) || !strings.Contains(list, "nas.homelab.example") {
		t.Error("the EAB list shows the MAC or misses the key")
	}
	for _, bad := range []url.Values{{"label": {""}, "days": {"7"}}, {"label": {"x"}, "days": {"365"}}, {"label": {"x"}, "days": {"many"}}} {
		bad.Set("csrf_token", token)
		if rr := b.post(t, "/acme/eab", bad); rr.Code != http.StatusSeeOther {
			t.Errorf("bad EAB form %v: %d", bad, rr.Code)
		}
	}
	if page := b.get(t, "/acme/orders"); page.Code != http.StatusOK || !strings.Contains(page.html(), "No orders yet.") {
		t.Errorf("orders: %d", page.Code)
	}

	// A viewer sees the queues, not the forms, and can't approve.
	v.User(t, "viewer", false, authz.Binding{Role: authz.Viewer})
	vw := v.browser("192.0.2.2")
	vw.signIn(t, "viewer", testinstance.Password)
	for _, p := range []string{"/acme/accounts", "/acme/names", "/acme/eab"} {
		if page := vw.get(t, p).html(); strings.Contains(page, `action="/acme/`) {
			t.Errorf("%s offers a form to a viewer", p)
		}
	}
	if q.InsertACMEAccount(ctx, pkidb.InsertACMEAccountParams{ID: "acct_two", KeyThumbprint: "tp-two", Jwk: `{}`, Status: "valid", Contact: `[]`,
		CreatedAt: "2026-10-22T09:00:00Z", CreatedIp: "192.0.2.11", UpdatedAt: "2026-10-22T09:00:00Z"}) != nil {
		t.Fatal("insert")
	}
	vw.post(t, "/acme/accounts/approve", url.Values{"csrf_token": {vw.csrf(t)}, "id": {"acct_two"}})
	if a, _ := q.GetACMEAccount(ctx, "acct_two"); a.ApprovedAt != (sql.NullString{}) {
		t.Error("a viewer approved an account")
	}
	if rr := vw.post(t, "/acme/eab", url.Values{"csrf_token": {vw.csrf(t)}, "label": {"sneaky"}, "days": {"7"}}); strings.Contains(rr.html(), "MAC key") {
		t.Error("a viewer created an EAB key")
	}
	if keys, _ := q.ListACMEEABKeys(ctx, 10); len(keys) != 1 {
		t.Errorf("%d EAB keys, want the admin's one", len(keys))
	}

	// A role on one CA only doesn't show the tenant's ACME accounts.
	v.User(t, "caop", false, authz.Binding{Role: authz.Operator, CA: "issuing"})
	op := v.browser("192.0.2.3")
	op.signIn(t, "caop", testinstance.Password)
	for _, p := range []string{"/acme/accounts", "/acme/names", "/acme/eab", "/acme/orders"} {
		if page := op.get(t, p); page.Code != http.StatusForbidden || strings.Contains(page.html(), "acct_two") {
			t.Errorf("%s for a CA operator: %d", p, page.Code)
		}
	}
}

// TestACMEPagesOff: without acme.base_url the pages say how to switch it on.
func TestACMEPagesOff(t *testing.T) {
	t.Parallel()
	v := newUIEnvWith(t, false)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	for _, p := range []string{"/acme/accounts", "/acme/names", "/acme/eab", "/acme/orders"} {
		if page := b.get(t, p); page.Code != http.StatusOK || !strings.Contains(page.html(), "acme.base_url") {
			t.Errorf("%s: %d", p, page.Code)
		}
	}
}
