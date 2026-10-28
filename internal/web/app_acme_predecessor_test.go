package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

func TestACMEAccountPredecessorPolicyUI(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.Unseal(t)
	q := pkidb.New(v.Engine.PKI)
	if err := q.InsertACMEAccount(t.Context(), pkidb.InsertACMEAccountParams{
		ID: "acct_policy", KeyThumbprint: "policy-thumbprint", Jwk: `{}`, Status: "valid", Contact: `["mailto:proxy@homelab.lan"]`,
		CreatedAt: "2026-10-22T08:00:00Z", CreatedIp: "192.0.2.10", UpdatedAt: "2026-10-22T08:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	csrf := b.csrf(t)
	page := b.get(t, "/acme/accounts/acct_policy")
	if page.Code != http.StatusOK || !strings.Contains(page.html(), "Multiple hosts sharing this account and name set") || !strings.Contains(page.html(), `value="after" selected`) {
		t.Fatalf("account policy form: %d %s", page.Code, page.html())
	}
	v.Clock.Advance(authz.StepUpWindow + time.Second)
	r := b.post(t, "/acme/accounts/acct_policy/predecessor-policy", url.Values{
		"csrf_token": {csrf}, "predecessor": {"never"}, "predecessor_days": {"7"},
	})
	if r.Code != http.StatusSeeOther || r.location() != "/step-up" {
		t.Fatalf("policy step-up: %d %q", r.Code, r.location())
	}
	challenge := b.get(t, "/step-up").html()
	if !strings.Contains(challenge, "never revoke the predecessor") {
		t.Errorf("summary: %s", challenge)
	}
	if r = confirmPending(t, b, csrf, "demo"); r.Code != http.StatusSeeOther {
		t.Fatalf("continued policy: %d", r.Code)
	}
	account, err := q.GetACMEAccount(t.Context(), "acct_policy")
	if err != nil || account.PredecessorChoice.String != "never" {
		t.Fatalf("stored override: %+v, %v", account, err)
	}
}
