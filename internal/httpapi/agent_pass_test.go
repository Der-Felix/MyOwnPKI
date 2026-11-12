package httpapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/http"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// tokenFor creates an API token with one tenant-wide role for the signed-in
// admin and returns its Authorization header.
func tokenFor(t *testing.T, admin *client, role string) []string {
	t.Helper()
	admin.stepUp(t, "demo")
	r := admin.do(t, http.MethodPost, "/tokens", map[string]any{
		"name": "pin-" + role, "expires_at": admin.v.clk.Now().Add(24 * time.Hour).Format(time.RFC3339),
		"roles": []map[string]any{{"role": role, "scope": map[string]string{"type": "tenant"}}},
	})
	secret, _ := r.body["secret"].(string)
	if r.Code != http.StatusCreated || secret == "" {
		t.Fatalf("token %s: %d %s", role, r.Code, r.Body.String())
	}
	return []string{"Authorization", "Bearer " + secret}
}

// TestAPITokensCannotMintOrAdmitHosts pins the design of docs/PHASE3.md
// section 11: an API token, whatever its role, never creates, withdraws or
// revokes a join token or an enrollment pass and never decides an
// enrollment. agent.manage needs a person with a fresh second factor; the
// automation that consumes a pass holds a viewer token at most.
func TestAPITokensCannotMintOrAdmitHosts(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.unseal(t)
	admin := v.client("192.0.2.1")
	admin.signIn(t, "demo", v.demoPass)

	// Something to act on: a waiting enrollment and a join token.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	enr, err := v.agents.Enroll(t.Context(), agents.EnrollInput{Hostname: "waiting.homelab.lan", Method: agents.MethodWebroot, SourceIP: "192.0.2.50", CSRDER: csr})
	if err != nil {
		t.Fatal(err)
	}
	_, jt, err := v.agents.CreateJoinToken(t.Context(), testinstance.Console, "pinned", []string{"pinned.homelab.lan"}, 0)
	if err != nil {
		t.Fatal(err)
	}

	passBody := map[string]any{"kind": "pass", "label": "rollout", "names": []string{"*.homelab.lan"}, "max_uses": 5, "valid_hours": 2}
	tokenBody := map[string]any{"label": "one", "names": []string{"one.homelab.lan"}, "valid_hours": 2}
	for _, role := range []string{"viewer", "operator", "admin"} {
		header := tokenFor(t, admin, role)
		bot := v.client("192.0.2.77")
		for _, tc := range []struct {
			name, method, path string
			body               any
		}{
			{"create a join token", http.MethodPost, "/agent-join-tokens", tokenBody},
			{"create an enrollment pass", http.MethodPost, "/agent-join-tokens", passBody},
			{"withdraw a join token", http.MethodDelete, "/agent-join-tokens/" + jt.ID, nil},
			{"revoke a join token or pass", http.MethodPost, "/agent-join-tokens/" + jt.ID + "/revoke", nil},
			{"approve an enrollment", http.MethodPost, "/agent-enrollments/" + enr.ID + "/approve", nil},
			{"refuse an enrollment", http.MethodPost, "/agent-enrollments/" + enr.ID + "/deny", nil},
		} {
			r := bot.do(t, tc.method, tc.path, tc.body, header...)
			const want = "an API token can't manage agents – sign in and confirm with a fresh code"
			if r.Code != http.StatusForbidden || r.problemType() != "forbidden" || r.body["detail"] != want {
				t.Errorf("%s token, %s: %d %s", role, tc.name, r.Code, r.Body.String())
			}
		}
	}

	// Nothing happened: the join token is still there and usable, the
	// enrollment still waits, and no pass exists.
	list, err := v.agents.ListJoinTokens(t.Context(), testinstance.Console)
	if err != nil || len(list) != 1 || list[0].ID != jt.ID || !list[0].Usable(v.clk.Now()) {
		t.Errorf("join tokens after the refusals: %+v %v", list, err)
	}
	open, err := v.agents.ListEnrollments(t.Context(), testinstance.Console, true)
	if err != nil || len(open) != 1 || open[0].ID != enr.ID {
		t.Errorf("enrollments after the refusals: %+v %v", open, err)
	}
}

// TestPassNeedsAFreshSecondFactor: a signed-in admin without a fresh second
// factor is asked for it (step-up-required, not forbidden); the same request
// with one is created and returns the secret once.
func TestPassNeedsAFreshSecondFactor(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.unseal(t)
	admin := v.client("192.0.2.1")
	admin.signIn(t, "demo", v.demoPass)
	v.clk.Advance(authz.StepUpWindow + time.Second)

	passBody := map[string]any{"kind": "pass", "label": "rollout", "names": []string{"*.homelab.lan"}, "max_uses": 5, "valid_hours": 2}
	r := admin.do(t, http.MethodPost, "/agent-join-tokens", passBody)
	if r.Code != http.StatusForbidden || r.problemType() != "step-up-required" {
		t.Fatalf("pass without a fresh second factor: %d %s", r.Code, r.Body.String())
	}
	if list, err := v.agents.ListJoinTokens(t.Context(), testinstance.Console); err != nil || len(list) != 0 {
		t.Errorf("a pass exists after the refusal: %+v %v", list, err)
	}
	r = admin.do(t, http.MethodPost, "/agent-join-tokens/jtk_doesnotexist0000000/revoke", nil)
	if r.Code != http.StatusForbidden || r.problemType() != "step-up-required" {
		t.Errorf("revoke without a fresh second factor: %d %s", r.Code, r.Body.String())
	}
}
