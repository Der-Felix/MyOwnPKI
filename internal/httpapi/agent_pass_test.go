package httpapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
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

// TestEnrollmentPassOverTheAPI follows a pass the way a roll-out does: an
// admin with a fresh second factor creates it and sees the secret once; a
// viewer token (the automation) reads the list, the host and its enrollment
// but never the secret; a host enrolls with the pass; the admin revokes it
// and the next host is turned away.
func TestEnrollmentPassOverTheAPI(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.unseal(t)
	ctx := t.Context()
	console := testinstance.Console
	if _, err := v.engine.CreateIntermediate(ctx, ca.IntermediateRequest{
		CASettings: ca.CASettings{Name: "agent-ca", BaseURL: "http://pki.homelab.lan"}, Parent: "root",
		Subject: ca.Subject{CommonName: "Agent CA"}, EKULimit: []string{"clientAuth"}, Who: console,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.engine.CreateDomain(ctx, ca.DomainRequest{Name: "homelab.lan", DomainSettings: ca.DomainSettings{CA: ptrTo("issuing")}, Who: console}); err != nil {
		t.Fatal(err)
	}
	admin := v.client("192.0.2.1")
	admin.signIn(t, "demo", v.demoPass)
	admin.stepUp(t, "demo")
	viewerHeader := tokenFor(t, admin, "viewer")
	admin.stepUp(t, "demo")

	created := admin.do(t, http.MethodPost, "/agent-join-tokens", map[string]any{
		"kind": "pass", "label": "salt rollout", "names": []string{"*.homelab.lan"}, "max_uses": 2, "valid_hours": 4,
	})
	secret, _ := created.body["secret"].(string)
	id, _ := created.body["id"].(string)
	if created.Code != http.StatusCreated || !strings.HasPrefix(secret, agents.PassPrefix) || created.body["kind"] != "pass" || created.body["max_uses"] != float64(2) ||
		created.body["state"] != "active" || created.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}

	bot := v.client("192.0.2.77")
	list := bot.do(t, http.MethodGet, "/agent-join-tokens", nil, viewerHeader...)
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), secret) || strings.Contains(list.Body.String(), secret[len(agents.PassPrefix):]) || strings.Contains(list.Body.String(), "secret") {
		t.Fatalf("list as a viewer token: %d %s", list.Code, list.Body.String())
	}

	enroll := func(host string) *agents.Status {
		t.Helper()
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		out, err := v.agents.Enroll(ctx, agents.EnrollInput{Hostname: host, Token: secret, Method: agents.MethodWebroot, SourceIP: "192.0.2.50", CSRDER: csr})
		if err != nil {
			t.Fatal(err)
		}
		st, err := v.agents.EnrollStatus(ctx, agents.StatusInput{ID: out.ID, Handle: out.Handle, CheckReady: true, SourceIP: "192.0.2.50"})
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	if st := enroll("minion-01.homelab.lan"); st.State != agents.StateAdmitted {
		t.Fatalf("first host: %s %s", st.State, st.Message)
	}

	// The automation checks on the host it rolled out with a viewer token.
	hosts := bot.do(t, http.MethodGet, "/agents?hostname=Minion-01.homelab.lan", nil, viewerHeader...)
	var agentList []any
	if err := json.Unmarshal(hosts.Body.Bytes(), &agentList); err != nil || hosts.Code != http.StatusOK || len(agentList) != 1 {
		t.Fatalf("agents of the host: %d %s", hosts.Code, hosts.Body.String())
	}
	if other := bot.do(t, http.MethodGet, "/agents?hostname=other.homelab.lan", nil, viewerHeader...); other.Body.String() != "[]\n" && other.Body.String() != "[]" {
		t.Errorf("agents of another host: %s", other.Body.String())
	}
	enrollments := bot.do(t, http.MethodGet, "/agent-enrollments?state=all&hostname=minion-01.homelab.lan", nil, viewerHeader...)
	var enrollmentList []any
	if err := json.Unmarshal(enrollments.Body.Bytes(), &enrollmentList); err != nil || enrollments.Code != http.StatusOK || len(enrollmentList) != 1 {
		t.Fatalf("enrollments of the host: %d %s", enrollments.Code, enrollments.Body.String())
	}

	// The pass lists the host it admitted.
	list = bot.do(t, http.MethodGet, "/agent-join-tokens", nil, viewerHeader...)
	var tokens []map[string]any
	if err := json.Unmarshal(list.Body.Bytes(), &tokens); err != nil || len(tokens) != 1 || tokens[0]["use_count"] != float64(1) {
		t.Fatalf("list after a use: %d %s", list.Code, list.Body.String())
	}
	hs, _ := tokens[0]["hosts"].([]any)
	first := map[string]any{}
	if len(hs) == 1 {
		first, _ = hs[0].(map[string]any)
	}
	if len(hs) != 1 || first["hostname"] != "minion-01.homelab.lan" || first["state"] != "admitted" || first["agent_id"] == nil {
		t.Errorf("hosts of the pass: %v", tokens[0]["hosts"])
	}

	// Revoke: the agent it admitted stays, the next host is turned away.
	admin.stepUp(t, "demo")
	revoked := admin.do(t, http.MethodPost, "/agent-join-tokens/"+id+"/revoke", nil)
	if revoked.Code != http.StatusOK || revoked.body["state"] != "revoked" || revoked.body["revoked_by"] == "" {
		t.Fatalf("revoke: %d %s", revoked.Code, revoked.Body.String())
	}
	if st := enroll("minion-02.homelab.lan"); st.State != agents.StatePending || !strings.Contains(st.Message, "the pass was revoked") {
		t.Errorf("host after the revocation: %s %s", st.State, st.Message)
	}
	if hosts = bot.do(t, http.MethodGet, "/agents?hostname=minion-01.homelab.lan", nil, viewerHeader...); !strings.Contains(hosts.Body.String(), `"status":"active"`) {
		t.Errorf("the admitted agent after the revocation: %s", hosts.Body.String())
	}

	// Audit: create, use and revoke are there, the secret is nowhere.
	v.deliver(t)
	got := strings.Join(v.audit(t, v.ta), " ")
	for _, want := range []string{"agent.token.create/success", "agent.enroll/success", "agent.token.revoke/success"} {
		if !strings.Contains(got, want) {
			t.Errorf("tenant audit lacks %s: %s", want, got)
		}
	}
	var details strings.Builder
	rows, err := v.ta.Read.QueryContext(ctx, `SELECT details_json || target_id FROM audit_entries`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		details.WriteString(s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(details.String(), secret[len(agents.PassPrefix):]) || strings.Contains(v.logs.String(), secret[len(agents.PassPrefix):]) {
		t.Error("the pass secret is in the audit log or the log")
	}
}

func ptrTo[T any](v T) *T { return &v }
