package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	agentservice "github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/predecessor"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

func TestRenewalPredecessorUIAndStepUpContinuation(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.Unseal(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	csrf := b.csrf(t)
	issued := stepUpCertificate(t, v, "renew-policy.homelab.lan")
	renewPage := b.get(t, "/certificates/"+issued.ID+"/renew")
	if renewPage.Code != http.StatusOK || !strings.Contains(renewPage.html(), `value="after" selected>Revoke after N days`) || !strings.Contains(renewPage.html(), `name="predecessor_days" value="7"`) {
		t.Fatalf("effective default not preselected: %s", renewPage.html())
	}
	b.v.Clock.Advance(authz.StepUpWindow + time.Second)
	r := b.post(t, "/certificates/"+issued.ID+"/renew", url.Values{
		"csrf_token": {csrf}, "alg": {"ecdsa-p256"}, "predecessor": {"after"}, "predecessor_days": {"3"},
	})
	if r.Code != http.StatusSeeOther || r.location() != "/step-up" {
		t.Fatalf("begin renewal: %d %q", r.Code, r.location())
	}
	challenge := b.get(t, "/step-up")
	if !strings.Contains(challenge.html(), "revoke the predecessor as superseded after 3 days") {
		t.Fatalf("step-up summary: %s", challenge.html())
	}
	r = confirmPending(t, b, csrf, "demo")
	if r.Code != http.StatusSeeOther || !strings.HasPrefix(r.location(), "/certificates/crt_") {
		t.Fatalf("continued renewal: %d %q", r.Code, r.location())
	}
	plan, err := pkidb.New(v.PKIDB.Write).GetRevocationPlan(t.Context(), issued.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := v.Clock.Now().Add(3 * 24 * time.Hour).Format(time.RFC3339)
	if plan.PlannedAt != want {
		t.Errorf("planned at %s, want %s", plan.PlannedAt, want)
	}
	dashboard := b.get(t, "/")
	if !strings.Contains(dashboard.html(), "Revocations due in next 7 days") || !strings.Contains(dashboard.html(), `href="/certificates?status=planned">1</a>`) {
		t.Error("dashboard does not count planned revocations")
	}
	filter := b.get(t, "/certificates?status=planned")
	if !strings.Contains(filter.html(), "Revocation planned · ") || !strings.Contains(filter.html(), "renew-policy.homelab.lan") {
		t.Error("planned filter or status missing")
	}
}

func TestAgentRenewalConfirmationPreselectsEffectivePolicy(t *testing.T) {
	t.Parallel()
	v, svc := newAgentsUIEnv(t)
	secret, _, err := svc.CreateJoinToken(t.Context(), testinstance.Console, "policy", []string{"proxy1.homelab.lan"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	enroll(t, svc, "proxy1.homelab.lan", secret, "0.3.0")
	agents, err := svc.ListAgents(t.Context(), testinstance.Console)
	if err != nil || len(agents) != 1 {
		t.Fatalf("agents: %v", err)
	}
	caller := &agentservice.Caller{Agent: pkidb.Agent{ID: agents[0].ID}, Who: testinstance.Console}
	if err := svc.Report(t.Context(), caller, agentservice.ReportInput{Deployments: []agentservice.DeploymentReport{{Name: "proxy", State: "pending"}}}); err != nil {
		t.Fatal(err)
	}
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	agentPage := b.get(t, "/agents/"+agents[0].ID+"/deployments/proxy/renew")
	if agentPage.Code != http.StatusOK || !strings.Contains(agentPage.html(), `value="now" selected>Revoke now`) {
		t.Fatalf("agent effective default not preselected: %s", agentPage.html())
	}
	agentPolicy := predecessor.Policy{Choice: predecessor.After, Days: 2}
	if err := svc.SetPredecessorPolicy(t.Context(), testinstance.Console, agents[0].ID, "", &agentPolicy); err != nil {
		t.Fatal(err)
	}
	deploymentPolicy := predecessor.Policy{Choice: predecessor.After, Days: 4}
	if err := svc.SetPredecessorPolicy(t.Context(), testinstance.Console, agents[0].ID, "proxy", &deploymentPolicy); err != nil {
		t.Fatal(err)
	}
	agentPage = b.get(t, "/agents/"+agents[0].ID+"/deployments/proxy/renew")
	if !strings.Contains(agentPage.html(), `value="after" selected>Revoke after N days`) || !strings.Contains(agentPage.html(), `name="predecessor_days" value="4"`) {
		t.Fatalf("deployment override not preselected: %s", agentPage.html())
	}
}

func TestPlanCancelUIAndBounds(t *testing.T) {
	t.Parallel()
	v := newUIEnv(t)
	v.Unseal(t)
	b := v.browser("192.0.2.1")
	b.signIn(t, "demo", v.DemoPassword)
	csrf := b.csrf(t)
	issued := stepUpCertificate(t, v, "plan-actions.homelab.lan")
	for _, days := range []string{"0", "-1", "31", "junk"} {
		r := b.post(t, "/certificates/"+issued.ID+"/revocation-plan", url.Values{"csrf_token": {csrf}, "days": {days}})
		if r.Code != http.StatusSeeOther || r.location() != "/certificates/"+issued.ID+"/revocation-plan" {
			t.Fatalf("%s days: %d %q", days, r.Code, r.location())
		}
		if !strings.Contains(flashOf(t, b, r.location()), "1 to 30") {
			t.Errorf("%s days: no validation message", days)
		}
	}
	if _, err := pkidb.New(v.PKIDB.Write).GetRevocationPlan(t.Context(), issued.ID); err == nil {
		t.Fatal("invalid UI input created a plan")
	}

	b.v.Clock.Advance(authz.StepUpWindow + time.Second)
	r := b.post(t, "/certificates/"+issued.ID+"/revocation-plan", url.Values{"csrf_token": {csrf}, "days": {"5"}})
	if r.Code != http.StatusSeeOther || r.location() != "/step-up" {
		t.Fatalf("begin plan: %d %q", r.Code, r.location())
	}
	challenge := b.get(t, "/step-up")
	if !strings.Contains(challenge.html(), "Plan certificate revocation") || !strings.Contains(challenge.html(), "Revocation planned · ") || !strings.Contains(challenge.html(), "superseded") {
		t.Fatalf("plan summary: %s", challenge.html())
	}
	r = confirmPending(t, b, csrf, "demo")
	if r.Code != http.StatusSeeOther || !strings.Contains(flashOf(t, b, r.location()), "Revocation planned") {
		t.Fatalf("continued plan: %d %q", r.Code, r.location())
	}
	if _, err := pkidb.New(v.PKIDB.Write).GetRevocationPlan(t.Context(), issued.ID); err != nil {
		t.Fatal(err)
	}

	b.v.Clock.Advance(authz.StepUpWindow + time.Second)
	r = b.post(t, "/certificates/"+issued.ID+"/revocation-cancel", url.Values{"csrf_token": {csrf}})
	if r.Code != http.StatusSeeOther || r.location() != "/step-up" {
		t.Fatalf("begin cancel: %d %q", r.Code, r.location())
	}
	challenge = b.get(t, "/step-up")
	if !strings.Contains(challenge.html(), "Cancel planned certificate revocation") || !strings.Contains(challenge.html(), "otherwise unchanged") {
		t.Fatalf("cancel summary: %s", challenge.html())
	}
	r = confirmPending(t, b, csrf, "demo")
	if r.Code != http.StatusSeeOther {
		t.Fatalf("continued cancel: %d %q", r.Code, r.location())
	}
	info, err := v.Engine.Certificate(t.Context(), testinstance.Console, issued.ID)
	if err != nil || info.Status != ca.CertValid || info.RevocationPlannedAt != nil {
		t.Fatalf("after cancellation: %+v, %v", info, err)
	}
}
