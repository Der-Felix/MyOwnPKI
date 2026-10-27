package agents

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/predecessor"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

func predecessorAccount(t *testing.T, e *env, agentID string) string {
	t.Helper()
	id := "acct-" + agentID
	stamp := dbTime(e.inst.Clock.Now())
	q := pkidb.New(e.s.PKI)
	if err := q.InsertACMEAccount(t.Context(), pkidb.InsertACMEAccountParams{
		ID: id, KeyThumbprint: id, Jwk: "{}", Status: "valid", Contact: "[]", CreatedAt: stamp, UpdatedAt: stamp,
	}); err != nil {
		t.Fatal(err)
	}
	if err := q.BindACMEAccount(t.Context(), pkidb.BindACMEAccountParams{AgentID: nullString(agentID), UpdatedAt: stamp, ID: id}); err != nil {
		t.Fatal(err)
	}
	return id
}

func predecessorCertificate(t *testing.T, e *env, account string, names ...string) *ca.Issued {
	t.Helper()
	e.inst.Clock.Advance(time.Second)
	issued := predecessorBareCertificate(t, e, names...)
	predecessorLink(t, e, account, issued, names...)
	return issued
}

func predecessorBareCertificate(t *testing.T, e *env, names ...string) *ca.Issued {
	t.Helper()
	issued, err := e.inst.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: names, Who: testinstance.Console})
	if err != nil {
		t.Fatal(err)
	}
	return issued
}

func predecessorLink(t *testing.T, e *env, account string, issued *ca.Issued, names ...string) {
	t.Helper()
	identifiers := make([]map[string]string, 0, len(names))
	for _, name := range names {
		identifiers = append(identifiers, map[string]string{"type": "dns", "value": name})
	}
	raw, _ := json.Marshal(identifiers)
	stamp := dbTime(e.inst.Clock.Now())
	q := pkidb.New(e.s.PKI)
	orderID := "ord-" + issued.ID
	if orderErr := q.InsertACMEOrder(t.Context(), pkidb.InsertACMEOrderParams{
		ID: orderID, AccountID: account, Status: "processing", Identifiers: string(raw), ExpiresAt: dbTime(e.inst.Clock.Now().Add(time.Hour)),
		CreatedAt: stamp, UpdatedAt: stamp,
	}); orderErr != nil {
		t.Fatal(orderErr)
	}
	n, err := q.SetACMEOrderValid(t.Context(), pkidb.SetACMEOrderValidParams{CertificateID: sql.NullString{String: issued.ID, Valid: true}, UpdatedAt: stamp, ID: orderID})
	if err != nil || n != 1 {
		t.Fatalf("order link %d: %v", n, err)
	}
}

func deploymentResult(cert *ca.Issued, state string, names ...string) DeploymentReport {
	return DeploymentReport{Name: "proxy", Names: names, State: state, Serial: cert.SerialHex, Fingerprint: cert.Fingerprint, CheckConfigured: true}
}

func revokedReason(t *testing.T, e *env, id string) string {
	t.Helper()
	row, err := pkidb.New(e.s.PKI).GetRevocation(t.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return row.Reason
}

func plannedTime(t *testing.T, e *env, id string) time.Time {
	t.Helper()
	row, err := pkidb.New(e.s.PKI).GetRevocationPlan(t.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}
	}
	if err != nil {
		t.Fatal(err)
	}
	return parseTime(row.PlannedAt)
}

func TestAgentImmediateIncludesDiscardedAndIsIdempotent(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	caller := agentCaller(t, e, "proxy1.homelab.lan")
	account := predecessorAccount(t, e, caller.Agent.ID)
	old := predecessorCertificate(t, e, account, "www.homelab.lan")
	discarded := predecessorCertificate(t, e, account, "www.homelab.lan")
	current := predecessorCertificate(t, e, account, "www.homelab.lan")
	report := ReportInput{Deployments: []DeploymentReport{deploymentResult(current, "deployed", "www.homelab.lan")}}
	for range 2 {
		if err := e.s.Report(t.Context(), caller, report); err != nil {
			t.Fatal(err)
		}
	}
	for _, cert := range []*ca.Issued{old, discarded} {
		if got := revokedReason(t, e, cert.ID); got != ca.ReasonSuperseded {
			t.Errorf("predecessor %s reason %q", cert.ID, got)
		}
	}
	if got := revokedReason(t, e, current.ID); got != "" {
		t.Errorf("current revoked %q", got)
	}
	if got := plannedTime(t, e, current.ID); !got.IsZero() {
		t.Errorf("unchanged serial created a plan at %v", got)
	}
	n, err := pkidb.New(e.s.PKI).CountAgentDeploymentHistory(t.Context(), pkidb.CountAgentDeploymentHistoryParams{AgentID: caller.Agent.ID, Deployment: "proxy", CertificateID: current.ID})
	if err != nil || n != 1 {
		t.Fatalf("history %d: %v", n, err)
	}
}

func TestAgentDelayStartsAtDeployedAndFailuresDoNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	e.s.AgentPredecessor = func(context.Context) (predecessor.Policy, error) {
		return predecessor.Policy{Choice: predecessor.After, Days: 2}, nil
	}
	caller := agentCaller(t, e, "proxy1.homelab.lan")
	account := predecessorAccount(t, e, caller.Agent.ID)
	old := predecessorCertificate(t, e, account, "www.homelab.lan")
	failed := predecessorCertificate(t, e, account, "www.homelab.lan")
	if err := e.s.Report(t.Context(), caller, ReportInput{Deployments: []DeploymentReport{deploymentResult(failed, "failed", "www.homelab.lan")}}); err != nil {
		t.Fatal(err)
	}
	rolledBack := predecessorCertificate(t, e, account, "www.homelab.lan")
	if err := e.s.Report(t.Context(), caller, ReportInput{Deployments: []DeploymentReport{deploymentResult(rolledBack, "rolled_back", "www.homelab.lan")}}); err != nil {
		t.Fatal(err)
	}
	for _, cert := range []*ca.Issued{old, failed, rolledBack} {
		if got := revokedReason(t, e, cert.ID); got != "" || !plannedTime(t, e, cert.ID).IsZero() {
			t.Fatalf("failed/rollback action on %s: %q %v", cert.ID, got, plannedTime(t, e, cert.ID))
		}
	}
	current := predecessorCertificate(t, e, account, "www.homelab.lan")
	deployedAt := e.inst.Clock.Now().Truncate(time.Second)
	report := ReportInput{Deployments: []DeploymentReport{deploymentResult(current, "deployed", "www.homelab.lan")}}
	if err := e.s.Report(t.Context(), caller, report); err != nil {
		t.Fatal(err)
	}
	for _, cert := range []*ca.Issued{old, failed, rolledBack} {
		want := deployedAt.Add(48 * time.Hour)
		if got := plannedTime(t, e, cert.ID); !got.Equal(want) {
			t.Errorf("plan for %s = %v, want %v", cert.ID, got, want)
		}
	}
	e.inst.Clock.Advance(24 * time.Hour)
	if err := e.s.Report(t.Context(), caller, report); err != nil {
		t.Fatal(err)
	}
	if got := plannedTime(t, e, old.ID); !got.Equal(deployedAt.Add(48 * time.Hour)) {
		t.Errorf("repeated report moved plan to %v", got)
	}
}

func TestAgentNeverAndCurrentServingExclusion(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	caller := agentCaller(t, e, "proxy1.homelab.lan")
	account := predecessorAccount(t, e, caller.Agent.ID)
	serving := predecessorCertificate(t, e, account, "www.homelab.lan")
	discarded := predecessorCertificate(t, e, account, "www.homelab.lan")
	current := predecessorCertificate(t, e, account, "www.homelab.lan")
	other := deploymentResult(serving, "deployed", "www.homelab.lan")
	other.Name = "other"
	report := ReportInput{Deployments: []DeploymentReport{other, deploymentResult(current, "deployed", "www.homelab.lan")}}
	if err := e.s.Report(t.Context(), caller, report); err != nil {
		t.Fatal(err)
	}
	if got := revokedReason(t, e, serving.ID); got != "" {
		t.Errorf("currently serving revoked %q", got)
	}
	if got := revokedReason(t, e, discarded.ID); got != ca.ReasonSuperseded {
		t.Errorf("discarded reason %q", got)
	}

	never := predecessor.Policy{Choice: predecessor.Never}
	if err := e.s.SetPredecessorPolicy(t.Context(), testinstance.Console, caller.Agent.ID, "proxy", &never); err != nil {
		t.Fatal(err)
	}
	older := predecessorCertificate(t, e, account, "www.homelab.lan")
	newer := predecessorCertificate(t, e, account, "www.homelab.lan")
	if err := e.s.Report(t.Context(), caller, ReportInput{Deployments: []DeploymentReport{other, deploymentResult(newer, "deployed", "www.homelab.lan")}}); err != nil {
		t.Fatal(err)
	}
	if got := revokedReason(t, e, older.ID); got != "" || !plannedTime(t, e, older.ID).IsZero() {
		t.Errorf("never choice acted: %q %v", got, plannedTime(t, e, older.ID))
	}
}

func TestAgentAmbiguousMappingsDoNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	caller := agentCaller(t, e, "proxy1.homelab.lan")
	account := predecessorAccount(t, e, caller.Agent.ID)
	old := predecessorCertificate(t, e, account, "www.homelab.lan")
	current := predecessorCertificate(t, e, account, "www.homelab.lan")
	result := deploymentResult(current, "deployed", "www.homelab.lan")
	result.Fingerprint = ""
	if err := e.s.Report(t.Context(), caller, ReportInput{Deployments: []DeploymentReport{result}}); err != nil {
		t.Fatal(err)
	}
	if got := revokedReason(t, e, old.ID); got != "" {
		t.Errorf("empty fingerprint revoked %q", got)
	}
	result = deploymentResult(current, "deployed", "different.homelab.lan")
	if err := e.s.Report(t.Context(), caller, ReportInput{Deployments: []DeploymentReport{result}}); err != nil {
		t.Fatal(err)
	}
	if got := revokedReason(t, e, old.ID); got != "" {
		t.Errorf("name mismatch revoked %q", got)
	}
}

func TestAgentMissingOrderTimestampTieAndOtherAccount(t *testing.T) {
	t.Parallel()
	t.Run("missing current order", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, tenant.EnrollAuto)
		caller := agentCaller(t, e, "proxy1.homelab.lan")
		account := predecessorAccount(t, e, caller.Agent.ID)
		old := predecessorCertificate(t, e, account, "www.homelab.lan")
		current := predecessorBareCertificate(t, e, "www.homelab.lan")
		if err := e.s.Report(t.Context(), caller, ReportInput{Deployments: []DeploymentReport{deploymentResult(current, "deployed", "www.homelab.lan")}}); err != nil {
			t.Fatal(err)
		}
		if got := revokedReason(t, e, old.ID); got != "" {
			t.Errorf("missing order revoked %q", got)
		}
	})
	t.Run("timestamp tie", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, tenant.EnrollAuto)
		caller := agentCaller(t, e, "proxy1.homelab.lan")
		account := predecessorAccount(t, e, caller.Agent.ID)
		old := predecessorCertificate(t, e, account, "www.homelab.lan")
		current := predecessorBareCertificate(t, e, "www.homelab.lan")
		predecessorLink(t, e, account, current, "www.homelab.lan")
		if err := e.s.Report(t.Context(), caller, ReportInput{Deployments: []DeploymentReport{deploymentResult(current, "deployed", "www.homelab.lan")}}); err != nil {
			t.Fatal(err)
		}
		if got := revokedReason(t, e, old.ID); got != "" {
			t.Errorf("timestamp tie revoked %q", got)
		}
	})
	t.Run("other account", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, tenant.EnrollAuto)
		caller := agentCaller(t, e, "proxy1.homelab.lan")
		account := predecessorAccount(t, e, caller.Agent.ID)
		stamp := dbTime(e.inst.Clock.Now())
		if err := pkidb.New(e.s.PKI).InsertACMEAccount(t.Context(), pkidb.InsertACMEAccountParams{
			ID: "acct-foreign", KeyThumbprint: "acct-foreign", Jwk: "{}", Status: "valid", Contact: "[]", CreatedAt: stamp, UpdatedAt: stamp,
		}); err != nil {
			t.Fatal(err)
		}
		old := predecessorCertificate(t, e, "acct-foreign", "www.homelab.lan")
		current := predecessorCertificate(t, e, account, "www.homelab.lan")
		if err := e.s.Report(t.Context(), caller, ReportInput{Deployments: []DeploymentReport{deploymentResult(current, "deployed", "www.homelab.lan")}}); err != nil {
			t.Fatal(err)
		}
		if got := revokedReason(t, e, old.ID); got != "" {
			t.Errorf("other account certificate revoked %q", got)
		}
	})
}

func TestAgentPolicyOverridesAndOneOperationSnapshot(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	caller := agentCaller(t, e, "proxy1.homelab.lan")
	if err := e.s.Report(t.Context(), caller, ReportInput{Deployments: []DeploymentReport{{Name: "proxy", State: "pending"}}}); err != nil {
		t.Fatal(err)
	}
	agentPolicy := predecessor.Policy{Choice: predecessor.After, Days: 5}
	if err := e.s.SetPredecessorPolicy(t.Context(), testinstance.Console, caller.Agent.ID, "", &agentPolicy); err != nil {
		t.Fatal(err)
	}
	never := predecessor.Policy{Choice: predecessor.Never}
	if err := e.s.SetPredecessorPolicy(t.Context(), testinstance.Console, caller.Agent.ID, "proxy", &never); err != nil {
		t.Fatal(err)
	}
	if err := e.s.RequestRenewal(t.Context(), testinstance.Console, caller.Agent.ID, "proxy"); err != nil {
		t.Fatal(err)
	}
	q := pkidb.New(e.s.PKI)
	row, err := q.GetAgentDeployment(t.Context(), pkidb.GetAgentDeploymentParams{AgentID: caller.Agent.ID, Name: "proxy"})
	if err != nil || row.RenewPredecessorChoice.String != predecessor.Never {
		t.Fatalf("effective snapshot %+v: %v", row, err)
	}
	if withdrawErr := e.s.WithdrawRenewal(t.Context(), testinstance.Console, caller.Agent.ID, "proxy"); withdrawErr != nil {
		t.Fatal(withdrawErr)
	}
	once := predecessor.Policy{Choice: predecessor.After, Days: 3}
	if requestErr := e.s.RequestRenewal(t.Context(), testinstance.Console, caller.Agent.ID, "proxy", once); requestErr != nil {
		t.Fatal(requestErr)
	}
	row, err = q.GetAgentDeployment(t.Context(), pkidb.GetAgentDeploymentParams{AgentID: caller.Agent.ID, Name: "proxy"})
	if err != nil || row.RenewPredecessorChoice.String != predecessor.After || row.RenewPredecessorDays.Int64 != 3 {
		t.Fatalf("one-operation snapshot %+v: %v", row, err)
	}
}

func TestWrittenFingerprintOnlyWithoutCheck(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	caller := agentCaller(t, e, "proxy1.homelab.lan")
	account := predecessorAccount(t, e, caller.Agent.ID)
	serving := predecessorCertificate(t, e, account, "www.homelab.lan")
	discarded := predecessorCertificate(t, e, account, "www.homelab.lan")
	current := predecessorCertificate(t, e, account, "www.homelab.lan")
	other := deploymentResult(serving, "deployed", "www.homelab.lan")
	other.Name = "other"
	other.CheckConfigured = false
	other.Fingerprint = ""
	other.WrittenFingerprint = serving.Fingerprint
	result := deploymentResult(current, "deployed", "www.homelab.lan")
	result.CheckConfigured = false
	result.Fingerprint = ""
	result.WrittenFingerprint = current.Fingerprint
	if err := e.s.Report(t.Context(), caller, ReportInput{Deployments: []DeploymentReport{other, result}}); err != nil {
		t.Fatal(err)
	}
	if got := revokedReason(t, e, serving.ID); got != "" {
		t.Errorf("check-less serving certificate revoked: %q", got)
	}
	if got := revokedReason(t, e, discarded.ID); got != ca.ReasonSuperseded {
		t.Errorf("check-less discarded certificate not revoked: %q", got)
	}

	withCheck := deploymentResult(current, "deployed", "www.homelab.lan")
	withCheck.Fingerprint = ""
	withCheck.WrittenFingerprint = current.Fingerprint
	if err := e.s.Report(t.Context(), caller, ReportInput{Deployments: []DeploymentReport{withCheck}}); err != nil {
		t.Fatal(err)
	}
	if got := revokedReason(t, e, current.ID); got != "" {
		t.Errorf("written fingerprint replaced a missing TLS fingerprint: %q", got)
	}
	oldAgent := deploymentResult(current, "deployed", "www.homelab.lan")
	oldAgent.CheckConfigured = false
	oldAgent.Fingerprint = ""
	if err := e.s.Report(t.Context(), caller, ReportInput{Deployments: []DeploymentReport{oldAgent}}); err != nil {
		t.Fatal(err)
	}
	if got := revokedReason(t, e, current.ID); got != "" {
		t.Errorf("legacy agent without proof fields revoked: %q", got)
	}
}

func TestWrittenFingerprintCanBePlanned(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	e.s.AgentPredecessor = func(context.Context) (predecessor.Policy, error) {
		return predecessor.Policy{Choice: predecessor.After, Days: 2}, nil
	}
	caller := agentCaller(t, e, "proxy1.homelab.lan")
	account := predecessorAccount(t, e, caller.Agent.ID)
	old := predecessorCertificate(t, e, account, "www.homelab.lan")
	current := predecessorCertificate(t, e, account, "www.homelab.lan")
	result := deploymentResult(current, "deployed", "www.homelab.lan")
	result.CheckConfigured = false
	result.Fingerprint = ""
	result.WrittenFingerprint = current.Fingerprint
	if err := e.s.Report(t.Context(), caller, ReportInput{Deployments: []DeploymentReport{result}}); err != nil {
		t.Fatal(err)
	}
	if got := plannedTime(t, e, old.ID); got.IsZero() {
		t.Fatal("check-less deployment did not plan the predecessor")
	}
}
