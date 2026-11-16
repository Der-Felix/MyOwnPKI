package agents

import (
	"context"
	"database/sql"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/predecessor"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
)

// logBuffer collects the service log, so a test can tell why a mapping was
// not trusted.
type logBuffer struct {
	mu sync.Mutex
	sb strings.Builder
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sb.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.sb.String()
}

func (e *env) captureLog() *logBuffer {
	buf := &logBuffer{}
	e.s.Log = slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	return buf
}

func (e *env) historyCount(t *testing.T, agentID string, cert *ca.Issued) int64 {
	t.Helper()
	n, err := pkidb.New(e.s.PKI).CountAgentDeploymentHistory(t.Context(), pkidb.CountAgentDeploymentHistoryParams{AgentID: agentID, Deployment: "proxy", CertificateID: cert.ID})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// predecessorFixture is an agent whose account has an old certificate that
// the deployment "proxy" serves, and a newer one that is about to be
// reported.
type predecessorFixture struct {
	e       *env
	caller  *Caller
	account string
	old     *ca.Issued
	current *ca.Issued
	log     *logBuffer
}

func newPredecessorFixture(t *testing.T, policy predecessor.Policy) *predecessorFixture {
	t.Helper()
	e := newEnv(t, tenant.EnrollAuto)
	e.s.AgentPredecessor = func(context.Context) (predecessor.Policy, error) { return policy, nil }
	f := &predecessorFixture{e: e, log: e.captureLog()}
	f.caller = agentCaller(t, e, "proxy1.homelab.lan")
	f.account = predecessorAccount(t, e, f.caller.Agent.ID)
	f.old = predecessorCertificate(t, e, f.account, "www.homelab.lan")
	f.current = predecessorCertificate(t, e, f.account, "www.homelab.lan")
	// The old certificate is what the deployment serves; nothing is older.
	f.report(t, deploymentResult(f.old, "deployed", "www.homelab.lan"))
	return f
}

func (f *predecessorFixture) report(t *testing.T, d DeploymentReport) {
	t.Helper()
	if err := f.e.s.Report(t.Context(), f.caller, ReportInput{Deployments: []DeploymentReport{d}}); err != nil {
		t.Fatal(err)
	}
}

// TestApplyDeployedPerStateAndPolicy: only a deployment that reports the
// replacement as deployed touches its predecessor, and what happens is the
// predecessor policy – whatever the other states say.
func TestApplyDeployedPerStateAndPolicy(t *testing.T) {
	t.Parallel()
	type outcome int
	const (
		nothing outcome = iota
		revokedNow
		planned
	)
	policies := []struct {
		name   string
		policy predecessor.Policy
		days   int
		deploy outcome // what a deployed replacement does to the predecessor
	}{
		{"now", predecessor.Policy{Choice: predecessor.Now}, 0, revokedNow},
		{"after 3 days", predecessor.Policy{Choice: predecessor.After, Days: 3}, 3, planned},
		{"after 30 days", predecessor.Policy{Choice: predecessor.After, Days: 30}, 30, planned},
		{"never", predecessor.Policy{Choice: predecessor.Never}, 0, nothing},
	}
	for _, p := range policies {
		for _, state := range []string{"deployed", "pending", "failed", "rolled_back"} {
			t.Run(p.name+"/"+state, func(t *testing.T) {
				t.Parallel()
				f := newPredecessorFixture(t, p.policy)
				at := f.e.inst.Clock.Now().Truncate(time.Second)
				f.report(t, deploymentResult(f.current, state, "www.homelab.lan"))

				want := nothing
				if state == "deployed" {
					want = p.deploy
				}
				reason, plan := revokedReason(t, f.e, f.old.ID), plannedTime(t, f.e, f.old.ID)
				switch want {
				case nothing:
					if reason != "" || !plan.IsZero() {
						t.Errorf("predecessor touched: revoked %q, planned %v", reason, plan)
					}
				case revokedNow:
					if reason != ca.ReasonSuperseded || !plan.IsZero() {
						t.Errorf("predecessor: revoked %q, planned %v, want superseded now", reason, plan)
					}
				case planned:
					if want := at.AddDate(0, 0, p.days); reason != "" || !plan.Equal(want) {
						t.Errorf("predecessor: revoked %q, planned %v, want a plan for %v", reason, plan, want)
					}
				}
				// The replacement itself is never touched, and the history knows it
				// only when it was deployed.
				if got := revokedReason(t, f.e, f.current.ID); got != "" {
					t.Errorf("the replacement is revoked: %q", got)
				}
				wantHistory := int64(0)
				if state == "deployed" {
					wantHistory = 1
				}
				if got := f.e.historyCount(t, f.caller.Agent.ID, f.current); got != wantHistory {
					t.Errorf("history rows of the replacement: %d, want %d", got, wantHistory)
				}
			})
		}
	}
}

// TestApplyDeployedProof: what counts as proof that the replacement is what
// the host serves, and the reason when a mapping is not trusted.
func TestApplyDeployedProof(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		mod  func(d *DeploymentReport, f *predecessorFixture)
		act  bool
		log  string // the reason in the warning, "" = no warning
	}{
		{"exact serial and fingerprint", func(*DeploymentReport, *predecessorFixture) {}, true, ""},
		{"serial in lower case", func(d *DeploymentReport, _ *predecessorFixture) { d.Serial = strings.ToLower(d.Serial) }, true, ""},
		{"fingerprint in capitals", func(d *DeploymentReport, _ *predecessorFixture) { d.Fingerprint = strings.ToUpper(d.Fingerprint) }, true, ""},
		{"names in capitals and with a trailing space", func(d *DeploymentReport, _ *predecessorFixture) { d.Names = []string{" WWW.Homelab.LAN "} }, true, ""},
		{"no serial", func(d *DeploymentReport, _ *predecessorFixture) { d.Serial = "" }, false, ""},
		{"no fingerprint while a check is configured", func(d *DeploymentReport, _ *predecessorFixture) { d.Fingerprint = "" }, false, ""},
		{"a written fingerprint doesn't replace the check", func(d *DeploymentReport, _ *predecessorFixture) {
			d.WrittenFingerprint, d.Fingerprint = d.Fingerprint, ""
		}, false, ""},
		{"no fingerprint and no check: the written one counts", func(d *DeploymentReport, _ *predecessorFixture) {
			d.WrittenFingerprint, d.Fingerprint, d.CheckConfigured = d.Fingerprint, "", false
		}, true, ""},
		{"no fingerprint, no check and nothing written", func(d *DeploymentReport, _ *predecessorFixture) {
			d.Fingerprint, d.CheckConfigured = "", false
		}, false, ""},
		{"the fingerprint of another certificate", func(d *DeploymentReport, f *predecessorFixture) { d.Fingerprint = f.old.Fingerprint },
			false, "certificate order or deployment fingerprint is not unique and exact"},
		{"a serial that no certificate has", func(d *DeploymentReport, _ *predecessorFixture) { d.Serial = "0A0B0C0D" },
			false, "reported serial does not map to one certificate of the agent account"},
		{"a name that is not a host name", func(d *DeploymentReport, _ *predecessorFixture) { d.Names = []string{"not a name!"} },
			false, "invalid deployment name set"},
		{"other names than the order", func(d *DeploymentReport, _ *predecessorFixture) {
			d.Names = []string{"www.homelab.lan", "api.homelab.lan"}
		},
			false, "order and deployment name sets differ"},
		{"no names at all", func(d *DeploymentReport, _ *predecessorFixture) { d.Names = nil },
			false, "order and deployment name sets differ"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newPredecessorFixture(t, predecessor.Policy{Choice: predecessor.Now})
			d := deploymentResult(f.current, "deployed", "www.homelab.lan")
			tt.mod(&d, f)
			f.report(t, d)
			reason := revokedReason(t, f.e, f.old.ID)
			if tt.act && reason != ca.ReasonSuperseded {
				t.Errorf("predecessor not superseded: %q", reason)
			}
			if !tt.act && reason != "" {
				t.Errorf("predecessor revoked on weak proof: %q", reason)
			}
			if !tt.act && f.e.historyCount(t, f.caller.Agent.ID, f.current) != 0 {
				t.Error("history row written on weak proof")
			}
			logged := f.log.String()
			switch {
			case tt.log == "" && strings.Contains(logged, "ambiguous agent predecessor mapping"):
				t.Errorf("unexpected warning: %s", logged)
			case tt.log != "" && (!strings.Contains(logged, "ambiguous agent predecessor mapping") || !strings.Contains(logged, tt.log)):
				t.Errorf("log %q lacks %q", logged, tt.log)
			}
		})
	}
}

// TestApplyDeployedSecondOrder: a certificate with two orders is as
// ambiguous as no order – nothing is touched.
func TestApplyDeployedSecondOrder(t *testing.T) {
	t.Parallel()
	f := newPredecessorFixture(t, predecessor.Policy{Choice: predecessor.Now})
	stamp := dbTime(f.e.inst.Clock.Now())
	q := pkidb.New(f.e.s.PKI)
	if err := q.InsertACMEOrder(t.Context(), pkidb.InsertACMEOrderParams{
		ID: "ord-second", AccountID: f.account, Status: "processing", Identifiers: `[{"type":"dns","value":"www.homelab.lan"}]`,
		ExpiresAt: dbTime(f.e.inst.Clock.Now().Add(time.Hour)), CreatedAt: stamp, UpdatedAt: stamp,
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := q.SetACMEOrderValid(t.Context(), pkidb.SetACMEOrderValidParams{CertificateID: sql.NullString{String: f.current.ID, Valid: true}, UpdatedAt: stamp, ID: "ord-second"}); err != nil || n != 1 {
		t.Fatalf("second order link %d: %v", n, err)
	}
	f.report(t, deploymentResult(f.current, "deployed", "www.homelab.lan"))
	if got := revokedReason(t, f.e, f.old.ID); got != "" {
		t.Errorf("predecessor revoked: %q", got)
	}
}

// TestApplyDeployedOldIdentifiersAreChecked: an order whose identifiers
// can't be read is not trusted either – neither the replacement's nor an
// older certificate's.
func TestApplyDeployedOldIdentifiersAreChecked(t *testing.T) {
	t.Parallel()
	f := newPredecessorFixture(t, predecessor.Policy{Choice: predecessor.Now})
	if _, err := f.e.s.PKI.ExecContext(t.Context(), `UPDATE acme_orders SET identifiers = '{"a":1}' WHERE certificate_id = ?`, f.old.ID); err != nil {
		t.Fatal(err)
	}
	f.report(t, deploymentResult(f.current, "deployed", "www.homelab.lan"))
	if got := revokedReason(t, f.e, f.old.ID); got != "" {
		t.Errorf("a predecessor with unreadable identifiers was revoked: %q", got)
	}
	if !strings.Contains(f.log.String(), "invalid older order identifiers") {
		t.Errorf("log %q", f.log.String())
	}
	// The replacement's own order is the one that must be readable.
	if _, err := f.e.s.PKI.ExecContext(t.Context(), `UPDATE acme_orders SET identifiers = '{"a":1}' WHERE certificate_id = ?`, f.current.ID); err != nil {
		t.Fatal(err)
	}
	f.report(t, DeploymentReport{Name: "proxy", Names: []string{"www.homelab.lan"}, State: "deployed", Serial: f.old.SerialHex, Fingerprint: f.old.Fingerprint, CheckConfigured: true})
	f.report(t, deploymentResult(f.current, "deployed", "www.homelab.lan"))
	if !strings.Contains(f.log.String(), "invalid order identifiers") {
		t.Errorf("log %q", f.log.String())
	}
}
