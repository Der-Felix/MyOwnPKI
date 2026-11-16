package agents

import (
	"bytes"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// queued enrolls host in manual mode without a token and without a passed
// check: the enrollment waits in the approval queue.
func (e *env) queued(t *testing.T, host string) *EnrollOutput {
	t.Helper()
	_, csr := newCSR(t)
	out, st := e.enroll(t, host, "", false, csr)
	if st.State != StatePending {
		t.Fatalf("%s: %+v", host, st)
	}
	return out
}

func (e *env) enrollmentState(t *testing.T, id string) string {
	t.Helper()
	var state string
	if err := e.inst.PKIDB.Read.QueryRowContext(t.Context(), `SELECT state FROM agent_enrollments WHERE id = ?`, id).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}

func (e *env) agentCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := e.inst.PKIDB.Read.QueryRowContext(t.Context(), `SELECT count(*) FROM agents`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestAdmitRefusesWhatIsNotOpen: only an enrollment that waits can be
// admitted – a decided one, an expired one and an unknown one cannot, and
// nothing changes.
func TestAdmitRefusesWhatIsNotOpen(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollManual)
	ctx := t.Context()

	if err := e.s.Approve(ctx, testinstance.Console, "enr_nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("an unknown enrollment: %v", err)
	}
	if err := e.s.admit(ctx, "enr_nope", tenant.EnrollManual, "adm", systemWho); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("admit of an unknown enrollment: %v", err)
	}

	// Still waiting for the check: the queue is where admins decide.
	_, csr := newCSR(t)
	waiting, err := e.s.Enroll(ctx, EnrollInput{Hostname: "waiting.homelab.lan", Method: MethodStandalone, SourceIP: "192.0.2.10", CSRDER: csr})
	if err != nil {
		t.Fatal(err)
	}
	if err = e.s.Approve(ctx, testinstance.Console, waiting.ID); !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "this enrollment is waiting_for_check – only one in the approval queue can be approved") {
		t.Errorf("an enrollment that waits for the check: %v", err)
	}

	denied := e.queued(t, "denied.homelab.lan")
	if err = e.s.Deny(ctx, testinstance.Console, denied.ID); err != nil {
		t.Fatal(err)
	}
	approved := e.queued(t, "approved.homelab.lan")
	if err = e.s.Approve(ctx, testinstance.Console, approved.ID); err != nil {
		t.Fatal(err)
	}
	stale := e.queued(t, "stale.homelab.lan")
	e.inst.Clock.Advance(ShortExpiry + time.Minute)
	if st, serr := e.s.EnrollStatus(ctx, StatusInput{ID: stale.ID, Handle: stale.Handle, SourceIP: "192.0.2.10"}); serr != nil || st.State != StateExpired {
		t.Fatalf("expired enrollment: %+v %v", st, serr)
	}

	agentsBefore := e.agentCount(t)
	for _, tt := range []struct {
		name  string
		id    string
		state string
	}{{"denied", denied.ID, StateDenied}, {"approved", approved.ID, StateAdmitted}, {"expired", stale.ID, StateExpired}} {
		err := e.s.Approve(ctx, testinstance.Console, tt.id)
		if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "this enrollment is "+tt.state) {
			t.Errorf("approve %s: %v", tt.name, err)
		}
		err = e.s.admit(ctx, tt.id, tenant.EnrollManual, "adm", systemWho)
		if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "this enrollment is "+tt.state) {
			t.Errorf("admit %s: %v", tt.name, err)
		}
		if got := e.enrollmentState(t, tt.id); got != tt.state {
			t.Errorf("%s: state %s, want %s", tt.name, got, tt.state)
		}
	}
	if n := e.agentCount(t); n != agentsBefore {
		t.Errorf("%d agents, want %d – a refused admit created one", n, agentsBefore)
	}
}

// TestAdmitOfAKnownAgentThatChanged: an enrollment that came back as a known
// agent is admitted only while that agent is active – disabled or revoked
// meanwhile means an admin must look again.
func TestAdmitOfAKnownAgentThatChanged(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	ctx := t.Context()
	key1, _, id1 := e.admitted(t, "proxy1.homelab.lan")
	key2, _, id2 := e.admitted(t, "proxy2.homelab.lan")
	e.mode = tenant.EnrollManual
	// Known key, check failed: it waits, marked as the known agent.
	_, st1 := e.enroll(t, "proxy1.homelab.lan", "", false, csrFor(t, key1))
	_, st2 := e.enroll(t, "proxy2.homelab.lan", "", false, csrFor(t, key2))
	if st1.State != StatePending || st2.State != StatePending {
		t.Fatalf("known keys without a check: %+v %+v", st1, st2)
	}
	open, err := e.s.ListEnrollments(ctx, testinstance.Console, true)
	if err != nil || len(open) != 2 || !open[0].KnownAgent || !open[1].KnownAgent {
		t.Fatalf("queue %+v %v", open, err)
	}
	if err = e.s.SetDisabled(ctx, testinstance.Console, id1, true); err != nil {
		t.Fatal(err)
	}
	if err = e.s.Revoke(ctx, testinstance.Console, id2); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ host, state string }{{"proxy1.homelab.lan", "disabled"}, {"proxy2.homelab.lan", "revoked"}} {
		var id string
		for _, en := range open {
			if en.Hostname == tt.host {
				id = en.ID
			}
		}
		err := e.s.Approve(ctx, testinstance.Console, id)
		if !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "agent "+tt.host+" is "+tt.state+" – it can't enroll again") {
			t.Errorf("approve for the %s agent: %v", tt.state, err)
		}
		if got := e.enrollmentState(t, id); got != StatePending {
			t.Errorf("%s: the enrollment is %s after the refusal", tt.host, got)
		}
	}
	if n := e.agentCount(t); n != 2 {
		t.Errorf("%d agents", n)
	}
}

// TestPassGuardOnAdmit: when a pass decides, the host must still have no
// agent inside the transaction; a person approving from the queue may replace
// one. A revoked agent doesn't count, a disabled one does.
func TestPassGuardOnAdmit(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	ctx := t.Context()
	e.admitted(t, "active.homelab.lan")
	_, _, disabled := e.admitted(t, "disabled.homelab.lan")
	_, _, revoked := e.admitted(t, "revoked.homelab.lan")
	if err := e.s.SetDisabled(ctx, testinstance.Console, disabled, true); err != nil {
		t.Fatal(err)
	}
	if err := e.s.Revoke(ctx, testinstance.Console, revoked); err != nil {
		t.Fatal(err)
	}
	e.mode = tenant.EnrollManual
	for _, tt := range []struct {
		host  string
		taken bool
	}{{"active.homelab.lan", true}, {"disabled.homelab.lan", true}, {"revoked.homelab.lan", false}} {
		out := e.queued(t, tt.host)
		before := e.agentCount(t)
		err := e.s.admitBy(ctx, out.ID, tenant.EnrollVerified, "mode verified", systemWho, true)
		switch {
		case tt.taken && !errors.Is(err, errHostTaken):
			t.Errorf("%s: %v, want errHostTaken", tt.host, err)
		case tt.taken && (e.agentCount(t) != before || e.enrollmentState(t, out.ID) != StatePending):
			t.Errorf("%s: a refused admit changed the state (%d agents, enrollment %s)", tt.host, e.agentCount(t), e.enrollmentState(t, out.ID))
		case !tt.taken && err != nil:
			t.Errorf("%s: %v", tt.host, err)
		case !tt.taken && (e.agentCount(t) != before+1 || e.enrollmentState(t, out.ID) != StateAdmitted):
			t.Errorf("%s: admitted without a new agent (%d agents)", tt.host, e.agentCount(t))
		}
	}
	// A person sees the reason in the queue and may replace the host.
	out := e.queued(t, "active.homelab.lan")
	before := e.agentCount(t)
	if err := e.s.Approve(ctx, testinstance.Console, out.ID); err != nil {
		t.Fatal(err)
	}
	if n := e.agentCount(t); n != before+1 {
		t.Errorf("%d agents after the approval, want %d", n, before+1)
	}
}

// TestApproveNeedsTheAdminAndAFreshSecondFactor: the same rule as the tokens,
// for the queue.
func TestApproveNeedsTheAdminAndAFreshSecondFactor(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollManual)
	ctx := t.Context()
	out := e.queued(t, "proxy1.homelab.lan")
	now := e.inst.Clock.Now()
	person := func(role authz.Role, stepUp time.Time, viaToken bool) keys.Who {
		return keys.Who{
			Actor:     audit.Actor{Type: audit.ActorUser, ID: "u1", Name: "someone"},
			Principal: &authz.Principal{Kind: authz.KindUser, UserID: "u1", Username: "someone", Bindings: []authz.Binding{{Tenant: "default", Role: role}}, StepUpAt: stepUp, ViaToken: viaToken},
		}
	}
	for _, tt := range []struct {
		name string
		who  keys.Who
		want error
	}{
		{"viewer", person(authz.Viewer, now, false), authz.ErrDenied},
		{"operator", person(authz.Operator, now, false), authz.ErrDenied},
		{"admin without a second factor", person(authz.Admin, time.Time{}, false), authz.ErrStepUpRequired},
		{"admin with an old second factor", person(authz.Admin, now.Add(-time.Hour), false), authz.ErrStepUpRequired},
		{"an admin's API token", person(authz.Admin, now, true), authz.ErrDenied},
		{"nobody", keys.Who{}, authz.ErrDenied},
	} {
		if err := e.s.Approve(ctx, tt.who, out.ID); !errors.Is(err, tt.want) {
			t.Errorf("%s approves: %v, want %v", tt.name, err, tt.want)
		}
		if err := e.s.Deny(ctx, tt.who, out.ID); !errors.Is(err, tt.want) {
			t.Errorf("%s denies: %v, want %v", tt.name, err, tt.want)
		}
	}
	if got := e.enrollmentState(t, out.ID); got != StatePending {
		t.Errorf("a refused user decided the enrollment: %s", got)
	}
	if err := e.s.Approve(ctx, person(authz.Admin, now, false), out.ID); err != nil {
		t.Errorf("admin with a fresh second factor: %v", err)
	}
}

// TestKeyReuseIsNotIdentity: a key is the identity of an agent only for the
// host name it was enrolled under, and only while that agent is active.
func TestKeyReuseIsNotIdentity(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	ctx := t.Context()
	key, _, id := e.admitted(t, "proxy1.homelab.lan")
	e.mode = tenant.EnrollManual

	// The same key under another name: a passed check, but no known agent.
	_, st := e.enroll(t, "proxy2.homelab.lan", "", true, csrFor(t, key))
	if st.State != StatePending || st.AgentID != "" {
		t.Errorf("the key of proxy1 under the name proxy2: %+v", st)
	}
	open, err := e.s.ListEnrollments(ctx, testinstance.Console, true)
	if err != nil || len(open) != 1 || open[0].KnownAgent || open[0].Hostname != "proxy2.homelab.lan" {
		t.Errorf("queue %+v %v", open, err)
	}
	// Its own name and key: known again.
	if _, st = e.enroll(t, "proxy1.homelab.lan", "", true, csrFor(t, key)); st.State != StateAdmitted || st.AgentID != id {
		t.Errorf("the key under its own name: %+v", st)
	}
	// Revoked, the key is nothing any more.
	if err = e.s.Revoke(ctx, testinstance.Console, id); err != nil {
		t.Fatal(err)
	}
	_, st = e.enroll(t, "proxy1.homelab.lan", "", true, csrFor(t, key))
	if st.State != StatePending || st.AgentID != "" {
		t.Errorf("the key of a revoked agent: %+v", st)
	}
	open, err = e.s.ListEnrollments(ctx, testinstance.Console, true)
	if err != nil || len(open) != 2 {
		t.Fatalf("queue %+v %v", open, err)
	}
	for _, en := range open {
		if en.KnownAgent {
			t.Errorf("%s is marked as a known agent", en.Hostname)
		}
	}
}

// TestDeliverAgain: two polls deliver one certificate. A poll that read the
// enrollment before the other one stored the certificate gets that
// certificate instead of issuing a second one.
func TestDeliverAgain(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	ctx := t.Context()
	out, st := e.enroll(t, "proxy1.homelab.lan", "", true, mustCSR(t))
	if st.State != StateAdmitted || len(st.CertDER) == 0 {
		t.Fatalf("first poll: %+v", st)
	}
	certs := func() int {
		var n int
		if err := e.inst.PKIDB.Read.QueryRowContext(ctx, `SELECT count(*) FROM certificates WHERE ca_id = (SELECT id FROM cas WHERE name = 'agent-ca')`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := certs(); n != 1 {
		t.Fatalf("%d agent certificates after the first poll", n)
	}

	// The second poll is a stale copy: it saw the enrollment before the
	// certificate was stored.
	row, err := e.s.enrollment(ctx, out.ID, out.Handle)
	if err != nil || !row.CertID.Valid {
		t.Fatalf("enrollment %+v %v", row, err)
	}
	stale := row
	stale.CertID = sql.NullString{}
	got, err := e.s.deliver(ctx, stale, &Status{State: StateAdmitted})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.CertDER, st.CertDER) || got.Message != "admitted" || len(got.Chain) == 0 {
		t.Errorf("the stale poll got another certificate or none: %+v", got)
	}
	if n := certs(); n != 1 {
		t.Errorf("%d agent certificates after the stale poll – it issued a second one", n)
	}
	var agentCert string
	if err = e.inst.PKIDB.Read.QueryRowContext(ctx, `SELECT cert_id FROM agents WHERE id = ?`, st.AgentID).Scan(&agentCert); err != nil || agentCert != row.CertID.String {
		t.Errorf("the agent's certificate is %q, the enrollment's %q (%v)", agentCert, row.CertID.String, err)
	}

	// Direct calls.
	if got, err = e.s.deliverAgain(ctx, out.ID, &Status{State: StateAdmitted}); err != nil || !bytes.Equal(got.CertDER, st.CertDER) {
		t.Errorf("deliverAgain of a delivered enrollment: %+v %v", got, err)
	}
	if _, err = e.s.deliverAgain(ctx, "enr_nope", &Status{}); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("deliverAgain of an unknown enrollment: %v", err)
	}
	e.mode = tenant.EnrollManual
	_, csr := newCSR(t)
	open, _ := e.enroll(t, "proxy2.homelab.lan", "", false, csr)
	if _, err = e.s.deliverAgain(ctx, open.ID, &Status{}); err == nil || !strings.Contains(err.Error(), "the agent certificate was not stored") {
		t.Errorf("deliverAgain without a certificate: %v", err)
	}
}

// TestDeliverToAnAgentThatIsNotActive: an admitted enrollment whose agent was
// disabled or revoked before the certificate was issued gets none.
func TestDeliverToAnAgentThatIsNotActive(t *testing.T) {
	t.Parallel()
	for _, state := range []string{StatusDisabled, StatusRevoked} {
		t.Run(state, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, tenant.EnrollAuto)
			ctx := t.Context()
			if err := e.inst.Ring.Seal(ctx, testinstance.Console); err != nil {
				t.Fatal(err)
			}
			out, st := e.enroll(t, "proxy1.homelab.lan", "", true, mustCSR(t))
			if st.State != StateWaitingForUnseal {
				t.Fatalf("sealed: %+v", st)
			}
			agent, err := e.s.ListAgents(ctx, testinstance.Console)
			if err != nil || len(agent) != 1 {
				t.Fatalf("agents %+v %v", agent, err)
			}
			if state == StatusDisabled {
				err = e.s.SetDisabled(ctx, testinstance.Console, agent[0].ID, true)
			} else {
				err = e.s.Revoke(ctx, testinstance.Console, agent[0].ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			e.inst.Unseal(t)
			st, err = e.s.EnrollStatus(ctx, StatusInput{ID: out.ID, Handle: out.Handle, SourceIP: "192.0.2.10"})
			if err != nil {
				t.Fatal(err)
			}
			if st.State != StateDenied || st.Message != "this agent is "+state || len(st.CertDER) != 0 {
				t.Errorf("poll for a %s agent: %+v", state, st)
			}
			var certs int
			if err = e.inst.PKIDB.Read.QueryRowContext(ctx, `SELECT count(*) FROM certificates WHERE ca_id = (SELECT id FROM cas WHERE name = 'agent-ca')`).Scan(&certs); err != nil || certs != 0 {
				t.Errorf("%d agent certificates issued for a %s agent (%v)", certs, state, err)
			}
		})
	}
}
