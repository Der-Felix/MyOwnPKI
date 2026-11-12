package agents

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// pass makes an enrollment pass as the console.
func (e *env) pass(t *testing.T, uses int, ttl time.Duration, patterns ...string) (string, *JoinToken) {
	t.Helper()
	secret, jt, err := e.s.CreateEnrollmentPass(t.Context(), testinstance.Console, "rollout", patterns, uses, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return secret, jt
}

// enrollOnly sends an enrollment without a check (the service still has to
// decide about the token).
func (e *env) enrollOnly(t *testing.T, host, token string) (*EnrollOutput, []byte) {
	t.Helper()
	_, csr := newCSR(t)
	out, err := e.s.Enroll(t.Context(), EnrollInput{Hostname: host, Token: token, Method: MethodWebroot, OS: "linux", Arch: "amd64", Version: "0.3.5", SourceIP: "192.0.2.10", CSRDER: csr})
	if err != nil {
		t.Fatalf("enroll %s: %v", host, err)
	}
	return out, csr
}

// find returns the pass or token with that ID from the list.
func (e *env) find(t *testing.T, id string) JoinToken {
	t.Helper()
	list, err := e.s.ListJoinTokens(t.Context(), testinstance.Console)
	if err != nil {
		t.Fatal(err)
	}
	for _, jt := range list {
		if jt.ID == id {
			return jt
		}
	}
	t.Fatalf("join token %s is not in the list", id)
	return JoinToken{}
}

// TestPassCreateRules: the limits of docs/PHASE3.md section 11.2 – a label,
// 1 to 5 patterns, 2 to 25 uses (default 10), 5 minutes to 7 days (default
// 24 hours) – and every pattern must lie in a domain.
func TestPassCreateRules(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollVerified)
	ctx := t.Context()
	if _, err := e.inst.Engine.CreateDomain(ctx, ca.DomainRequest{Name: "apps.example", DomainSettings: ca.DomainSettings{CA: ptr("issuing")}, Who: testinstance.Console}); err != nil {
		t.Fatal(err)
	}
	create := func(label string, patterns []string, uses int, ttl time.Duration) (string, *JoinToken, error) {
		return e.s.CreateEnrollmentPass(ctx, testinstance.Console, label, patterns, uses, ttl)
	}
	secret, jt, err := create("defaults", []string{"*.homelab.lan"}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if jt.Kind != KindPass || jt.MaxUses != DefaultPassUses || jt.UseCount != 0 || !jt.ExpiresAt.Equal(e.inst.Clock.Now().Add(DefaultPassTTL).Truncate(time.Second)) {
		t.Errorf("defaults: %+v", jt)
	}
	if !strings.HasPrefix(secret, PassPrefix) || len(secret) != len(PassPrefix)+43 {
		t.Errorf("secret %q", secret)
	}
	for _, tt := range []struct {
		name     string
		label    string
		patterns []string
		uses     int
		ttl      time.Duration
		want     string // part of the error; "" = accepted
	}{
		{"label required", "", []string{"*.homelab.lan"}, 5, time.Hour, "label: required"},
		{"label with a control character", "a\nb", []string{"*.homelab.lan"}, 5, time.Hour, "label"},
		{"no pattern", "x", nil, 5, time.Hour, "names: 1 to 5"},
		{"five patterns", "x", []string{"a.homelab.lan", "b.homelab.lan", "c.homelab.lan", "d.homelab.lan", "e.homelab.lan"}, 5, time.Hour, ""},
		{"six patterns", "x", []string{"a.homelab.lan", "b.homelab.lan", "c.homelab.lan", "d.homelab.lan", "e.homelab.lan", "f.homelab.lan"}, 5, time.Hour, "names: 1 to 5"},
		{"a bare wildcard", "x", []string{"*"}, 5, time.Hour, "name"},
		{"a TLD wildcard", "x", []string{"*.lan"}, 5, time.Hour, "fully qualified"},
		{"one use", "x", []string{"*.homelab.lan"}, 1, time.Hour, "uses: a pass admits 2 to 25"},
		{"two uses", "x", []string{"*.homelab.lan"}, 2, time.Hour, ""},
		{"25 uses", "x", []string{"*.homelab.lan"}, 25, time.Hour, ""},
		{"26 uses", "x", []string{"*.homelab.lan"}, 26, time.Hour, "uses: a pass admits 2 to 25"},
		{"negative uses", "x", []string{"*.homelab.lan"}, -1, time.Hour, "uses"},
		{"5 minutes", "x", []string{"*.homelab.lan"}, 5, 5 * time.Minute, ""},
		{"4m59s", "x", []string{"*.homelab.lan"}, 5, 5*time.Minute - time.Second, "5 minutes to 7 days"},
		{"7 days", "x", []string{"*.homelab.lan"}, 5, 7 * 24 * time.Hour, ""},
		{"7 days and a second", "x", []string{"*.homelab.lan"}, 5, 7*24*time.Hour + time.Second, "5 minutes to 7 days"},
		{"30 days is a token's limit, not a pass's", "x", []string{"*.homelab.lan"}, 5, MaxTokenTTL, "5 minutes to 7 days"},
		{"an exact name in a domain", "x", []string{"nas.apps.example"}, 5, time.Hour, ""},
		{"a wildcard in a domain", "x", []string{"*.apps.example"}, 5, time.Hour, ""},
		{"an exact name no domain covers", "x", []string{"nas.nodomain.lan"}, 5, time.Hour, "no domain covers nas.nodomain.lan"},
		{"a wildcard no domain covers", "x", []string{"*.nodomain.lan"}, 5, time.Hour, "no domain covers *.nodomain.lan"},
		{"one covered, one not", "x", []string{"a.homelab.lan", "b.nodomain.lan"}, 5, time.Hour, "no domain covers b.nodomain.lan"},
	} {
		_, _, cerr := create(tt.label, tt.patterns, tt.uses, tt.ttl)
		switch {
		case tt.want == "" && cerr != nil:
			t.Errorf("%s: %v", tt.name, cerr)
		case tt.want != "" && (!errors.Is(cerr, ErrInvalid) || !strings.Contains(cerr.Error(), tt.want)):
			t.Errorf("%s: %v, want %q", tt.name, cerr, tt.want)
		}
	}
	// The secret is stored as a hash only, and a pass is not a token.
	var n int
	if qerr := e.inst.PKIDB.Read.QueryRowContext(ctx, `SELECT count(*) FROM join_tokens WHERE token_hash = ? OR instr(token_hash, ?) > 0`, secret, secret[len(PassPrefix):]).Scan(&n); qerr != nil || n != 0 {
		t.Errorf("the secret is stored: %d %v", n, qerr)
	}
	if got := e.find(t, jt.ID); got.Kind != KindPass || got.MaxUses != DefaultPassUses || len(got.Hosts) != 0 {
		t.Errorf("listed pass: %+v", got)
	}
	// A plain token is unchanged: one use, 30 days, no domain needed.
	tok, plain, err := e.s.CreateJoinToken(ctx, testinstance.Console, "", []string{"anything.nodomain.lan"}, MaxTokenTTL)
	if err != nil || plain.Kind != KindToken || plain.MaxUses != 1 || !strings.HasPrefix(tok, TokenPrefix) {
		t.Errorf("token: %+v %v", plain, err)
	}
}

// TestPassClock: the expiry is to the second on the injected clock, and the
// 7-day maximum is measured from the creation time.
func TestPassClock(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollVerified)
	start := e.inst.Clock.Now()
	secret, jt := e.pass(t, 5, time.Hour, "*.homelab.lan")
	if want := start.Add(time.Hour).Truncate(time.Second); !jt.ExpiresAt.Equal(want) {
		t.Fatalf("expires %v, want %v", jt.ExpiresAt, want)
	}
	e.inst.Clock.Advance(time.Hour - time.Second)
	if _, st := e.enroll(t, "a.homelab.lan", secret, true, mustCSR(t)); st.State != StateAdmitted {
		t.Errorf("one second before the end: %+v", st)
	}
	e.inst.Clock.Advance(time.Second)
	if _, st := e.enroll(t, "b.homelab.lan", secret, true, mustCSR(t)); st.State != StatePending || !strings.Contains(st.Message, "the pass expired") {
		t.Errorf("at the end: %+v", st)
	}
	if got := e.find(t, jt.ID); got.State(e.inst.Clock.Now()) != TokenExpired || got.UseCount != 1 {
		t.Errorf("after expiry: state %v, uses %d", got.State(e.inst.Clock.Now()), got.UseCount)
	}
	// The longest pass dies after 7 days, not a second later.
	secret7, long := e.pass(t, 5, MaxPassTTL, "*.homelab.lan")
	e.inst.Clock.Advance(MaxPassTTL - time.Second)
	if _, st := e.enroll(t, "c.homelab.lan", secret7, true, mustCSR(t)); st.State != StateAdmitted {
		t.Errorf("7 days less a second: %+v", st)
	}
	e.inst.Clock.Advance(time.Second)
	if _, st := e.enroll(t, "d.homelab.lan", secret7, true, mustCSR(t)); st.State != StatePending || !strings.Contains(st.Message, "expired") {
		t.Errorf("after 7 days: %+v", st)
	}
	if long.State(e.inst.Clock.Now()) != TokenExpired {
		t.Errorf("state %v", long.State(e.inst.Clock.Now()))
	}
}

func mustCSR(t *testing.T) []byte {
	t.Helper()
	_, csr := newCSR(t)
	return csr
}

// TestPassAdmitsOnlyWithAPassedCheck: a pass never replaces the proof of
// control. In auto mode a plain token admits without a passed check; a pass
// does not. In manual mode nothing admits.
func TestPassAdmitsOnlyWithAPassedCheck(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		mode   string
		passed bool
		want   string
	}{
		{tenant.EnrollAuto, true, StateAdmitted},
		{tenant.EnrollAuto, false, StatePending},
		{tenant.EnrollVerified, true, StateAdmitted},
		{tenant.EnrollVerified, false, StatePending},
		{tenant.EnrollManual, true, StatePending},
		{tenant.EnrollManual, false, StatePending},
	} {
		t.Run(fmt.Sprintf("%s check=%v", tt.mode, tt.passed), func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, tt.mode)
			secret, jt := e.pass(t, 3, time.Hour, "*.homelab.lan")
			_, st := e.enroll(t, "minion-01.homelab.lan", secret, tt.passed, mustCSR(t))
			if st.State != tt.want || !st.TokenValid || st.CheckPassed != tt.passed {
				t.Fatalf("%+v, want %s", st, tt.want)
			}
			// The use is spent either way: the enrollment presented a valid pass.
			if got := e.find(t, jt.ID); got.UseCount != 1 || len(got.Hosts) != 1 || got.Hosts[0].Hostname != "minion-01.homelab.lan" {
				t.Errorf("pass after the enrollment: %+v", got)
			}
		})
	}
	// The same plain token in auto mode with a failed check does admit, which
	// is exactly what a pass must not do.
	e := newEnv(t, tenant.EnrollAuto)
	if _, st := e.enroll(t, "proxy1.homelab.lan", e.token(t, "*.homelab.lan"), false, mustCSR(t)); st.State != StateAdmitted {
		t.Errorf("control: a token in auto mode: %+v", st)
	}
}

// TestPassGrantsTheHostNameOnly: the patterns decide who may enroll, not what
// the host may order. A single-use token with the same patterns still gives
// the host every pattern.
func TestPassGrantsTheHostNameOnly(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollVerified)
	secret, _ := e.pass(t, 3, time.Hour, "*.homelab.lan", "extra.homelab.lan")
	_, st := e.enroll(t, "minion-01.homelab.lan", secret, true, mustCSR(t))
	if st.State != StateAdmitted {
		t.Fatalf("%+v", st)
	}
	a, err := e.s.GetAgent(t.Context(), testinstance.Console, st.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Names) != 1 || a.Names[0].Pattern != "minion-01.homelab.lan" || a.Names[0].Source != "hostname" {
		t.Errorf("names of an agent admitted by a pass: %+v", a.Names)
	}
	_, st = e.enroll(t, "proxy1.homelab.lan", e.token(t, "*.homelab.lan"), true, mustCSR(t))
	b, err := e.s.GetAgent(t.Context(), testinstance.Console, st.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Names) != 2 {
		t.Errorf("control, names of an agent admitted by a token: %+v", b.Names)
	}
}

// TestPassNeverAdmitsOutsideItsPatternsOrDomain: a name outside the patterns
// waits in the queue and does not use the pass; so does a name in the pattern
// whose domain was removed since (the check needs a domain).
func TestPassNeverAdmitsOutsideItsPatternsOrDomain(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollVerified)
	ctx := t.Context()
	other, err := e.inst.Engine.CreateDomain(ctx, ca.DomainRequest{Name: "other.example", DomainSettings: ca.DomainSettings{CA: ptr("issuing")}, Who: testinstance.Console})
	if err != nil {
		t.Fatal(err)
	}
	secret, jt := e.pass(t, 9, time.Hour, "*.apps.homelab.lan", "exact.homelab.lan", "*.other.example")
	for _, tt := range []struct{ host, want string }{
		{"minion-01.homelab.lan", "the pass is not for minion-01.homelab.lan"}, // a domain covers it, the pattern does not
		{"apps.homelab.lan", "the pass is not for apps.homelab.lan"},           // *.suffix never covers the bare suffix
		{"exact.homelab.lan.evil.example", "the pass is not for exact.homelab.lan.evil.example"},
		{"xexact.homelab.lan", "the pass is not for xexact.homelab.lan"},
	} {
		if _, st := e.enroll(t, tt.host, secret, true, mustCSR(t)); st.State != StatePending || st.TokenValid || !strings.Contains(st.Message, tt.want) {
			t.Errorf("%s: %+v", tt.host, st)
		}
	}
	if got := e.find(t, jt.ID); got.UseCount != 0 {
		t.Errorf("a refused name spent %d uses", got.UseCount)
	}
	// In the pattern: one label or many labels below the suffix.
	for _, host := range []string{"a.apps.homelab.lan", "a.b.apps.homelab.lan", "exact.homelab.lan"} {
		if _, st := e.enroll(t, host, secret, true, mustCSR(t)); st.State != StateAdmitted {
			t.Errorf("%s: %+v", host, st)
		}
	}
	// The domain of a pattern is gone: the pattern matches, the check cannot
	// find a domain, so the host waits for an admin.
	if err := e.inst.Engine.DeleteDomain(ctx, other.ID, testinstance.Console); err != nil {
		t.Fatal(err)
	}
	if _, st := e.enroll(t, "a.other.example", secret, true, mustCSR(t)); st.State != StatePending || st.CheckPassed || !strings.Contains(st.Message, "no domain covers a.other.example") {
		t.Errorf("domain removed: %+v", st)
	}
}

// TestPassRefusesAHostThatHasAnAgent: a pass admits new hosts only. The
// enrollment waits and says why; the use is not spent. A revoked agent does
// not count, a disabled one does.
func TestPassRefusesAHostThatHasAnAgent(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollVerified)
	ctx := t.Context()
	secret, jt := e.pass(t, 5, time.Hour, "*.homelab.lan")
	_, st := e.enroll(t, "minion-01.homelab.lan", secret, true, mustCSR(t))
	if st.State != StateAdmitted {
		t.Fatalf("first: %+v", st)
	}
	agentID := st.AgentID
	_, st = e.enroll(t, "minion-01.homelab.lan", secret, true, mustCSR(t))
	if st.State != StatePending || st.TokenValid || !strings.Contains(st.Message, "an agent for minion-01.homelab.lan exists – a pass admits new hosts only") {
		t.Fatalf("second, active agent: %+v", st)
	}
	if got := e.find(t, jt.ID); got.UseCount != 1 {
		t.Errorf("uses after the refusal: %d, want 1", got.UseCount)
	}
	if err := e.s.SetDisabled(ctx, testinstance.Console, agentID, true); err != nil {
		t.Fatal(err)
	}
	if _, st = e.enroll(t, "minion-01.homelab.lan", secret, true, mustCSR(t)); st.State != StatePending || st.TokenValid {
		t.Fatalf("third, disabled agent: %+v", st)
	}
	if err := e.s.Revoke(ctx, testinstance.Console, agentID); err != nil {
		t.Fatal(err)
	}
	if _, st = e.enroll(t, "minion-01.homelab.lan", secret, true, mustCSR(t)); st.State != StateAdmitted {
		t.Fatalf("fourth, revoked agent: %+v", st)
	}
	if got := e.find(t, jt.ID); got.UseCount != 2 {
		t.Errorf("uses: %d, want 2", got.UseCount)
	}
}

// TestPassTwoEnrollmentsForOneHost: two enrollments for the same new name
// both present the pass before either has an agent. The first one admitted
// wins; the second is queued with the reason (its use stays spent).
func TestPassTwoEnrollmentsForOneHost(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollVerified)
	secret, jt := e.pass(t, 5, time.Hour, "*.homelab.lan")
	out1, csr1 := e.enrollOnly(t, "twin.homelab.lan", secret)
	out2, csr2 := e.enrollOnly(t, "twin.homelab.lan", secret)
	if got := e.find(t, jt.ID); got.UseCount != 2 {
		t.Fatalf("both used the pass: %d", got.UseCount)
	}
	status := func(out *EnrollOutput, csr []byte) *Status {
		t.Helper()
		spki, _ := csrKey(csr)
		e.check.place(out.CheckToken, out.CheckToken+"."+spki)
		st, err := e.s.EnrollStatus(t.Context(), StatusInput{ID: out.ID, Handle: out.Handle, CheckReady: true, SourceIP: "192.0.2.10"})
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	if st := status(out1, csr1); st.State != StateAdmitted {
		t.Fatalf("first: %+v", st)
	}
	st := status(out2, csr2)
	if st.State != StatePending || st.TokenValid || !strings.Contains(st.Message, "an agent for twin.homelab.lan exists – a pass admits new hosts only") {
		t.Fatalf("second: %+v", st)
	}
	list, err := e.s.ListAgents(t.Context(), testinstance.Console)
	if err != nil || len(list) != 1 {
		t.Errorf("agents: %d %v", len(list), err)
	}
	if got := e.find(t, jt.ID); got.UseCount != 2 || len(got.Hosts) != 2 {
		t.Errorf("the pass lists both uses: %+v", got)
	}
	// An admin may still decide to replace the host.
	open, _ := e.s.ListEnrollments(t.Context(), testinstance.Console, true)
	if len(open) != 1 || open[0].TokenProblem == "" {
		t.Errorf("the queue: %+v", open)
	}
}

// TestPassConcurrentUsesNeverExceedTheLimit: more enrollments than uses, all
// at once. Exactly max_uses of them hold a valid pass, the others are told
// there is none left; none is lost and the counter ends at the limit. This
// is the property of the one conditional UPDATE.
func TestPassConcurrentUsesNeverExceedTheLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollVerified)
	const uses, attempts = 5, 12
	secret, jt := e.pass(t, uses, time.Hour, "*.homelab.lan")
	csrs := make([][]byte, attempts)
	for i := range csrs {
		csrs[i] = mustCSR(t)
	}
	var wg sync.WaitGroup
	outs := make([]*EnrollOutput, attempts)
	errs := make([]error, attempts)
	for i := range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outs[i], errs[i] = e.s.Enroll(t.Context(), EnrollInput{
				Hostname: fmt.Sprintf("minion-%02d.homelab.lan", i), Token: secret, Method: MethodWebroot,
				OS: "linux", Arch: "amd64", Version: "0.3.5", SourceIP: "192.0.2.10", CSRDER: csrs[i],
			})
		}()
	}
	wg.Wait()
	valid, refused := 0, 0
	for i := range attempts {
		if errs[i] != nil {
			t.Fatalf("enrollment %d: %v", i, errs[i])
		}
		var tokenValid int
		var problem string
		if err := e.inst.PKIDB.Read.QueryRowContext(t.Context(), `SELECT token_valid, coalesce(token_problem, '') FROM agent_enrollments WHERE id = ?`, outs[i].ID).Scan(&tokenValid, &problem); err != nil {
			t.Fatal(err)
		}
		switch {
		case tokenValid == 1:
			valid++
		case strings.Contains(problem, "no uses left (5 of 5)"):
			refused++
		default:
			t.Errorf("enrollment %d: valid %d, problem %q", i, tokenValid, problem)
		}
	}
	if valid != uses || refused != attempts-uses {
		t.Errorf("%d enrollments held a valid pass, %d were refused; want %d and %d", valid, refused, uses, attempts-uses)
	}
	got := e.find(t, jt.ID)
	if got.UseCount != uses || got.State(e.inst.Clock.Now()) != TokenUsedUp || got.UsedAt.IsZero() || len(got.Hosts) != uses {
		t.Errorf("the pass afterwards: uses %d, state %v, used_at %v, hosts %d", got.UseCount, got.State(e.inst.Clock.Now()), got.UsedAt, len(got.Hosts))
	}
	// Every use is in the audit log with its number.
	e.inst.Deliver(t)
	var logged int
	if err := e.inst.TenantAudit.Read.QueryRowContext(t.Context(), `SELECT count(*) FROM audit_entries WHERE action = 'agent.enroll' AND instr(details_json, '"token_kind":"pass"') > 0 AND instr(details_json, ' of 5"') > 0`).Scan(&logged); err != nil || logged != uses {
		t.Errorf("%d enrollments audited with a use number, want %d (%v)", logged, uses, err)
	}
}

// TestPassSaysWhyItDoesNotCount: used up, expired and revoked are told apart –
// to whoever holds the secret, in the words of docs/PHASE3.md section 11.2,
// the way a plain token already does. An unknown secret is just unknown.
func TestPassSaysWhyItDoesNotCount(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollVerified)
	ctx := t.Context()
	used, _ := e.pass(t, 2, time.Hour, "*.homelab.lan")
	for _, h := range []string{"a.homelab.lan", "b.homelab.lan"} {
		if _, st := e.enroll(t, h, used, true, mustCSR(t)); st.State != StateAdmitted {
			t.Fatalf("%s: %+v", h, st)
		}
	}
	if _, st := e.enroll(t, "c.homelab.lan", used, true, mustCSR(t)); st.State != StatePending || !strings.Contains(st.Message, "the enrollment pass has no uses left (2 of 2) – ask an admin for a new one") {
		t.Errorf("used up: %+v", st)
	}
	revoked, rjt := e.pass(t, 3, time.Hour, "*.homelab.lan")
	if err := e.s.RevokeJoinToken(ctx, testinstance.Console, rjt.ID); err != nil {
		t.Fatal(err)
	}
	if _, st := e.enroll(t, "d.homelab.lan", revoked, true, mustCSR(t)); st.State != StatePending || !strings.Contains(st.Message, "the pass was revoked") {
		t.Errorf("revoked: %+v", st)
	}
	if _, st := e.enroll(t, "e.homelab.lan", "mjp_"+strings.Repeat("A", 43), true, mustCSR(t)); !strings.Contains(st.Message, "unknown join token") {
		t.Errorf("unknown: %+v", st)
	}
	if got := e.find(t, rjt.ID); got.UseCount != 0 || got.State(e.inst.Clock.Now()) != TokenRevoked {
		t.Errorf("revoked pass: %+v", got)
	}
}

// TestPassRevoke: revoking ends use at once and leaves what the pass already
// produced alone – the agent stays active, a waiting enrollment still waits
// and can be approved. A revoked pass can't be revoked again; an unused one
// can still be withdrawn, a used one stays as a record.
func TestPassRevoke(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollManual) // manual: the enrollments wait for a person
	ctx := t.Context()
	secret, jt := e.pass(t, 4, time.Hour, "*.homelab.lan")
	_, waiting := e.enroll(t, "waiting.homelab.lan", secret, true, mustCSR(t))
	if waiting.State != StatePending || !waiting.TokenValid {
		t.Fatalf("%+v", waiting)
	}
	e.mode = tenant.EnrollVerified
	_, admitted := e.enroll(t, "admitted.homelab.lan", secret, true, mustCSR(t))
	if admitted.State != StateAdmitted {
		t.Fatalf("%+v", admitted)
	}
	if err := e.s.RevokeJoinToken(ctx, testinstance.Console, jt.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.s.RevokeJoinToken(ctx, testinstance.Console, jt.ID); !errors.Is(err, ErrConflict) {
		t.Errorf("revoked twice: %v", err)
	}
	if err := e.s.RevokeJoinToken(ctx, testinstance.Console, "jtk_nothere"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown: %v", err)
	}
	// Use ends at once ...
	if _, st := e.enroll(t, "late.homelab.lan", secret, true, mustCSR(t)); st.TokenValid || st.State != StatePending {
		t.Errorf("after the revocation: %+v", st)
	}
	// ... and nothing else changes.
	a, err := e.s.GetAgent(ctx, testinstance.Console, admitted.AgentID)
	if err != nil || a.Status != StatusActive {
		t.Errorf("the agent the pass admitted: %+v %v", a, err)
	}
	got := e.find(t, jt.ID)
	if got.RevokedAt.IsZero() || got.RevokedBy == "" || got.UseCount != 2 || len(got.Hosts) != 2 {
		t.Errorf("revoked pass: %+v", got)
	}
	states := map[string]string{}
	for _, h := range got.Hosts {
		states[h.Hostname] = h.State
		if h.State == StateAdmitted && h.AgentID != admitted.AgentID {
			t.Errorf("host %s: agent %q", h.Hostname, h.AgentID)
		}
	}
	if states["waiting.homelab.lan"] != StatePending || states["admitted.homelab.lan"] != StateAdmitted {
		t.Errorf("hosts of the pass: %v", states)
	}
	open, err := e.s.ListEnrollments(ctx, testinstance.Console, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range open {
		if o.Hostname == "waiting.homelab.lan" {
			if err := e.s.Approve(ctx, testinstance.Console, o.ID); err != nil {
				t.Errorf("an admin approves what the revoked pass started: %v", err)
			}
		}
	}
	// Withdraw: only a pass nobody used.
	_, unused := e.pass(t, 3, time.Hour, "*.homelab.lan")
	if err := e.s.DeleteJoinToken(ctx, testinstance.Console, unused.ID); err != nil {
		t.Errorf("withdraw an unused pass: %v", err)
	}
	if err := e.s.DeleteJoinToken(ctx, testinstance.Console, jt.ID); !errors.Is(err, ErrConflict) {
		t.Errorf("withdraw a used pass: %v", err)
	}
	// An expired or used-up pass has nothing left to revoke.
	_, done := e.pass(t, 2, time.Hour, "*.homelab.lan")
	e.inst.Clock.Advance(2 * time.Hour)
	if err := e.s.RevokeJoinToken(ctx, testinstance.Console, done.ID); !errors.Is(err, ErrConflict) || !strings.Contains(err.Error(), "expired") {
		t.Errorf("revoke an expired pass: %v", err)
	}
}

// TestPassNeedsAFreshSecondFactorAndTheAdminRole: the service decides, not
// only the handlers. A viewer and an operator are denied, an admin without a
// fresh second factor is asked for it, and an API token is refused outright
// whatever its role.
func TestPassNeedsAFreshSecondFactorAndTheAdminRole(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollVerified)
	ctx := t.Context()
	now := e.inst.Clock.Now()
	person := func(role authz.Role, stepUp time.Time, viaToken bool) keys.Who {
		return keys.Who{
			Actor:     audit.Actor{Type: audit.ActorUser, ID: "u1", Name: "someone"},
			Principal: &authz.Principal{Kind: authz.KindUser, UserID: "u1", Username: "someone", Bindings: []authz.Binding{{Tenant: "default", Role: role}}, StepUpAt: stepUp, ViaToken: viaToken},
		}
	}
	_, victim := e.pass(t, 3, time.Hour, "*.homelab.lan")
	for _, tt := range []struct {
		name string
		who  keys.Who
		want error
	}{
		{"viewer", person(authz.Viewer, now, false), authz.ErrDenied},
		{"operator", person(authz.Operator, now, false), authz.ErrDenied},
		{"admin without a second factor", person(authz.Admin, time.Time{}, false), authz.ErrStepUpRequired},
		{"admin with an old second factor", person(authz.Admin, now.Add(-time.Hour), false), authz.ErrStepUpRequired},
		{"admin token with a fresh second factor on the session", person(authz.Admin, now, true), authz.ErrDenied},
		{"viewer token", person(authz.Viewer, now, true), authz.ErrDenied},
		{"nobody", keys.Who{}, authz.ErrDenied},
	} {
		if _, _, err := e.s.CreateEnrollmentPass(ctx, tt.who, "x", []string{"*.homelab.lan"}, 5, time.Hour); !errors.Is(err, tt.want) {
			t.Errorf("%s creates a pass: %v, want %v", tt.name, err, tt.want)
		}
		if err := e.s.RevokeJoinToken(ctx, tt.who, victim.ID); !errors.Is(err, tt.want) {
			t.Errorf("%s revokes a pass: %v, want %v", tt.name, err, tt.want)
		}
		if err := e.s.DeleteJoinToken(ctx, tt.who, victim.ID); !errors.Is(err, tt.want) {
			t.Errorf("%s withdraws a pass: %v, want %v", tt.name, err, tt.want)
		}
	}
	if _, _, err := e.s.CreateEnrollmentPass(ctx, person(authz.Admin, now, false), "x", []string{"*.homelab.lan"}, 5, time.Hour); err != nil {
		t.Errorf("an admin with a fresh second factor: %v", err)
	}
	// Reading is for every role, tokens included.
	for _, who := range []keys.Who{person(authz.Viewer, time.Time{}, false), person(authz.Viewer, time.Time{}, true)} {
		if _, err := e.s.ListJoinTokens(ctx, who); err != nil {
			t.Errorf("list: %v", err)
		}
	}
	if got := e.find(t, victim.ID); !got.RevokedAt.IsZero() {
		t.Errorf("a refused revocation took effect")
	}
}

// TestPassSecretIsNeverLoggedOrAudited: the secret appears in no audit entry
// and no log line of create, use, refusal and revoke, and the audit entries
// name the pass and the use number.
func TestPassSecretIsNeverLoggedOrAudited(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollVerified)
	var logs bytes.Buffer
	e.s.Log = slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ctx := t.Context()
	secret, jt := e.pass(t, 2, time.Hour, "*.homelab.lan")
	e.enroll(t, "a.homelab.lan", secret, true, mustCSR(t))
	e.enroll(t, "b.homelab.lan", secret, false, mustCSR(t)) // a failed check is logged
	e.enroll(t, "c.homelab.lan", secret, true, mustCSR(t))  // no uses left
	// Wrong-pattern and failing-create paths are audited too.
	_, _, _ = e.s.CreateEnrollmentPass(ctx, testinstance.Console, "bad", []string{"*.nodomain.lan"}, 5, time.Hour)
	if err := e.s.RevokeJoinToken(ctx, testinstance.Console, jt.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("revoke a used-up pass: %v", err)
	}
	live, ljt := e.pass(t, 3, time.Hour, "*.homelab.lan")
	if err := e.s.RevokeJoinToken(ctx, testinstance.Console, ljt.ID); err != nil {
		t.Fatal(err)
	}
	e.enroll(t, "d.homelab.lan", live, true, mustCSR(t))
	e.inst.Deliver(t)

	rows, err := e.inst.TenantAudit.Read.QueryContext(ctx, `SELECT action, result, target_id, details_json FROM audit_entries ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var all strings.Builder
	actions := map[string]int{}
	for rows.Next() {
		var action, result, target, details string
		if err := rows.Scan(&action, &result, &target, &details); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&all, "%s %s %s %s\n", action, result, target, details)
		actions[action+"/"+result]++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{secret, secret[len(PassPrefix):], live, live[len(PassPrefix):], hashToken(secret), hashToken(live)} {
		if strings.Contains(all.String(), s) || strings.Contains(logs.String(), s) {
			t.Errorf("a secret or its hash is in the audit log or the log: %q", s[:8])
		}
	}
	if actions["agent.token.create/success"] != 2 || actions["agent.token.create/failure"] != 1 || actions["agent.token.revoke/success"] != 1 ||
		actions["agent.token.revoke/failure"] != 1 || actions["agent.enroll/success"] != 4 {
		t.Errorf("audit actions: %v\n%s", actions, all.String())
	}
	for _, want := range []string{
		`"token_kind":"pass"`, `"token_id":"` + jt.ID + `"`, `"use":"1 of 2"`, `"use":"2 of 2"`, // the two uses
		`the enrollment pass has no uses left (2 of 2)`, `the pass was revoked`, // the refusals name the reason
		`"kind":"pass"`, `"max_uses":2`, `no domain covers *.nodomain.lan`,
	} {
		if !strings.Contains(all.String(), want) {
			t.Errorf("the audit log lacks %s:\n%s", want, all.String())
		}
	}
}

// String keeps a failing test from printing certificates.
func (s Status) String() string {
	return fmt.Sprintf("state %s, token valid %v, check passed %v, message %q", s.State, s.TokenValid, s.CheckPassed, s.Message)
}
