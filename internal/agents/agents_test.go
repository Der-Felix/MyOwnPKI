package agents

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// fakeChecker answers the http-01 check: it passes when the agent "placed"
// the right content for the token (want), and records the policy.
type fakeChecker struct {
	mu     sync.Mutex
	placed map[string]string // token -> content the agent serves
	calls  []string
}

func (f *fakeChecker) Check(_ context.Context, host, token, want, policy string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, host+" "+policy)
	if f.placed[token] != want {
		return errors.New("http://" + host + "/.well-known/acme-challenge/" + token + " answered 404")
	}
	return nil
}

func (f *fakeChecker) place(token, content string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.placed[token] = content
}

type env struct {
	inst  *testinstance.Instance
	s     *Service
	check *fakeChecker
	mode  string
}

func newEnv(t *testing.T, mode string) *env {
	t.Helper()
	inst := testinstance.New(t, testinstance.Options{})
	inst.Unseal(t)
	ctx := t.Context()
	if _, err := inst.Engine.CreateIntermediate(ctx, ca.IntermediateRequest{
		CASettings: ca.CASettings{Name: "agent-ca", BaseURL: "http://pki.homelab.lan"}, Parent: "root",
		Subject: ca.Subject{CommonName: "Agent CA"}, EKULimit: []string{"clientAuth"}, Who: testinstance.Console,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := inst.Engine.CreateDomain(ctx, ca.DomainRequest{Name: "homelab.lan", DomainSettings: ca.DomainSettings{CA: ptr("issuing")}, Who: testinstance.Console}); err != nil {
		t.Fatal(err)
	}
	e := &env{inst: inst, check: &fakeChecker{placed: map[string]string{}}, mode: mode}
	e.s = &Service{
		PKI: inst.PKIDB.Write, Tenant: "default", Engine: inst.Engine, CA: "agent-ca", Checker: e.check, Clock: inst.Clock,
		Log: slog.New(slog.DiscardHandler), Mode: func(context.Context) (string, error) { return e.mode, nil },
	}
	return e
}

func ptr[T any](v T) *T { return &v }

func newCSR(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key, csrFor(t, key)
}

func csrFor(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "evil.example"}, DNSNames: []string{"evil.example"}, // ignored by the server
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// enroll runs Enroll and – if place – answers the check correctly.
func (e *env) enroll(t *testing.T, host, token string, place bool, csr []byte) (*EnrollOutput, *Status) {
	t.Helper()
	out, err := e.s.Enroll(t.Context(), EnrollInput{Hostname: host, Token: token, Method: MethodWebroot, OS: "linux", Arch: "amd64", Version: "0.3.0", SourceIP: "192.0.2.10", CSRDER: csr})
	if err != nil {
		t.Fatalf("enroll %s: %v", host, err)
	}
	if place {
		spki, _ := csrKey(csr)
		e.check.place(out.CheckToken, out.CheckToken+"."+spki)
	}
	st, err := e.s.EnrollStatus(t.Context(), StatusInput{ID: out.ID, Handle: out.Handle, CheckReady: true, SourceIP: "192.0.2.10"})
	if err != nil {
		t.Fatalf("status %s: %v", host, err)
	}
	return out, st
}

func (e *env) token(t *testing.T, patterns ...string) string {
	t.Helper()
	tok, _, err := e.s.CreateJoinToken(t.Context(), testinstance.Console, "test", patterns, 0)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// TestEnrollModes is the table of docs/PHASE3.md §6.1: each mode × (token,
// check) admits or queues.
func TestEnrollModes(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		mode          string
		token, passed bool
		want          string
	}{
		{tenant.EnrollAuto, true, true, StateAdmitted},
		{tenant.EnrollAuto, true, false, StateAdmitted},
		{tenant.EnrollAuto, false, true, StateAdmitted},
		{tenant.EnrollAuto, false, false, StatePending},
		{tenant.EnrollVerified, true, true, StateAdmitted},
		{tenant.EnrollVerified, true, false, StatePending},
		{tenant.EnrollVerified, false, true, StatePending},
		{tenant.EnrollVerified, false, false, StatePending},
		{tenant.EnrollManual, true, true, StatePending},
		{tenant.EnrollManual, true, false, StatePending},
		{tenant.EnrollManual, false, true, StatePending},
		{tenant.EnrollManual, false, false, StatePending},
	} {
		name := fmt.Sprintf("%s token=%v check=%v", tt.mode, tt.token, tt.passed)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, tt.mode)
			tok := ""
			if tt.token {
				tok = e.token(t, "*.homelab.lan")
			}
			_, csr := newCSR(t)
			_, st := e.enroll(t, "proxy1.homelab.lan", tok, tt.passed, csr)
			if st.State != tt.want || st.TokenValid != tt.token || st.CheckPassed != tt.passed {
				t.Fatalf("%+v, want %s", st, tt.want)
			}
			if tt.want == StateAdmitted {
				cert, err := x509.ParseCertificate(st.CertDER)
				if err != nil {
					t.Fatal(err)
				}
				// The certificate: the hostname only (the CSR's names are ignored),
				// clientAuth only, 7 days, from the agent CA.
				if cert.Subject.CommonName != "proxy1.homelab.lan" || len(cert.DNSNames) != 1 || cert.DNSNames[0] != "proxy1.homelab.lan" ||
					len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
					cert.NotAfter.Sub(cert.NotBefore) != CertificateDays*24*time.Hour-time.Second || cert.Issuer.CommonName != "Agent CA" {
					t.Errorf("certificate: CN %q SANs %v EKU %v validity %v issuer %q", cert.Subject.CommonName, cert.DNSNames, cert.ExtKeyUsage,
						cert.NotAfter.Sub(cert.NotBefore), cert.Issuer.CommonName)
				}
				if len(st.Chain) != 1 { // the agent CA; the root is the agent's trust anchor
					t.Errorf("chain of %d", len(st.Chain))
				}
				if a, err := e.s.GetAgent(t.Context(), testinstance.Console, st.AgentID); err != nil || a.Status != StatusActive || len(a.Names) == 0 {
					t.Errorf("agent: %+v %v", a, err)
				}
			}
			if !strings.Contains(e.check.calls[0], "proxy1.homelab.lan internal") {
				t.Errorf("check: %v", e.check.calls)
			}
		})
	}
}

// TestJoinToken: single-use, expiring, only for its names; a token that
// doesn't count is no error, the queue names why. The secret is never stored.
func TestJoinToken(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollVerified)
	ctx := t.Context()
	tok := e.token(t, "proxy1.homelab.lan")
	if !strings.HasPrefix(tok, TokenPrefix) || len(tok) < 40 {
		t.Fatalf("token %q", tok)
	}
	var n int
	if err := e.inst.PKIDB.Read.QueryRowContext(ctx, `SELECT count(*) FROM join_tokens WHERE token_hash = ?`, tok).Scan(&n); err != nil || n != 0 {
		t.Errorf("the secret is stored: %d %v", n, err)
	}
	_, csr := newCSR(t)
	if _, st := e.enroll(t, "other.homelab.lan", tok, true, csr); st.State != StatePending || st.TokenValid ||
		!strings.Contains(st.Message, "not for other.homelab.lan") {
		t.Errorf("other host: %+v", st)
	}
	_, csr = newCSR(t)
	if _, st := e.enroll(t, "proxy1.homelab.lan", tok, true, csr); st.State != StateAdmitted {
		t.Errorf("first use: %+v", st)
	}
	_, csr = newCSR(t)
	if _, st := e.enroll(t, "proxy1.homelab.lan", tok, true, csr); st.State != StatePending || !strings.Contains(st.Message, "used already") {
		t.Errorf("second use: %+v", st)
	}
	old := e.token(t, "proxy2.homelab.lan")
	e.inst.Clock.Advance(DefaultTokenTTL + time.Second)
	_, csr = newCSR(t)
	if _, st := e.enroll(t, "proxy2.homelab.lan", old, true, csr); st.State != StatePending || !strings.Contains(st.Message, "expired") {
		t.Errorf("expired: %+v", st)
	}
	if _, st := e.enroll(t, "proxy3.homelab.lan", "mjt_guessed", true, csr); !strings.Contains(st.Message, "unknown join token") {
		t.Errorf("unknown: %+v", st)
	}
	// Patterns and limits.
	for _, bad := range [][]string{nil, {"*"}, {"*.lan"}, {"10.0.0.1"}, {"a b.homelab.lan"}} {
		if _, _, err := e.s.CreateJoinToken(ctx, testinstance.Console, "x", bad, 0); !errors.Is(err, ErrInvalid) {
			t.Errorf("%v: %v", bad, err)
		}
	}
	if _, _, err := e.s.CreateJoinToken(ctx, testinstance.Console, "x", []string{"a.homelab.lan"}, MaxTokenTTL+time.Hour); !errors.Is(err, ErrInvalid) {
		t.Errorf("31 days: %v", err)
	}
	// A used token can't be withdrawn, an unused one can.
	list, err := e.s.ListJoinTokens(ctx, testinstance.Console)
	if err != nil {
		t.Fatal(err)
	}
	for _, jt := range list {
		err := e.s.DeleteJoinToken(ctx, testinstance.Console, jt.ID)
		if used := !jt.UsedAt.IsZero(); used != errors.Is(err, ErrConflict) || !used && err != nil {
			t.Errorf("delete %s (used %v): %v", jt.Patterns, used, err)
		}
	}
}

// TestQueueLimit (owner 2026-10-24): 100 junk enrollments fill the queue; a
// further one without a token is refused, an agent with a token is not –
// and in verified with a passed check it is admitted at once. Junk expires
// after 24 hours, an enrollment with a passed check after 7 days.
func TestQueueLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollVerified)
	ctx := t.Context()
	_, csr := newCSR(t)
	for i := range MaxOpenWithoutToken {
		// From different addresses, as an attacker would.
		if _, err := e.s.Enroll(ctx, EnrollInput{Hostname: fmt.Sprintf("junk%d.homelab.lan", i), Method: MethodStandalone, SourceIP: fmt.Sprintf("198.51.100.%d", i%250), CSRDER: csr}); err != nil {
			t.Fatalf("junk %d: %v", i, err)
		}
	}
	if _, err := e.s.Enroll(ctx, EnrollInput{Hostname: "junk.homelab.lan", Method: MethodStandalone, SourceIP: "203.0.113.1", CSRDER: csr}); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("101st without token: %v", err)
	}
	_, mine := newCSR(t)
	if _, st := e.enroll(t, "proxy1.homelab.lan", e.token(t, "proxy1.homelab.lan"), true, mine); st.State != StateAdmitted {
		t.Fatalf("with a token behind 100 junk enrollments: %+v", st)
	}
	// A passed check without token: 7 days; junk: 24 hours.
	e.mode = tenant.EnrollManual
	_, csr2 := newCSR(t)
	e.inst.Clock.Advance(ShortExpiry + time.Minute) // the junk expires
	keep, st := e.enroll(t, "proxy2.homelab.lan", "", true, csr2)
	if st.State != StatePending {
		t.Fatalf("manual: %+v", st)
	}
	open, err := e.s.ListEnrollments(ctx, testinstance.Console, true)
	if err != nil || len(open) != 1 || open[0].ID != keep.ID {
		t.Fatalf("after 24 hours %d open (%v), want only proxy2", len(open), err)
	}
	e.inst.Clock.Advance(ShortExpiry + time.Hour)
	if open, _ := e.s.ListEnrollments(ctx, testinstance.Console, true); len(open) != 1 {
		t.Errorf("a passed check expired after 24 hours")
	}
	e.inst.Clock.Advance(LongExpiry)
	if open, _ := e.s.ListEnrollments(ctx, testinstance.Console, true); len(open) != 0 {
		t.Errorf("open after 7 days: %d", len(open))
	}
	if st, err := e.s.EnrollStatus(ctx, StatusInput{ID: keep.ID, Handle: keep.Handle}); err != nil || st.State != StateExpired {
		t.Errorf("expired enrollment: %+v %v", st, err)
	}
}

// TestApproveDeny: an admin admits or refuses from the queue; a viewer and
// an operator can't; a decided enrollment can't be decided again.
func TestApproveDeny(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollManual)
	ctx := t.Context()
	_, csr := newCSR(t)
	out, _ := e.enroll(t, "proxy1.homelab.lan", "", true, csr)
	_, csr2 := newCSR(t)
	out2, _ := e.enroll(t, "proxy2.homelab.lan", "", false, csr2)
	viewer := keys.Who{Principal: &authz.Principal{Kind: authz.KindUser, Username: "v", Bindings: []authz.Binding{{Tenant: "default", Role: authz.Operator}}}}
	if err := e.s.Approve(ctx, viewer, out.ID); !errors.Is(err, authz.ErrDenied) {
		t.Errorf("operator approved: %v", err)
	}
	if err := e.s.Approve(ctx, testinstance.Console, out.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.s.Approve(ctx, testinstance.Console, out.ID); !errors.Is(err, ErrConflict) {
		t.Errorf("approved twice: %v", err)
	}
	st, err := e.s.EnrollStatus(ctx, StatusInput{ID: out.ID, Handle: out.Handle})
	if err != nil || st.State != StateAdmitted || len(st.CertDER) == 0 {
		t.Fatalf("after approval: %+v %v", st, err)
	}
	if err := e.s.Deny(ctx, testinstance.Console, out2.ID); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.s.EnrollStatus(ctx, StatusInput{ID: out2.ID, Handle: out2.Handle}); st.State != StateDenied {
		t.Errorf("denied: %+v", st)
	}
	// A wrong handle looks like an unknown enrollment.
	if _, err := e.s.EnrollStatus(ctx, StatusInput{ID: out.ID, Handle: "wrong"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("wrong handle: %v", err)
	}
}

// TestSealed: an admitted agent waits for the unseal – without a refused
// issuance in the audit log per poll – and gets its certificate after it.
func TestSealed(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	ctx := t.Context()
	if err := e.inst.Ring.Seal(ctx, testinstance.Console); err != nil {
		t.Fatal(err)
	}
	_, csr := newCSR(t)
	out, st := e.enroll(t, "proxy1.homelab.lan", "", true, csr)
	for range 3 {
		st, _ = e.s.EnrollStatus(ctx, StatusInput{ID: out.ID, Handle: out.Handle})
	}
	if st.State != StateWaitingForUnseal {
		t.Fatalf("sealed: %+v", st)
	}
	if got := strings.Join(testinstance.Audit(t, e.inst.TenantAudit), " "); strings.Contains(got, ca.ActionIssue+"/") {
		t.Errorf("refusals in the audit log: %s", got)
	}
	e.inst.Unseal(t)
	if st, _ = e.s.EnrollStatus(ctx, StatusInput{ID: out.ID, Handle: out.Handle}); st.State != StateAdmitted || len(st.CertDER) == 0 {
		t.Errorf("after the unseal: %+v", st)
	}
}

// admitted enrolls an agent in auto mode and returns its key and certificate.
func (e *env) admitted(t *testing.T, host string) (*ecdsa.PrivateKey, *x509.Certificate, string) {
	t.Helper()
	key, csr := newCSR(t)
	_, st := e.enroll(t, host, "", true, csr)
	if st.State != StateAdmitted {
		t.Fatalf("%s: %+v", host, st)
	}
	cert, err := x509.ParseCertificate(st.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert, st.AgentID
}

// TestIdentifyRenewRevoke: the current and the previous certificate
// identify the agent; a renewal needs a new key; disable and revoke cut it
// off at the next call; revoke puts its certificates on the CRL.
func TestIdentifyRenewRevoke(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	ctx := t.Context()
	key, first, id := e.admitted(t, "proxy1.homelab.lan")
	c, err := e.s.Identify(ctx, first, "192.0.2.10")
	if err != nil || c.Agent.ID != id {
		t.Fatalf("identify: %v", err)
	}
	if _, _, rerr := e.s.RenewCertificate(ctx, c, csrFor(t, key)); !errors.Is(rerr, ErrInvalid) {
		t.Errorf("renewed with the same key: %v", rerr)
	}
	_, csr2 := newCSR(t)
	der, chain, err := e.s.RenewCertificate(ctx, c, csr2)
	if err != nil || len(chain) != 1 {
		t.Fatalf("renew: %v", err)
	}
	second, _ := x509.ParseCertificate(der)
	for _, cert := range []*x509.Certificate{first, second} {
		if _, err := e.s.Identify(ctx, cert, ""); err != nil {
			t.Errorf("%s after one renewal: %v", ca.SerialHex(cert.SerialNumber), err)
		}
	}
	c2, _ := e.s.Identify(ctx, second, "")
	_, csr3 := newCSR(t)
	if _, _, err := e.s.RenewCertificate(ctx, c2, csr3); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.Identify(ctx, first, ""); !errors.Is(err, ErrUnknownAgent) {
		t.Errorf("the certificate before the previous one: %v", err)
	}
	// A foreign certificate with a known serial is refused.
	forged := *second
	forged.Raw = append([]byte{}, second.Raw...)
	forged.Raw[len(forged.Raw)-1] ^= 1
	if _, err := e.s.Identify(ctx, &forged, ""); !errors.Is(err, ErrUnknownAgent) {
		t.Errorf("forged: %v", err)
	}
	if err := e.s.SetDisabled(ctx, testinstance.Console, id, true); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.Identify(ctx, second, ""); !errors.Is(err, ErrUnknownAgent) {
		t.Errorf("disabled: %v", err)
	}
	if err := e.s.SetDisabled(ctx, testinstance.Console, id, false); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.Identify(ctx, second, ""); err != nil {
		t.Errorf("enabled again: %v", err)
	}
	if err := e.s.Revoke(ctx, testinstance.Console, id); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.Identify(ctx, second, ""); !errors.Is(err, ErrUnknownAgent) {
		t.Errorf("revoked: %v", err)
	}
	var revoked int
	if err := e.inst.PKIDB.Read.QueryRowContext(ctx, `SELECT count(*) FROM revocations`).Scan(&revoked); err != nil || revoked != 2 {
		t.Errorf("%d certificates on the CRL (%v), want the current and the previous", revoked, err)
	}
	if err := e.s.SetDisabled(ctx, testinstance.Console, id, false); !errors.Is(err, ErrConflict) {
		t.Errorf("a revoked agent was enabled: %v", err)
	}
}

// TestEnrollAgain (owner 2026-10-24): an agent whose certificate expired
// comes back with the key of its last certificate and a passed check –
// without a token, even in manual – as the same agent. Another key, or a
// disabled agent, goes through the table again.
func TestEnrollAgain(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	ctx := t.Context()
	key, _, id := e.admitted(t, "proxy1.homelab.lan")
	e.mode = tenant.EnrollManual
	e.inst.Clock.Advance(8 * 24 * time.Hour) // the certificate expired
	_, st := e.enroll(t, "proxy1.homelab.lan", "", true, csrFor(t, key))
	if st.State != StateAdmitted || st.AgentID != id {
		t.Fatalf("the known key: %+v (want agent %s)", st, id)
	}
	if list, _ := e.s.ListAgents(ctx, testinstance.Console); len(list) != 1 {
		t.Errorf("%d agents, want 1", len(list))
	}
	_, other := newCSR(t)
	if _, st := e.enroll(t, "proxy1.homelab.lan", "", true, other); st.State != StatePending {
		t.Errorf("another key: %+v", st)
	}
	if err := e.s.SetDisabled(ctx, testinstance.Console, id, true); err != nil {
		t.Fatal(err)
	}
	if _, st := e.enroll(t, "proxy1.homelab.lan", "", true, csrFor(t, key)); st.State != StatePending {
		t.Errorf("disabled agent with its key: %+v", st)
	}
	// Without a passed check, the known key alone is not enough.
	if err := e.s.SetDisabled(ctx, testinstance.Console, id, false); err != nil {
		t.Fatal(err)
	}
	if _, st := e.enroll(t, "proxy1.homelab.lan", "", false, csrFor(t, key)); st.State != StatePending {
		t.Errorf("known key, failed check: %+v", st)
	}
}

// TestNames: an admin adds and removes names; patterns are checked.
func TestNames(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	ctx := t.Context()
	_, _, id := e.admitted(t, "proxy1.homelab.lan")
	if err := e.s.AddName(ctx, testinstance.Console, id, "*.apps.homelab.lan"); err != nil {
		t.Fatal(err)
	}
	if err := e.s.AddName(ctx, testinstance.Console, id, "bad name"); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad name: %v", err)
	}
	if err := e.s.RemoveName(ctx, testinstance.Console, id, "nope.homelab.lan"); !errors.Is(err, ErrNotFound) {
		t.Errorf("remove unknown: %v", err)
	}
	a, err := e.s.GetAgent(ctx, testinstance.Console, id)
	if err != nil || len(a.Names) != 2 || a.Names[0].Pattern != "*.apps.homelab.lan" || a.Names[0].Source != "admin" || a.Names[1].Source != "hostname" {
		t.Errorf("names: %+v %v", a, err)
	}
}

func TestMatches(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		pattern, name string
		want          bool
	}{
		{"proxy1.homelab.lan", "proxy1.homelab.lan", true},
		{"*.homelab.lan", "proxy1.homelab.lan", true},
		{"*.homelab.lan", "a.b.homelab.lan", true},
		{"*.homelab.lan", "homelab.lan", false},
		{"*.homelab.lan", "evilhomelab.lan", false},
		{"*.homelab.lan", "*.homelab.lan", true},
		{"*.homelab.lan", "*.a.homelab.lan", false},
		{"proxy1.homelab.lan", "proxy2.homelab.lan", false},
	} {
		if got := Matches(tt.pattern, tt.name); got != tt.want {
			t.Errorf("Matches(%q, %q) = %v", tt.pattern, tt.name, got)
		}
	}
	for _, bad := range []string{"", "lan", "-a.lan", "a..lan", "10.0.0.1", "*.homelab.lan", "a_b.lan", strings.Repeat("a", 64) + ".lan"} {
		if _, err := CheckHostname(bad); err == nil {
			t.Errorf("hostname %q accepted", bad)
		}
	}
}

// TestEnrollInput: what the unauthenticated call refuses before anything
// is stored, and the rate limit per address.
func TestEnrollInput(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	ctx := t.Context()
	_, csr := newCSR(t)
	for name, in := range map[string]EnrollInput{
		"method":  {Hostname: "a.homelab.lan", Method: "dns-01", CSRDER: csr},
		"csr":     {Hostname: "a.homelab.lan", Method: MethodStandalone, CSRDER: []byte("junk")},
		"big csr": {Hostname: "a.homelab.lan", Method: MethodStandalone, CSRDER: make([]byte, maxCSR+1)},
		"host":    {Hostname: "localhost", Method: MethodStandalone, CSRDER: csr},
		"os":      {Hostname: "a.homelab.lan", Method: MethodStandalone, OS: "linux\x00", CSRDER: csr},
	} {
		in.SourceIP = "192.0.2.99"
		if _, err := e.s.Enroll(ctx, in); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	var last error
	for range enrollPerWindow + 1 {
		_, last = e.s.Enroll(ctx, EnrollInput{Hostname: "a.homelab.lan", Method: MethodStandalone, SourceIP: "192.0.2.50", CSRDER: csr})
	}
	if !errors.Is(last, ErrRateLimited) {
		t.Errorf("rate limit: %v", last)
	}
}

// TestRenewLimit: at most 6 renewals per agent and hour (ResourceExhausted
// on the channel, TestRPCErrors); another agent and the next hour are not
// affected.
func TestRenewLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	ctx := t.Context()
	_, cert, _ := e.admitted(t, "proxy1.homelab.lan")
	_, other, _ := e.admitted(t, "proxy2.homelab.lan")
	renew := func(cert *x509.Certificate) (*x509.Certificate, error) {
		t.Helper()
		c, err := e.s.Identify(ctx, cert, "")
		if err != nil {
			t.Fatal(err)
		}
		_, csr := newCSR(t)
		der, _, err := e.s.RenewCertificate(ctx, c, csr)
		if err != nil {
			return cert, err
		}
		return x509.ParseCertificate(der)
	}
	var err error
	for i := range renewPerHour {
		if cert, err = renew(cert); err != nil {
			t.Fatalf("renewal %d: %v", i+1, err)
		}
	}
	if _, err = renew(cert); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("renewal %d: %v, want the limit", renewPerHour+1, err)
	}
	if _, err := renew(other); err != nil {
		t.Errorf("another agent: %v", err)
	}
	e.inst.Clock.Advance(time.Hour)
	if _, err := renew(cert); err != nil {
		t.Errorf("an hour later: %v", err)
	}
}
