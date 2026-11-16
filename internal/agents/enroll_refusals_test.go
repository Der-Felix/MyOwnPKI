package agents

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// ed25519CSR returns a CSR of exactly size bytes of DER. Ed25519 signatures
// have a fixed length, so the size follows the length of one DN value.
func ed25519CSR(t *testing.T, size int) []byte {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	build := func(pad int) []byte {
		der, cerr := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "pad", Organization: []string{strings.Repeat("x", pad)}},
		}, key)
		if cerr != nil {
			t.Fatal(cerr)
		}
		return der
	}
	pad := size - 200
	for range 3 {
		der := build(pad)
		if len(der) == size {
			return der
		}
		pad += size - len(der)
	}
	t.Fatalf("no CSR of %d bytes", size)
	return nil
}

func (e *env) enrollmentCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := e.inst.PKIDB.Read.QueryRowContext(t.Context(), `SELECT count(*) FROM agent_enrollments`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestEnrollRefusals: what Enroll refuses before anything is stored – the
// call is anonymous, so every field is checked by the server.
func TestEnrollRefusals(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	csr := mustCSR(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "rsa"}}, rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	flipped := append([]byte{}, csr...)
	flipped[len(flipped)-1] ^= 0xff
	label63 := strings.Repeat("a", 63)
	ascii64 := strings.Repeat("v", 64)

	base := EnrollInput{Hostname: "proxy1.homelab.lan", Method: MethodStandalone, OS: "linux", Arch: "amd64", Version: "0.3.8", CSRDER: csr}
	with := func(mod func(*EnrollInput)) EnrollInput {
		in := base
		mod(&in)
		return in
	}
	refused := []struct {
		name string
		in   EnrollInput
		want string
	}{
		{"no host name", with(func(in *EnrollInput) { in.Hostname = "" }), "hostname"},
		{"a single label", with(func(in *EnrollInput) { in.Hostname = "proxy1" }), "want a fully qualified name"},
		{"a wildcard", with(func(in *EnrollInput) { in.Hostname = "*.homelab.lan" }), "only letters, digits, '-' and '.'"},
		{"an underscore", with(func(in *EnrollInput) { in.Hostname = "pro_xy.homelab.lan" }), "only letters, digits"},
		{"an empty label", with(func(in *EnrollInput) { in.Hostname = "a..homelab.lan" }), "every label 1 to 63 characters"},
		{"a label starting with a dash", with(func(in *EnrollInput) { in.Hostname = "-a.homelab.lan" }), "every label 1 to 63 characters"},
		{"a label of 64 characters", with(func(in *EnrollInput) { in.Hostname = label63 + "a.homelab.lan" }), "every label 1 to 63 characters"},
		{"254 characters", with(func(in *EnrollInput) { in.Hostname = strings.Repeat(label63+".", 3) + strings.Repeat("a", 58) + ".lan" }), "1 to 253 characters"},
		{"an IP address", with(func(in *EnrollInput) { in.Hostname = "10.0.0.1" }), "an IP address is not a host name"},
		{"a non-ASCII name", with(func(in *EnrollInput) { in.Hostname = "pröxy.homelab.lan" }), "only letters, digits"},
		{"a name with a path", with(func(in *EnrollInput) { in.Hostname = "a.homelab.lan/x" }), "only letters, digits"},
		{"no method", with(func(in *EnrollInput) { in.Method = "" }), "check method: standalone or webroot"},
		{"a method in capitals", with(func(in *EnrollInput) { in.Method = "Standalone" }), "check method: standalone or webroot"},
		{"a version of 65 characters", with(func(in *EnrollInput) { in.Version = ascii64 + "v" }), "at most 64 printable ASCII characters"},
		{"an os with a control character", with(func(in *EnrollInput) { in.OS = "li\x1fnux" }), "at most 64 printable ASCII characters"},
		{"an arch with DEL", with(func(in *EnrollInput) { in.Arch = "amd\x7f64" }), "at most 64 printable ASCII characters"},
		{"a non-ASCII version", with(func(in *EnrollInput) { in.Version = "0.3.8é" }), "at most 64 printable ASCII characters"},
		{"no CSR", with(func(in *EnrollInput) { in.CSRDER = nil }), "CSR: 1 byte to 8 KiB of DER"},
		{"a CSR of 8193 bytes", with(func(in *EnrollInput) { in.CSRDER = ed25519CSR(t, maxCSR+1) }), "CSR: 1 byte to 8 KiB of DER"},
		{"junk instead of a CSR", with(func(in *EnrollInput) { in.CSRDER = []byte("junk") }), "CSR: not a PKCS#10 request"},
		{"a CSR with data after it", with(func(in *EnrollInput) { in.CSRDER = append(append([]byte{}, csr...), 0) }), "CSR: not a PKCS#10 request"},
		{"a CSR with a damaged signature", with(func(in *EnrollInput) { in.CSRDER = flipped }), "CSR: the signature doesn't match its key"},
	}
	for _, tt := range refused {
		tt.in.SourceIP = "192.0.2.99"
		_, err := e.s.Enroll(t.Context(), tt.in)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: %v, want an invalid request with %q", tt.name, err, tt.want)
		}
	}
	if n := e.enrollmentCount(t); n != 0 {
		t.Errorf("%d enrollments stored by refused requests", n)
	}
	for _, row := range testinstance.Audit(t, e.inst.TenantAudit) {
		if strings.Contains(row, ActionEnroll) {
			t.Errorf("a refused request is in the audit log: %s", row)
		}
	}

	accepted := []struct {
		name string
		in   EnrollInput
	}{
		{"a name with capitals and a trailing dot", with(func(in *EnrollInput) { in.Hostname = "Proxy1.HomeLab.LAN." })},
		{"a name of 253 characters", with(func(in *EnrollInput) { in.Hostname = strings.Repeat(label63+".", 3) + strings.Repeat("a", 57) + ".lan" })},
		{"64 printable characters in every field", with(func(in *EnrollInput) { in.OS, in.Arch, in.Version = ascii64, ascii64, ascii64 })},
		{"the space and the tilde", with(func(in *EnrollInput) { in.OS = " ~" })},
		{"a CSR of exactly 8192 bytes", with(func(in *EnrollInput) { in.CSRDER = ed25519CSR(t, maxCSR) })},
		{"an RSA key", with(func(in *EnrollInput) { in.CSRDER = rsaCSR })},
		{"the webroot method", with(func(in *EnrollInput) { in.Method = MethodWebroot })},
	}
	for i, tt := range accepted {
		tt.in.SourceIP = "192.0.2." + string(rune('1'+i))
		if _, err := e.s.Enroll(t.Context(), tt.in); err != nil {
			t.Errorf("%s: %v", tt.name, err)
		}
	}
	rows, err := e.inst.PKIDB.Read.QueryContext(t.Context(), `SELECT hostname FROM agent_enrollments`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	hosts := map[string]int{}
	for rows.Next() {
		var h string
		if err = rows.Scan(&h); err != nil {
			t.Fatal(err)
		}
		hosts[h]++
		if h != strings.ToLower(h) || strings.HasSuffix(h, ".") {
			t.Errorf("stored host name %q is not in canonical form", h)
		}
	}
	if hosts["proxy1.homelab.lan"] != len(accepted)-1 {
		t.Errorf("%d enrollments for proxy1.homelab.lan, want %d (the capitals and the trailing dot are normalized)", hosts["proxy1.homelab.lan"], len(accepted)-1)
	}
	if n := e.enrollmentCount(t); n != len(accepted) {
		t.Errorf("%d enrollments stored, want %d", n, len(accepted))
	}
}

// TestEnrollNeedsAnAgentCA: without agent.ca nothing is stored.
func TestEnrollNeedsAnAgentCA(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	e.s.CA = ""
	if _, err := e.s.Enroll(t.Context(), EnrollInput{Hostname: "a.homelab.lan", Method: MethodStandalone, SourceIP: "192.0.2.1", CSRDER: mustCSR(t)}); !errors.Is(err, errNoAgentCA) {
		t.Errorf("without an agent CA: %v", err)
	}
	if n := e.enrollmentCount(t); n != 0 {
		t.Errorf("%d enrollments", n)
	}
}

// TestEnrollRateLimitIsPerAddressAndWindow: 30 enrollments per address and
// 10 minutes; another address and the next window are not affected.
func TestEnrollRateLimitIsPerAddressAndWindow(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollManual)
	csr := mustCSR(t)
	enroll := func(ip string) error {
		_, err := e.s.Enroll(t.Context(), EnrollInput{Hostname: "a.homelab.lan", Method: MethodStandalone, SourceIP: ip, CSRDER: csr})
		return err
	}
	for i := range enrollPerWindow {
		if err := enroll("192.0.2.1"); err != nil {
			t.Fatalf("enrollment %d: %v", i+1, err)
		}
	}
	if err := enroll("192.0.2.1"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("enrollment %d: %v, want the limit", enrollPerWindow+1, err)
	}
	if n := e.enrollmentCount(t); n != enrollPerWindow {
		t.Errorf("%d enrollments stored, want %d", n, enrollPerWindow)
	}
	if err := enroll("192.0.2.2"); err != nil {
		t.Errorf("another address: %v", err)
	}
	e.inst.Clock.Advance(10*time.Minute + time.Second)
	if err := enroll("192.0.2.1"); err != nil {
		t.Errorf("the next window: %v", err)
	}
}

// TestEnrollTokenProblems: a token that doesn't count never refuses the
// enrollment – it waits in the queue with the reason, and the token's use is
// not spent for it.
func TestEnrollTokenProblems(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollVerified)
	ctx := t.Context()
	tests := []struct {
		name  string
		token func(t *testing.T) string
		host  string
		want  string
	}{
		{"revoked", func(t *testing.T) string {
			secret, jt, err := e.s.CreateJoinToken(ctx, testinstance.Console, "x", []string{"*.homelab.lan"}, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err = e.s.RevokeJoinToken(ctx, testinstance.Console, jt.ID); err != nil {
				t.Fatal(err)
			}
			return secret
		}, "a.homelab.lan", "the join token was revoked"},
		{"another host name", func(t *testing.T) string { return e.token(t, "b.homelab.lan") }, "a.homelab.lan", "the join token is not for a.homelab.lan"},
		{"a pattern that only ends alike", func(t *testing.T) string { return e.token(t, "*.homelab.lan") }, "a.evilhomelab.lan", "the join token is not for a.evilhomelab.lan"},
		{"the domain itself", func(t *testing.T) string { return e.token(t, "*.homelab.lan") }, "homelab.lan", "the join token is not for homelab.lan"},
		{"an unknown secret", func(*testing.T) string { return "mjt_" + strings.Repeat("0", 43) }, "a.homelab.lan", "unknown join token"},
		{"the pass prefix with a token's secret", func(t *testing.T) string {
			return PassPrefix + strings.TrimPrefix(e.token(t, "a.homelab.lan"), TokenPrefix)
		}, "a.homelab.lan", "unknown join token"},
	}
	for _, tt := range tests {
		secret := tt.token(t)
		out, _ := e.enrollOnly(t, tt.host, secret)
		st, err := e.s.EnrollStatus(ctx, StatusInput{ID: out.ID, Handle: out.Handle, SourceIP: "192.0.2.10"})
		if err != nil {
			t.Fatal(err)
		}
		if st.State != StateWaitingForCheck || st.TokenValid {
			t.Errorf("%s: %+v", tt.name, st)
		}
		var problem sql.NullString
		var used int
		if err = e.inst.PKIDB.Read.QueryRowContext(ctx, `SELECT token_problem FROM agent_enrollments WHERE id = ?`, out.ID).Scan(&problem); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(problem.String, tt.want) {
			t.Errorf("%s: token problem %q, want %q", tt.name, problem.String, tt.want)
		}
		if err = e.inst.PKIDB.Read.QueryRowContext(ctx, `SELECT coalesce(sum(use_count), 0) FROM join_tokens`).Scan(&used); err != nil || used != 0 {
			t.Errorf("%s: %d uses spent (%v)", tt.name, used, err)
		}
	}
}

// TestSingleUseTokenIsSpentOnce: many enrollments with one token at the same
// time – exactly one holds it.
func TestSingleUseTokenIsSpentOnce(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollManual)
	secret := e.token(t, "*.homelab.lan")
	const n = 12
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Go(func() {
			_, err := e.s.Enroll(t.Context(), EnrollInput{
				Hostname: "h" + string(rune('a'+i)) + ".homelab.lan", Token: secret, Method: MethodStandalone, SourceIP: "192.0.2.10", CSRDER: mustCSR(t),
			})
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("enroll: %v", err)
		}
	}
	var valid, problems, uses int
	if err := e.inst.PKIDB.Read.QueryRowContext(t.Context(), `SELECT sum(token_valid), sum(token_problem LIKE '%used already%'), (SELECT sum(use_count) FROM join_tokens) FROM agent_enrollments`).Scan(&valid, &problems, &uses); err != nil {
		t.Fatal(err)
	}
	if valid != 1 || problems != n-1 || uses != 1 {
		t.Errorf("%d enrollments with a valid token, %d told it was used, use count %d; want 1, %d and 1", valid, problems, uses, n-1)
	}
}
