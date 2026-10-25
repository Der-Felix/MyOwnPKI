package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// issuedEnv is a test instance (sealed) with a TLS directory and a
// bootstrap certificate for one listener.
type issuedEnv struct {
	inst *testinstance.Instance
	dir  string
	boot *tls.Certificate
	logs *logBuf
}

func newIssuedEnv(t *testing.T) *issuedEnv {
	t.Helper()
	inst := testinstance.New(t, testinstance.Options{})
	dir := filepath.Join(t.TempDir(), "tls")
	boot, _, err := bootstrap(dir, bootstrapCert, bootstrapKey, "test bootstrap", "names changed", []string{"pki.homelab.lan"}, nil, inst.Clock.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return &issuedEnv{inst: inst, dir: dir, boot: boot, logs: &logBuf{}}
}

func (e *issuedEnv) manager(issuer string, names []string, ips ...string) *issuedTLS {
	var addrs []netip.Addr
	for _, ip := range ips {
		addrs = append(addrs, netip.MustParseAddr(ip))
	}
	return newIssuedTLS("admin", "admin.tls_names", "admin.tls_issuer", issuer, names, addrs, e.dir, e.boot, e.inst.Engine, e.inst.Clock,
		slog.New(slog.NewJSONHandler(e.logs, nil)))
}

// served is what a handshake gets now.
func served(t *testing.T, m *issuedTLS) *tls.Certificate {
	t.Helper()
	c, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "pki.homelab.lan"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e *issuedEnv) rootPool(t *testing.T) *x509.CertPool {
	t.Helper()
	root, err := e.inst.Engine.CAChain(t.Context(), testinstance.Console, e.inst.CAIDs["root"])
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(root[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}

// verify checks c as a TLS client would: fullchain without the root, the
// root as the only trust anchor.
func (e *issuedEnv) verify(t *testing.T, c *tls.Certificate, name string) *x509.Certificate {
	t.Helper()
	if len(c.Certificate) != 2 {
		t.Fatalf("want the certificate and the issuing CA, got %d certificates", len(c.Certificate))
	}
	inter := x509.NewCertPool()
	issuing, err := x509.ParseCertificate(c.Certificate[1])
	if err != nil {
		t.Fatal(err)
	}
	inter.AddCert(issuing)
	if _, err := c.Leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: e.rootPool(t), Intermediates: inter,
		CurrentTime: e.inst.Clock.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return c.Leaf
}

func kinds(msgs []view.Message) string {
	var out []string
	for _, m := range msgs {
		out = append(out, string(m.Kind)+": "+m.Text)
	}
	return strings.Join(out, "\n")
}

// TestIssuedTLSLifecycle: nothing while sealed, issued at the unseal (ECDSA
// P-256, 90 days, fullchain, key file 0600, audit entry of the system),
// kept across a restart, renewed at 2/3, for new names and after a
// revocation, and the bootstrap certificate when it expired while sealed.
func TestIssuedTLSLifecycle(t *testing.T) {
	t.Parallel()
	e := newIssuedEnv(t)
	ctx := t.Context()
	m := e.manager("issuing", []string{"pki.homelab.lan"}, "192.0.2.5")

	// Sealed, nothing stored: the bootstrap certificate, nothing issued.
	m.renew(ctx)
	if served(t, m) != e.boot {
		t.Error("sealed without a certificate: not the bootstrap certificate")
	}
	if got := kinds(m.attention(true)); !strings.Contains(got, "info: The admin TLS certificate is issued by CA issuing at the unseal") {
		t.Errorf("attention while sealed: %q", got)
	}

	e.inst.Unseal(t)
	m.renew(ctx)
	c := served(t, m)
	if c == e.boot {
		t.Fatalf("not issued at the unseal:\n%s", e.logs)
	}
	leaf := e.verify(t, c, "pki.homelab.lan")
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Errorf("key: %T", leaf.PublicKey)
	}
	if d := leaf.NotAfter.Sub(leaf.NotBefore); d != issuedMaxDays*24*time.Hour-time.Second {
		t.Errorf("validity %v", d)
	}
	if !slices.Equal(leaf.DNSNames, []string{"pki.homelab.lan"}) || len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "192.0.2.5" || leaf.Subject.CommonName != "pki.homelab.lan" {
		t.Errorf("names: %v %v %q", leaf.DNSNames, leaf.IPAddresses, leaf.Subject.CommonName)
	}
	if len(m.attention(false)) != 0 {
		t.Errorf("attention with a fresh certificate: %s", kinds(m.attention(false)))
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(filepath.Join(e.dir, "admin.key")); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("key file: %v %v", fi, err)
		}
	}
	// The audit entry: an issuance by the system.
	e.inst.Deliver(t)
	var actorType, actorName string
	if err := e.inst.TenantAudit.Read.QueryRowContext(ctx, `SELECT actor_type, actor_name FROM audit_entries WHERE action = ? AND result = 'success' ORDER BY seq DESC LIMIT 1`,
		ca.ActionIssue).Scan(&actorType, &actorName); err != nil || actorType != "system" || actorName != "server" {
		t.Errorf("audit entry: %q %q %v", actorType, actorName, err)
	}

	// Nothing due: the same certificate; a new manager (a restart) loads it.
	m.renew(ctx)
	if served(t, m) != c {
		t.Error("renewed although nothing was due")
	}
	m = e.manager("issuing", []string{"pki.homelab.lan"}, "192.0.2.5")
	if got := served(t, m); got.Leaf.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Error("the stored certificate was not loaded")
	}

	// 2/3 of 90 days: 60 days.
	e.inst.Clock.Advance(59 * 24 * time.Hour)
	m.renew(ctx)
	if served(t, m).Leaf.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Error("renewed before 2/3 of the lifetime")
	}
	e.inst.Clock.Advance(2 * 24 * time.Hour)
	m.renew(ctx)
	renewed := served(t, m).Leaf
	if renewed.SerialNumber.Cmp(leaf.SerialNumber) == 0 || !strings.Contains(e.logs.String(), `"reason":"2/3 of its lifetime passed"`) {
		t.Fatalf("not renewed at 2/3:\n%s", e.logs)
	}

	// New names: issued again at once, with exactly the new names.
	m = e.manager("issuing", []string{"pki.homelab.lan", "ca.homelab.lan"})
	m.renew(ctx)
	if got := e.verify(t, served(t, m), "ca.homelab.lan"); len(got.IPAddresses) != 0 || len(got.DNSNames) != 2 {
		t.Errorf("names after the change: %v %v", got.DNSNames, got.IPAddresses)
	}

	// Revoked: issued again at once.
	before := served(t, m).Leaf
	page, err := e.inst.Engine.Certificates(ctx, testinstance.Console, ca.CertificateFilter{Status: ca.CertValid, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	for _, info := range page.Items {
		if strings.EqualFold(strings.ReplaceAll(info.Fingerprint, ":", ""), strings.ReplaceAll(Fingerprint(before.Raw), ":", "")) {
			if _, rerr := e.inst.Engine.Revoke(ctx, ca.RevokeRequest{CertificateID: info.ID, Reason: "superseded", Who: testinstance.Console}); rerr != nil {
				t.Fatal(rerr)
			}
		}
	}
	m.renew(ctx)
	if served(t, m).Leaf.SerialNumber.Cmp(before.SerialNumber) == 0 || !strings.Contains(e.logs.String(), `"reason":"it was revoked"`) {
		t.Fatalf("not issued again after the revocation:\n%s", e.logs)
	}

	// The CA renewed with a new key: issued again from the new generation.
	before = served(t, m).Leaf
	if _, rerr := e.inst.Engine.RenewCA(ctx, ca.RenewRequest{Name: "issuing", Who: testinstance.Console}); rerr != nil {
		t.Fatal(rerr)
	}
	m.renew(ctx)
	if served(t, m).Leaf.SerialNumber.Cmp(before.SerialNumber) == 0 || !strings.Contains(e.logs.String(), `"reason":"it is not signed by the current certificate of CA issuing"`) {
		t.Fatalf("not issued again after the CA renewal:\n%s", e.logs)
	}

	// Expired while sealed: the bootstrap certificate, a warning in the log
	// and on the dashboard; the unseal issues a new one.
	if err := e.inst.Ring.Seal(ctx, testinstance.Console); err != nil {
		t.Fatal(err)
	}
	e.inst.Clock.Advance(91 * 24 * time.Hour)
	m.renew(ctx)
	if served(t, m) != e.boot {
		t.Error("expired while sealed: not the bootstrap certificate")
	}
	if !strings.Contains(e.logs.String(), "TLS certificate expired while sealed") {
		t.Errorf("no warning in the log:\n%s", e.logs)
	}
	if got := kinds(m.attention(true)); !strings.Contains(got, "warn: The admin TLS certificate expired on") || !strings.Contains(got, "bootstrap certificate until the unseal") {
		t.Errorf("attention: %q", got)
	}
	e.inst.Unseal(t)
	m.renew(ctx)
	if c := served(t, m); c == e.boot {
		t.Error("not issued after the unseal")
	} else {
		e.verify(t, c, "pki.homelab.lan")
	}
}

// TestIssuedTLSDenied: a name outside the CA's name constraints is refused
// with the engine's reason – in the log and on the dashboard – and not
// tried again for six hours, so the audit log doesn't fill up.
func TestIssuedTLSDenied(t *testing.T) {
	t.Parallel()
	e := newIssuedEnv(t)
	ctx := t.Context()
	e.inst.Unseal(t)
	if _, err := e.inst.Engine.CreateIntermediate(ctx, ca.IntermediateRequest{
		CASettings: ca.CASettings{Name: "lab", BaseURL: "http://pki.homelab.lan"}, Parent: "root",
		Subject: ca.Subject{CommonName: "Lab CA"}, NameConstraints: ca.NameConstraints{PermittedDNS: []string{"dmz.homelab.lan"}},
		Who: testinstance.Console,
	}); err != nil {
		t.Fatal(err)
	}
	m := e.manager("lab", []string{"pki.homelab.lan"})
	m.renew(ctx)
	if served(t, m) != e.boot {
		t.Fatal("issued outside the name constraints")
	}
	want := `"pki.homelab.lan" is outside the name constraints of CA "lab"`
	if got := kinds(m.attention(false)); !strings.Contains(got, "crit: The admin TLS certificate can't be issued by CA lab") || !strings.Contains(got, want) {
		t.Errorf("attention: %q", got)
	}
	if !strings.Contains(e.logs.String(), "TLS certificate can't be issued") || !strings.Contains(e.logs.String(), "outside the name constraints") {
		t.Errorf("log:\n%s", e.logs)
	}
	denied := func() int {
		t.Helper()
		return strings.Count(strings.Join(testinstance.Audit(t, e.inst.TenantAudit), " "), ca.ActionIssue+"/denied")
	}
	m.renew(ctx)
	e.inst.Clock.Advance(5 * time.Hour)
	m.renew(ctx)
	if n := denied(); n != 1 {
		t.Errorf("tried again within six hours: %d refusals", n)
	}
	e.inst.Clock.Advance(2 * time.Hour)
	m.renew(ctx)
	if n := denied(); n != 2 {
		t.Errorf("after six hours: %d refusals, want 2", n)
	}

	// A name inside the constraints: issued, and the message is gone.
	m = e.manager("lab", []string{"pki.dmz.homelab.lan"})
	m.renew(ctx)
	if served(t, m) == e.boot || len(m.attention(false)) != 0 {
		t.Errorf("pki.dmz.homelab.lan: %s\n%s", kinds(m.attention(false)), e.logs)
	}
	// An unknown CA: refused with its name.
	m = e.manager("nope", []string{"pki.homelab.lan"})
	m.renew(ctx)
	if got := kinds(m.attention(false)); !strings.Contains(got, `there is no CA named "nope"`) {
		t.Errorf("unknown CA: %q", got)
	}
}

// TestIssuedTLSRootIssuer: a root CA as issuer is named with the fix (the
// intermediates under it), nothing is issued or tried – no refusals in the
// audit log – and the listener serves the bootstrap certificate, even when
// an older certificate from an intermediate is still valid.
func TestIssuedTLSRootIssuer(t *testing.T) {
	t.Parallel()
	e := newIssuedEnv(t)
	ctx := t.Context()
	e.inst.Unseal(t)
	ok := e.manager("issuing", []string{"pki.homelab.lan"})
	ok.renew(ctx)
	if served(t, ok) == e.boot {
		t.Fatalf("not issued from issuing:\n%s", e.logs)
	}
	crt := filepath.Join(e.dir, issuedCertFile("admin"))
	before, err := os.ReadFile(crt) // #nosec G304 -- test file
	if err != nil {
		t.Fatal(err)
	}

	m := e.manager("root", []string{"pki.homelab.lan"}) // loads the certificate from issuing
	for range 3 {
		m.renew(ctx)
		e.inst.Clock.Advance(7 * time.Hour) // past the retry wait of a refusal
	}
	if served(t, m) != e.boot {
		t.Error("root as issuer: not the bootstrap certificate")
	}
	if _, issued := m.serving(e.inst.Clock.Now()); issued {
		t.Error("serving reports an issued certificate")
	}
	want := "CA root is a root – name the issuing intermediate in admin.tls_issuer (intermediates of root: issuing)"
	if got := kinds(m.attention(false)); got != "crit: The admin TLS certificate: "+want+". Until then the listener serves the bootstrap certificate." {
		t.Errorf("attention: %q", got)
	}
	if n := strings.Count(e.logs.String(), "can't come from a root CA"); n != 1 || !strings.Contains(e.logs.String(), want) {
		t.Errorf("logged %d times, want once with the fix:\n%s", n, e.logs)
	}
	if n := strings.Count(strings.Join(testinstance.Audit(t, e.inst.TenantAudit), " "), ca.ActionIssue+"/denied"); n != 0 {
		t.Errorf("issuance tried with the root: %d refusals in the audit log", n)
	}
	if after, rerr := os.ReadFile(crt); rerr != nil || !bytes.Equal(after, before) { // #nosec G304 -- test file
		t.Errorf("the stored certificate changed: %v", rerr)
	}
	if start := fmt.Sprint(m.startInfo()...); !strings.Contains(start, "source=bootstrap") || !strings.Contains(start, want) {
		t.Errorf("start log: %s", start)
	}

	// Intermediates and unknown names are not this check's business.
	for _, name := range []string{"issuing", "nope"} {
		if p, err := IssuerProblem(ctx, e.inst.Engine.PKI, name, "admin.tls_issuer"); p != "" || err != nil {
			t.Errorf("%s: %q, %v", name, p, err)
		}
	}
}

// TestIssuedTLSRootAtStart: the server names a root as issuer at the start –
// sealed, before any renewal – in the log and on the dashboard, and
// `config check` names it while the database is readable.
func TestIssuedTLSRootAtStart(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	cfg.Admin.TLSIssuer, cfg.Admin.TLSNames = "root", "pki.homelab.lan"
	cfg.ACME.BaseURL, cfg.ACME.Listen, cfg.ACME.TLSIssuer = "https://acme.homelab.lan/acme", "127.0.0.1:0", "issuing"
	initialized(t, cfg)
	var logs logBuf
	srv, err := Open(t.Context(), Options{Config: cfg, Log: slog.New(slog.NewJSONHandler(&logs, nil)), Hostname: "pki01", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.closeDBs()
	if !strings.Contains(logs.String(), "can't come from a root CA") || !strings.Contains(logs.String(), "CA root is a root – name the issuing intermediate in admin.tls_issuer") {
		t.Errorf("start log:\n%s", logs.String())
	}
	got := kinds(srv.tlsAttention(true))
	if !strings.Contains(got, "crit: The admin TLS certificate: CA root is a root") || strings.Contains(got, "ACME listener: CA") {
		t.Errorf("dashboard: %q", got)
	}
	if in := srv.ServedAdminCertificate(); in.Fingerprint != srv.CertInfo.Fingerprint {
		t.Errorf("served %+v, want the bootstrap certificate", in)
	}
	problems, err := TLSIssuerProblems(t.Context(), cfg)
	if err != nil || len(problems) != 1 || !strings.HasPrefix(problems[0], "CA root is a root") {
		t.Errorf("config check: %q, %v", problems, err)
	}
}

// TestIssuedTLSValidity: never beyond the CA's maximum, never beyond its end.
func TestIssuedTLSValidity(t *testing.T) {
	t.Parallel()
	e := newIssuedEnv(t)
	ctx := t.Context()
	e.inst.Unseal(t)
	for _, c := range []ca.IntermediateRequest{
		{CASettings: ca.CASettings{Name: "short-max", BaseURL: "http://pki.homelab.lan", MaxValidityDays: 30}, Subject: ca.Subject{CommonName: "Short max"}},
		{CASettings: ca.CASettings{Name: "ends-soon", BaseURL: "http://pki.homelab.lan"}, Subject: ca.Subject{CommonName: "Ends soon"}, ValidityDays: 20},
	} {
		c.Parent, c.Who = "root", testinstance.Console
		if _, err := e.inst.Engine.CreateIntermediate(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	m := e.manager("short-max", []string{"pki.homelab.lan"})
	m.renew(ctx)
	if d := served(t, m).Leaf.NotAfter.Sub(served(t, m).Leaf.NotBefore); d != 30*24*time.Hour-time.Second {
		t.Errorf("CA maximum 30 days: %v\n%s", d, e.logs)
	}
	m = e.manager("ends-soon", []string{"pki.homelab.lan"})
	m.renew(ctx)
	leaf := served(t, m).Leaf
	caCert := e.caCert(t, "ends-soon")
	if leaf == e.boot.Leaf || leaf.NotAfter.After(caCert.NotAfter) || leaf.NotAfter.Sub(leaf.NotBefore) < 18*24*time.Hour {
		t.Errorf("CA ends %v: certificate %v – %v\n%s", caCert.NotAfter, leaf.NotBefore, leaf.NotAfter, e.logs)
	}
	// Less than a day left: refused with a clear reason.
	e.inst.Clock.Set(caCert.NotAfter.Add(-12 * time.Hour))
	m = e.manager("ends-soon", []string{"other.homelab.lan"})
	m.renew(ctx)
	if got := kinds(m.attention(false)); !strings.Contains(got, "CA ends-soon ends on") {
		t.Errorf("CA at its end: %q", got)
	}
}

func (e *issuedEnv) caCert(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	cas, err := e.inst.Engine.CAs(t.Context(), testinstance.Console)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cas {
		if c.Name == name {
			chain, cerr := e.inst.Engine.CAChain(t.Context(), testinstance.Console, c.ID)
			if cerr != nil {
				t.Fatal(cerr)
			}
			cert, perr := x509.ParseCertificate(chain[0])
			if perr != nil {
				t.Fatal(perr)
			}
			return cert
		}
	}
	t.Fatalf("no CA %s", name)
	return nil
}

// TestIssuedListeners: with admin.tls_issuer and acme.tls_issuer both
// listeners serve their bootstrap certificate while sealed and the issued
// one right after the unseal – without a restart. The ACME listener speaks
// TLS, and a client that trusts only the root verifies it.
func TestIssuedListeners(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	cfg.Admin.TLSIssuer, cfg.Admin.TLSNames = "issuing", "pki.homelab.lan"
	cfg.ACME.BaseURL, cfg.ACME.Listen, cfg.ACME.TLSIssuer = "https://acme.homelab.lan/acme", "127.0.0.1:0", "issuing"
	pass := initialized(t, cfg)
	var logs logBuf
	srv, err := Open(t.Context(), Options{Config: cfg, Log: slog.New(slog.NewJSONHandler(&logs, nil)), Hostname: "pki01", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if lerr := srv.Listen(t.Context()); lerr != nil {
		t.Fatal(lerr)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	defer func() {
		cancel()
		<-done
	}()
	handshake := func(addr, name string) []*x509.Certificate {
		t.Helper()
		d := tls.Dialer{Config: &tls.Config{ServerName: name, InsecureSkipVerify: true}} // #nosec G402 -- the test checks the chain itself
		conn, derr := d.DialContext(t.Context(), "tcp", addr)
		if derr != nil {
			t.Fatal(derr)
		}
		defer func() { _ = conn.Close() }()
		tc, _ := conn.(*tls.Conn)
		return tc.ConnectionState().PeerCertificates
	}
	if got := handshake(srv.AdminAddr(), "pki.homelab.lan"); Fingerprint(got[0].Raw) != srv.CertInfo.Fingerprint {
		t.Error("sealed: the admin listener doesn't serve the bootstrap certificate")
	}
	if got := handshake(srv.ACMEAddr(), "acme.homelab.lan"); got[0].Subject.CommonName != "MyOwnPKI ACME (bootstrap)" {
		t.Errorf("sealed: the ACME listener serves %q", got[0].Subject.CommonName)
	}
	if !strings.Contains(logs.String(), `"msg":"admin TLS certificate from admin.tls_issuer"`) || !strings.Contains(logs.String(), `"source":"bootstrap"`) {
		t.Errorf("start log:\n%s", logs.String())
	}

	if uerr := srv.Unseal(t.Context(), []byte(pass), console); uerr != nil {
		t.Fatal(uerr)
	}
	// The root from the public listener is the only trust anchor.
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.PublicAddr()+"/ca/root/1.crt", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "acme.homelab.lan", MinVersion: tls.VersionTLS12}}}
	req, _ = http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+srv.ACMEAddr()+"/acme/directory", nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("ACME over TLS with the root as trust anchor: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"newOrder":"https://acme.homelab.lan/acme/new-order"`) {
		t.Errorf("directory: %d %s", resp.StatusCode, body)
	}
	admin := handshake(srv.AdminAddr(), "pki.homelab.lan")
	inter := x509.NewCertPool()
	for _, c := range admin[1:] {
		inter.AddCert(c)
	}
	if _, verr := admin[0].Verify(x509.VerifyOptions{DNSName: "pki.homelab.lan", Roots: roots, Intermediates: inter}); verr != nil || len(admin) != 2 {
		t.Errorf("admin listener after the unseal: %d certificates, %v", len(admin), verr)
	}
	if in := srv.ServedAdminCertificate(); in.Source != "issued by CA issuing" || in.Fingerprint != Fingerprint(admin[0].Raw) {
		t.Errorf("served: %+v", in)
	}
	if !slices.Equal(AdminCertFiles(cfg), []string{filepath.Join(cfg.DataDir, "tls", "admin-bootstrap.crt"), filepath.Join(cfg.DataDir, "tls", "admin.crt")}) {
		t.Errorf("healthcheck files: %v", AdminCertFiles(cfg))
	}
}
