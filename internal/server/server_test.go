package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/auth"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/setup"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/testutil"
)

var t0 = time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC)

var console = keys.Who{Actor: audit.Actor{Type: audit.ActorUser, Name: "console:test"}, Principal: authz.Console()}

// logBuf collects log lines from several goroutines.
type logBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func testConfig(t *testing.T) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.DataDir = filepath.Join(t.TempDir(), "data")
	cfg.Admin.Listen, cfg.Public.Listen = "127.0.0.1:0", "127.0.0.1:0"
	return cfg
}

// initialized runs init --demo with a test CA and returns the passphrase.
func initialized(t *testing.T, cfg config.Config) string {
	t.Helper()
	res, err := setup.Run(t.Context(), setup.Options{
		Config: cfg, Mode: setup.Demo, CABaseURL: "http://pki.homelab.lan", Hostname: "pki01", Who: console,
	}, setup.NewLineInput(strings.NewReader(""), io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(res.DemoSecretsFile)
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if p, ok := strings.CutPrefix(strings.TrimRight(line, "\r"), "unseal passphrase: "); ok {
			return p
		}
	}
	t.Fatal("no passphrase in the demo file")
	return ""
}

func TestBootstrapCertificate(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	cfg.Admin.Listen, cfg.Admin.TLSNames = "192.0.2.5:9443", "pki.homelab.lan, 198.51.100.7"
	c, in, err := adminCertificate(cfg, "WIN-PKI01", t0, nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf := c.Leaf
	if !in.Created || in.Source != "bootstrap" || leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || !leaf.NotAfter.Equal(t0.Add(397*24*time.Hour)) {
		t.Errorf("bootstrap certificate: %+v\n%+v", in, leaf)
	}
	for _, name := range []string{"win-pki01", "localhost", "pki.homelab.lan"} {
		roots := x509.NewCertPool()
		roots.AddCert(leaf)
		if _, verr := leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots, CurrentTime: t0, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); verr != nil {
			t.Errorf("%s: %v", name, verr)
		}
	}
	for _, ip := range []string{"127.0.0.1", "::1", "192.0.2.5", "198.51.100.7"} {
		if !covers(leaf, nil, []netip.Addr{netip.MustParseAddr(ip)}) {
			t.Errorf("IP %s missing", ip)
		}
	}
	if runtime.GOOS != "windows" {
		if fi, serr := os.Stat(filepath.Join(cfg.DataDir, "tls", bootstrapKey)); serr != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("key file: %v %v", fi.Mode(), serr)
		}
	}

	// Next start: the same certificate.
	_, again, err := adminCertificate(cfg, "WIN-PKI01", t0.Add(24*time.Hour), nil)
	if err != nil || again.Created || again.Fingerprint != in.Fingerprint {
		t.Errorf("second start: %+v %v", again, err)
	}
	// 30 days before the end: a new one, with a reason.
	_, renewed, err := adminCertificate(cfg, "WIN-PKI01", leaf.NotAfter.Add(-29*24*time.Hour), nil)
	if err != nil || !renewed.Created || renewed.Fingerprint == in.Fingerprint || !strings.Contains(renewed.Reason, "30 days") {
		t.Errorf("renewal: %+v %v", renewed, err)
	}
	// A new name: a new certificate.
	cfg.Admin.TLSNames += ", ca.homelab.lan"
	_, named, err := adminCertificate(cfg, "WIN-PKI01", leaf.NotAfter.Add(-29*24*time.Hour), nil)
	if err != nil || !named.Created || !strings.Contains(named.Reason, "names changed") {
		t.Errorf("new name: %+v %v", named, err)
	}
}

func TestOperatorCertificate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "pki.homelab.lan"}, NotBefore: t0, NotAfter: t0.AddDate(1, 0, 0)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	pk, _ := x509.MarshalPKCS8PrivateKey(key)
	cfg := testConfig(t)
	cfg.Admin.TLSCertFile, cfg.Admin.TLSKeyFile = filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	_ = os.WriteFile(cfg.Admin.TLSCertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(cfg.Admin.TLSKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), 0o600)
	_, in, err := adminCertificate(cfg, "host", t0, nil)
	if err != nil || in.Source != "operator" || in.Fingerprint != Fingerprint(der) || in.Created {
		t.Errorf("operator certificate: %+v %v", in, err)
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, "tls")); !errors.Is(err, os.ErrNotExist) {
		t.Error("a bootstrap certificate was made although the operator has one")
	}
}

func TestAllowList(t *testing.T) {
	t.Parallel()
	var logs logBuf
	refused := newRefusalLog(slog.New(slog.NewJSONHandler(&logs, nil)), clock.NewFake(t0))
	try := func(allowed string) (net.Conn, error) {
		t.Helper()
		nets, err := config.ParseNetworks(allowed)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ln := &allowListener{Listener: raw, allowed: nets, refused: refused}
		t.Cleanup(func() { _ = ln.Close() })
		accepted := make(chan net.Conn, 1)
		go func() {
			if c, aerr := ln.Accept(); aerr == nil {
				accepted <- c
			}
		}()
		c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", raw.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		select {
		case a := <-accepted:
			return a, nil
		case <-time.After(500 * time.Millisecond):
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			_, rerr := c.Read(make([]byte, 1))
			return nil, rerr
		}
	}
	if c, err := try("127.0.0.0/8"); c == nil {
		t.Errorf("allowed peer refused: %v", err)
	}
	if c, err := try("10.0.0.0/8, 192.0.2.0/24"); c != nil || !errors.Is(err, io.EOF) && !isReset(err) {
		t.Errorf("peer outside the list: accepted=%v, read %v", c != nil, err)
	}
	if c, _ := try(""); c == nil {
		t.Error("an empty list must allow everybody")
	}
	if !strings.Contains(logs.String(), `"msg":"admin connections refused (not in admin.allowed_networks)"`) {
		t.Errorf("refusal not logged: %s", logs.String())
	}
	if got := peerIP(&net.TCPAddr{IP: net.ParseIP("::ffff:10.1.2.3"), Port: 1}); got.String() != "10.1.2.3" {
		t.Errorf("IPv4-mapped peer: %s", got)
	}
}

func isReset(err error) bool {
	var ne net.Error
	return err != nil && (errors.As(err, &ne) || strings.Contains(err.Error(), "forcibly closed") || strings.Contains(err.Error(), "reset"))
}

// TestRefusalLogIsThrottled: a scanner can't flood the log – at most one
// summary a minute.
func TestRefusalLogIsThrottled(t *testing.T) {
	t.Parallel()
	var logs logBuf
	clk := clock.NewFake(t0)
	r := newRefusalLog(slog.New(slog.NewJSONHandler(&logs, nil)), clk)
	lines := func() int { return strings.Count(logs.String(), "admin connections refused") }
	for i := range 500 {
		r.add(netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}))
	}
	if lines() != 1 {
		t.Fatalf("%d lines for a burst, want 1 (the first refusal)", lines())
	}
	clk.Advance(30 * time.Second)
	r.add(netip.MustParseAddr("203.0.113.1"))
	r.flush()
	if lines() != 1 {
		t.Errorf("%d lines within a minute", lines())
	}
	clk.Advance(31 * time.Second)
	r.flush()
	if lines() != 2 || !strings.Contains(logs.String(), `"count":500`) {
		t.Errorf("summary after a minute:\n%s", logs.String())
	}
}

func TestExposureWarning(t *testing.T) {
	t.Parallel()
	for listen, loop := range map[string]bool{"127.0.0.1:9443": true, "[::1]:9443": true, ":9443": false, "0.0.0.0:9443": false, "192.0.2.5:9443": false} {
		if loopbackOnly(listen) != loop {
			t.Errorf("%s: loopback %v", listen, !loop)
		}
	}
}

func TestServerStartUnsealAndStop(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
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

	// Admin: TLS with the logged certificate, /healthz only, HSTS and CSP.
	var peer string
	// Redirects are not followed: an answer must be the server's own.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- the test compares the fingerprint instead
		VerifyConnection: func(cs tls.ConnectionState) error {
			peer = Fingerprint(cs.PeerCertificates[0].Raw)
			return nil
		},
	}}}
	get := func(url string) (int, string, http.Header) {
		t.Helper()
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
		resp, derr := client.Do(req)
		if derr != nil {
			t.Fatal(derr)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), resp.Header
	}
	code, body, h := get("https://" + srv.AdminAddr() + "/healthz")
	if code != http.StatusOK || body != "ok\n" || h.Get("Strict-Transport-Security") != "max-age=31536000" || h.Get("Content-Security-Policy") == "" {
		t.Errorf("healthz: %d %q %v", code, body, h)
	}
	if peer != srv.CertInfo.Fingerprint {
		t.Errorf("served certificate %s, logged %s", peer, srv.CertInfo.Fingerprint)
	}
	// The UI: without a session to the sign-in page, which says nothing about
	// the instance (no demo mark, no seal state, no version).
	if code, _, h := get("https://" + srv.AdminAddr() + "/certificates"); code != http.StatusSeeOther || h.Get("Location") != "/login?next=%2Fcertificates" {
		t.Errorf("UI page without a session: %d %q", code, h.Get("Location"))
	}
	if code, body, _ := get("https://" + srv.AdminAddr() + "/login"); code != http.StatusOK || strings.Contains(body, "DEMO") || strings.Contains(body, "sealed") || strings.Contains(body, "test") {
		t.Errorf("sign-in page: %d\n%s", code, body)
	}
	// The API is mounted; an unclean path is a 404 problem, not a redirect.
	if code, _, h := get("https://" + srv.AdminAddr() + "/api/v1/certificates//download/fullchain"); code != http.StatusNotFound || h.Get("Content-Type") != "application/problem+json" {
		t.Errorf("unclean API path: %d %s", code, h.Get("Content-Type"))
	}
	if code, _, h := get("https://" + srv.AdminAddr() + "/api/v1/system/status"); code != http.StatusUnauthorized || h.Get("X-Request-ID") == "" {
		t.Errorf("API without a session: %d", code)
	}
	// Public: CRLs and CA certificates, nothing of the admin side.
	if code, _, _ := get(srv.PublicAddr() + "/ca/root/1.crt"); code != http.StatusOK {
		t.Errorf("public CA certificate: %d", code)
	}
	if code, _, _ := get(srv.PublicAddr() + "/healthz"); code != http.StatusNotFound {
		t.Errorf("public /healthz: %d", code)
	}

	// A wrong passphrase leaves the server running sealed.
	if uerr := srv.Unseal(t.Context(), []byte("wrong passphrase, long enough"), console); !errors.Is(uerr, keys.ErrWrongSecret) || !srv.Sealed() {
		t.Errorf("wrong passphrase: %v, sealed %v", uerr, srv.Sealed())
	}
	if code, _, _ := get("https://" + srv.AdminAddr() + "/healthz"); code != http.StatusOK {
		t.Error("the server stopped after a wrong passphrase")
	}
	if uerr := srv.Unseal(t.Context(), []byte(pass), console); uerr != nil || srv.Sealed() {
		t.Fatalf("unseal: %v", uerr)
	}
	// Something happens while unsealed: the checkpoint before the seal must
	// cover it.
	if _, cerr := srv.auth.CreateUser(t.Context(), auth.NewUserRequest{Username: "carol", Password: "a long password for the test", Who: console}); cerr != nil {
		t.Fatal(cerr)
	}

	start := time.Now()
	cancel()
	if serr := <-done; serr != nil {
		t.Fatal(serr)
	}
	if took := time.Since(start); took > ShutdownBudget {
		t.Errorf("shutdown took %v", took)
	}

	// The audit log: checkpoint after the unseal, checkpoint before the seal.
	ia, err := store.OpenReadOnly(t.Context(), store.Layout{DataDir: cfg.DataDir}.InstanceAuditDB())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ia.Close() }()
	rows, err := ia.Read.QueryContext(t.Context(), `SELECT action, result FROM audit_entries ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var actions []string
	for rows.Next() {
		var a, r string
		if err := rows.Scan(&a, &r); err != nil {
			t.Fatal(err)
		}
		actions = append(actions, a+"/"+r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(actions, " ")
	if !strings.Contains(got, "system.unseal/failure system.unseal/success audit.checkpoint/success") ||
		!strings.HasSuffix(got, "user.create/success audit.checkpoint/success system.seal/success") {
		t.Errorf("audit: %s", got)
	}
	for _, want := range []string{`"msg":"admin TLS certificate"`, `"msg":"audit head"`, `"msg":"` + setup.DemoWarning + `"`, `"msg":"stopped"`} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log lacks %s", want)
		}
	}
	// The test CAs came with their first CRLs: nothing to warn about.
	if strings.Contains(logs.String(), `"msg":"crl attention"`) {
		t.Errorf("CRL warning right after init:\n%s", logs.String())
	}
}

// TestCRLsRightAfterInit: the CAs of init --with-ca have CRL number 1, so a
// server started sealed publishes both (owner finding 2026-10-16: they were
// 404 until the first unseal, and strict relying parties refused every
// certificate below). While sealed, the CRL job warns from half of the
// lifetime on.
func TestCRLsRightAfterInit(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	initialized(t, cfg)
	clk := clock.NewFake(time.Now().UTC())
	var logs logBuf
	srv, err := Open(t.Context(), Options{Config: cfg, Log: slog.New(slog.NewJSONHandler(&logs, nil)), Clock: clk, Hostname: "pki01", Version: "test"})
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
		if serr := <-done; serr != nil {
			t.Error(serr)
		}
	}()
	if !srv.Sealed() {
		t.Fatal("not sealed")
	}

	for name, days := range map[string]int{"root": 30, "issuing": 7} {
		url := srv.PublicAddr() + "/crl/" + name + "/1.crl"
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
		resp, derr := http.DefaultClient.Do(req)
		if derr != nil {
			t.Fatal(derr)
		}
		der, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: %d", url, resp.StatusCode)
			continue
		}
		crl, perr := x509.ParseRevocationList(der)
		if perr != nil {
			t.Fatalf("%s: %v", url, perr)
		}
		if want := clk.Now().AddDate(0, 0, days); crl.Number.Int64() != 1 || crl.NextUpdate.Sub(want).Abs() > time.Hour {
			t.Errorf("%s: number %v, nextUpdate %v (want about %v)", name, crl.Number, crl.NextUpdate, want)
		}
		// Cross-check with OpenSSL: number and nextUpdate as a client sees them.
		p := filepath.Join(t.TempDir(), name+".crl")
		if werr := os.WriteFile(p, der, 0o600); werr != nil {
			t.Fatal(werr)
		}
		out, oerr := exec.CommandContext(t.Context(), testutil.OpenSSL(t), "crl", "-inform", "DER", "-in", p, "-noout", "-crlnumber", "-nextupdate").CombinedOutput() // #nosec G204 -- test binary and temp file
		if oerr != nil || !strings.Contains(string(out), "crlNumber=0x01") || !strings.Contains(string(out), "nextUpdate="+crl.NextUpdate.UTC().Format("Jan _2 15:04:05 2006 GMT")) {
			t.Errorf("openssl crl %s: %v\n%s", name, oerr, out)
		}
	}

	// Four days later the 7-day CRL of the intermediate is past half its
	// lifetime: the sealed server says so, the root's is still fine.
	clk.Advance(4 * 24 * time.Hour)
	if werr := srv.warnSealedCRLs(t.Context()); werr != nil {
		t.Fatal(werr)
	}
	l := logs.String()
	if !strings.Contains(l, `"msg":"crl attention","ca":"issuing","generation":1,"state":"warning"`) || strings.Contains(l, `"ca":"root","generation":1,"state"`) {
		t.Errorf("sealed CRL warnings:\n%s", l)
	}
}

func TestServerRefusesToStart(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	if _, err := store.Migrate(t.Context(), store.Layout{DataDir: cfg.DataDir}, store.DefaultTenant, clock.NewFake(t0).Now); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), Options{Config: cfg}); !errors.Is(err, ErrNotInitialized) {
		t.Errorf("before init: %v", err)
	}
	cfg2 := testConfig(t)
	initialized(t, cfg2)
	if err := os.Remove(cfg2.AuthKeyFile()); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), Options{Config: cfg2}); err == nil || !strings.Contains(err.Error(), "auth key") {
		t.Errorf("without auth key: %v", err)
	}
}

// TestOutboxPilesUpLoudly: when the audit log can't be written, business
// changes still succeed (their entries wait in the outbox) and the server
// warns with count and age; nothing is lost.
func TestOutboxPilesUpLoudly(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	initialized(t, cfg)
	var logs logBuf
	clk := clock.NewFake(t0)
	srv, err := Open(t.Context(), Options{Config: cfg, Log: slog.New(slog.NewJSONHandler(&logs, nil)), Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(t.Context()) }()
	ro, err := store.OpenReadOnly(t.Context(), store.Layout{DataDir: cfg.DataDir}.InstanceAuditDB())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	srv.deliverer.Routes[0].To = ro.Read

	if _, err := srv.auth.CreateUser(t.Context(), auth.NewUserRequest{Username: "bob", Password: "a long password for the test", Who: console}); err != nil {
		t.Fatalf("a business change must not wait for the audit log: %v", err)
	}
	clk.Advance(90 * time.Second)
	srv.deliver(t.Context())
	if !strings.Contains(logs.String(), `"msg":"audit delivery failing – entries wait in the outbox"`) ||
		!strings.Contains(logs.String(), `"system":{"pending":1,"oldest_age":"1m30s"}`) {
		t.Errorf("no loud warning:\n%s", logs.String())
	}
	// Once the audit log works again, the entry arrives.
	srv.deliverer.Routes[0].To = srv.ia.Write
	srv.deliver(t.Context())
	if backlog, _ := srv.deliverer.Backlog(t.Context()); backlog[0].Pending != 0 {
		t.Errorf("still pending: %+v", backlog)
	}
}

func TestJobs(t *testing.T) {
	t.Parallel()
	var logs logBuf
	clk := clock.NewFake(t0)
	s := &scheduler{clk: clk, log: slog.New(slog.NewJSONHandler(&logs, nil))}
	runs := map[string]int{}
	s.add("now", time.Minute, 0, func(context.Context) error { runs["now"]++; return nil })
	s.add("later", time.Hour, time.Hour, func(context.Context) error { runs["later"]++; return errors.New("boom") })
	s.runDue(t.Context())
	clk.Advance(time.Hour)
	s.runDue(t.Context())
	s.runDue(t.Context())
	clk.Advance(time.Hour)
	s.runDue(t.Context())
	if runs["now"] != 3 || runs["later"] != 2 {
		t.Errorf("runs %v", runs)
	}
	if strings.Count(logs.String(), `"job":"later"`) != 2 {
		t.Errorf("failing job not logged each time:\n%s", logs.String())
	}
}

func TestBootstrapNamesHaveNoDuplicates(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	cfg.Admin.Listen, cfg.Admin.TLSNames = "127.0.0.1:9443", "localhost, 127.0.0.1, ::1"
	names, ips, err := wantedNames(cfg, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || len(ips) != 2 {
		t.Errorf("duplicates: %v %v", names, ips)
	}
}

// TestACMEListener (PHASE2, owner Q1): with acme.base_url the server opens
// its own plain-HTTP ACME listener; the directory names the base URL; the
// public CRL port has no ACME.
func TestACMEListener(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	initialized(t, cfg)
	cfg.ACME.BaseURL, cfg.ACME.Listen = "https://pki.homelab.lan/acme", "127.0.0.1:0"
	srv, err := Open(t.Context(), Options{Config: cfg, Log: slog.New(slog.DiscardHandler), Hostname: "pki01", Version: "test"})
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
	get := func(u string) (int, string) {
		t.Helper()
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, u, nil)
		resp, derr := http.DefaultClient.Do(req)
		if derr != nil {
			t.Fatal(derr)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if srv.ACMEAddr() == "" {
		t.Fatal("no ACME listener")
	}
	code, body := get("http://" + srv.ACMEAddr() + "/acme/directory")
	if code != http.StatusOK || !strings.Contains(body, `"newAccount":"https://pki.homelab.lan/acme/new-account"`) {
		t.Errorf("directory: %d %s", code, body)
	}
	if code, _ := get(srv.PublicAddr() + "/acme/directory"); code != http.StatusNotFound {
		t.Errorf("ACME on the public CRL port: %d", code)
	}
}
