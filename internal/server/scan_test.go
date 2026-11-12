package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/setup"
	"github.com/Der-Felix/MyOwnPKI/internal/tlsscan"
)

// scanServer opens a server (sealed) of an instance with the test CA and the
// domain homelab.lan.
func scanServer(t *testing.T, edit func(*config.Config)) (*Server, *clock.Fake, string) {
	t.Helper()
	cfg := testConfig(t)
	if edit != nil {
		edit(&cfg)
	}
	clk := clock.NewFake(t0)
	res, err := setup.Run(t.Context(), setup.Options{
		Config: cfg, Mode: setup.Demo, WithCA: true, CABaseURL: "http://pki.homelab.lan", Hostname: "pki01", Who: console, TestKDF: true, Clock: clk,
	}, setup.NewLineInput(strings.NewReader(""), io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := os.ReadFile(res.DemoSecretsFile)
	if err != nil {
		t.Fatal(err)
	}
	var passphrase string
	for line := range strings.SplitSeq(string(secrets), "\n") {
		if p, ok := strings.CutPrefix(strings.TrimRight(line, "\r"), "unseal passphrase: "); ok {
			passphrase = p
		}
	}
	srv, err := Open(t.Context(), Options{Config: cfg, Log: slog.New(slog.DiscardHandler), Clock: clk, Hostname: "pki01", Version: "test", Release: "0.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Shutdown(context.WithoutCancel(t.Context())) })
	issuing := "issuing"
	if _, err := srv.engine.CreateDomain(t.Context(), ca.DomainRequest{Name: "homelab.lan", DomainSettings: ca.DomainSettings{CA: &issuing}, Who: console}); err != nil {
		t.Fatal(err)
	}
	return srv, clk, passphrase
}

func hasJob(s *Server, name string) bool {
	for _, j := range s.jobs.jobs {
		if j.name == name {
			return true
		}
	}
	return false
}

// TestScanJobOnlyDispatches: the scheduler is one goroutine that runs its
// jobs one after the other – a host that never answers must not hold up the
// jobs behind the scan (the CRL, ACME and alert jobs).
func TestScanJobOnlyDispatches(t *testing.T) {
	t.Parallel()
	srv, clk, _ := scanServer(t, func(c *config.Config) { c.Monitor.ScanTimeout = "30s" }) // longer than the wait below
	if srv.Endpoints() == nil || !hasJob(srv, jobScan) {
		t.Fatal("the scan is not wired")
	}
	scanner := srv.scan.scanner
	started := make(chan struct{}, 8)
	scanner.LookupIP = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
	}
	scanner.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		started <- struct{}{}
		<-ctx.Done() // never answers
		return nil, &net.OpError{Op: "dial", Err: syscall.ETIMEDOUT}
	}
	ep, err := srv.Endpoints().Create(t.Context(), console, tlsscan.Request{Host: "www.homelab.lan", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	// Before the first dispatch (30 seconds after the start) nothing runs.
	srv.jobs.runDue(t.Context())
	select {
	case <-started:
		t.Fatal("scanned before the first dispatch")
	default:
	}
	clk.Advance(tlsscan.DispatchEvery)
	done := make(chan struct{})
	go func() { srv.jobs.runDue(t.Context()); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the scheduler waited for the scan")
	}
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("the scan did not start")
	}
	// Closing cancels the running scan and waits for it; nothing is recorded
	// (Shutdown does this before the databases close).
	scanner.Close()
	if got, err := srv.Endpoints().Get(t.Context(), console, ep.ID); err != nil || got.Scanned() || got.FailStreak != 0 {
		t.Errorf("a canceled scan was recorded: %+v, %v", got, err)
	}
}

// TestScanWorksWhileSealed: nothing is decrypted, so a sealed server scans.
func TestScanWorksWhileSealed(t *testing.T) {
	t.Parallel()
	srv, clk, _ := scanServer(t, nil)
	if !srv.Sealed() {
		t.Fatal("not sealed")
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "www.homelab.lan"}, DNSNames: []string{"www.homelab.lan"},
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
				if tc.HandshakeContext(t.Context()) == nil {
					_, _ = io.Copy(io.Discard, tc)
				}
			}()
		}
	}()
	scanner := srv.scan.scanner
	scanner.LookupIP = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
	}
	scanner.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, ln.Addr().String())
	}
	ep, err := srv.Endpoints().Create(t.Context(), console, tlsscan.Request{Host: "www.homelab.lan", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(tlsscan.DispatchEvery)
	srv.jobs.runDue(t.Context())
	scanner.Wait()
	got, err := srv.Endpoints().Get(t.Context(), console, ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.FailStreak != 0 || got.Fingerprint == "" || got.ChainState != tlsscan.ChainUntrusted || !got.Scanned() {
		t.Errorf("%+v", got)
	}
}

func TestScanOffRegistersNoJob(t *testing.T) {
	t.Parallel()
	srv, clk, _ := scanServer(t, func(c *config.Config) { c.Monitor.ScanInterval = "off" })
	if hasJob(srv, jobScan) {
		t.Error("the scan job is registered while scan_interval is off")
	}
	ep, err := srv.Endpoints().Create(t.Context(), console, tlsscan.Request{Host: "www.homelab.lan", Port: 443})
	if err != nil {
		t.Fatal(err) // endpoints can still be entered
	}
	clk.Advance(time.Hour)
	srv.jobs.runDue(t.Context())
	srv.scan.scanner.Wait()
	if got, _ := srv.Endpoints().Get(t.Context(), console, ep.ID); got.Scanned() {
		t.Errorf("scanned while off: %+v", got)
	}
}

func TestScanSettingsComeFromTheConfiguration(t *testing.T) {
	t.Parallel()
	srv, _, _ := scanServer(t, func(c *config.Config) {
		c.Monitor.ScanPorts, c.Monitor.ScanMaxEndpoints, c.Monitor.ScanTimeout, c.Monitor.ScanInterval = "443, 9999", "1", "3s", "30m"
	})
	st := srv.scan.svc.Settings
	if st.MaxEndpoints != 1 || st.Timeout != 3*time.Second || st.Interval != 30*time.Minute || len(st.Ports) != 2 || st.Ports[1] != 9999 {
		t.Errorf("%+v", st)
	}
	if _, err := srv.Endpoints().Create(t.Context(), console, tlsscan.Request{Host: "a.homelab.lan", Port: 9999}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Endpoints().Create(t.Context(), console, tlsscan.Request{Host: "b.homelab.lan", Port: 443}); err == nil {
		t.Error("the limit of 1 endpoint did not hold")
	}
}
