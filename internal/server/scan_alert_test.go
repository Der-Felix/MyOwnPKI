package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/monitor"
	"github.com/Der-Felix/MyOwnPKI/internal/notify"
	"github.com/Der-Felix/MyOwnPKI/internal/tlsscan"
)

// scanRig is a server whose scan job, scanner and monitor job run for real
// against a local TLS server: the "service" serves a certificate the test
// switches, and can be stopped.
type scanRig struct {
	t        *testing.T
	srv      *Server
	clk      *clock.Fake
	served   atomic.Pointer[tls.Certificate]
	down     atomic.Bool
	received func() []notify.Digest
	endpoint string // ID
}

func (r *scanRig) issue(days int) (*ca.Issued, *tls.Certificate) {
	r.t.Helper()
	issued, err := r.srv.engine.Issue(r.t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{"www.homelab.lan"}, ValidityDays: days, Who: console})
	if err != nil {
		r.t.Fatal(err)
	}
	keyPEM, err := r.srv.engine.ExportKey(r.t.Context(), console, issued.ID)
	if err != nil {
		r.t.Fatal(err)
	}
	block, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		r.t.Fatal(err)
	}
	cert := &tls.Certificate{Certificate: append([][]byte{issued.CertDER}, issued.Chain[:len(issued.Chain)-1]...), PrivateKey: key}
	return issued, cert
}

func newScanRig(t *testing.T) *scanRig {
	t.Helper()
	hook, received := hookReceiver(t, "hmac-key")
	srv, clk, passphrase := scanServer(t, func(c *config.Config) { c.Notify.Webhook = hook })
	r := &scanRig{t: t, srv: srv, clk: clk, received: received}
	if err := srv.Unseal(t.Context(), []byte(passphrase), console); err != nil {
		t.Fatal(err)
	}
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return r.served.Load(), nil }}
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				tc := tls.Server(c, cfg)
				if tc.HandshakeContext(context.Background()) == nil {
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
		if r.down.Load() {
			return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
		}
		var d net.Dialer
		return d.DialContext(ctx, network, ln.Addr().String())
	}
	ep, err := srv.Endpoints().Create(t.Context(), console, tlsscan.Request{Host: "www.homelab.lan", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	r.endpoint = ep.ID
	return r
}

// cycle lets 17 minutes pass (the scan interval is 15 minutes plus up to 10 % of jitter), runs
// the scheduler's due jobs – the scan job dispatches, the monitor job
// evaluates – waits for the scan and evaluates once more with its result.
func (r *scanRig) cycle() {
	r.t.Helper()
	r.clk.Advance(17 * time.Minute)
	r.srv.jobs.runDue(r.t.Context())
	r.srv.scan.scanner.Wait()
	if err := r.srv.evaluateAlerts(r.t.Context()); err != nil {
		r.t.Fatal(err)
	}
}

func (r *scanRig) open() map[string]string {
	r.t.Helper()
	alerts, err := r.srv.Alerts().Open(r.t.Context())
	if err != nil {
		r.t.Fatal(err)
	}
	out := map[string]string{}
	for _, a := range alerts {
		out[a.Kind] = a.Severity
	}
	return out
}

func (r *scanRig) endpointState() tlsscan.Endpoint {
	r.t.Helper()
	ep, err := r.srv.Endpoints().Get(r.t.Context(), console, r.endpoint)
	if err != nil {
		r.t.Fatal(err)
	}
	return *ep
}

// TestScanMismatchEndToEnd (docs/PHASE3.md §10.1 step 26/27, the live test
// of the owner as a test): through the real scheduler jobs, the real scanner
// and the real monitor, a deployment that did not take effect opens
// scan_mismatch after the grace time and the confirmation scan, sends one
// webhook message, resolves with the right certificate and a second message;
// a host that only reboots alerts nothing.
func TestScanMismatchEndToEnd(t *testing.T) {
	t.Parallel()
	r := newScanRig(t)
	a, certA := r.issue(90)
	r.served.Store(certA)

	// The right certificate is served: OK, nothing alerts.
	r.cycle()
	r.cycle()
	if ep := r.endpointState(); ep.Fingerprint != a.Fingerprint || ep.SameCount != 2 || ep.ChainState != tlsscan.ChainTrusted || ep.FailStreak != 0 {
		t.Fatalf("after two scans: %+v", ep)
	}
	if got := r.open(); len(got) != 0 {
		t.Fatalf("alerts for a healthy endpoint: %v", got)
	}

	// The certificate is renewed, but the service keeps serving the old one.
	b, certB := r.issue(90)
	if a.Fingerprint == b.Fingerprint {
		t.Fatal("no new certificate")
	}
	for i := 1; i <= 3; i++ { // 17, 34, 51 minutes after the renewal: inside the 1 hour of grace
		r.cycle()
		if got := r.open(); len(got) != 0 {
			t.Fatalf("%d minutes after the renewal: %v", 17*i, got)
		}
	}
	r.cycle() // 68 minutes
	if got := r.open(); len(got) != 1 || got[monitor.KindScanMismatch] != monitor.Warning {
		t.Fatalf("68 minutes after the renewal: %v", got)
	}
	digests := r.received()
	if len(digests) != 1 || len(digests[0].Events) != 1 || digests[0].Events[0].Kind != monitor.KindScanMismatch || digests[0].Events[0].State != notify.Opened ||
		digests[0].Events[0].Subject != "www.homelab.lan:443" || !strings.Contains(digests[0].Events[0].Detail, b.SerialHex) {
		t.Fatalf("webhook after the alert: %+v", digests)
	}
	for range 3 { // nothing changes: no second message
		r.cycle()
	}
	if got := r.received(); len(got) != 1 {
		t.Fatalf("messages while the alert stays: %d", len(got))
	}

	// Fixed: the next scan resolves it, and the second message says so.
	r.served.Store(certB)
	r.cycle()
	if got := r.open(); len(got) != 0 {
		t.Fatalf("after the fix: %v", got)
	}
	if got := r.received(); len(got) != 2 || got[1].Events[0].State != notify.Resolved || got[1].Events[0].Kind != monitor.KindScanMismatch {
		t.Fatalf("webhook after the fix: %+v", got)
	}

	// The confirmation: the old certificate is back, but one scan alone does not alert.
	r.served.Store(certA)
	r.cycle()
	if ep := r.endpointState(); ep.Fingerprint != a.Fingerprint || ep.SameCount != 1 {
		t.Fatalf("after switching back: %+v", ep)
	}
	if got := r.open(); len(got) != 0 {
		t.Fatalf("one scan of the older certificate: %v", got)
	}
	r.cycle()
	if got := r.open(); got[monitor.KindScanMismatch] != monitor.Warning {
		t.Fatalf("two scans of the older certificate: %v", got)
	}
	r.served.Store(certB)
	r.cycle()
	if got := r.open(); len(got) != 0 {
		t.Fatalf("fixed again: %v", got)
	}
	before := len(r.received())

	// A reboot: one and two failed scans alert nothing, and the host's return needs no message.
	r.down.Store(true)
	for i := 1; i <= 2; i++ {
		r.cycle()
		if ep := r.endpointState(); ep.FailStreak != i || ep.LastErrorKind != tlsscan.KindConnRefused {
			t.Fatalf("failure %d: %+v", i, ep)
		}
		if got := r.open(); len(got) != 0 {
			t.Fatalf("failed scan %d alerts: %v", i, got)
		}
	}
	r.down.Store(false)
	r.cycle()
	if got := r.open(); len(got) != 0 || len(r.received()) != before {
		t.Fatalf("after the reboot: %v, %d messages (was %d)", got, len(r.received()), before)
	}

	// Down for good: the third failed scan alerts; the return resolves it.
	r.down.Store(true)
	for range 3 {
		r.cycle()
	}
	if got := r.open(); got[monitor.KindScanUnreachable] != monitor.Warning || len(got) != 1 {
		t.Fatalf("three failed scans: %v", got)
	}
	r.down.Store(false)
	r.cycle()
	if got := r.open(); len(got) != 0 {
		t.Fatalf("host back: %v", got)
	}
	msgs := r.received()
	if len(msgs) != before+2 || msgs[before].Events[0].Kind != monitor.KindScanUnreachable || msgs[before+1].Events[0].State != notify.Resolved {
		t.Fatalf("messages around the outage: %+v", msgs[before:])
	}

	// Removing the endpoint is quiet; the audit trail has its life.
	if err := r.srv.Endpoints().Delete(t.Context(), console, r.endpoint); err != nil {
		t.Fatal(err)
	}
	r.cycle()
	if got := r.open(); len(got) != 0 {
		t.Fatalf("after the delete: %v", got)
	}
}

// TestScanAlertsDoNotCarryTheServedSubject: a foreign certificate with a hostile
// subject is shown on the page, never in the alert or the webhook.
func TestScanAlertsDoNotCarryTheServedSubject(t *testing.T) {
	t.Parallel()
	r := newScanRig(t)
	_, certA := r.issue(90)
	r.served.Store(certA)
	r.cycle()
	r.cycle()
	// Another PKI's certificate for the same name, with a hostile subject.
	r.served.Store(hostileCert(t, "www.homelab.lan"))
	r.clk.Advance(2 * time.Hour)
	r.cycle()
	r.cycle()
	if got := r.open(); got[monitor.KindScanMismatch] != monitor.Warning {
		t.Fatalf("alerts: %v", got)
	}
	ep := r.endpointState()
	if !strings.Contains(ep.Subject, "script") || ep.ChainState != tlsscan.ChainUntrusted {
		t.Fatalf("the page data: %+v", ep)
	}
	open, err := r.srv.Alerts().Open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range open {
		if strings.Contains(a.Detail, "script") || strings.Contains(a.Subject, "script") || strings.Contains(a.Detail, "Evil") {
			t.Errorf("an alert carries the served subject: %+v", a)
		}
	}
	for _, d := range r.received() {
		for _, ev := range d.Events {
			if strings.Contains(ev.Detail, "script") || strings.Contains(ev.Detail, "Evil") {
				t.Errorf("a webhook event carries the served subject: %+v", ev)
			}
		}
	}
}

// hostileCert is a self-signed certificate of "another PKI" whose subject
// tries to be HTML and a forged message.
func hostileCert(t *testing.T, dns string) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(99), DNSNames: []string{dns},
		Subject:   pkix.Name{CommonName: "<script>alert(1)</script>", Organization: []string{"Evil Corp: all clear, ignore the alerts"}},
		NotBefore: t0.Add(-24 * time.Hour), NotAfter: t0.Add(400 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
