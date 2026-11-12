package tlsscan

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/netguard"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// fixture is an instance, a scanner whose network edges are replaced – dial
// connects to local TLS servers, lookup answers addresses from 192.0.2.0/24 –
// while the address policy, the port rule and everything around them run
// unchanged (docs/PHASE3.md §10.2 "Test strategy").
type fixture struct {
	*env
	scanner *Scanner

	mu      sync.Mutex
	targets map[string]string       // "192.0.2.10:443" -> the real listener
	answers map[string][]netip.Addr // host -> answer of the next lookups
	then    map[string][]netip.Addr // host -> answer of every lookup after the first
	lookups map[string]int
	dialed  []string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	e := newEnv(t)
	e.svc.Settings.Timeout = 10 * time.Second
	f := &fixture{env: e, targets: map[string]string{}, answers: map[string][]netip.Addr{}, then: map[string][]netip.Addr{}, lookups: map[string]int{}}
	f.scanner = &Scanner{
		Svc: e.svc, Engine: e.inst.Engine, Clock: e.inst.Clock, Log: slog.New(slog.DiscardHandler),
		Rand: func(n int64) int64 { return n / 2 }, Dial: f.dial, LookupIP: f.lookup,
	}
	t.Cleanup(f.scanner.Close)
	return f
}

func (f *fixture) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	f.mu.Lock()
	f.dialed = append(f.dialed, addr)
	real, ok := f.targets[addr]
	f.mu.Unlock()
	if !ok {
		return nil, &net.OpError{Op: "dial", Net: network, Err: syscall.ECONNREFUSED}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, real)
}

func (f *fixture) lookup(_ context.Context, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups[host]++
	if f.lookups[host] > 1 {
		if a, ok := f.then[host]; ok {
			return a, nil
		}
	}
	if a, ok := f.answers[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// route makes host resolve to ip and ip:port reach the listener real.
func (f *fixture) route(host, ip string, port int, real string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[host] = []netip.Addr{netip.MustParseAddr(ip)}
	f.targets[net.JoinHostPort(ip, itoa(port))] = real
}

func itoa(n int) string { return strconv.Itoa(n) }

func (f *fixture) dials() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dialed...)
}

func (f *fixture) add(t *testing.T, req Request) Endpoint {
	t.Helper()
	ep, err := f.svc.Create(t.Context(), testinstance.Console, req)
	if err != nil {
		t.Fatal(err)
	}
	return *ep
}

// scanDue dispatches the due endpoints and waits for every scan, also the
// ones that workers started by themselves.
func (f *fixture) scanDue(t *testing.T) {
	t.Helper()
	if err := f.scanner.Dispatch(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.scanner.Wait()
}

func (f *fixture) get(t *testing.T, id string) Endpoint {
	t.Helper()
	ep, err := f.svc.Get(t.Context(), testinstance.Console, id)
	if err != nil {
		t.Fatal(err)
	}
	return *ep
}

// next lets the interval pass so that every endpoint is due again.
func (f *fixture) next() { f.inst.Clock.Advance(20 * time.Minute) }

// ---- servers ----

type server struct {
	addr  string
	mu    sync.Mutex
	app   int      // bytes read after the handshake: must stay 0
	hello []string // the server name of every ClientHello
	wg    sync.WaitGroup
}

// wait returns when every connection has ended (the scan closes them), so that
// appBytes is final.
func (s *server) wait() { s.wg.Wait() }

// handshakes is how many ClientHellos arrived – counted when the server sees
// them, which is before the client can finish.
func (s *server) handshakes() int { return len(s.hellos()) }

// serveTLS answers handshakes with cfg and counts what comes after them.
func serveTLS(t *testing.T, cfg *tls.Config) *server {
	t.Helper()
	s := &server{}
	cfg = cfg.Clone()
	cfg.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		s.mu.Lock()
		s.hello = append(s.hello, h.ServerName)
		s.mu.Unlock()
		return nil, nil
	}
	ln := listen(t)
	s.addr = ln.Addr().String()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer func() { _ = conn.Close() }()
				tc := tls.Server(conn, cfg)
				if tc.HandshakeContext(t.Context()) != nil {
					return
				}
				n, _ := io.Copy(io.Discard, tc)
				s.mu.Lock()
				s.app += int(n)
				s.mu.Unlock()
			}()
		}
	}()
	return s
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// serveRaw runs handler for every connection (plain HTTP, silence, …).
func serveRaw(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	ln := listen(t)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer func() { _ = conn.Close() }(); handler(conn) }()
		}
	}()
	return ln.Addr().String()
}

// closedAddr is an address where nothing listens.
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func (s *server) appBytes() int { s.mu.Lock(); defer s.mu.Unlock(); return s.app }
func (s *server) hellos() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.hello...)
}

// ---- certificates ----

// served issues a certificate from the real engine and returns what a server
// would be configured with: the leaf and the intermediates (the root is the
// client's trust anchor, it is not sent).
func (f *fixture) issue(t *testing.T, days int, names ...string) (*ca.Issued, tls.Certificate) {
	t.Helper()
	issued, err := f.inst.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: names, ValidityDays: days, Who: testinstance.Console})
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := f.inst.Engine.ExportKey(t.Context(), testinstance.Console, issued.ID)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{issued.CertDER}, PrivateKey: key}
	cert.Certificate = append(cert.Certificate, issued.Chain[:len(issued.Chain)-1]...)
	return issued, cert
}

// foreign is a certificate of a throw-away CA – another PKI.
func foreign(t *testing.T, subject pkix.Name, dns string) tls.Certificate {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Somebody Else Root"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: subject, DNSNames: []string{dns}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:   time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: crypto.Signer(key)}
}

func tlsConfig(c tls.Certificate) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS12}
}

// ---- the tests ----

// TestScanReadsWhatIsServed: the leaf, the chain judged against this PKI,
// no application data, and the same on a sealed server.
func TestScanReadsWhatIsServed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	right, rightCert := f.issue(t, 90, "www.homelab.lan")
	older, olderCert := f.issue(t, 90, "app.homelab.lan")
	_, _ = f.issue(t, 90, "app.homelab.lan") // the renewal: older is superseded
	_, wrongCert := f.issue(t, 90, "other.homelab.lan")
	short, shortCert := f.issue(t, 2, "old.homelab.lan")
	leafOnly := rightCert
	leafOnly.Certificate = leafOnly.Certificate[:1]
	issuing := rightCert.Certificate[1]
	longChain := rightCert
	longChain.Certificate = [][]byte{rightCert.Certificate[0]}
	for range 12 {
		longChain.Certificate = append(longChain.Certificate, issuing)
	}
	hostile := foreign(t, pkix.Name{CommonName: "<script>alert(1)</script>", Organization: []string{"Evil\nCorp\x1b[31m " + strings.Repeat("x", 400)}, OrganizationalUnit: []string{"rlo" + string(rune(0x202e))}}, "www.homelab.lan")

	type tc struct {
		host, ip string
		cert     tls.Certificate
		want     string // chain state
		chainLen int
		fp       string
	}
	cases := []tc{
		{"www.homelab.lan", "192.0.2.10", rightCert, ChainTrusted, 2, right.Fingerprint},
		{"app.homelab.lan", "192.0.2.11", olderCert, ChainTrusted, 2, older.Fingerprint},
		{"web.homelab.lan", "192.0.2.12", wrongCert, ChainTrusted, 2, ""}, // the name is not compared here
		{"old.homelab.lan", "192.0.2.13", shortCert, ChainTrusted, 2, short.Fingerprint},
		{"leaf.homelab.lan", "192.0.2.14", leafOnly, ChainIncomplete, 1, right.Fingerprint},
		{"long.homelab.lan", "192.0.2.15", longChain, ChainTrusted, 9, right.Fingerprint}, // only the leaf and 8 intermediates are looked at
		{"evil.homelab.lan", "192.0.2.16", hostile, ChainUntrusted, 2, ""},
	}
	servers := map[string]*server{}
	ids := map[string]string{}
	for _, c := range cases {
		s := serveTLS(t, tlsConfig(c.cert))
		servers[c.host] = s
		f.route(c.host, c.ip, 443, s.addr)
		ids[c.host] = f.add(t, Request{Host: c.host, Port: 443}).ID
	}
	// The cert of "short" expires in 2 days; the scan is 3 days later.
	f.inst.Clock.Advance(3 * 24 * time.Hour)
	if err := f.inst.Ring.Seal(t.Context(), testinstance.Console); err != nil { // nothing is decrypted: a sealed server scans
		t.Fatal(err)
	}
	f.scanDue(t)
	for _, c := range cases {
		ep := f.get(t, ids[c.host])
		if ep.FailStreak != 0 || ep.LastErrorKind != "" || !ep.Scanned() || ep.LastOKAt.IsZero() || ep.SameCount != 1 {
			t.Errorf("%s: %+v", c.host, ep)
			continue
		}
		if ep.ChainState != c.want || ep.ChainLen != c.chainLen || ep.TLSVersion != "TLS 1.3" {
			t.Errorf("%s: chain %s/%d, %s; want %s/%d", c.host, ep.ChainState, ep.ChainLen, ep.TLSVersion, c.want, c.chainLen)
		}
		if c.fp != "" && ep.Fingerprint != c.fp {
			t.Errorf("%s: fingerprint %s, want %s", c.host, ep.Fingerprint, c.fp)
		}
		if len(ep.Fingerprint) != 64 || ep.Serial == "" || ep.NotAfter.IsZero() || ep.Subject == "" || ep.Issuer == "" {
			t.Errorf("%s: incomplete metadata %+v", c.host, ep)
		}
		servers[c.host].wait()
		if servers[c.host].appBytes() != 0 {
			t.Errorf("%s: the scan sent application data", c.host)
		}
		// Clipped, valid, no control characters – whatever the server calls itself.
		for _, text := range []string{ep.Subject, ep.Issuer} {
			if len(text) > MaxText || !utf8.ValidString(text) || strings.ContainsFunc(text, func(r rune) bool { return r < 0x20 || r == 0x7f || r == 0x202e }) {
				t.Errorf("%s: unclean text %q", c.host, text)
			}
		}
	}
	if ep := f.get(t, ids["old.homelab.lan"]); !ep.NotAfter.Before(f.inst.Clock.Now()) {
		t.Errorf("the short certificate has not ended: %v", ep.NotAfter)
	}
	if ep := f.get(t, ids["evil.homelab.lan"]); !strings.Contains(ep.Subject, "script") {
		t.Errorf("the hostile subject was dropped instead of being kept as data: %q", ep.Subject) // it is escaped on output, not here
	}
}

func TestScanFailureKinds(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.svc.Settings.Timeout = 400 * time.Millisecond
	_, cert := f.issue(t, 90, "www.homelab.lan")
	mtls13 := tlsConfig(cert)
	mtls13.ClientAuth = tls.RequireAnyClientCert
	mtls12 := mtls13.Clone()
	mtls12.MaxVersion = tls.VersionTLS12

	silent := make(chan struct{})
	t.Cleanup(func() { close(silent) })
	for _, tc := range []struct {
		host, ip string
		addr     string
		kind     string // "" = a certificate was read
	}{
		{"http.homelab.lan", "192.0.2.20", serveRaw(t, func(c net.Conn) {
			_, _ = io.WriteString(c, "HTTP/1.1 400 Bad Request\r\nSecret: SECRET-REMOTE-TEXT\r\n\r\n")
		}), KindHandshake},
		{"eof.homelab.lan", "192.0.2.21", serveRaw(t, func(net.Conn) {}), KindHandshake},
		{"silent.homelab.lan", "192.0.2.22", serveRaw(t, func(net.Conn) { <-silent }), KindTimeout},
		{"closed.homelab.lan", "192.0.2.23", closedAddr(t), KindConnRefused},
		{"mtls13.homelab.lan", "192.0.2.24", serveTLS(t, mtls13).addr, ""}, // TLS 1.3 shows the certificate before the server rejects us
		{"mtls12.homelab.lan", "192.0.2.25", serveTLS(t, mtls12).addr, KindClientCert},
	} {
		f.route(tc.host, tc.ip, 443, tc.addr)
		ep := f.add(t, Request{Host: tc.host, Port: 443})
		f.scanDue(t)
		got := f.get(t, ep.ID)
		if tc.kind == "" {
			if got.FailStreak != 0 || got.Fingerprint == "" {
				t.Errorf("%s: %+v", tc.host, got)
			}
			continue
		}
		if got.LastErrorKind != tc.kind || got.LastError != tc.kind || got.FailStreak != 1 || got.Fingerprint != "" || !got.LastOKAt.IsZero() {
			t.Errorf("%s: kind %q / %q, streak %d, fingerprint %q; want %q", tc.host, got.LastErrorKind, got.LastError, got.FailStreak, got.Fingerprint, tc.kind)
		}
		if strings.Contains(got.LastError, "SECRET") {
			t.Errorf("%s: a remote text was stored: %q", tc.host, got.LastError)
		}
	}
	// A name that does not resolve.
	gone := f.add(t, Request{Host: "gone.homelab.lan", Port: 443})
	f.scanDue(t)
	if got := f.get(t, gone.ID); got.LastErrorKind != KindDNS {
		t.Errorf("no DNS answer: %+v", got)
	}
	// Counted as an outage or not.
	for kind, want := range map[string]bool{
		KindDNS: true, KindTimeout: true, KindConnRefused: true, KindCouldNotConnect: true, KindHandshake: true, KindNoCertificate: true,
		KindClientCert: false, KindRefusedPolicy: false, KindRefusedDomain: false, KindRefusedPort: false, "": false, "whatever": false,
	} {
		if Counts(kind) != want {
			t.Errorf("Counts(%q) = %v", kind, !want)
		}
	}
}

// TestScanFollowsTheGuard: the address policy of the covering domain is
// applied at every scan, not only when the endpoint is added; so are the
// domain itself and the port list.
func TestScanFollowsTheGuard(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, cert := f.issue(t, 90, "www.homelab.lan")
	s := serveTLS(t, tlsConfig(cert))

	// Resolving to a loopback address: refused, nothing is dialed.
	f.answers["loop.homelab.lan"] = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	loop := f.add(t, Request{Host: "loop.homelab.lan", Port: 443})
	// Resolving to a private address is fine under "internal", refused once the domain says "public".
	f.route("priv.homelab.lan", "10.9.8.7", 443, s.addr)
	priv := f.add(t, Request{Host: "priv.homelab.lan", Port: 443})
	f.scanDue(t)
	if got := f.get(t, loop.ID); got.LastErrorKind != KindRefusedPolicy || got.FailStreak != 1 {
		t.Errorf("loopback: %+v", got)
	}
	if got := f.get(t, priv.ID); got.LastErrorKind != "" || got.Fingerprint == "" {
		t.Errorf("private under internal: %+v", got)
	}
	if len(f.dials()) != 1 || f.dials()[0] != "10.9.8.7:443" {
		t.Errorf("dialed %v", f.dials())
	}

	// The domain turns "public": the same endpoint is refused at the next scan.
	f.next()
	public := ca.AddressPublic
	domains, _ := f.inst.Engine.ListDomains(t.Context(), testinstance.Console)
	for _, d := range domains {
		if d.Name == "homelab.lan" {
			if _, err := f.inst.Engine.UpdateDomain(t.Context(), d.ID, ca.DomainSettings{AddressPolicy: &public}, testinstance.Console); err != nil {
				t.Fatal(err)
			}
		}
	}
	f.scanDue(t)
	got := f.get(t, priv.ID)
	if got.LastErrorKind != KindRefusedPolicy || got.FailStreak != 1 || got.Fingerprint == "" {
		t.Errorf("private under public: %+v", got) // the last good data stays
	}
	if !IsRefusal(got.LastErrorKind) || Counts(got.LastErrorKind) {
		t.Error("a refusal counts as an outage")
	}

	// The domain is deleted: no domain covers the host any more.
	f.next()
	for _, d := range domains {
		if d.Name == "homelab.lan" {
			if err := f.inst.Engine.DeleteDomain(t.Context(), d.ID, testinstance.Console); err != nil {
				t.Fatal(err)
			}
		}
	}
	f.scanDue(t)
	if got := f.get(t, priv.ID); got.LastErrorKind != KindRefusedDomain {
		t.Errorf("no domain: %+v", got)
	}

	// The port leaves monitor.scan_ports.
	f.next()
	f.svc.Settings.Ports = []int{8443}
	f.scanDue(t)
	if got := f.get(t, priv.ID); got.LastErrorKind != KindRefusedPort {
		t.Errorf("port: %+v", got)
	}
}

// TestScanResolvesOnce: a second lookup would answer 127.0.0.1; the
// connection goes to the address that was checked.
func TestScanResolvesOnceAndConnectsToTheCheckedAddress(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, cert := f.issue(t, 90, "www.homelab.lan")
	s := serveTLS(t, tlsConfig(cert))
	f.route("www.homelab.lan", "192.0.2.10", 443, s.addr)
	f.then["www.homelab.lan"] = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	ep := f.add(t, Request{Host: "www.homelab.lan", Port: 443})
	f.scanDue(t)
	if got := f.get(t, ep.ID); got.Fingerprint == "" || got.FailStreak != 0 {
		t.Fatalf("%+v", got)
	}
	if f.lookups["www.homelab.lan"] != 1 || len(f.dials()) != 1 || f.dials()[0] != "192.0.2.10:443" {
		t.Errorf("lookups %d, dialed %v", f.lookups["www.homelab.lan"], f.dials())
	}
}

// TestScanTriesAtMostFourAddresses: a name with many records can't hold a
// worker; an address that fails is followed by the next.
func TestScanTriesAtMostFourAddresses(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, cert := f.issue(t, 90, "www.homelab.lan")
	s := serveTLS(t, tlsConfig(cert))
	var addrs []netip.Addr
	for i := 1; i <= 6; i++ {
		addrs = append(addrs, netip.MustParseAddr("192.0.2."+itoa(100+i)))
	}
	f.answers["many.homelab.lan"] = addrs
	ep := f.add(t, Request{Host: "many.homelab.lan", Port: 443})
	f.scanDue(t)
	if got := f.get(t, ep.ID); got.LastErrorKind != KindConnRefused || len(f.dials()) != MaxTries {
		t.Errorf("%+v, dialed %v", got, f.dials())
	}
	// The third address answers: the first two are tried and failed.
	f.next()
	f.mu.Lock()
	f.dialed = nil
	f.targets["192.0.2.103:443"] = s.addr
	f.mu.Unlock()
	f.scanDue(t)
	if got := f.get(t, ep.ID); got.LastErrorKind != "" || got.Fingerprint == "" || len(f.dials()) != 3 {
		t.Errorf("%+v, dialed %v", got, f.dials())
	}
}

func TestScanSendsTheRightSNI(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, cert := f.issue(t, 90, "www.homelab.lan")
	s := serveTLS(t, tlsConfig(cert))
	f.route("www.homelab.lan", "192.0.2.10", 443, s.addr)
	f.route("www.homelab.lan", "192.0.2.10", 8443, s.addr)
	f.targets["192.0.2.30:443"] = s.addr
	f.targets["192.0.2.30:9443"] = s.addr
	f.add(t, Request{Host: "www.homelab.lan", Port: 443})                            // the host is the SNI
	f.add(t, Request{Host: "www.homelab.lan", Port: 8443, SNI: "alias.homelab.lan"}) // an explicit name
	f.add(t, Request{Host: "192.0.2.30", Port: 443})                                 // an IP sends none
	f.add(t, Request{Host: "192.0.2.30", Port: 9443, SNI: "named.homelab.lan"})      // an IP with a name
	f.scanDue(t)
	got := map[string]int{}
	for _, h := range s.hellos() {
		got[h]++
	}
	want := map[string]int{"www.homelab.lan": 1, "alias.homelab.lan": 1, "": 1, "named.homelab.lan": 1}
	if len(got) != len(want) {
		t.Fatalf("SNI seen: %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("SNI %q seen %d times, want %d (all: %v)", k, got[k], v, got)
		}
	}
}

// TestScanHistory: the failure streak, the served data that stays across
// failures, and the successful scans in a row that saw one fingerprint.
func TestScanHistory(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	a, certA := f.issue(t, 90, "www.homelab.lan")
	b, certB := f.issue(t, 90, "www.homelab.lan", "x.homelab.lan")
	srvA := serveTLS(t, tlsConfig(certA))
	srvB := serveTLS(t, tlsConfig(certB))
	f.route("www.homelab.lan", "192.0.2.10", 443, srvA.addr)
	ep := f.add(t, Request{Host: "www.homelab.lan", Port: 443})

	f.scanDue(t)
	got := f.get(t, ep.ID)
	since := got.FingerprintSince
	if got.SameCount != 1 || got.Fingerprint != a.Fingerprint || since.IsZero() {
		t.Fatalf("first scan: %+v", got)
	}
	f.next()
	f.scanDue(t)
	if got = f.get(t, ep.ID); got.SameCount != 2 || !got.FingerprintSince.Equal(since) {
		t.Fatalf("second scan: %+v", got)
	}
	// The host goes away: failures count, the last good data stays.
	f.mu.Lock()
	delete(f.targets, "192.0.2.10:443")
	f.mu.Unlock()
	for i := 1; i <= 2; i++ {
		f.next()
		f.scanDue(t)
		got = f.get(t, ep.ID)
		if got.FailStreak != i || got.LastErrorKind != KindConnRefused || got.Fingerprint != a.Fingerprint || got.SameCount != 2 {
			t.Fatalf("failure %d: %+v", i, got)
		}
	}
	// Back with the same certificate: the streak ends, the count goes on.
	f.mu.Lock()
	f.targets["192.0.2.10:443"] = srvA.addr
	f.mu.Unlock()
	f.next()
	f.scanDue(t)
	if got = f.get(t, ep.ID); got.FailStreak != 0 || got.LastErrorKind != "" || got.LastError != "" || got.SameCount != 3 {
		t.Fatalf("recovered: %+v", got)
	}
	// Another certificate: the count starts again.
	f.mu.Lock()
	f.targets["192.0.2.10:443"] = srvB.addr
	f.mu.Unlock()
	f.next()
	f.scanDue(t)
	if got = f.get(t, ep.ID); got.Fingerprint != b.Fingerprint || got.SameCount != 1 || !got.FingerprintSince.After(since) {
		t.Fatalf("new certificate: %+v", got)
	}
}

// TestDispatchOnlyHandsOver: the scheduler's job returns at once, at most
// four scans run, a busy pool claims nothing more, and a backlog is worked
// off by the workers themselves.
func TestDispatchOnlyHandsOver(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	release := make(chan struct{})
	var inflight, peak, started atomic.Int32
	startedCh := make(chan struct{}, 32)
	f.scanner.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		n := inflight.Add(1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		started.Add(1)
		startedCh <- struct{}{}
		defer inflight.Add(-1)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}
	}
	var ids []string
	for i := 0; i < 10; i++ {
		h := "h" + itoa(i) + ".homelab.lan"
		f.answers[h] = []netip.Addr{netip.MustParseAddr("192.0.2.50")}
		ids = append(ids, f.add(t, Request{Host: h, Port: 443}).ID)
	}
	done := make(chan error, 1)
	go func() { done <- f.scanner.Dispatch(t.Context()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Dispatch waited for the scans")
	}
	for range 4 {
		<-startedCh
	}
	if err := f.scanner.Dispatch(t.Context()); err != nil { // the pool is busy: nothing is claimed
		t.Fatal(err)
	}
	f.scanner.mu.Lock()
	busy := len(f.scanner.running)
	f.scanner.mu.Unlock()
	if busy != 4 || started.Load() != 4 {
		t.Fatalf("running %d, started %d, want 4", busy, started.Load())
	}
	close(release)
	f.scanner.Wait()
	if peak.Load() != 4 || started.Load() != 10 {
		t.Errorf("peak %d, started %d", peak.Load(), started.Load())
	}
	for _, id := range ids {
		if got := f.get(t, id); !got.Scanned() || got.FailStreak != 1 {
			t.Errorf("%s: %+v", got.Host, got)
		}
	}
}

// TestDispatchClaimsAScanBeforeItRuns: the next scan moves forward at the
// claim (the interval plus a share of jitter), so a crash can't rescan at
// once and a second dispatch doesn't scan again.
func TestDispatchClaimsAScanBeforeItRuns(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, cert := f.issue(t, 90, "www.homelab.lan")
	s := serveTLS(t, tlsConfig(cert))
	f.route("www.homelab.lan", "192.0.2.10", 443, s.addr)
	ep := f.add(t, Request{Host: "www.homelab.lan", Port: 443})
	start := f.inst.Clock.Now().Truncate(time.Second)
	f.scanDue(t)
	f.scanDue(t) // nothing is due
	if s.handshakes() != 1 {
		t.Fatalf("scanned %d times", s.handshakes())
	}
	// The jitter source answers n/2 here: 15 minutes plus 5 % of it.
	want := start.Add(15*time.Minute + 45*time.Second)
	if got := f.get(t, ep.ID); !got.NextScanAt.Equal(want) {
		t.Errorf("next scan %v, want %v", got.NextScanAt, want)
	}
	f.inst.Clock.Advance(15*time.Minute + 44*time.Second)
	f.scanDue(t)
	if s.handshakes() != 1 {
		t.Error("scanned before the next time")
	}
	f.inst.Clock.Advance(time.Second)
	f.scanDue(t)
	if s.handshakes() != 2 {
		t.Errorf("scanned %d times", s.handshakes())
	}
	// Jitter stays within 0 to 10 % with the real source too.
	f.scanner.Rand = nil
	for range 50 {
		d := f.scanner.nextScan(start).Sub(start)
		if d < 15*time.Minute || d >= 16*time.Minute+30*time.Second {
			t.Fatalf("next scan after %v", d)
		}
	}
}

func TestCloseCancelsRunningScansAndRecordsNothing(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.svc.Settings.Timeout = 30 * time.Second
	started := make(chan struct{}, 1)
	f.scanner.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
		started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	f.answers["www.homelab.lan"] = []netip.Addr{netip.MustParseAddr("192.0.2.10")}
	ep := f.add(t, Request{Host: "www.homelab.lan", Port: 443})
	if err := f.scanner.Dispatch(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-started
	closed := make(chan struct{})
	go func() { f.scanner.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not stop the running scan")
	}
	if got := f.get(t, ep.ID); got.Scanned() || got.FailStreak != 0 {
		t.Errorf("a canceled scan was recorded: %+v", got)
	}
	// Closed: nothing starts any more.
	f.inst.Clock.Advance(time.Hour)
	if err := f.scanner.Dispatch(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.scanner.Kick()
	f.scanner.Wait()
	if got := f.get(t, ep.ID); got.Scanned() {
		t.Errorf("scanned after Close: %+v", got)
	}
}

func TestScanOffDoesNotConnect(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.answers["www.homelab.lan"] = []netip.Addr{netip.MustParseAddr("192.0.2.10")}
	ep := f.add(t, Request{Host: "www.homelab.lan", Port: 443})
	f.svc.Settings.Interval = 0
	f.scanDue(t)
	if got := f.get(t, ep.ID); got.Scanned() || len(f.dials()) != 0 {
		t.Errorf("scanned while off: %+v, %v", got, f.dials())
	}
}

// TestScanNowKicksTheDispatcher: scan now makes the endpoint due and the
// service tells the scanner, so the scan doesn't wait for the 30-second tick.
func TestScanNowKicksTheDispatcher(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	_, cert := f.issue(t, 90, "www.homelab.lan")
	s := serveTLS(t, tlsConfig(cert))
	f.route("www.homelab.lan", "192.0.2.10", 443, s.addr)
	ep := f.add(t, Request{Host: "www.homelab.lan", Port: 443})
	f.scanDue(t)
	f.svc.Kick = f.scanner.Kick
	if err := f.svc.ScanNow(t.Context(), testinstance.Console, ep.ID); err != nil {
		t.Fatal(err)
	}
	f.scanner.Wait()
	if got := f.get(t, ep.ID); got.SameCount != 2 || s.handshakes() != 2 {
		t.Errorf("scan now did not scan: %+v, %d handshakes", got, s.handshakes())
	}
}

func TestClassify(t *testing.T) {
	t.Parallel()
	opErr := func(e error) error { return &net.OpError{Op: "dial", Net: "tcp", Err: e} }
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"refused":                     {opErr(syscall.ECONNREFUSED), KindConnRefused},
		"refused as Windows says":     {opErr(syscall.Errno(10061)), KindConnRefused},
		"deadline":                    {context.DeadlineExceeded, KindTimeout},
		"timeout error":               {opErr(timeoutError{}), KindTimeout},
		"no route":                    {opErr(syscall.EHOSTUNREACH), KindCouldNotConnect},
		"something else":              {errors.New("boom"), KindCouldNotConnect},
		"dns":                         {&netguard.Error{Kind: netguard.KindDNS}, KindDNS},
		"all refused by the policy":   {&netguard.Error{Kind: netguard.KindConnection, Refused: true}, KindRefusedPolicy},
		"the last dial error is kept": {&netguard.Error{Kind: netguard.KindConnection, Err: opErr(syscall.ECONNREFUSED)}, KindConnRefused},
		"no error behind it":          {&netguard.Error{Kind: netguard.KindConnection}, KindCouldNotConnect},
	} {
		if got := classifyDial(tc.err); got != tc.want {
			t.Errorf("%s: classifyDial = %q, want %q", name, got, tc.want)
		}
	}
	for name, tc := range map[string]struct {
		err   error
		chain bool
		want  string
	}{
		"deadline":                        {context.DeadlineExceeded, true, KindTimeout},
		"alert certificate required":      {remote("certificate required"), false, KindClientCert},
		"bad certificate after a chain":   {remote("bad certificate"), true, KindClientCert},
		"bad certificate without chain":   {remote("bad certificate"), false, KindHandshake},
		"handshake failure after chain":   {remote("handshake failure"), true, KindClientCert},
		"handshake failure without chain": {remote("handshake failure"), false, KindHandshake},
		"another alert after a chain":     {remote("internal error"), true, KindHandshake},
		"not TLS":                         {tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}, false, KindHandshake},
		"eof":                             {io.EOF, false, KindHandshake},
		"text of the remote end in err":   {errors.New("remote said SECRET"), true, KindHandshake},
	} {
		if got := classifyHandshake(tc.err, tc.chain); got != tc.want {
			t.Errorf("%s: classifyHandshake = %q, want %q", name, got, tc.want)
		}
	}
}

// remote is what crypto/tls returns for an alert of the peer.
func remote(text string) error {
	return &net.OpError{Op: "remote error", Err: errors.New("tls: " + text)}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// TestScanLogsOnChangesAndNeverRemoteText: one Info line when the outcome
// changes, each scan at Debug, no subject and no remote bytes.
func TestScanLogsOnChangesAndNeverRemoteText(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	var buf lockedBuf
	f.scanner.Log = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	hostile := foreign(t, pkix.Name{CommonName: "SUBJECT-MUST-NOT-BE-LOGGED"}, "www.homelab.lan")
	s := serveTLS(t, tlsConfig(hostile))
	f.route("www.homelab.lan", "192.0.2.10", 443, s.addr)
	ep := f.add(t, Request{Host: "www.homelab.lan", Port: 443})
	f.scanDue(t)
	f.next()
	f.scanDue(t) // the same certificate: only a Debug line
	f.mu.Lock()
	delete(f.targets, "192.0.2.10:443")
	f.mu.Unlock()
	for range 3 {
		f.next()
		f.scanDue(t) // the first failure is an Info line, the repeats are not
	}
	infos, debugs := 0, 0
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		switch {
		case rec["msg"] == "scan" && rec["level"] == "INFO":
			infos++
		case rec["msg"] == "scan done" && rec["level"] == "DEBUG":
			debugs++
			if rec["kind"] == nil && rec["address"] == nil {
				t.Errorf("a scan line without the address: %s", line)
			}
		}
	}
	if infos != 2 || debugs != 5 { // reachable once, failed once; five scans
		t.Errorf("%d Info and %d Debug lines:\n%s", infos, debugs, buf.String())
	}
	if all := buf.String(); strings.Contains(all, "SUBJECT-MUST-NOT-BE-LOGGED") || !strings.Contains(all, ep.Host) || !strings.Contains(all, "192.0.2.10") {
		t.Errorf("log:\n%s", all)
	}
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// TestScanOfAnEndpointDeletedMeanwhile: the result of a scan that was running
// when its endpoint was removed is dropped quietly.
func TestScanOfAnEndpointDeletedMeanwhile(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	var buf lockedBuf
	f.scanner.Log = slog.New(slog.NewJSONHandler(&buf, nil))
	_, cert := f.issue(t, 90, "www.homelab.lan")
	s := serveTLS(t, tlsConfig(cert))
	f.route("www.homelab.lan", "192.0.2.10", 443, s.addr)
	started, release := make(chan struct{}), make(chan struct{})
	f.scanner.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		close(started)
		<-release
		return f.dial(ctx, network, addr)
	}
	ep := f.add(t, Request{Host: "www.homelab.lan", Port: 443})
	if err := f.scanner.Dispatch(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-started
	if err := f.svc.Delete(t.Context(), testinstance.Console, ep.ID); err != nil {
		t.Fatal(err)
	}
	close(release)
	f.scanner.Wait()
	if _, err := f.svc.Get(t.Context(), testinstance.Console, ep.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("the endpoint is back: %v", err)
	}
	if strings.Contains(buf.String(), "not stored") || strings.Contains(buf.String(), "could not run") {
		t.Errorf("log:\n%s", buf.String())
	}
}
