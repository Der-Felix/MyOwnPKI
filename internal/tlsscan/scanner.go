package tlsscan

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/netguard"
)

// Scanner scans the endpoints that are due with a bounded pool of workers.
// Dispatch only hands work over and returns at once: the server's scheduler
// is one goroutine that runs its jobs one after the other, and a scan inside
// it would stall the CRL, ACME and alert jobs (docs/PHASE3.md §10.2).
type Scanner struct {
	Svc    *Service
	Engine *ca.Engine
	Clock  clock.Clock
	Log    *slog.Logger
	// Resolver is acme.resolver ("" = the system's).
	Resolver string
	// Who reads the CAs and domains: a system principal that may read the
	// whole tenant.
	Who keys.Who

	// The network edges; tests replace them, never the rules around them.
	Dial     netguard.DialFunc
	LookupIP netguard.LookupFunc
	// Rand returns a number in [0, n) for the jitter; nil = crypto/rand.
	Rand func(n int64) int64

	once       sync.Once
	ctx        context.Context
	cancel     context.CancelFunc
	dispatchMu sync.Mutex
	mu         sync.Mutex
	running    map[string]bool
	closed     bool
	wg         sync.WaitGroup
	resolver   *net.Resolver
}

// SystemWho is the principal of the scanner and the evaluation: the server's
// own job, tenant-wide.
var SystemWho = keys.Who{Actor: audit.Actor{Type: audit.ActorSystem, Name: "tlsscan"}, Principal: authz.System("tlsscan")}

func (s *Scanner) init() {
	s.once.Do(func() {
		s.ctx, s.cancel = context.WithCancel(context.Background())
		s.running = map[string]bool{}
		if s.Log == nil {
			s.Log = slog.New(slog.DiscardHandler)
		}
		s.resolver = netguard.NewResolver(s.Resolver)
		if s.LookupIP == nil {
			s.LookupIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
				return s.resolver.LookupNetIP(ctx, "ip", host)
			}
		}
		if s.Who.Principal == nil {
			s.Who = SystemWho
		}
	})
}

func (s *Scanner) workers() int {
	if w := s.Svc.Settings.Workers; w > 0 {
		return w
	}
	return DefaultWorkers
}

// Close stops new scans, cancels the running ones and waits for them – before
// the databases close. A canceled scan records nothing.
func (s *Scanner) Close() {
	s.init()
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.cancel()
	s.wg.Wait()
}

// Wait returns when no scan is running (for tests).
func (s *Scanner) Wait() { s.init(); s.wg.Wait() }

// Kick looks for due endpoints at once in the background – after a "scan
// now". It never blocks.
func (s *Scanner) Kick() {
	s.init()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		if err := s.Dispatch(s.ctx); err != nil && s.ctx.Err() == nil {
			s.Log.Warn("tls scan: dispatch failed", slog.Any("error", err))
		}
	}()
}

// Dispatch claims the endpoints that are due, as many as there are free
// workers, and starts their scans. It does not wait for them.
func (s *Scanner) Dispatch(ctx context.Context) error {
	s.init()
	if s.Svc.Settings.Off() {
		return nil
	}
	s.dispatchMu.Lock()
	defer s.dispatchMu.Unlock()
	s.mu.Lock()
	free := s.workers() - len(s.running)
	closed := s.closed
	s.mu.Unlock()
	if closed || free <= 0 {
		return nil
	}
	now := s.Clock.Now().UTC().Truncate(time.Second)
	claimed, err := s.Svc.claimDue(ctx, now, free,
		func(id string) bool { s.mu.Lock(); defer s.mu.Unlock(); return s.running[id] },
		func() time.Time { return s.nextScan(now) })
	if err != nil {
		return err
	}
	for _, ep := range claimed {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return nil
		}
		s.running[ep.ID] = true
		s.wg.Add(1)
		s.mu.Unlock()
		go s.run(ep)
	}
	return nil
}

// nextScan is now plus the interval plus a random 0 to 10 % of it: 100
// endpoints do not all fire together after a restart.
func (s *Scanner) nextScan(now time.Time) time.Time {
	iv := s.Svc.Settings.Interval
	return now.Add(iv + time.Duration(s.jitter(int64(iv)/10)))
}

func (s *Scanner) jitter(n int64) int64 {
	if n <= 0 {
		return 0
	}
	if s.Rand != nil {
		return s.Rand(n)
	}
	v, err := rand.Int(rand.Reader, big.NewInt(n))
	if err != nil {
		return 0
	}
	return v.Int64()
}

// run scans one endpoint, then looks for more work: a backlog (after a restart,
// or many endpoints) is worked off at the speed of the workers, not of the
// 30-second dispatch tick.
func (s *Scanner) run(ep Endpoint) {
	defer s.wg.Done()
	s.scan(ep)
	s.mu.Lock()
	delete(s.running, ep.ID)
	s.mu.Unlock()
	if err := s.Dispatch(s.ctx); err != nil && s.ctx.Err() == nil {
		s.Log.Warn("tls scan: dispatch failed", slog.Any("error", err))
	}
}

func (s *Scanner) scan(ep Endpoint) {
	ctx, cancel := context.WithTimeout(s.ctx, s.Svc.Settings.Timeout)
	defer cancel()
	res, perr := s.probe(ctx, ep)
	if s.ctx.Err() != nil {
		return // the server is closing: not a result
	}
	if perr != nil {
		// A reason of ours (the database): no result, not an outage of the
		// endpoint; the next scan is already planned.
		s.Log.Error("tls scan: could not run", slog.String("host", ep.Host), slog.Int("port", ep.Port), slog.Any("error", perr))
		return
	}
	now := s.Clock.Now().UTC().Truncate(time.Second)
	next := s.nextScan(now)
	// The database may be slower than the scan; the scan's own deadline is over.
	wctx, wcancel := context.WithTimeout(context.WithoutCancel(s.ctx), 10*time.Second)
	defer wcancel()
	var err error
	if res.Fail != nil {
		err = s.Svc.recordFailure(wctx, ep.ID, now, next, res.Fail.Kind, res.Fail.Message)
	} else {
		err = s.Svc.recordSuccess(wctx, ep.ID, now, next, res.Served)
	}
	if err != nil {
		s.Log.Warn("tls scan: result not stored", slog.String("host", ep.Host), slog.Int("port", ep.Port), slog.Any("error", err))
		return
	}
	s.logResult(ep, res)
}

// logResult: one Info line when the outcome of an endpoint changes (reachable
// to unreachable, a new certificate, …), each scan at Debug. A remote text
// never gets here.
func (s *Scanner) logResult(ep Endpoint, res Result) {
	switch {
	case res.Fail != nil:
		if ep.LastErrorKind != res.Fail.Kind || ep.FailStreak == 0 {
			s.Log.Info("scan", slog.String("host", ep.Host), slog.Int("port", ep.Port), slog.String("state", "failed"), slog.String("kind", res.Fail.Kind))
		}
	case ep.FailStreak > 0 || !ep.Scanned():
		s.Log.Info("scan", slog.String("host", ep.Host), slog.Int("port", ep.Port), slog.String("state", "reachable"), slog.String("fingerprint", res.Served.Fingerprint))
	case ep.Fingerprint != res.Served.Fingerprint:
		s.Log.Info("scan", slog.String("host", ep.Host), slog.Int("port", ep.Port), slog.String("state", "certificate changed"), slog.String("fingerprint", res.Served.Fingerprint))
	}
	attrs := []any{slog.String("host", ep.Host), slog.Int("port", ep.Port)}
	if res.Address != "" {
		attrs = append(attrs, slog.String("address", res.Address))
	}
	if res.Fail != nil {
		attrs = append(attrs, slog.String("kind", res.Fail.Kind))
	} else {
		attrs = append(attrs, slog.String("chain", res.Served.ChainState))
	}
	s.Log.Debug("scan done", attrs...)
}

// Failure is a failed scan: a kind of the fixed vocabulary and a fixed
// message. What the remote end said is in neither.
type Failure struct{ Kind, Message string }

// Result is the outcome of one scan.
type Result struct {
	Fail    *Failure // nil = the leaf was read
	Served  served
	Address string // the address that was connected to – for the log only
}

func fail(kind string) Result { return Result{Fail: &Failure{Kind: kind, Message: kind}} }

// Probe scans one endpoint now and returns what it found; nothing is
// stored. (For tests and for the dispatcher.)
func (s *Scanner) Probe(ctx context.Context, ep Endpoint) (Result, error) {
	s.init()
	return s.probe(ctx, ep)
}

func (s *Scanner) probe(ctx context.Context, ep Endpoint) (Result, error) {
	if !s.Svc.Settings.portAllowed(ep.Port) {
		return fail(KindRefusedPort), nil
	}
	typ := "dns"
	if ep.IsIP() {
		typ = "ip"
	}
	d, err := s.Engine.DomainFor(ctx, typ, ep.Host)
	if err != nil {
		return Result{}, err
	}
	if d == nil {
		return fail(KindRefusedDomain), nil
	}
	g := netguard.Dialer{
		Policy: d.AddressPolicy, Dial: s.Dial, LookupIP: s.LookupIP,
		CheckPort: func(p uint16) error {
			if int(p) != ep.Port || !s.Svc.Settings.portAllowed(int(p)) {
				return &netguard.Error{Kind: netguard.KindConnection, Detail: "port is not scannable"}
			}
			return nil
		},
		Log: s.Log, LogName: "tls scan", LogLevel: slog.LevelDebug, MaxTries: MaxTries, TryTimeout: TryTimeout,
	}
	conn, err := g.DialContext(ctx, "tcp", net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port)))
	if err != nil {
		return fail(classifyDial(err)), nil
	}
	defer func() { _ = conn.Close() }()
	res := Result{Address: conn.RemoteAddr().String()}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	// Collect, don't trust: the chain is judged afterwards (chainState).
	var gotChain bool
	cfg := &tls.Config{
		InsecureSkipVerify: true, // #nosec G402 -- this handshake only collects what the endpoint serves; trust is decided afterwards against this PKI's CAs
		MinVersion:         tls.VersionTLS12,
		Time:               s.Clock.Now,
		VerifyConnection: func(cs tls.ConnectionState) error {
			gotChain = len(cs.PeerCertificates) > 0
			return nil
		},
	}
	if name := ep.Name(); !isIPLiteral(name) {
		cfg.ServerName = name // an IP literal is never sent as SNI (RFC 6066)
	}
	tc := tls.Client(conn, cfg)
	if herr := tc.HandshakeContext(ctx); herr != nil {
		res.Fail = &Failure{Kind: classifyHandshake(herr, gotChain)}
		res.Fail.Message = res.Fail.Kind
		return res, nil
	}
	state := tc.ConnectionState()
	_ = tc.Close() // no application data: the handshake was the whole conversation
	if len(state.PeerCertificates) == 0 {
		res.Fail = &Failure{Kind: KindNoCertificate, Message: KindNoCertificate}
		return res, nil
	}
	certs := state.PeerCertificates
	leaf := certs[0]
	inter := certs[1:min(len(certs), 1+MaxIntermediate)]
	sum := sha256.Sum256(leaf.Raw)
	res.Served = served{
		Fingerprint: strings.ToUpper(hex.EncodeToString(sum[:])), Serial: clean(strings.ToUpper(leaf.SerialNumber.Text(16)), 64),
		Subject: clean(leaf.Subject.String(), MaxText), Issuer: clean(leaf.Issuer.String(), MaxText),
		NotBefore: leaf.NotBefore.UTC(), NotAfter: leaf.NotAfter.UTC(),
		ChainLen: min(len(certs), 1+MaxIntermediate), TLSVersion: tls.VersionName(state.Version),
	}
	res.Served.ChainState, err = s.chainState(ctx, leaf, inter)
	return res, err
}

func isIPLiteral(s string) bool { _, err := netip.ParseAddr(s); return err == nil }

// chainState verifies the served chain against the CAs of this PKI: trusted
// with the intermediates the endpoint sent, incomplete if it needs this
// PKI's own intermediates as well, untrusted if it does not lead here. The
// host name is not part of it (Assess compares names), and a leaf that has
// expired is verified at its last valid second so that expiry does not hide
// a chain problem – expiry has its own alert.
func (s *Scanner) chainState(ctx context.Context, leaf *x509.Certificate, served []*x509.Certificate) (string, error) {
	anchors, err := s.Engine.TrustAnchors(ctx, s.Who)
	if err != nil {
		return "", err
	}
	roots := x509.NewCertPool()
	for _, r := range anchors.Roots {
		roots.AddCert(r)
	}
	pool := x509.NewCertPool()
	for _, c := range served {
		pool.AddCert(c)
	}
	opts := x509.VerifyOptions{
		Roots: roots, Intermediates: pool, CurrentTime: verifyTime(leaf, s.Clock.Now()),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if _, err := leaf.Verify(opts); err == nil {
		return ChainTrusted, nil
	}
	for _, c := range anchors.Intermediates {
		pool.AddCert(c)
	}
	if _, err := leaf.Verify(opts); err == nil {
		return ChainIncomplete, nil
	}
	return ChainUntrusted, nil
}

// verifyTime is now, or the leaf's last valid second if it has ended (its
// first, if it has not started).
func verifyTime(leaf *x509.Certificate, now time.Time) time.Time {
	switch {
	case now.After(leaf.NotAfter):
		return leaf.NotAfter.Add(-time.Second)
	case now.Before(leaf.NotBefore):
		return leaf.NotBefore
	}
	return now
}

// classifyDial maps a failed connect to the fixed vocabulary.
func classifyDial(err error) string {
	var ge *netguard.Error
	if errors.As(err, &ge) {
		switch {
		case ge.Kind == netguard.KindDNS:
			return KindDNS
		case ge.Refused:
			return KindRefusedPolicy
		case ge.Err == nil:
			return KindCouldNotConnect
		}
		err = ge.Err
	}
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return KindTimeout
	case isConnRefused(err):
		return KindConnRefused
	}
	return KindCouldNotConnect
}

// isConnRefused is ECONNREFUSED, also as Windows reports it (WSAECONNREFUSED).
func isConnRefused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var errno syscall.Errno
	return errors.As(err, &errno) && uintptr(errno) == 10061
}

// classifyHandshake maps a failed handshake to the fixed vocabulary; the
// peer's own words are never used.
func classifyHandshake(err error, gotChain bool) string {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout() {
		return KindTimeout
	}
	// A remote alert is a *net.OpError whose Err is crypto/tls's own (unexported)
	// alert type: its text is one of the stdlib's fixed names for a one-byte
	// code, never a string of the peer. TLS 1.2 shows the chain, then the server
	// rejects our missing certificate.
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "remote error" && op.Err != nil {
		switch op.Err.Error() {
		case "tls: certificate required":
			return KindClientCert
		case "tls: bad certificate", "tls: handshake failure":
			// Go sends handshake_failure in TLS 1.2 when it requires a client
			// certificate and gets none. After a served chain nothing else is
			// left to refuse: the server has accepted its own part.
			if gotChain {
				return KindClientCert
			}
		}
	}
	return KindHandshake
}
