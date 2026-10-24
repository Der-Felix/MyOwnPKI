package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	agentv1 "github.com/Der-Felix/MyOwnPKI/internal/gen/myownpki/agent/v1"
)

// Waits (docs/PHASE3.md §6.1, §6.2).
const (
	pollEvery      = 30 * time.Second // a pending enrollment
	notEnrolledLog = time.Minute      // not enrolled: look again for `enroll`
	maxBackoff     = time.Hour
	agentFile      = "agent.json"
)

// ErrEnrolled: enroll on an agent whose certificate is still valid.
var ErrEnrolled = errors.New("this agent is enrolled and its certificate is valid")

// Agent is myownpki-agent.
type Agent struct {
	cfg      *Config
	st       state
	ch       *channel
	log      *slog.Logger
	passMu   sync.Mutex // one ACME pass; responders share port 80 and the state directory
	acmeDial func(context.Context, string, string) (net.Conn, error)

	// Version, OS and Arch are reported at enrollment.
	Version, OS, Arch string
	// StandaloneAddr is where challenge: standalone listens (":80").
	StandaloneAddr string
	// Now and Sleep: the clock and the wait; tests replace them.
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
}

// New prepares the agent: the state directory, the trust anchor and the
// channel; the identity on disk, if there is one, becomes the client
// certificate.
func New(cfg *Config, log *slog.Logger, version string) (*Agent, error) {
	roots, err := rootPool(cfg.CABundle)
	if err != nil {
		return nil, err
	}
	ch, err := newChannel(cfg, roots)
	if err != nil {
		return nil, err
	}
	a := &Agent{
		cfg: cfg, st: state{dir: cfg.StateDir}, ch: ch, log: log, Version: version, OS: runtime.GOOS, Arch: runtime.GOARCH,
		StandaloneAddr: ":80", Now: clock.System{}.Now, Sleep: sleep,
		acmeDial: defaultACMEDial,
	}
	if err := a.st.ensure(); err != nil {
		return nil, fmt.Errorf("state directory: %w", err)
	}
	if id, err := a.st.identity(); err == nil {
		ch.use(id)
	}
	return a, nil
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Result is where an enrollment stands, for the operator.
type Result struct {
	State   agentv1.EnrollState
	Message string
	AgentID string
}

// Admitted reports whether the agent has its certificate now.
func (r *Result) Admitted() bool { return r.State == agentv1.EnrollState_ENROLL_STATE_ADMITTED }

// Enroll enrolls this host: a new key – or, when its certificate expired,
// the key of the last certificate (the server knows it then) – a CSR, the
// check file, the decision. A pending enrollment is kept for `run`.
func (a *Agent) Enroll(ctx context.Context, token string) (*Result, error) {
	a.st.cleanupWritten()
	var key *ecdsa.PrivateKey
	again := false
	if id, err := a.st.identity(); err == nil {
		if a.Now().Before(id.Leaf.NotAfter) {
			return nil, fmt.Errorf("%w until %s – nothing to do", ErrEnrolled, id.Leaf.NotAfter.Format(time.DateTime))
		}
		if key, err = a.st.currentKey(); err != nil {
			return nil, err
		}
		again = true
	} else {
		a.ch.use(nil)
		if key, err = a.st.pendingKey(true); err != nil {
			return nil, err
		}
	}
	csr, err := makeCSR(key, a.cfg.Hostname)
	if err != nil {
		return nil, err
	}
	method := agentv1.CheckMethod_CHECK_METHOD_STANDALONE
	if a.cfg.Enrollment.Challenge == ChallengeWebroot {
		method = agentv1.CheckMethod_CHECK_METHOD_WEBROOT
	}
	out, err := a.ch.client.Enroll(ctx, connect.NewRequest(&agentv1.EnrollRequest{
		Hostname: a.cfg.Hostname, CsrDer: csr, JoinToken: token, CheckMethod: method,
		AgentVersion: a.Version, Os: a.OS, Arch: a.Arch,
	}))
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", explainTLS(err))
	}
	e := &enrollmentState{ID: out.Msg.EnrollmentId, Handle: out.Msg.Handle, Again: again}
	if serr := a.st.saveEnrollment(e); serr != nil {
		return nil, serr
	}
	r := newResponder(a.cfg.Enrollment.Challenge, a.cfg.Enrollment.Webroot, a.cfg.Paths, a.st, a.StandaloneAddr, a.log)
	if perr := r.place(out.Msg.CheckToken, out.Msg.CheckToken+"."+spkiHash(key)); perr != nil {
		return nil, perr
	}
	defer r.remove(out.Msg.CheckToken)
	st, err := a.ch.client.EnrollStatus(ctx, connect.NewRequest(&agentv1.EnrollStatusRequest{
		EnrollmentId: e.ID, Handle: e.Handle, CheckReady: true,
	}))
	if err != nil {
		return nil, fmt.Errorf("enrollment check: %w", explainTLS(err))
	}
	return a.handle(e, key, st.Msg)
}

// Poll asks for the decision on the kept enrollment; nil result: none open.
func (a *Agent) Poll(ctx context.Context) (*Result, error) {
	e, err := a.st.enrollment()
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	st, err := a.ch.client.EnrollStatus(ctx, connect.NewRequest(&agentv1.EnrollStatusRequest{EnrollmentId: e.ID, Handle: e.Handle}))
	if connect.CodeOf(err) == connect.CodeNotFound {
		a.st.clearEnrollment()
		return &Result{State: agentv1.EnrollState_ENROLL_STATE_EXPIRED, Message: "the server doesn't know this enrollment – enroll again"}, nil
	}
	if err != nil {
		return nil, explainTLS(err)
	}
	var key *ecdsa.PrivateKey
	if e.Again {
		key, err = a.st.currentKey()
	} else {
		key, err = a.st.pendingKey(false)
	}
	if err != nil {
		return nil, err
	}
	return a.handle(e, key, st.Msg)
}

// handle stores what the server decided.
func (a *Agent) handle(e *enrollmentState, key *ecdsa.PrivateKey, m *agentv1.EnrollStatusResponse) (*Result, error) {
	res := &Result{State: m.State, Message: m.Message, AgentID: m.AgentId}
	switch m.State {
	case agentv1.EnrollState_ENROLL_STATE_ADMITTED:
		id, err := a.st.install(key, m.CertificateDer, m.ChainDer)
		if err != nil {
			return nil, fmt.Errorf("store the agent certificate: %w", err)
		}
		a.ch.use(id)
		a.st.clearEnrollment()
		if err := a.saveAgentID(m.AgentId); err != nil {
			return nil, err
		}
		a.log.Info("enrolled", slog.String("agent", m.AgentId), slog.String("hostname", a.cfg.Hostname), slog.Time("certificate_until", id.Leaf.NotAfter))
	case agentv1.EnrollState_ENROLL_STATE_DENIED, agentv1.EnrollState_ENROLL_STATE_EXPIRED:
		a.st.clearEnrollment()
	default:
		e.Message = m.Message
		if err := a.st.saveEnrollment(e); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// Run keeps the agent's certificate: it waits for a pending enrollment,
// renews at 2/3 of the 7 days (with jitter), and enrolls again with the key
// of the last certificate when that one expired. Later blocks add the
// heartbeat, the desired state and the deployments.
func (a *Agent) Run(ctx context.Context) error {
	backoff := time.Minute
	for ctx.Err() == nil { // a stop (SIGTERM) ends the loop; it is no failure
		backoff = a.next(ctx, backoff)
	}
	return nil
}

// next runs one step; after a failure it logs, waits the back-off and
// returns a longer one, after a success the shortest.
func (a *Agent) next(ctx context.Context, backoff time.Duration) time.Duration {
	err := a.step(ctx)
	if err == nil {
		return time.Minute
	}
	if ctx.Err() == nil {
		a.log.Error("agent", slog.Any("error", err), slog.Duration("retry_in", backoff))
		_ = a.Sleep(ctx, jitter(backoff))
	}
	return min(backoff*2, maxBackoff)
}

// step does the next thing – wait for an enrollment, enroll again, wait
// for the renewal or renew – and returns what failed; Run retries that with
// a growing back-off.
func (a *Agent) step(ctx context.Context) error {
	id, err := a.st.identity()
	switch {
	case errors.Is(err, os.ErrNotExist):
		return a.waitForEnrollment(ctx)
	case err != nil:
		return fmt.Errorf("the agent's key or certificate can't be read: %w", err)
	}
	now := a.Now()
	if !now.Before(id.Leaf.NotAfter) {
		if err := a.enrollAgain(ctx); err != nil {
			return fmt.Errorf("the agent certificate expired; enrolling again: %w", err)
		}
		return nil
	}
	if at := RenewAt(id.Leaf, serialFraction(id.Leaf)); now.Before(at) {
		// Wake at least hourly: a new `enroll` or a changed state counts.
		return a.Sleep(ctx, min(at.Sub(now), time.Hour))
	}
	if err := a.renew(ctx); err != nil {
		return fmt.Errorf("agent certificate renewal: %w", err)
	}
	return nil
}

// waitForEnrollment polls an open enrollment, or says how to enroll.
func (a *Agent) waitForEnrollment(ctx context.Context) error {
	res, err := a.Poll(ctx)
	if err != nil {
		return err
	}
	switch {
	case res == nil:
		a.log.Warn("not enrolled – run: myownpki-agent enroll --token-file FILE")
		return a.Sleep(ctx, notEnrolledLog)
	case res.Admitted():
		return nil
	case res.State == agentv1.EnrollState_ENROLL_STATE_DENIED || res.State == agentv1.EnrollState_ENROLL_STATE_EXPIRED:
		a.log.Error("enrollment ended", slog.String("state", res.State.String()), slog.String("message", res.Message))
		return a.Sleep(ctx, notEnrolledLog)
	}
	a.log.Info("enrollment waits", slog.String("state", res.State.String()), slog.String("message", res.Message))
	return a.Sleep(ctx, jitter(pollEvery))
}

// enrollAgain: the agent certificate expired. An open enrollment is polled,
// otherwise a new one starts with the key of the last certificate.
func (a *Agent) enrollAgain(ctx context.Context) error {
	if e, err := a.st.enrollment(); err == nil && e.Again {
		res, perr := a.Poll(ctx)
		if perr != nil || res == nil || res.Admitted() {
			return perr
		}
		return a.Sleep(ctx, jitter(pollEvery))
	}
	res, err := a.Enroll(ctx, "")
	if err != nil {
		return err
	}
	if !res.Admitted() {
		a.log.Warn("enrolling again waits", slog.String("state", res.State.String()), slog.String("message", res.Message))
		return a.Sleep(ctx, jitter(pollEvery))
	}
	return nil
}

// renew gets a new certificate for a new key over the current one.
func (a *Agent) renew(ctx context.Context) error {
	key, err := a.st.pendingKey(false)
	if err != nil {
		return err
	}
	csr, err := makeCSR(key, a.cfg.Hostname)
	if err != nil {
		return err
	}
	out, err := a.ch.client.RenewCertificate(ctx, connect.NewRequest(&agentv1.RenewCertificateRequest{CsrDer: csr}))
	if err != nil {
		return explainTLS(err)
	}
	id, err := a.st.install(key, out.Msg.CertificateDer, out.Msg.ChainDer)
	if err != nil {
		return err
	}
	a.ch.use(id)
	a.log.Info("agent certificate renewed", slog.Time("until", id.Leaf.NotAfter))
	return nil
}

// RenewAt is when the agent renews its certificate: at 2/3 of the
// lifetime, up to 10 % of it earlier (r in [0,1) from the caller), so
// agents enrolled together don't renew together.
func RenewAt(leaf *x509.Certificate, r float64) time.Time {
	life := leaf.NotAfter.Sub(leaf.NotBefore)
	return leaf.NotBefore.Add(life * 2 / 3).Add(-time.Duration(r * float64(life) / 10))
}

// jitter is d plus or minus up to a sixth of it.
func jitter(d time.Duration) time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(d/3)+1))
	if err != nil {
		return d
	}
	return d - d/6 + time.Duration(n.Int64())
}

// Status describes the agent for `myownpki-agent status`.
type Status struct {
	Hostname   string
	AgentID    string
	Enrolled   bool
	NotAfter   time.Time
	Serial     string
	Enrollment string // the open enrollment's last message
}

// Status reads the state directory.
func (a *Agent) Status() Status {
	s := Status{Hostname: a.cfg.Hostname, AgentID: a.agentID()}
	if id, err := a.st.identity(); err == nil {
		s.Enrolled, s.NotAfter, s.Serial = true, id.Leaf.NotAfter, fmt.Sprintf("%X", id.Leaf.SerialNumber)
	}
	if e, err := a.st.enrollment(); err == nil {
		s.Enrollment = e.ID + ": " + e.Message
	}
	return s
}

func (a *Agent) saveAgentID(id string) error {
	data, err := json.Marshal(map[string]string{"id": id})
	if err != nil {
		return err
	}
	return writeFile(a.st.path(agentFile), data, 0o600)
}

func (a *Agent) agentID() string {
	data, err := os.ReadFile(a.st.path(agentFile))
	if err != nil {
		return ""
	}
	var m map[string]string
	_ = json.Unmarshal(data, &m)
	return m["id"]
}

func makeCSR(key *ecdsa.PrivateKey, host string) ([]byte, error) {
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: host}}, key)
}

// spkiHash binds the check file to the key, as the server expects.
func spkiHash(key *ecdsa.PrivateKey) string {
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(spki)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Identity returns the agent's current certificate, or nil.
func (a *Agent) Identity() *tls.Certificate { return a.ch.cert.Load() }

// serialFraction is a number in [0,1) from the certificate's serial – the
// jitter stays the same for one certificate (the agent wakes hourly) and
// differs between agents (serials are random).
func serialFraction(leaf *x509.Certificate) float64 {
	sum := sha256.Sum256(leaf.SerialNumber.Bytes())
	return float64(uint16(sum[0])<<8|uint16(sum[1])) / 65536
}
