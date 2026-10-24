package agents

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"connectrpc.com/connect"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	agentv1 "github.com/Der-Felix/MyOwnPKI/internal/gen/myownpki/agent/v1"
	"github.com/Der-Felix/MyOwnPKI/internal/gen/myownpki/agent/v1/agentv1connect"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
)

// maxMessage bounds every request of an agent (a CSR is the largest part).
const maxMessage = 64 << 10

// Handler returns the Connect-RPC handler of the agent listener: only the
// AgentService path, every other path 404. The peer's address and
// certificate come from the TLS connection – never from a header.
func (s *Service) Handler() http.Handler {
	path, h := agentv1connect.NewAgentServiceHandler(&rpc{s: s}, connect.WithReadMaxBytes(maxMessage))
	mux := http.NewServeMux()
	mux.Handle(path, h)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "TLS only", http.StatusForbidden)
			return
		}
		p := peer{}
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			p.ip = host
		}
		if len(r.TLS.PeerCertificates) > 0 {
			p.cert = r.TLS.PeerCertificates[0]
		}
		mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), peerKey{}, p)))
	})
}

type peerKey struct{}

type peer struct {
	ip   string
	cert *x509.Certificate // verified against the agent CA by the TLS handshake
}

func peerOf(ctx context.Context) peer {
	p, _ := ctx.Value(peerKey{}).(peer)
	return p
}

// rpc implements AgentService.
type rpc struct {
	agentv1connect.UnimplementedAgentServiceHandler
	s *Service
}

func (r *rpc) Enroll(ctx context.Context, req *connect.Request[agentv1.EnrollRequest]) (*connect.Response[agentv1.EnrollResponse], error) {
	m := req.Msg
	method := ""
	switch m.GetCheckMethod() {
	case agentv1.CheckMethod_CHECK_METHOD_STANDALONE:
		method = MethodStandalone
	case agentv1.CheckMethod_CHECK_METHOD_WEBROOT:
		method = MethodWebroot
	case agentv1.CheckMethod_CHECK_METHOD_UNSPECIFIED: // refused by the service
	}
	out, err := r.s.Enroll(ctx, EnrollInput{
		Hostname: m.GetHostname(), Token: m.GetJoinToken(), Method: method, OS: m.GetOs(), Arch: m.GetArch(),
		Version: m.GetAgentVersion(), SourceIP: peerOf(ctx).ip, CSRDER: m.GetCsrDer(),
	})
	if err != nil {
		return nil, r.s.rpcError("Enroll", err)
	}
	return connect.NewResponse(&agentv1.EnrollResponse{EnrollmentId: out.ID, Handle: out.Handle, CheckToken: out.CheckToken}), nil
}

func (r *rpc) EnrollStatus(ctx context.Context, req *connect.Request[agentv1.EnrollStatusRequest]) (*connect.Response[agentv1.EnrollStatusResponse], error) {
	st, err := r.s.EnrollStatus(ctx, StatusInput{
		ID: req.Msg.GetEnrollmentId(), Handle: req.Msg.GetHandle(), CheckReady: req.Msg.GetCheckReady(), SourceIP: peerOf(ctx).ip,
	})
	if err != nil {
		return nil, r.s.rpcError("EnrollStatus", err)
	}
	return connect.NewResponse(&agentv1.EnrollStatusResponse{
		State: enrollState(st.State), Message: st.Message, AgentId: st.AgentID, TokenValid: st.TokenValid,
		CheckPassed: st.CheckPassed, CertificateDer: st.CertDER, ChainDer: st.Chain,
	}), nil
}

func (r *rpc) RenewCertificate(ctx context.Context, req *connect.Request[agentv1.RenewCertificateRequest]) (*connect.Response[agentv1.RenewCertificateResponse], error) {
	c, err := r.caller(ctx)
	if err != nil {
		return nil, err
	}
	der, chain, err := r.s.RenewCertificate(ctx, c, req.Msg.GetCsrDer())
	if err != nil {
		return nil, r.s.rpcError("RenewCertificate", err)
	}
	return connect.NewResponse(&agentv1.RenewCertificateResponse{CertificateDer: der, ChainDer: chain}), nil
}

// caller authenticates a procedure that needs an agent certificate – per
// request (docs/PHASE3.md §2).
func (r *rpc) caller(ctx context.Context) (*Caller, error) {
	p := peerOf(ctx)
	if p.cert == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("this procedure needs an agent certificate – enroll first"))
	}
	c, err := r.s.Identify(ctx, p.cert, p.ip)
	if err != nil {
		return nil, r.s.rpcError("identify", err)
	}
	return c, nil
}

func enrollState(s string) agentv1.EnrollState {
	switch s {
	case StateWaitingForCheck:
		return agentv1.EnrollState_ENROLL_STATE_WAITING_FOR_CHECK
	case StatePending:
		return agentv1.EnrollState_ENROLL_STATE_PENDING_APPROVAL
	case StateWaitingForUnseal:
		return agentv1.EnrollState_ENROLL_STATE_WAITING_FOR_UNSEAL
	case StateAdmitted:
		return agentv1.EnrollState_ENROLL_STATE_ADMITTED
	case StateDenied:
		return agentv1.EnrollState_ENROLL_STATE_DENIED
	case StateExpired:
		return agentv1.EnrollState_ENROLL_STATE_EXPIRED
	}
	return agentv1.EnrollState_ENROLL_STATE_UNSPECIFIED
}

// rpcError maps service errors to Connect codes. What the agent may fix
// comes back with its text; anything else is logged here and answered
// without details.
func (s *Service) rpcError(proc string, err error) error {
	var d *ca.DeniedError
	switch {
	case errors.Is(err, ErrInvalid):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, ErrNotFound):
		return connect.NewError(connect.CodeNotFound, errors.New("no such enrollment"))
	case errors.Is(err, ErrQueueFull), errors.Is(err, ErrRateLimited):
		return connect.NewError(connect.CodeResourceExhausted, err)
	case errors.Is(err, ErrUnknownAgent):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, keys.ErrSealed):
		return connect.NewError(connect.CodeUnavailable, errors.New("the server is sealed – try again after the unseal"))
	case errors.Is(err, ErrConflict), errors.As(err, &d), errors.Is(err, errNoAgentCA):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	}
	s.Log.Error("agent request failed", slog.String("procedure", proc), slog.Any("error", err))
	return connect.NewError(connect.CodeInternal, errors.New("the server failed – its log has the details"))
}

// ClientCAs are the certificates of the agent CA – every generation that is
// valid at now: the only anchors of the listener's client authentication.
func (s *Service) ClientCAs(ctx context.Context, now time.Time) (*x509.CertPool, int, error) {
	q := pkidb.New(s.PKI)
	row, err := q.GetCAByName(ctx, s.CA)
	if err != nil {
		return nil, 0, err
	}
	gens, err := q.ListCAGenerations(ctx, row.ID)
	if err != nil {
		return nil, 0, err
	}
	pool := x509.NewCertPool()
	n := 0
	for _, g := range gens {
		if len(g.CertDer) == 0 {
			continue
		}
		c, err := x509.ParseCertificate(g.CertDer)
		if err != nil || now.After(c.NotAfter) || now.Before(c.NotBefore) {
			continue
		}
		pool.AddCert(c)
		n++
	}
	return pool, n, nil
}
