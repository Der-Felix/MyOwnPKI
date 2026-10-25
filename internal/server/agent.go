package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/acme"
	"github.com/Der-Felix/MyOwnPKI/internal/agents"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

// The agent listener (ADR-08, ADR-10, docs/PHASE3.md §2).
const (
	agentBootstrapCert = "agent-bootstrap.crt"
	agentBootstrapKey  = "agent-bootstrap.key"
	jobAgentCAs        = "agent-cas"
	agentCAsEvery      = time.Minute
)

// agentSide is what the server keeps for the agent listener.
type agentSide struct {
	svc     *agents.Service
	tls     *issuedTLS
	pool    atomic.Pointer[x509.CertPool]
	problem atomic.Pointer[string] // what is wrong with agent.ca; nil = nothing
	hs      *http.Server
	ln      net.Listener
}

// agentBootstrap is the self-signed certificate of the agent listener until
// the server has issued its own: agents refuse it and retry.
func agentBootstrap(cfg config.Config, now time.Time, rnd io.Reader) (*tls.Certificate, CertInfo, error) {
	names, ips := hostNames(config.AgentHost(cfg.Agent.BaseURL))
	return bootstrap(filepath.Join(cfg.DataDir, "tls"), agentBootstrapCert, agentBootstrapKey, "MyOwnPKI agent (bootstrap)",
		"the host of agent.base_url changed", names, ips, now, rnd)
}

// buildAgents wires the agent service (with agent.base_url only).
func (s *Server) buildAgents() error {
	cfg := s.opt.Config
	if !cfg.Agent.Enabled() {
		return nil
	}
	resolver, err := config.ACMEResolver(cfg.ACME.Resolver)
	if err != nil {
		return fmt.Errorf("acme.resolver: %w", err)
	}
	settings := &tenant.Store{DB: s.sys.Read, Clock: s.clk} // only read here
	s.agent = &agentSide{svc: &agents.Service{
		PKI: s.pki.Write, Tenant: store.DefaultTenant, Engine: s.engine, CA: cfg.Agent.CA,
		Mode:    func(ctx context.Context) (string, error) { return settings.AgentEnrollment(ctx, store.DefaultTenant) },
		Checker: acme.NewHTTP01Checker(resolver, s.log), Clock: s.clk, Log: s.log, Wake: s.wakeUp,
	}}
	s.jobs.add(jobAgentCAs, agentCAsEvery, agentCAsEvery, func(ctx context.Context) error { s.refreshAgentCAs(ctx); return nil })
	return nil
}

// refreshAgentCAs reloads the client CAs of the agent listener (a new
// generation of the agent CA counts within a minute) and what is wrong
// with agent.ca, logged when it changes.
func (s *Server) refreshAgentCAs(ctx context.Context) {
	a := s.agent
	problem, err := AgentCAProblem(ctx, s.pki.Read, a.svc.CA)
	if err != nil {
		s.log.Error("agent CA: can't read the CA from the database", slog.Any("error", err))
		return
	}
	old := a.problem.Load()
	switch {
	case problem != "" && (old == nil || *old != problem):
		s.log.Error("agent CA: agents can't enroll", slog.String("problem", problem))
		a.problem.Store(&problem)
	case problem == "" && old != nil:
		s.log.Info("agent CA: fixed", slog.String("ca", a.svc.CA))
		a.problem.Store(nil)
	}
	pool, n, err := a.svc.ClientCAs(ctx, s.clk.Now())
	if err != nil {
		pool = x509.NewCertPool() // no CA: no client certificate passes
	}
	if n == 0 && problem == "" {
		s.log.Warn("agent CA: no valid certificate – no agent certificate passes the listener", slog.String("ca", a.svc.CA))
	}
	a.pool.Store(pool)
}

// agentAttention is what the dashboard shows about the agent listener.
func (s *Server) agentAttention(sealed bool) []view.Message {
	if s.agent == nil {
		return nil
	}
	var out []view.Message
	if p := s.agent.problem.Load(); p != nil {
		out = append(out, view.Message{Kind: view.MessageError, Text: "Agents can't enroll: " + *p + "."})
	}
	if s.agent.tls != nil {
		out = append(out, s.agent.tls.attention(sealed)...)
	}
	return out
}

// listenAgents opens the agent listener: TLS 1.3, the issued certificate,
// client authentication against the agent CA only (VerifyClientCertIfGiven:
// a certificate from any other CA fails the handshake; without one only
// Enroll and EnrollStatus answer – the service checks every other call).
func (s *Server) listenAgents(ctx context.Context, lc *net.ListenConfig) error {
	a := s.agent
	raw, err := lc.Listen(ctx, "tcp", s.opt.Config.Agent.Listen)
	if err != nil {
		return fmt.Errorf("agent listener %s: %w", s.opt.Config.Agent.Listen, err)
	}
	s.refreshAgentCAs(ctx)
	base := &tls.Config{
		MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: a.tls.GetCertificate, ClientAuth: tls.VerifyClientCertIfGiven,
	}
	cfg := base.Clone()
	cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		c := base.Clone()
		c.ClientCAs = a.pool.Load()
		return c, nil
	}
	a.ln = tls.NewListener(raw, cfg)
	a.hs = &http.Server{
		Handler: a.svc.Handler(),
		// WriteTimeout leaves room for the http-01 check inside a call and
		// for the long-poll of the desired state (at most 50 s, step 8a).
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 75 * time.Second, IdleTimeout: 120 * time.Second,
		MaxHeaderBytes: 16 << 10, ErrorLog: slog.NewLogLogger(httpErrorLogHandler{Handler: s.log.Handler()}, slog.LevelDebug),
	}
	s.log.Info("agents listening", slog.String("listen", "https://"+a.ln.Addr().String()), slog.String("base_url", s.opt.Config.Agent.BaseURL),
		slog.String("agent_ca", a.svc.CA))
	return nil
}

// AgentAddr is "" while the agent listener is off; else its address (tests
// use port 0).
func (s *Server) AgentAddr() string {
	if s.agent == nil || s.agent.ln == nil {
		return ""
	}
	return s.agent.ln.Addr().String()
}

// Agents is the agent service, nil while agents are off.
func (s *Server) Agents() *agents.Service {
	if s.agent == nil {
		return nil
	}
	return s.agent.svc
}
