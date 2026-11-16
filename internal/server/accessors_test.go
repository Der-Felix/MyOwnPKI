package server

import (
	"context"

	"github.com/Der-Felix/MyOwnPKI/internal/monitor"
	"github.com/Der-Felix/MyOwnPKI/internal/tlsscan"
)

// Accessors that only the tests of this package use (the binaries read the
// same fields directly). They live here, not in server.go, so that
// `task deadcode` reports nothing for them.

// AgentAddr is "" while the agent listener is off; else its address (tests
// use port 0).
func (s *Server) AgentAddr() string {
	if s.agent == nil || s.agent.ln == nil {
		return ""
	}
	return s.agent.ln.Addr().String()
}

// ACMEAddr is "" when ACME is off; else the listener's address (tests use port 0).
func (s *Server) ACMEAddr() string {
	if s.acmeLn == nil {
		return ""
	}
	return s.acmeLn.Addr().String()
}

// Sealed reports the seal state.
func (s *Server) Sealed() bool { return s.ring.Status().Sealed }

// Endpoints is the TLS scan endpoint service.
func (s *Server) Endpoints() *tlsscan.Service {
	if s.scan == nil {
		return nil
	}
	return s.scan.svc
}

// EndpointStates is every TLS endpoint with its assessed state, the same one
// the scan alerts follow. Without monitoring it returns nothing.
func (s *Server) EndpointStates(ctx context.Context) ([]monitor.EndpointState, error) {
	if s.monitor == nil {
		return nil, nil
	}
	return s.monitor.eval.EndpointStates(ctx, s.clk.Now())
}
