package acme

import "net/http"

// revokeCert (step 10) and renewalInfo (step 12) follow in their own steps.

func (s *Server) revokeCert(w http.ResponseWriter, _ *http.Request) {
	s.problem(w, http.StatusNotImplemented, "malformed", "revokeCert is not available yet", nil)
}

func (s *Server) renewalInfo(w http.ResponseWriter, _ *http.Request) {
	s.problem(w, http.StatusNotImplemented, "malformed", "renewalInfo is not available yet", nil)
}
