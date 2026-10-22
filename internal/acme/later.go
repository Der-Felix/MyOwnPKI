package acme

import "net/http"

// renewalInfo (step 12) follows in its own step.

func (s *Server) renewalInfo(w http.ResponseWriter, _ *http.Request) {
	s.problem(w, http.StatusNotImplemented, "malformed", "renewalInfo is not available yet", nil)
}
