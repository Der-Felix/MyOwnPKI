package server

import (
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/tlsscan"
)

// TestEndpointAdminIsWired: the REST API and the UI get the endpoint service
// together with the assessment the alerts use.
func TestEndpointAdminIsWired(t *testing.T) {
	t.Parallel()
	r := newScanRig(t)
	if r.srv.EndpointAdmin() == nil || r.srv.endpointAdmin() == nil {
		t.Fatal("the endpoint service is not wired")
	}
	states, err := r.srv.EndpointAdmin().List(t.Context(), console)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || states[0].Endpoint.ID != r.endpoint || states[0].Assessment.State != tlsscan.StatePending {
		t.Fatalf("states: %+v", states)
	}
	if r.srv.EndpointAdmin().Settings().Off() {
		t.Error("scanning is off in the test configuration")
	}
}
