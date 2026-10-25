package agents

import (
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"

	agentv1 "github.com/Der-Felix/MyOwnPKI/internal/gen/myownpki/agent/v1"
	"github.com/Der-Felix/MyOwnPKI/internal/gen/myownpki/agent/v1/agentv1connect"
	"github.com/Der-Felix/MyOwnPKI/internal/store/pkidb"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
)

func assertMissingDomainResult(t *testing.T, e *env, enrollmentID, message string) {
	t.Helper()
	want := "no domain covers outside.example – an admin of the PKI must add one"
	if !strings.Contains(message, want) {
		t.Fatalf("enrollment message lacks the missing-domain explanation: %q", message)
	}
	row, err := pkidb.New(e.s.PKI).GetEnrollment(t.Context(), enrollmentID)
	if err != nil {
		t.Fatal(err)
	}
	if row.CheckState != "failed" || row.CheckError.String != want {
		t.Fatalf("stored check result: state=%q error=%q", row.CheckState, row.CheckError.String)
	}
}

func TestEnrollmentWithoutMatchingDomainFailsClearly(t *testing.T) {
	t.Parallel()
	t.Run("service", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, tenant.EnrollAuto)
		_, csr := newCSR(t)
		out, status := e.enroll(t, "outside.example", "", false, csr)
		if status.State != StatePending || status.CheckPassed {
			t.Fatalf("enrollment state: %+v", status)
		}
		assertMissingDomainResult(t, e, out.ID, status.Message)
	})
	t.Run("rpc", func(t *testing.T) {
		t.Parallel()
		e := newEnv(t, tenant.EnrollAuto)
		server := httptest.NewTLSServer(e.s.Handler())
		t.Cleanup(server.Close)
		client := agentv1connect.NewAgentServiceClient(server.Client(), server.URL)
		_, csr := newCSR(t)
		enrolled, err := client.Enroll(t.Context(), connect.NewRequest(&agentv1.EnrollRequest{Hostname: "outside.example", CheckMethod: agentv1.CheckMethod_CHECK_METHOD_WEBROOT,
			Os: "linux", Arch: "amd64", AgentVersion: "0.3.0", CsrDer: csr}))
		if err != nil {
			t.Fatal(err)
		}
		status, err := client.EnrollStatus(t.Context(), connect.NewRequest(&agentv1.EnrollStatusRequest{EnrollmentId: enrolled.Msg.EnrollmentId,
			Handle: enrolled.Msg.Handle, CheckReady: true}))
		if err != nil {
			t.Fatal(err)
		}
		if status.Msg.State != agentv1.EnrollState_ENROLL_STATE_PENDING_APPROVAL || status.Msg.CheckPassed {
			t.Fatalf("RPC enrollment state: %+v", status.Msg)
		}
		assertMissingDomainResult(t, e, enrolled.Msg.EnrollmentId, status.Msg.Message)
	})
}
