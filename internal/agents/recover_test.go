package agents

import (
	"bytes"
	"context"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"

	agentv1 "github.com/Der-Felix/MyOwnPKI/internal/gen/myownpki/agent/v1"
	"github.com/Der-Felix/MyOwnPKI/internal/gen/myownpki/agent/v1/agentv1connect"
	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
)

type panicChecker struct{}

func (panicChecker) Check(context.Context, string, string, string, string) error {
	panic("test handler panic")
}

func TestConnectPanicLogsProcedureAndStack(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	var logs bytes.Buffer
	e.s.Log = slog.New(slog.NewJSONHandler(&logs, nil))
	e.s.Checker = panicChecker{}
	server := httptest.NewTLSServer(e.s.Handler())
	t.Cleanup(server.Close)
	client := agentv1connect.NewAgentServiceClient(server.Client(), server.URL)
	_, csr := newCSR(t)
	enrolled, err := client.Enroll(t.Context(), connect.NewRequest(&agentv1.EnrollRequest{Hostname: "proxy1.homelab.lan", CheckMethod: agentv1.CheckMethod_CHECK_METHOD_WEBROOT,
		Os: "linux", Arch: "amd64", AgentVersion: "0.3.0", CsrDer: csr}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.EnrollStatus(t.Context(), connect.NewRequest(&agentv1.EnrollStatusRequest{EnrollmentId: enrolled.Msg.EnrollmentId,
		Handle: enrolled.Msg.Handle, CheckReady: true}))
	if connect.CodeOf(err) != connect.CodeInternal {
		t.Fatalf("panic response: %v", err)
	}
	for _, want := range []string{`"level":"ERROR"`, "agent RPC panic", "test handler panic", "/myownpki.agent.v1.AgentService/EnrollStatus", `"stack"`, "panicChecker.Check"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("panic log lacks %q: %s", want, logs.String())
		}
	}
}
