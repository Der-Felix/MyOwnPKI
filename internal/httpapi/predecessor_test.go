package httpapi

import (
	"net/http"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

func TestRenewalLegacyPointerAndPlanBounds(t *testing.T) {
	t.Parallel()
	v := newEnv(t)
	v.unseal(t)
	admin := v.client("192.0.2.1")
	admin.signIn(t, "demo", v.demoPass)
	issue := func(name string) string {
		t.Helper()
		issued, err := v.in.Engine.Issue(t.Context(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{name}, Who: testinstance.Console})
		if err != nil {
			t.Fatal(err)
		}
		return issued.ID
	}
	for _, tc := range []struct {
		name, wantStatus string
		body             any
		planned          bool
	}{
		{name: "legacy-false.homelab.lan", body: map[string]any{"revoke_previous": false}, wantStatus: ca.CertValid},
		{name: "legacy-true.homelab.lan", body: map[string]any{"revoke_previous": true}, wantStatus: ca.CertRevoked},
		{name: "legacy-omitted.homelab.lan", body: map[string]any{}, wantStatus: ca.CertValid, planned: true},
	} {
		id := issue(tc.name)
		response := admin.do(t, http.MethodPost, "/certificates/"+id+"/renew", tc.body)
		if response.Code != http.StatusCreated {
			t.Fatalf("%s renewal: %d %s", tc.name, response.Code, response.Body.String())
		}
		info, err := v.in.Engine.Certificate(t.Context(), testinstance.Console, id)
		if err != nil || info.Status != tc.wantStatus || (info.RevocationPlannedAt != nil) != tc.planned {
			t.Errorf("%s: %+v, %v", tc.name, info, err)
		}
	}

	id := issue("plan-bounds.homelab.lan")
	response := admin.do(t, http.MethodPut, "/certificates/"+id+"/revocation-plan", map[string]any{"planned_at": v.clk.Now().Add(31 * 24 * time.Hour).Format(time.RFC3339)})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("31-day plan: %d %s", response.Code, response.Body.String())
	}
}
