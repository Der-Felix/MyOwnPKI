package web

import (
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/monitor"
	"github.com/Der-Felix/MyOwnPKI/internal/web/view"
)

func TestAlertsOnTheDashboard(t *testing.T) {
	t.Parallel()
	open := []monitor.Alert{
		{Kind: monitor.KindAgentSilent, Severity: monitor.Warning, Detail: "silent"},
		{Kind: monitor.KindDeployFailed, Severity: monitor.Warning, Detail: "failed"},
		{Kind: monitor.KindCertExpiry, Severity: monitor.Warning, Detail: "soon"},
		{Kind: monitor.KindCertExpiry, Severity: monitor.Critical, Detail: "expired"},
		{Kind: monitor.KindCRL, Severity: monitor.Critical, Detail: "crl"},
		{Kind: monitor.KindCAExpiry, Severity: monitor.Warning, Detail: "ca"},
	}
	got := alertMessages(open)
	want := []string{"silent", "failed", "expired"}
	if len(got) != len(want) {
		t.Fatalf("messages: %+v", got)
	}
	for i, m := range got {
		if m.Text != want[i] {
			t.Errorf("message %d = %q, want %q", i, m.Text, want[i])
		}
	}
	if got[2].Kind != view.MessageError || got[0].Kind != view.MessageWarning {
		t.Errorf("kinds: %+v", got)
	}
	if n := alertNumber(open); n.Value != "6" || n.Status != view.StatusCrit {
		t.Errorf("number: %+v", n)
	}
	if n := alertNumber(open[:1]); n.Status != view.StatusWarn {
		t.Errorf("warnings only: %+v", n)
	}
	if n := alertNumber(nil); n.Value != "0" || n.Status != "" {
		t.Errorf("none: %+v", n)
	}
}
