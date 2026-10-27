package agents

import (
	"errors"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

func TestReportPackageFormat(t *testing.T) {
	t.Parallel()
	for _, format := range []string{"", "deb", "rpm", "tarball"} {
		in := ReportInput{PackageFormat: format, Deployments: []DeploymentReport{{Name: "proxy", State: "deployed"}}}
		if err := validReport(in); err != nil {
			t.Errorf("format %q: %v", format, err)
		}
	}
	for _, format := range []string{"zip", "DEB", "../deb", "deb\x00"} {
		if err := validReport(ReportInput{PackageFormat: format}); !errors.Is(err, ErrInvalid) {
			t.Errorf("format %q accepted: %v", format, err)
		}
	}

	e := newEnv(t, tenant.EnrollAuto)
	caller := agentCaller(t, e, "proxy1.homelab.lan")
	if err := e.s.Report(t.Context(), caller, ReportInput{PackageFormat: "rpm"}); err != nil {
		t.Fatal(err)
	}
	a, err := e.s.GetAgent(t.Context(), testinstance.Console, caller.Agent.ID)
	if err != nil || a.PackageFormat != "rpm" {
		t.Fatalf("stored format %q: %v", a.PackageFormat, err)
	}
	if err = e.s.Report(t.Context(), caller, ReportInput{}); err != nil {
		t.Fatal(err)
	}
	a, err = e.s.GetAgent(t.Context(), testinstance.Console, caller.Agent.ID)
	if err != nil || a.PackageFormat != "tarball" {
		t.Fatalf("legacy report format %q: %v", a.PackageFormat, err)
	}
}
