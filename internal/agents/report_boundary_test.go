package agents

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/tenant"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

// boundaryReport is a report that is accepted; every row of the table below
// changes one field of it.
func boundaryReport() ReportInput {
	return ReportInput{Version: "0.3.8", OS: "linux", Arch: "amd64", PackageFormat: "deb",
		Deployments: []DeploymentReport{{Name: "proxy", State: "deployed"}}}
}

func rep(n int, s string) string { return strings.Repeat(s, n) }

// TestReportLimitsAtTheBoundary: what the limits of validReport allow is
// accepted to the last byte and refused one beyond. The limits are the ones
// of docs/PHASE3.md (100 names, 253 characters a name, 64 hex digits).
// Lengths count bytes, so a multi-byte character costs more than one.
func TestReportLimitsAtTheBoundary(t *testing.T) {
	t.Parallel()
	hex64 := rep(64, "a")
	tests := []struct {
		name string
		mod  func(*ReportInput)
		ok   bool
	}{
		{"version 64 bytes", func(in *ReportInput) { in.Version = rep(64, "v") }, true},
		{"version 65 bytes", func(in *ReportInput) { in.Version = rep(65, "v") }, false},
		{"version 32 two-byte characters", func(in *ReportInput) { in.Version = rep(32, "ä") }, true},
		{"version 33 two-byte characters", func(in *ReportInput) { in.Version = rep(33, "ä") }, false},
		{"os 32 bytes", func(in *ReportInput) { in.OS = rep(32, "o") }, true},
		{"os 33 bytes", func(in *ReportInput) { in.OS = rep(33, "o") }, false},
		{"arch 32 bytes", func(in *ReportInput) { in.Arch = rep(32, "a") }, true},
		{"arch 33 bytes", func(in *ReportInput) { in.Arch = rep(33, "a") }, false},
		{"empty version, os and arch", func(in *ReportInput) { in.Version, in.OS, in.Arch = "", "", "" }, true},
		{"a NUL in the version", func(in *ReportInput) { in.Version = "0.3\x008" }, false},
		{"invalid UTF-8 in the os", func(in *ReportInput) { in.OS = "li\xffnux" }, false},
		{"package format deb", func(in *ReportInput) { in.PackageFormat = "deb" }, true},
		{"package format rpm", func(in *ReportInput) { in.PackageFormat = "rpm" }, true},
		{"package format tarball", func(in *ReportInput) { in.PackageFormat = "tarball" }, true},
		{"package format empty", func(in *ReportInput) { in.PackageFormat = "" }, true},
		{"package format zip", func(in *ReportInput) { in.PackageFormat = "zip" }, false},
		{"package format in capitals", func(in *ReportInput) { in.PackageFormat = "DEB" }, false},

		{"101 deployments", func(in *ReportInput) { in.Deployments = distinctDeployments(MaxReportDeployments) }, true},
		{"102 deployments", func(in *ReportInput) { in.Deployments = distinctDeployments(MaxReportDeployments + 1) }, false},
		{"no deployments", func(in *ReportInput) { in.Deployments = nil }, true},
		{"the same deployment twice", func(in *ReportInput) { in.Deployments = append(in.Deployments, in.Deployments[0]) }, false},

		{"deployment name of 1 character", func(in *ReportInput) { in.Deployments[0].Name = "a" }, true},
		{"deployment name of 64 characters", func(in *ReportInput) { in.Deployments[0].Name = "a" + rep(62, "b") + "c" }, true},
		{"deployment name of 65 characters", func(in *ReportInput) { in.Deployments[0].Name = "a" + rep(63, "b") + "c" }, false},
		{"deployment name with an inner dash", func(in *ReportInput) { in.Deployments[0].Name = "web-proxy-2" }, true},
		{"deployment name starting with a dash", func(in *ReportInput) { in.Deployments[0].Name = "-proxy" }, false},
		{"deployment name ending with a dash", func(in *ReportInput) { in.Deployments[0].Name = "proxy-" }, false},
		{"deployment name in capitals", func(in *ReportInput) { in.Deployments[0].Name = "Proxy" }, false},
		{"deployment name with a dot", func(in *ReportInput) { in.Deployments[0].Name = "a.b" }, false},
		{"deployment name with a path", func(in *ReportInput) { in.Deployments[0].Name = "../x" }, false},
		{"empty deployment name", func(in *ReportInput) { in.Deployments[0].Name = "" }, false},

		{"profile 32 bytes", func(in *ReportInput) { in.Deployments[0].Profile = rep(32, "p") }, true},
		{"profile 33 bytes", func(in *ReportInput) { in.Deployments[0].Profile = rep(33, "p") }, false},
		{"challenge 32 bytes", func(in *ReportInput) { in.Deployments[0].Challenge = rep(32, "c") }, true},
		{"challenge 33 bytes", func(in *ReportInput) { in.Deployments[0].Challenge = rep(33, "c") }, false},

		{"state pending", func(in *ReportInput) { in.Deployments[0].State = "pending" }, true},
		{"state failed", func(in *ReportInput) { in.Deployments[0].State = "failed" }, true},
		{"state rolled_back", func(in *ReportInput) { in.Deployments[0].State = "rolled_back" }, true},
		{"state empty", func(in *ReportInput) { in.Deployments[0].State = "" }, false},
		{"state in capitals", func(in *ReportInput) { in.Deployments[0].State = "Deployed" }, false},
		{"state with a space", func(in *ReportInput) { in.Deployments[0].State = "deployed " }, false},

		{"100 names", func(in *ReportInput) { in.Deployments[0].Names = make([]string, 100) }, true},
		{"101 names", func(in *ReportInput) { in.Deployments[0].Names = make([]string, 101) }, false},
		{"a name of 253 bytes", func(in *ReportInput) { in.Deployments[0].Names = []string{rep(253, "n")} }, true},
		{"a name of 254 bytes", func(in *ReportInput) { in.Deployments[0].Names = []string{rep(254, "n")} }, false},
		{"a name of 126 two-byte characters", func(in *ReportInput) { in.Deployments[0].Names = []string{rep(126, "ä")} }, true},
		{"a name of 127 two-byte characters", func(in *ReportInput) { in.Deployments[0].Names = []string{rep(127, "ä")} }, false},
		{"the last of 100 names too long", func(in *ReportInput) {
			names := make([]string, 100)
			names[99] = rep(254, "n")
			in.Deployments[0].Names = names
		}, false},

		{"error of 1024 bytes", func(in *ReportInput) { in.Deployments[0].LastError = rep(1024, "e") }, true},
		{"error of 1025 bytes", func(in *ReportInput) { in.Deployments[0].LastError = rep(1025, "e") }, false},
		{"error of 512 two-byte characters", func(in *ReportInput) { in.Deployments[0].LastError = rep(512, "ä") }, true},
		{"error of 513 two-byte characters", func(in *ReportInput) { in.Deployments[0].LastError = rep(513, "ä") }, false},

		{"serial of 64 hex digits", func(in *ReportInput) { in.Deployments[0].Serial = hex64 }, true},
		{"serial of 66 hex digits", func(in *ReportInput) { in.Deployments[0].Serial = rep(66, "a") }, false},
		{"serial of 63 hex digits (odd)", func(in *ReportInput) { in.Deployments[0].Serial = rep(63, "a") }, false},
		{"serial of 1 hex digit (odd)", func(in *ReportInput) { in.Deployments[0].Serial = "a" }, false},
		{"serial of 2 hex digits", func(in *ReportInput) { in.Deployments[0].Serial = "0A" }, true},
		{"serial in capitals", func(in *ReportInput) { in.Deployments[0].Serial = rep(64, "A") }, true},
		{"serial that isn't hex", func(in *ReportInput) { in.Deployments[0].Serial = "0g" }, false},
		{"serial with a prefix", func(in *ReportInput) { in.Deployments[0].Serial = "0x0a" }, false},
		{"fingerprint of 64 hex digits", func(in *ReportInput) { in.Deployments[0].Fingerprint = hex64 }, true},
		{"fingerprint of 62 hex digits", func(in *ReportInput) { in.Deployments[0].Fingerprint = rep(62, "a") }, false},
		{"fingerprint of 66 hex digits", func(in *ReportInput) { in.Deployments[0].Fingerprint = rep(66, "a") }, false},
		{"fingerprint that isn't hex", func(in *ReportInput) { in.Deployments[0].Fingerprint = rep(64, "z") }, false},
		{"written fingerprint of 64 hex digits", func(in *ReportInput) { in.Deployments[0].WrittenFingerprint = hex64 }, true},
		{"written fingerprint of 62 hex digits", func(in *ReportInput) { in.Deployments[0].WrittenFingerprint = rep(62, "a") }, false},
		{"written fingerprint of 66 hex digits", func(in *ReportInput) { in.Deployments[0].WrittenFingerprint = rep(66, "a") }, false},

		{"notAfter of 35 characters", func(in *ReportInput) { in.Deployments[0].NotAfter = "2026-10-13T08:00:00.123456789+01:00" }, true},
		{"notAfter of 36 characters", func(in *ReportInput) { in.Deployments[0].NotAfter = "2026-10-13T08:00:00.1234567890+01:00" }, false},
		{"notAfter in UTC", func(in *ReportInput) { in.Deployments[0].NotAfter = "2026-10-13T08:00:00Z" }, true},
		{"notAfter without a zone", func(in *ReportInput) { in.Deployments[0].NotAfter = "2026-10-13T08:00:00" }, false},
		{"notAfter as a date", func(in *ReportInput) { in.Deployments[0].NotAfter = "2026-10-13" }, false},
		{"deployedAt in UTC", func(in *ReportInput) { in.Deployments[0].DeployedAt = "2026-10-13T08:00:00Z" }, true},
		{"deployedAt that isn't a time", func(in *ReportInput) { in.Deployments[0].DeployedAt = "yesterday" }, false},

		{"renewal acknowledgement 0", func(in *ReportInput) { in.Deployments[0].HandledRenewalVersion = 0 }, true},
		{"renewal acknowledgement of the largest number", func(in *ReportInput) { in.Deployments[0].HandledRenewalVersion = 1<<63 - 1 }, true},
		{"renewal acknowledgement -1", func(in *ReportInput) { in.Deployments[0].HandledRenewalVersion = -1 }, false},
	}
	for _, tt := range tests {
		in := boundaryReport()
		tt.mod(&in)
		err := validReport(in)
		switch {
		case tt.ok && err != nil:
			t.Errorf("%s: refused: %v", tt.name, err)
		case !tt.ok && !errors.Is(err, ErrInvalid):
			t.Errorf("%s: accepted (%v), want ErrInvalid", tt.name, err)
		}
	}
}

func distinctDeployments(n int) []DeploymentReport {
	out := make([]DeploymentReport, n)
	for i := range out {
		out[i] = DeploymentReport{Name: fmt.Sprintf("d%d", i), State: "pending"}
	}
	return out
}

// TestReportAtEveryLimitIsStoredAsSent: a report with every field at its
// limit is accepted by the service and read back unchanged – nothing is cut
// on the way into the database, and the 101st deployment (the one that is
// drained) fits.
func TestReportAtEveryLimitIsStoredAsSent(t *testing.T) {
	t.Parallel()
	e := newEnv(t, tenant.EnrollAuto)
	caller := agentCaller(t, e, "proxy1.homelab.lan")
	names := make([]string, 100)
	for i := range names {
		names[i] = fmt.Sprintf("%03d%s", i, rep(250, "x")) // 253 bytes
	}
	d := DeploymentReport{
		Name: "a" + rep(62, "b") + "c", Profile: rep(32, "p"), Names: names, Challenge: rep(32, "c"), State: "failed",
		Serial: rep(64, "A"), NotAfter: "2026-10-13T08:00:00.123456789+01:00", Fingerprint: rep(64, "b"),
		DeployedAt: "2026-10-13T08:00:00Z", LastError: rep(1024, "e"), WrittenFingerprint: rep(64, "c"),
	}
	in := ReportInput{Version: rep(64, "v"), OS: rep(32, "o"), Arch: rep(32, "a"), PackageFormat: "rpm", Deployments: []DeploymentReport{d}}
	if err := e.s.Report(t.Context(), caller, in); err != nil {
		t.Fatalf("a report at every limit: %v", err)
	}
	a, err := e.s.GetAgent(t.Context(), testinstance.Console, caller.Agent.ID)
	if err != nil {
		t.Fatal(err)
	}
	if a.Version != in.Version || a.OS != in.OS || a.Arch != in.Arch || a.PackageFormat != "rpm" || len(a.Deployments) != 1 {
		t.Fatalf("agent %+v", a)
	}
	got := a.Deployments[0]
	if got.Name != d.Name || got.Profile != d.Profile || got.Challenge != d.Challenge || got.State != d.State || got.LastError != d.LastError ||
		got.Serial != d.Serial || got.Fingerprint != d.Fingerprint || len(got.Names) != 100 || got.Names[99] != names[99] || len(got.Names[0]) != 253 {
		t.Errorf("stored deployment differs from the report: %+v", got)
	}
	if got.NotAfter.UTC().Format("2006-01-02T15:04:05Z") != "2026-10-13T07:00:00Z" {
		t.Errorf("notAfter %v, want 2026-10-13T07:00:00Z", got.NotAfter)
	}
}
