package agent

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentv1 "github.com/Der-Felix/MyOwnPKI/internal/gen/myownpki/agent/v1"
)

func TestSetupRecordsInstalledPackageFormat(t *testing.T) {
	f := newSetupFixture(t, agentv1.EnrollState_ENROLL_STATE_ADMITTED)
	f.opts.PackageFormat = "deb"
	if err := Setup(t.Context(), f.opts); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(f.dir, "state", packageFormatFile))
	if err != nil || string(data) != "deb\n" {
		t.Fatalf("package format: %q %v", data, err)
	}
	cfg, err := LoadConfig(f.opts.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg, slog.New(slog.DiscardHandler), "0.3.1")
	if err != nil {
		t.Fatal(err)
	}
	if a.packageFormat() != "deb" {
		t.Errorf("reported format %q", a.packageFormat())
	}
}

func TestSetupPackageFormatAllowlistAndLegacyDefault(t *testing.T) {
	f := newSetupFixture(t, agentv1.EnrollState_ENROLL_STATE_ADMITTED)
	f.opts.PackageFormat = "zip"
	if err := Setup(t.Context(), f.opts); err == nil || !strings.Contains(err.Error(), "package-format") {
		t.Fatalf("invalid format: %v", err)
	}
	f = newSetupFixture(t, agentv1.EnrollState_ENROLL_STATE_ADMITTED)
	if err := Setup(t.Context(), f.opts); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(f.dir, "state", packageFormatFile))
	if err != nil || string(data) != "tarball\n" {
		t.Fatalf("legacy default: %q %v", data, err)
	}
}
