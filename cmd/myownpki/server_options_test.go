package main

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/version"
)

// TestServerOptionsRelease: the agent listener names its packages after
// Options.Release, so the real server must pass the bare version there – in
// v0.3.1 it got only the full version line and every download was a 404.
func TestServerOptionsRelease(t *testing.T) {
	t.Parallel()
	opt := serverOptions(config.Config{}, slog.New(slog.DiscardHandler))
	info := version.Get()
	if opt.Release != info.Version {
		t.Errorf("Release = %q, want the bare version %q", opt.Release, info.Version)
	}
	if strings.ContainsAny(opt.Release, " ()") {
		t.Errorf("Release %q is not a bare version", opt.Release)
	}
	if opt.Version != info.String(binary) {
		t.Errorf("Version = %q, want the full version line", opt.Version)
	}
}
