package server

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/monitor"
)

// TestMonitorJob: a server that stays sealed opens a "sealed" alert after
// 10 minutes, logs it once and keeps it in system.db.
func TestMonitorJob(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	initialized(t, cfg)
	var logs logBuf
	clk := clock.NewFake(t0)
	srv, err := Open(t.Context(), Options{Config: cfg, Log: slog.New(slog.NewJSONHandler(&logs, nil)), Clock: clk, Hostname: "pki01", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(t.Context()) }()
	if !srv.Sealed() {
		t.Fatal("not sealed")
	}
	if eerr := srv.evaluateAlerts(t.Context()); eerr != nil {
		t.Fatal(eerr)
	}
	if open, _ := srv.Alerts().Open(t.Context()); len(open) != 0 {
		t.Fatalf("alerts right after the start: %+v", open)
	}
	clk.Advance(11 * time.Minute)
	for range 2 {
		if eerr := srv.evaluateAlerts(t.Context()); eerr != nil {
			t.Fatal(eerr)
		}
	}
	open, err := srv.Alerts().Open(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 || open[0].Kind != monitor.KindSealed || open[0].Severity != monitor.Warning {
		t.Fatalf("open alerts: %+v", open)
	}
	if n := strings.Count(logs.String(), `"msg":"alert","state":"opened","kind":"sealed"`); n != 1 {
		t.Errorf("logged %d times:\n%s", n, logs.String())
	}
}
