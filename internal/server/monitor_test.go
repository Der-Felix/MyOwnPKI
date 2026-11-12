package server

import (
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/monitor"
	"github.com/Der-Felix/MyOwnPKI/internal/notify"
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

// hookReceiver is a webhook receiver over TLS; it returns the config
// section and a function that lists the received digests.
func hookReceiver(t *testing.T, secret string) (config.Webhook, func() []notify.Digest) {
	t.Helper()
	var (
		mu  sync.Mutex
		got []notify.Digest
	)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get(notify.SignatureHeader) != notify.Sign([]byte(secret), body) {
			http.Error(w, "bad signature", http.StatusUnauthorized)
			return
		}
		d, err := notify.ParseDigest(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		got = append(got, d)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(ts.Close)
	dir := t.TempDir()
	ca, sec := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "secret")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sec, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.Webhook{URL: ts.URL + "/hook", SecretFile: sec, CAFile: ca}, func() []notify.Digest {
		mu.Lock()
		defer mu.Unlock()
		return append([]notify.Digest(nil), got...)
	}
}

// TestMonitorNotifies: a sealed server sends one signed webhook after 10
// minutes, nothing more while nothing changes, and one when it is unsealed.
func TestMonitorNotifies(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	passphrase := initialized(t, cfg)
	hook, received := hookReceiver(t, "hmac-key")
	cfg.Notify.Webhook = hook
	clk := clock.NewFake(t0)
	srv, err := Open(t.Context(), Options{Config: cfg, Log: slog.New(slog.DiscardHandler), Clock: clk, Hostname: "pki01", Version: "test", Release: "0.3.3"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Shutdown(t.Context()) }()
	run := func() {
		t.Helper()
		if eerr := srv.evaluateAlerts(t.Context()); eerr != nil {
			t.Fatal(eerr)
		}
	}
	run()
	clk.Advance(11 * time.Minute)
	run()
	clk.Advance(time.Minute)
	run()
	got := received()
	if len(got) != 1 || got[0].Server != "pki01" || len(got[0].Events) != 1 || got[0].Events[0].Kind != monitor.KindSealed || got[0].Events[0].State != notify.Opened {
		t.Fatalf("webhooks while sealed: %+v", got)
	}
	if uerr := srv.Unseal(t.Context(), []byte(passphrase), console); uerr != nil {
		t.Fatal(uerr)
	}
	clk.Advance(time.Minute)
	run()
	got = received()
	if len(got) != 2 || got[1].Events[0].State != notify.Resolved {
		t.Fatalf("webhooks after the unseal: %+v", got)
	}
}

func TestUILink(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	if uiLink(cfg) != nil {
		t.Error("a link without admin.tls_names")
	}
	cfg.Admin.TLSNames = "192.0.2.10, pki.homelab.lan"
	if l := uiLink(cfg); l == nil || l("/alerts") != "https://pki.homelab.lan:9443/alerts" {
		t.Errorf("link with names")
	}
	cfg.Admin.TLSNames, cfg.Admin.Listen = "2001:db8::10", "[::]:8443"
	if l := uiLink(cfg); l == nil || l("/") != "https://[2001:db8::10]:8443/" {
		t.Errorf("link with an IPv6 address")
	}
}
