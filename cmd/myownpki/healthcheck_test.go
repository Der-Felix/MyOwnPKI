package main

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestHealthcheck runs against a TLS stand-in for the admin listener: ok
// with the pinned certificate and "ok", unhealthy otherwise.
func TestHealthcheck(t *testing.T) {
	t.Parallel()
	body := "ok\n"
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, body)
	}))
	ts.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	ts.StartTLS()
	t.Cleanup(ts.Close)

	_, cfg := e2eConfig(t, filepath.Join(t.TempDir(), "data"))
	cfg.Admin.Listen = strings.TrimPrefix(ts.URL, "https://")
	certFile := filepath.Join(cfg.DataDir, "tls", "admin-bootstrap.crt")
	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := healthcheck(t.Context(), cfg, time.Second); err == nil || !strings.Contains(err.Error(), "admin certificate") {
		t.Errorf("without the certificate file: %v", err)
	}
	served := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	if err := os.WriteFile(certFile, served, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := healthcheck(t.Context(), cfg, time.Second); err != nil {
		t.Errorf("healthy: %v", err)
	}
	// admin.tls_issuer: the server serves the bootstrap or the issued
	// certificate (admin.crt, missing until the first unseal) – either passes.
	issued := cfg
	issued.Admin.TLSIssuer, issued.Admin.TLSNames = "issuing", "pki.homelab.lan"
	if err := healthcheck(t.Context(), issued, time.Second); err != nil {
		t.Errorf("issued certificate not there yet, bootstrap served: %v", err)
	}
	other := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not the served one")})
	if err := os.WriteFile(certFile, other, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.DataDir, "tls", "admin.crt"), served, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := healthcheck(t.Context(), issued, time.Second); err != nil {
		t.Errorf("issued certificate served: %v", err)
	}
	if err := healthcheck(t.Context(), cfg, time.Second); err == nil || !strings.Contains(err.Error(), "serves another certificate") {
		t.Errorf("without admin.tls_issuer the issued file doesn't count: %v", err)
	}
	if err := os.WriteFile(certFile, served, 0o600); err != nil {
		t.Fatal(err)
	}
	body = "sealed\n"
	if err := healthcheck(t.Context(), cfg, time.Second); err == nil || !strings.Contains(err.Error(), `"sealed\n"`) {
		t.Errorf("wrong answer: %v", err)
	}
	ts.Close()
	if err := healthcheck(t.Context(), cfg, time.Second); err == nil || !strings.Contains(err.Error(), "allowed_networks") {
		t.Errorf("nothing listening: %v", err)
	}
}

func TestHealthcheckCommand(t *testing.T) {
	t.Parallel()
	cfgFile, _ := e2eConfig(t, filepath.Join(t.TempDir(), "data"))
	var out bytes.Buffer
	if code := runHealthcheck(t.Context(), []string{"--config", cfgFile, "extra"}, &out, &out); code != exitUsage {
		t.Errorf("an argument: %d", code)
	}
	out.Reset()
	if code := runHealthcheck(t.Context(), []string{"--config", cfgFile, "--timeout", "1s"}, &out, &out); code != exitProblem || !strings.HasPrefix(out.String(), "unhealthy: ") {
		t.Errorf("no server: %d %s", code, out.String())
	}
}

func TestLocalAddr(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		":9443": "127.0.0.1:9443", "0.0.0.0:9443": "127.0.0.1:9443", "[::]:9443": "[::1]:9443",
		"192.0.2.10:9443": "192.0.2.10:9443", "127.0.0.1:9443": "127.0.0.1:9443",
	} {
		if got, err := localAddr(in); err != nil || got != want {
			t.Errorf("localAddr(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}
