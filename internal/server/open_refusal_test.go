package server

import (
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/config"
)

// TestOpenRefusesBadSettings: build and its helpers refuse a setting they
// can't use with a message that names the key, and a refused start leaves the
// data directory usable (the databases are closed, nothing half-built).
// Config validation catches most of these first; Open is the second line.
func TestOpenRefusesBadSettings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		edit func(c *config.Config)
		want string
	}{
		{"passkey origin over plain http", func(c *config.Config) { c.Auth.PasskeyOrigin = "http://pki.homelab.lan:9443" }, "passkeys need https"},
		{"passkey origin with an IP address", func(c *config.Config) { c.Auth.PasskeyOrigin = "https://192.0.2.10:9443" }, "host name, not an IP address"},
		{"passkey origin without a scheme", func(c *config.Config) { c.Auth.PasskeyOrigin = "pki.homelab.lan:9443" }, "auth.passkey_origin"},
		{"passkey origin with a path", func(c *config.Config) { c.Auth.PasskeyOrigin = "https://pki.homelab.lan/admin" }, "only scheme, host and port"},
		{"ACME base URL over http", func(c *config.Config) { c.ACME.BaseURL = "http://pki.homelab.lan/acme" }, "must be https://"},
		{"ACME base URL without a host", func(c *config.Config) { c.ACME.BaseURL = "https:///acme" }, "want https://host"},
		{"ACME trusted proxies that are no network", func(c *config.Config) {
			c.ACME.BaseURL, c.ACME.TrustedProxies = "https://pki.homelab.lan/acme", "10.0.0.0/33"
		}, "acme.trusted_proxies"},
		{"ACME resolver that is a name", func(c *config.Config) {
			c.ACME.BaseURL, c.ACME.Resolver = "https://pki.homelab.lan/acme", "dns.homelab.lan"
		}, "acme.resolver"},
		{"a resolver that is a name, ACME off", func(c *config.Config) { c.ACME.Resolver = "dns.homelab.lan" }, "acme.resolver"},
		{"a resolver with port 0, agents on", func(c *config.Config) {
			c.Agent.BaseURL, c.ACME.Resolver = "https://pki.homelab.lan:8444", "192.0.2.53:0"
		}, "acme.resolver"},
		{"expiry days that are not a pair", func(c *config.Config) { c.Monitor.ExpiryDays = "soon" }, "monitor.expiry_days"},
		{"expiry days the wrong way round", func(c *config.Config) { c.Monitor.ExpiryDays = "3, 14" }, "monitor.expiry_days"},
		{"a sealed_after that is no duration", func(c *config.Config) { c.Monitor.SealedAfter = "a while" }, "monitor.sealed_after"},
		{"a scan interval that is too short", func(c *config.Config) { c.Monitor.ScanInterval = "1s" }, "monitor.scan_interval"},
		{"scan ports that are no ports", func(c *config.Config) { c.Monitor.ScanPorts = "https" }, "monitor.scan_ports"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			good := testConfig(t)
			initialized(t, good)
			bad := good
			tc.edit(&bad)
			srv, err := Open(t.Context(), Options{Config: bad, Log: slog.New(slog.DiscardHandler), Hostname: "pki01", Version: "test"})
			if err == nil {
				_ = srv.Shutdown(t.Context())
				t.Fatalf("Open accepted the setting, want an error containing %q", tc.want)
			}
			if srv != nil {
				t.Error("a failed Open returned a server")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
			// The refusal leaves everything as it was: the same data directory starts
			// with the good configuration.
			srv, err = Open(t.Context(), Options{Config: good, Log: slog.New(slog.DiscardHandler), Hostname: "pki01", Version: "test"})
			if err != nil {
				t.Fatalf("Open after a refused start: %v", err)
			}
			if err := srv.Shutdown(t.Context()); err != nil {
				t.Error(err)
			}
		})
	}
}

// TestOpenRefusesBadAuthKey: the auth key file is checked before anything is
// wired; every way it can be wrong ends the start.
func TestOpenRefusesBadAuthKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		content string // "" = delete the file
		want    string
	}{
		{"missing", "", "myownpki init creates it"},
		{"empty", " ", "not an auth key file"},
		{"wrong header", "not-a-key AAAA", "not an auth key file"},
		{"header only", "myownpki-auth-key-v1", "not an auth key file"},
		{"damaged key", "myownpki-auth-key-v1 !!!!", "the key is damaged"},
		{"key too short", "myownpki-auth-key-v1 AAAA", "the key is damaged"},
		{"too large", strings.Repeat("x", 64<<10), "too large"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := testConfig(t)
			initialized(t, cfg)
			if tc.content == "" {
				if err := os.Remove(cfg.AuthKeyFile()); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(cfg.AuthKeyFile(), []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			srv, err := Open(t.Context(), Options{Config: cfg, Log: slog.New(slog.DiscardHandler)})
			if err == nil {
				_ = srv.Shutdown(t.Context())
				t.Fatal("Open accepted the auth key")
			}
			if !strings.Contains(err.Error(), "auth key") || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q, want it to name the auth key and contain %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "AAAA") || strings.Contains(err.Error(), "!!!!") {
				t.Errorf("the error repeats the file's content: %q", err)
			}
		})
	}
}
