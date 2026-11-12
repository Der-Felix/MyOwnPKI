package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// notifyFiles writes a config file with the data directory, the notify:
// block and the files the test names; it returns the config path.
type notifyFiles struct {
	dir string
}

func newNotifyFiles(t *testing.T) *notifyFiles { t.Helper(); return &notifyFiles{dir: t.TempDir()} }

func (n *notifyFiles) path(name string) string { return filepath.Join(n.dir, name) }

func (n *notifyFiles) write(t *testing.T, name, content string) string {
	t.Helper()
	if err := os.WriteFile(n.path(name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return n.path(name)
}

// caPEM is a self-signed certificate, generated here.
func caPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Mail Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// config returns the path of a config file with the data directory and
// extra YAML (a notify: block).
func (n *notifyFiles) config(t *testing.T, extra string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "config.yaml") // one per test: they run in parallel
	if err := os.WriteFile(file, []byte("data_dir: "+yamlPath(n.dir)+"\n"+extra), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

func yamlPath(p string) string { return `"` + strings.ReplaceAll(p, `\`, `\\`) + `"` }

// TestConfigCheckNotify (docs/PHASE3.md step 24): the channels and
// thresholds are shown without any secret, a missing, unreadable, empty or
// useless secret or CA file is an error that fails the check, and no channel
// is a warning.
func TestConfigCheckNotify(t *testing.T) {
	t.Parallel()
	const secret = "s3cret-value-that-must-not-appear"
	f := newNotifyFiles(t)
	password := f.write(t, "smtp-password", secret+"\n")
	hmacKey := f.write(t, "webhook-secret", secret+"\n")
	mailCA := f.write(t, "mail-ca.pem", caPEM(t))
	empty := f.write(t, "empty", " \n")
	junk := f.write(t, "junk.pem", "not a certificate\n")
	missing := f.path("does-not-exist")
	unreadable := f.dir // a directory can't be read as a file, on every platform

	email := func(passwordFile, caFile string) string {
		return "notify:\n  email:\n    smtp: mail.homelab.lan:587\n    security: starttls\n    username: pki@homelab.lan\n    password_file: " + yamlPath(passwordFile) +
			"\n    from: pki@homelab.lan\n    to: ops@homelab.lan, lead@homelab.lan\n    ca_file: " + yamlPath(caFile) + "\n"
	}
	webhook := func(secretFile string) string {
		return "  webhook:\n    url: https://hooks.homelab.lan/myownpki/TOKEN-IN-THE-PATH?key=QUERYSECRET\n    secret_file: " + yamlPath(secretFile) + "\n"
	}

	tests := []struct {
		name       string
		config     string
		env        []string
		wantCode   int
		wantStdout []string
		wantStderr []string
		notStdout  []string
		notStderr  []string
	}{
		{name: "both channels configured", config: email(password, mailCA) + webhook(hmacKey), wantCode: 0,
			wantStdout: []string{"Notifications (notify:)", "e-mail           mail.homelab.lan:587, starttls, 2 recipients",
				"webhook          hooks.homelab.lan, signed with HMAC-SHA256", "Alert thresholds (monitor:)",
				"certificates     warning 14 days, critical 3 days before they end", "CA certificates  warning 90 days, critical 30 days before they end",
				"sealed server    alert after 10m\n", "silent agent     alert after 1h\n", "every 24h while an alert is open", "Configuration is valid."},
			notStderr: []string{"Error", "Warning"}, notStdout: []string{"no notification channel"}},
		{name: "only a webhook", config: "notify:\n" + webhook(hmacKey), wantCode: 0,
			wantStdout: []string{"e-mail           off (notify.email.smtp is empty)", "hooks.homelab.lan, signed with HMAC-SHA256", "Configuration is valid."},
			notStderr:  []string{"Error", "Warning"}},
		{name: "no channel", config: "", wantCode: 0,
			wantStdout: []string{"off (notify.email.smtp is empty)", "off (notify.webhook.url is empty)", "Warning: no notification channel is configured – alerts are shown in the UI, nobody is notified.", "Configuration is valid."},
			notStderr:  []string{"Warning"}},
		{name: "thresholds from the environment", config: "", wantCode: 0,
			env:        []string{"MYOWNPKI_MONITOR_EXPIRY_DAYS=20, 5", "MYOWNPKI_MONITOR_REPEAT_EVERY=6h"},
			wantStdout: []string{"warning 20 days, critical 5 days before they end   (from MYOWNPKI_MONITOR_EXPIRY_DAYS)", "every 6h while an alert is open   (from MYOWNPKI_MONITOR_REPEAT_EVERY)"}},
		{name: "missing password file", config: email(missing, mailCA) + webhook(hmacKey), wantCode: 1,
			wantStderr: []string{"Error: notify.email.password_file " + missing + ": the file does not exist."}, notStderr: []string{"notify.webhook"}},
		{name: "unreadable webhook secret", config: email(password, mailCA) + webhook(unreadable), wantCode: 1,
			wantStderr: []string{"Error: notify.webhook.secret_file " + unreadable + ": the file can't be read (", "the service user must be able to read it"}, notStderr: []string{"notify.email"}},
		{name: "missing CA file", config: email(password, missing) + webhook(hmacKey), wantCode: 1,
			wantStderr: []string{"Error: notify.email.ca_file " + missing + ": the file does not exist."}},
		{name: "CA file without a certificate", config: email(password, junk) + webhook(hmacKey), wantCode: 1,
			wantStderr: []string{"Error: notify.email.ca_file " + junk + ": the file holds no PEM certificate."}},
		{name: "empty secret", config: email(empty, mailCA) + webhook(hmacKey), wantCode: 1,
			wantStderr: []string{"notify.email.password_file " + empty + ": the file is empty."}},
		{name: "TLS scan rows", config: "", wantCode: 0,
			wantStdout: []string{"TLS scan         every 15m, timeout 10s\n", "scan ports       443, 465, 636, 853, 993, 995, 5061, 6514, 8443, 8883, 9443\n",
				"scan limits      100 endpoints, unreachable after 3 failed scans, mismatch after 1h\n", "Configuration is valid."}},
		{name: "TLS scan from the environment", config: "", wantCode: 0,
			env: []string{"MYOWNPKI_MONITOR_SCAN_INTERVAL=30m", "MYOWNPKI_MONITOR_SCAN_PORTS=443, 8443", "MYOWNPKI_MONITOR_SCAN_MAX_ENDPOINTS=1"},
			wantStdout: []string{"every 30m, timeout 10s   (from MYOWNPKI_MONITOR_SCAN_INTERVAL)", "443, 8443   (from MYOWNPKI_MONITOR_SCAN_PORTS)",
				"1 endpoint, unreachable after 3 failed scans, mismatch after 1h   (from MYOWNPKI_MONITOR_SCAN_MAX_ENDPOINTS)"}},
		{name: "TLS scan off", config: "monitor:\n  scan_interval: off\n", wantCode: 0,
			wantStdout: []string{"TLS scan         off (monitor.scan_interval) – endpoints are kept, nothing connects"}},
		{name: "TLS scan out of range", config: "monitor:\n  scan_interval: 1m\n", wantCode: 1,
			wantStderr: []string{"monitor.scan_interval"}},
		{name: "TLS scan port list", config: "monitor:\n  scan_ports: \"443, 443\"\n", wantCode: 1,
			wantStderr: []string{"monitor.scan_ports", "listed twice"}},
		{name: "every problem is named", config: email(missing, junk) + webhook(unreadable), wantCode: 1,
			wantStderr: []string{"notify.email.password_file", "notify.email.ca_file", "notify.webhook.secret_file", "Notifications would fail until this is fixed."}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			code := runConfigCheck([]string{"--config", f.config(t, tt.config)}, tt.env, &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout.String(), stderr.String())
			}
			for _, want := range tt.wantStdout {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout lacks %q:\n%s", want, stdout.String())
				}
			}
			for _, not := range tt.notStdout {
				if strings.Contains(stdout.String(), not) {
					t.Errorf("stdout has %q:\n%s", not, stdout.String())
				}
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr lacks %q:\n%s", want, stderr.String())
				}
			}
			for _, not := range tt.notStderr {
				if strings.Contains(stderr.String(), not) {
					t.Errorf("stderr has %q:\n%s", not, stderr.String())
				}
			}
			if tt.wantCode != 0 && strings.Contains(stdout.String(), "Configuration is valid.") {
				t.Error("a failing check says the configuration is valid")
			}
			// Never a secret, never the path or query of the webhook URL.
			all := stdout.String() + stderr.String()
			for _, leak := range []string{secret, "TOKEN-IN-THE-PATH", "QUERYSECRET", "/myownpki/"} {
				if strings.Contains(all, leak) {
					t.Errorf("the output has %q:\n%s", leak, all)
				}
			}
		})
	}
}

// TestConfigCheckNamesAPermissionProblem: a secret file the service user
// may not read is named as such (not as missing). Not on Windows, and not as
// root, who reads everything.
func TestConfigCheckNamesAPermissionProblem(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("file modes don't restrict reading on Windows")
	}
	f := newNotifyFiles(t)
	locked := f.write(t, "webhook-secret", "key\n")
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(locked); err == nil {
		t.Skip("running as a user that reads every file")
	}
	var stdout, stderr bytes.Buffer
	code := runConfigCheck([]string{"--config", f.config(t, "notify:\n  webhook:\n    url: https://hooks.homelab.lan/x\n    secret_file: "+yamlPath(locked)+"\n")}, nil, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "notify.webhook.secret_file "+locked+": the file can't be read (permission denied)") {
		t.Errorf("exit %d\n%s", code, stderr.String())
	}
}
