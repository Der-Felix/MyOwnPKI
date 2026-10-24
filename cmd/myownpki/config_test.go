package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

func TestConfigCheck(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	valid := filepath.Join(dir, "valid.yaml")
	invalid := filepath.Join(dir, "invalid.yaml")
	quoted := strings.ReplaceAll(dir, `\`, `\\`)
	for file, content := range map[string]string{
		valid:   "data_dir: \"" + quoted + "\"\n",
		invalid: "data_dir: relative\nlog:\n  level: loud\n",
	} {
		if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name       string
		args, env  []string
		wantCode   int
		wantStdout []string
		wantStderr []string
	}{
		{name: "valid file", args: []string{"--config", valid}, wantCode: 0,
			wantStdout: []string{"Config file: " + valid, "127.0.0.1:9443", "self-signed bootstrap certificate", "Configuration is valid."}},
		{name: "file from MYOWNPKI_CONFIG", env: []string{"MYOWNPKI_CONFIG=" + valid}, wantCode: 0,
			wantStdout: []string{"Config file: " + valid}},
		{name: "override is marked", args: []string{"--config", valid}, env: []string{"MYOWNPKI_PUBLIC_LISTEN="}, wantCode: 0,
			wantStdout: []string{"disabled   (from MYOWNPKI_PUBLIC_LISTEN)", "off (acme.base_url is empty)"}},
		{name: "issued certificates", args: []string{"--config", valid}, wantCode: 0, env: []string{
			"MYOWNPKI_ADMIN_TLS_ISSUER=issuing", "MYOWNPKI_ADMIN_TLS_NAMES=pki.homelab.lan",
			"MYOWNPKI_ACME_BASE_URL=https://pki.homelab.lan/acme", "MYOWNPKI_ACME_LISTEN=:443", "MYOWNPKI_ACME_TLS_ISSUER=issuing",
		}, wantStdout: []string{"issued by CA issuing for pki.homelab.lan", ":443 – its own TLS, issued by CA issuing",
			"Not checked: whether the CA of tls_issuer is a root – the CA database can't be read", "Configuration is valid."}},
		{name: "ACME behind the proxy", args: []string{"--config", valid}, wantCode: 0, env: []string{"MYOWNPKI_ACME_BASE_URL=https://pki.homelab.lan/acme"},
			wantStdout: []string{"127.0.0.1:8081 – plain HTTP for the reverse proxy 127.0.0.1, ::1"}},
		{name: "invalid file names every problem", args: []string{"--config", invalid}, wantCode: 1,
			wantStderr: []string{"data_dir: must be an absolute path", "log.level"}},
		{name: "typo in variable", args: []string{"--config", valid}, env: []string{"MYOWNPKI_ADMIN_LISTN=:1"}, wantCode: 1,
			wantStderr: []string{"unknown environment variable MYOWNPKI_ADMIN_LISTN"}},
		{name: "missing file", args: []string{"--config", filepath.Join(dir, "nope.yaml")}, wantCode: 1,
			wantStderr: []string{"does not exist"}},
		{name: "extra argument", args: []string{"--config", valid, "now"}, wantCode: 2,
			wantStderr: []string{"unexpected argument"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			code := runConfigCheck(tt.args, tt.env, &stdout, &stderr)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstderr: %s", code, tt.wantCode, stderr.String())
			}
			for _, want := range tt.wantStdout {
				if !strings.Contains(stdout.String(), want) {
					t.Errorf("stdout lacks %q:\n%s", want, stdout.String())
				}
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr lacks %q:\n%s", want, stderr.String())
				}
			}
		})
	}
}

// TestConfigCheckRootIssuer: with a readable CA database, a root in
// admin.tls_issuer or acme.tls_issuer is a warning with the fix – on stderr,
// which install.sh shows – and the config stays valid (exit 0), like the
// server, which starts with it.
func TestConfigCheckRootIssuer(t *testing.T) {
	t.Parallel()
	inst := testinstance.New(t, testinstance.Options{})
	file := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(file, []byte("data_dir: \""+strings.ReplaceAll(inst.Config.DataDir, `\`, `\\`)+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		admin, acme string
		want        []string
	}{
		{admin: "root", acme: "issuing", want: []string{"Warning: CA root is a root – name the issuing intermediate in admin.tls_issuer (intermediates of root: issuing). Until then"}},
		{admin: "issuing", acme: "root", want: []string{"in acme.tls_issuer"}},
		{admin: "issuing", acme: "issuing"},
	} {
		var stdout, stderr bytes.Buffer
		code := runConfigCheck([]string{"--config", file}, []string{
			"MYOWNPKI_ADMIN_TLS_ISSUER=" + tt.admin, "MYOWNPKI_ADMIN_TLS_NAMES=pki.homelab.lan",
			"MYOWNPKI_ACME_BASE_URL=https://pki.homelab.lan/acme", "MYOWNPKI_ACME_LISTEN=:443", "MYOWNPKI_ACME_TLS_ISSUER=" + tt.acme,
		}, &stdout, &stderr)
		if code != 0 || !strings.Contains(stdout.String(), "Configuration is valid.") || strings.Contains(stdout.String(), "Not checked") {
			t.Errorf("%s/%s: exit %d\n%s%s", tt.admin, tt.acme, code, stdout.String(), stderr.String())
		}
		for _, w := range tt.want {
			if !strings.Contains(stderr.String(), w) {
				t.Errorf("%s/%s: stderr lacks %q:\n%s", tt.admin, tt.acme, w, stderr.String())
			}
		}
		if len(tt.want) == 0 && stderr.Len() != 0 {
			t.Errorf("intermediates only: %s", stderr.String())
		}
	}
}

func TestConfigCommandUsage(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"config"}, {"config", "show"}} {
		var stdout, stderr bytes.Buffer
		if code := run(t.Context(), args, &stdout, &stderr); code != 2 {
			t.Errorf("%v: exit code %d, want 2", args, code)
		}
		if !strings.Contains(stderr.String(), "config check") {
			t.Errorf("%v: usage missing: %s", args, stderr.String())
		}
	}
}
