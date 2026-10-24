package publish

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testRoot(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "Test Root CA – Ünïcödé"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// embeddedDER reads the certificate back out of a helper.
func embeddedDER(t *testing.T, cmd []byte) []byte {
	t.Helper()
	b, _ := pem.Decode(bytes.ReplaceAll(cmd, []byte("\r\n"), []byte("\n")))
	if b == nil || b.Type != "CERTIFICATE" {
		t.Fatal("no PEM certificate in the helper")
	}
	return b.Bytes
}

// TestWindowsHelperFile: ASCII only, CRLF only, the polyglot head, the
// root embedded unchanged with its fingerprint – on every OS.
func TestWindowsHelperFile(t *testing.T) {
	t.Parallel()
	der := testRoot(t)
	for _, scope := range []string{ScopeMachine, ScopeUser} {
		cmd := windowsHelper("root", 1, der, scope)
		for i, c := range cmd {
			if c >= 0x80 {
				t.Fatalf("%s: byte %d is not ASCII", scope, i)
			}
			if c == '\n' && (i == 0 || cmd[i-1] != '\r') {
				t.Fatalf("%s: line end at byte %d is not CRLF", scope, i)
			}
		}
		text := string(cmd)
		if !strings.HasPrefix(text, "<# : ") || !strings.Contains(text, "\r\n#>\r\n") || !strings.Contains(text, "exit /b %errorlevel%\r\n#>") {
			t.Errorf("%s: no Batch/PowerShell head:\n%s", scope, text)
		}
		if !bytes.Equal(embeddedDER(t, cmd), der) {
			t.Errorf("%s: the embedded certificate is not the CA's", scope)
		}
		if !strings.Contains(text, "$expected = '"+colonHex(der)+"'") {
			t.Errorf("%s: no fingerprint", scope)
		}
		want := map[string]string{ScopeMachine: "$store = 'LocalMachine'", ScopeUser: "$store = 'CurrentUser'"}[scope]
		if !strings.Contains(text, want) {
			t.Errorf("%s: want %s", scope, want)
		}
	}
}

// TestWindowsHelperRuns (Windows only – the windows CI job and a Windows
// workstation): cmd.exe runs the helper with /check, which imports nothing:
// the fingerprint passes; a copy with one changed character in the
// certificate stops with exit code 2 before any import.
func TestWindowsHelperRuns(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("cmd.exe and PowerShell only on Windows")
	}
	t.Parallel()
	der := testRoot(t)
	dir := filepath.Join(t.TempDir(), "with space")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	run := func(name string, data []byte, arg ...string) (int, string) {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if len(arg) == 0 {
			arg = []string{"/check"}
		}
		out, err := exec.CommandContext(t.Context(), "cmd.exe", append([]string{"/c", path}, arg...)...).CombinedOutput() // #nosec G204 -- test: the helper just written
		var exit *exec.ExitError
		switch {
		case err == nil:
			return 0, string(out)
		case errors.As(err, &exit):
			return exit.ExitCode(), string(out)
		}
		t.Fatalf("%s: %v", name, err)
		return 0, ""
	}
	for _, scope := range []string{ScopeMachine, ScopeUser} {
		cmd := windowsHelper("root", 1, der, scope)
		code, out := run("root-"+scope+".cmd", cmd)
		if code != 0 || !strings.Contains(out, "Fingerprint ok") || !strings.Contains(out, colonHex(der)) {
			t.Errorf("%s /check: exit %d\n%s", scope, code, out)
		}
		// A mistyped switch must never become an import (Git Bash, for
		// one, turns /check into a path).
		code, out = run("root-"+scope+"-arg.cmd", cmd, "/chek")
		if code != 64 || !strings.Contains(out, "nothing was imported") {
			t.Errorf("%s, unknown argument: exit %d\n%s", scope, code, out)
		}
		// One base64 character of the certificate changed (still valid base64).
		lines := strings.Split(string(cmd), "\r\n")
		for i, l := range lines {
			if strings.HasPrefix(l, "-----BEGIN") {
				target := lines[i+2]
				c := byte('A')
				if target[10] == 'A' {
					c = 'B'
				}
				lines[i+2] = target[:10] + string(c) + target[11:]
				break
			}
		}
		code, out = run("root-"+scope+"-changed.cmd", []byte(strings.Join(lines, "\r\n")))
		if code != 2 || !strings.Contains(out, "STOP: the certificate in this file does not match") {
			t.Errorf("%s, changed: exit %d\n%s", scope, code, out)
		}
	}
}
