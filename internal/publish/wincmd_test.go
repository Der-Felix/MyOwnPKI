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

// TestWindowsHelperFile checks the portable file contract, including the lack
// of an embedded expectation and forwarding of independently supplied values.
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
		if !strings.Contains(text, "$expected = ''") || strings.Contains(text, colonHex(der)) || strings.Contains(text, strings.ReplaceAll(colonHex(der), ":", "")) {
			t.Errorf("%s: helper contains an embedded expected fingerprint", scope)
		}
		want := map[string]string{ScopeMachine: "$store = 'LocalMachine'", ScopeUser: "$store = 'CurrentUser'"}[scope]
		if !strings.Contains(text, want) {
			t.Errorf("%s: want %s", scope, want)
		}
		for _, forwarding := range []string{
			"if ($expected -ne '') { $child += ' -ExpectedSha256 ' + $expected }",
			"if ($quiet) { $child += ' /quiet' }",
			"$p = Start-Process -FilePath $env:ComSpec -ArgumentList '/c', $child -Verb RunAs -Wait -PassThru",
		} {
			if !strings.Contains(text, forwarding) {
				t.Errorf("%s: elevation does not forward authorization as expected: %s", scope, forwarding)
			}
		}
	}
}

// instrumentedHelper replaces only the store block in a test copy. Production
// has no test switch or alternate import path.
func instrumentedHelper(t *testing.T, cmd []byte) []byte {
	t.Helper()
	const store = "$cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 (, $der)\r\n" +
		"$root = New-Object Security.Cryptography.X509Certificates.X509Store ('Root', $store)\r\n" +
		"$root.Open('ReadWrite')\r\n" +
		"try { $root.Add($cert) } finally { $root.Close() }"
	text := strings.Replace(string(cmd), store, "Write-Host 'TEST STORE REACHED'", 1)
	if !strings.Contains(text, "TEST STORE REACHED") {
		t.Fatal("could not instrument the test copy")
	}
	return []byte(text)
}

func changedHelper(t *testing.T, cmd []byte) []byte {
	t.Helper()
	lines := strings.Split(string(cmd), "\r\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "-----BEGIN") {
			target := lines[i+2]
			c := byte('A')
			if target[10] == 'A' {
				c = 'B'
			}
			lines[i+2] = target[:10] + string(c) + target[11:]
			return []byte(strings.Join(lines, "\r\n"))
		}
	}
	t.Fatal("no embedded certificate to change")
	return nil
}

// TestWindowsHelperRuns exercises cmd.exe and PowerShell on Windows. Every
// import-path test uses an instrumented test copy and never opens a real store.
func TestWindowsHelperRuns(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("cmd.exe and PowerShell only on Windows")
	}
	t.Parallel()
	der := testRoot(t)
	expected := strings.ReplaceAll(colonHex(der), ":", "")
	dir := filepath.Join(t.TempDir(), "with space")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	run := func(name string, data []byte, stdin string, arg ...string) (int, string) {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(t.Context(), "cmd.exe", append([]string{"/c", path}, arg...)...) // #nosec G204 -- test: the helper just written
		command.Stdin = strings.NewReader(stdin)
		out, err := command.CombinedOutput()
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
	runPowerShell := func(name string, data []byte, arg ...string) (int, string) {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		args := append([]string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "& ([ScriptBlock]::Create([IO.File]::ReadAllText($env:MYOWNPKI_SELF))) @args"}, arg...)
		command := exec.CommandContext(t.Context(), "powershell.exe", args...) // #nosec G204 -- test: the helper just written
		command.Env = append(os.Environ(), "MYOWNPKI_SELF="+path)
		out, err := command.CombinedOutput()
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
		code, out := run("root-"+scope+"-check.cmd", cmd, "", "/check")
		if code != 0 || !strings.Contains(out, colonHex(der)) || !strings.Contains(out, sha1ColonHex(der)) || !strings.Contains(out, "SHA-256 (authoritative)") || !strings.Contains(out, "SHA-1 (display only") {
			t.Errorf("%s /check: exit %d\n%s", scope, code, out)
		}
		code, out = run("root-"+scope+"-arg.cmd", cmd, "", "/chek")
		if code != 64 || !strings.Contains(out, "nothing was imported") {
			t.Errorf("%s, unknown argument: exit %d\n%s", scope, code, out)
		}
		code, out = run("root-"+scope+"-changed-check.cmd", changedHelper(t, cmd), "", "/check", "-ExpectedSha256", expected)
		if code != 2 || !strings.Contains(out, "does not match -ExpectedSha256") {
			t.Errorf("%s, changed certificate: exit %d\n%s", scope, code, out)
		}
	}

	cmd := instrumentedHelper(t, windowsHelper("root", 1, der, ScopeUser))
	assertAbort := func(name string, wantCode int, stdin string, args ...string) {
		t.Helper()
		code, out := run(name+".cmd", cmd, stdin, args...)
		if code != wantCode || strings.Contains(out, "TEST STORE REACHED") {
			t.Errorf("%s: exit %d, want %d\n%s", name, code, wantCode, out)
		}
	}
	assertAbort("missing-expected", 64, "", "-ExpectedSha256")
	for i, malformed := range []string{"", strings.Repeat("A", 63), strings.Repeat("A", 65), colonHex(der), expected[:32] + " " + expected[32:], expected[:32] + "\t" + expected[32:], strings.Repeat("G", 64)} {
		name := "malformed-expected-" + string(rune('a'+i))
		code, out := runPowerShell(name+".cmd", cmd, "-ExpectedSha256", malformed)
		if code != 64 || strings.Contains(out, "TEST STORE REACHED") {
			t.Errorf("%s: exit %d, want 64\n%s", name, code, out)
		}
	}
	assertAbort("wrong-expected", 2, "", "-ExpectedSha256", strings.Repeat("0", 64))
	code, out := run("changed-pem.cmd", instrumentedHelper(t, changedHelper(t, cmd)), "", "-ExpectedSha256", expected)
	if code != 2 || strings.Contains(out, "TEST STORE REACHED") {
		t.Errorf("changed PEM: exit %d\n%s", code, out)
	}
	assertAbort("quiet-without-expected", 3, "", "/quiet")
	for i, answer := range []string{"", "\n", "no\n", "other\n", "yes\n"} {
		assertAbort("confirmation-negative-"+string(rune('a'+i)), 3, answer)
	}

	code, out = run("expected-match.cmd", cmd, "", "-ExpectedSha256", expected)
	if code != 0 || !strings.Contains(out, "TEST STORE REACHED") || !strings.Contains(out, "SHA-256 matches") {
		t.Errorf("exact expected match: exit %d\n%s", code, out)
	}
	code, out = run("independent-confirmation.cmd", cmd, "YES\n")
	if code != 0 || !strings.Contains(out, "TEST STORE REACHED") || !strings.Contains(out, "Done: imported") {
		t.Errorf("independent confirmation: exit %d\n%s", code, out)
	}
}
