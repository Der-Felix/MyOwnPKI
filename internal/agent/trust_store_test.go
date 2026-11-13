package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeTrustRunner records what would run as root. It never runs anything.
type fakeTrustRunner struct {
	calls  [][]string
	envs   [][]string
	err    error
	output string
	// onRun runs while the "hook" runs, to look at the file system then.
	onRun func(argv []string)
}

func (f *fakeTrustRunner) Run(_ context.Context, argv, env []string) (string, error) {
	f.calls = append(f.calls, append([]string(nil), argv...))
	f.envs = append(f.envs, append([]string(nil), env...))
	if f.onRun != nil {
		f.onRun(argv)
	}
	return f.output, f.err
}

const (
	osReleaseDebian = "PRETTY_NAME=\"Debian GNU/Linux 12\"\nID=debian\n"
	osReleaseUbuntu = "ID=ubuntu\nID_LIKE=debian\n"
	osReleaseRocky  = "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n"
	osReleaseFedora = "ID=fedora\n"
)

// trustFixture is a fake file system root with an os-release, the anchors
// directory of the family, an agent.yaml and a ca_bundle that holds the root.
type trustFixture struct {
	t        *testing.T
	root     string
	dir      string
	family   *trustFamily
	config   string
	caBundle string
	pem      []byte
	pin      string
	runner   *fakeTrustRunner
	env      trustEnv
	stdout   *bytes.Buffer
	stderr   *bytes.Buffer
}

func newTrustFixture(t *testing.T, osRelease string) *trustFixture {
	t.Helper()
	dir := t.TempDir()
	f := &trustFixture{t: t, root: filepath.Join(dir, "root"), dir: dir, runner: &fakeTrustRunner{},
		stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	f.env = trustEnv{Root: f.root, Runner: f.runner, EUID: func() int { return 0 }}
	f.writeAt("/etc/os-release", osRelease)
	if fam, err := f.env.detect(); err == nil {
		f.family = fam
		mkdirAll(t, f.env.path(fam.Dir))
	}
	block, _ := setupRoot(t)
	f.pem = pem.EncodeToMemory(block)
	sum := sha256.Sum256(block.Bytes)
	f.pin = hex.EncodeToString(sum[:])
	f.caBundle = filepath.Join(dir, "etc", "root.pem")
	mkdirAll(t, filepath.Dir(f.caBundle))
	writeTestFile(t, f.caBundle, f.pem, 0o600)
	f.config = filepath.Join(dir, "etc", "agent.yaml")
	f.writeConfig("")
	return f
}

func mkdirAll(t *testing.T, dir string) {
	t.Helper()
	// #nosec G301 -- a temporary test directory.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeTestFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func (f *trustFixture) writeAt(slash, content string) {
	f.t.Helper()
	p := f.env.path(slash)
	mkdirAll(f.t, filepath.Dir(p))
	writeTestFile(f.t, p, []byte(content), 0o644)
}

// writeConfig writes a valid agent.yaml; extra is appended (top-level keys).
func (f *trustFixture) writeConfig(extra string) {
	f.t.Helper()
	body := "# agent of the test\nserver: \"https://pki.homelab.lan:8444\"\nca_bundle: " + yamlQuote(f.caBundle) +
		"\nhostname: \"proxy1.homelab.lan\"\nstate_dir: " + yamlQuote(filepath.Join(f.dir, "state")) + "\nlog_level: \"info\"\n" +
		"enrollment:\n  challenge: standalone\npaths: []\n" + extra + "deployments: []\n"
	writeTestFile(f.t, f.config, []byte(body), 0o644)
}

func yamlQuote(p string) string { return `"` + strings.ReplaceAll(p, `\`, `\\`) + `"` }

func (f *trustFixture) target() string { return filepath.Join(f.env.path(f.family.Dir), f.family.File) }

func (f *trustFixture) opts() TrustOptions {
	return TrustOptions{ConfigPath: f.config, RootSHA256: f.pin, Stdout: f.stdout, Stderr: f.stderr}
}

func (f *trustFixture) install() error {
	return installTrust(context.Background(), f.env, f.opts())
}

func (f *trustFixture) read(path string) string {
	f.t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		f.t.Fatal(err)
	}
	return string(data)
}

func (f *trustFixture) exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func TestInstallDebianWritesTheFileAndRunsOneFixedHook(t *testing.T) {
	t.Parallel()
	f := newTrustFixture(t, osReleaseDebian)
	f.runner.onRun = func([]string) {
		if f.read(f.target()) != string(f.pem) {
			t.Error("the hook ran before the root was in place")
		}
	}
	if err := f.install(); err != nil {
		t.Fatal(err)
	}
	if got := f.read(f.target()); got != string(f.pem) {
		t.Fatalf("target content = %q", got)
	}
	if want := filepath.Join(f.root, "usr", "local", "share", "ca-certificates", "myownpki-agent-root.crt"); f.target() != want {
		t.Fatalf("target = %s, want %s", f.target(), want)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(f.target()); st.Mode().Perm() != 0o644 {
			t.Errorf("mode = %o", st.Mode().Perm())
		}
	}
	if len(f.runner.calls) != 1 || strings.Join(f.runner.calls[0], " ") != "/usr/sbin/update-ca-certificates" {
		t.Fatalf("calls = %v", f.runner.calls)
	}
	if got := strings.Join(f.runner.envs[0], " "); got != "PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C" {
		t.Errorf("hook environment = %q", got)
	}
	cfg, err := LoadConfig(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SystemTrust == nil || cfg.SystemTrust.RootSHA256 != f.pin {
		t.Fatalf("recorded key: %+v", cfg.SystemTrust)
	}
	text := f.read(f.config)
	if !strings.Contains(text, "# agent of the test") || strings.Index(text, "system_trust:") > strings.Index(text, "deployments:") {
		t.Errorf("agent.yaml lost its comment or the key is out of order:\n%s", text)
	}
	if !strings.Contains(text, `root_sha256: "`+f.pin+`"`) {
		t.Errorf("the pin is not a quoted string:\n%s", text)
	}
	out := f.stdout.String()
	for _, want := range []string{f.target(), "/usr/sbin/update-ca-certificates", f.pin} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestInstallRedHatFamilies(t *testing.T) {
	t.Parallel()
	for name, osRelease := range map[string]string{"rocky": osReleaseRocky, "fedora": osReleaseFedora} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newTrustFixture(t, osRelease)
			if err := f.install(); err != nil {
				t.Fatal(err)
			}
			if want := filepath.Join(f.root, "etc", "pki", "ca-trust", "source", "anchors", "myownpki-agent-root.pem"); f.target() != want || !f.exists(want) {
				t.Fatalf("target %s, want %s", f.target(), want)
			}
			if len(f.runner.calls) != 1 || strings.Join(f.runner.calls[0], " ") != "/usr/bin/update-ca-trust" {
				t.Fatalf("calls = %v", f.runner.calls)
			}
		})
	}
}

func TestInstallIsIdempotent(t *testing.T) {
	t.Parallel()
	f := newTrustFixture(t, osReleaseUbuntu)
	if err := f.install(); err != nil {
		t.Fatal(err)
	}
	config := f.read(f.config)
	f.stdout.Reset()
	if err := f.install(); err != nil {
		t.Fatal(err)
	}
	if len(f.runner.calls) != 1 {
		t.Fatalf("a second run called the hook again: %v", f.runner.calls)
	}
	if got := f.read(f.config); got != config {
		t.Errorf("a second run changed agent.yaml:\n%s", got)
	}
	if !strings.Contains(f.stdout.String(), "already installed") {
		t.Errorf("output = %q", f.stdout.String())
	}
}

func TestInstallReplacesChangedContent(t *testing.T) {
	t.Parallel()
	f := newTrustFixture(t, osReleaseDebian)
	writeTestFile(t, f.target(), []byte("something else\n"), 0o644)
	if err := f.install(); err != nil {
		t.Fatal(err)
	}
	if got := f.read(f.target()); got != string(f.pem) {
		t.Fatalf("content = %q", got)
	}
	if len(f.runner.calls) != 1 {
		t.Fatalf("calls = %v", f.runner.calls)
	}
}

func TestInstallLeavesNoTemporaryFile(t *testing.T) {
	t.Parallel()
	f := newTrustFixture(t, osReleaseDebian)
	if err := f.install(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Dir(f.target()))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "myownpki-agent-root.crt" {
		t.Fatalf("directory = %v", entries)
	}
}

func TestFailedHookRestoresTheOldState(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 3000) + "\x1b[31mred\x00 end of the output"
	for _, tt := range []struct {
		name string
		old  string // "" = no file before
	}{{"first install", ""}, {"replacement", "the previous root\n"}} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newTrustFixture(t, osReleaseDebian)
			if tt.old != "" {
				writeTestFile(t, f.target(), []byte(tt.old), 0o644)
			}
			config := f.read(f.config)
			f.runner.err = errors.New("exit status 1")
			f.runner.output = long
			err := f.install()
			if err == nil {
				t.Fatal("a failed hook was reported as success")
			}
			if tt.old == "" && f.exists(f.target()) {
				t.Error("the new file stayed although the hook failed")
			}
			if tt.old != "" && f.read(f.target()) != tt.old {
				t.Errorf("the previous content is not back: %q", f.read(f.target()))
			}
			if f.read(f.config) != config {
				t.Error("agent.yaml was changed although the hook failed")
			}
			msg := err.Error()
			if len(msg) > 1400 || !strings.Contains(msg, "update-ca-certificates") || !strings.Contains(msg, "restored") || strings.ContainsAny(msg, "\x1b\x00") {
				t.Errorf("error is not bounded and clean (%d bytes): %q", len(msg), msg)
			}
			if !strings.Contains(msg, "end of the output") {
				t.Errorf("the tail of the output is missing: %q", msg)
			}
		})
	}
}

func TestInstallRefusesBeforeAnyWrite(t *testing.T) {
	t.Parallel()
	other, _ := setupRoot(t)
	otherSum := sha256.Sum256(other.Bytes)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	selfSigned := func(t *testing.T, tmpl *x509.Certificate) []byte {
		t.Helper()
		der, certErr := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &leafKey.PublicKey, leafKey)
		if certErr != nil {
			t.Fatal(certErr)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	base := func(ca bool) *x509.Certificate {
		return &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "Refused root"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: ca, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign}
	}
	setBundle := func(t *testing.T, f *trustFixture, data []byte) {
		t.Helper()
		writeTestFile(t, f.caBundle, data, 0o600)
		sum := sha256.Sum256(firstDER(t, data))
		f.pin = hex.EncodeToString(sum[:])
	}
	tests := []struct {
		name   string
		mutate func(f *trustFixture)
		want   string
	}{
		{"pin mismatch", func(f *trustFixture) { f.pin = hex.EncodeToString(otherSum[:]) }, "mismatch"},
		{"malformed pin", func(f *trustFixture) { f.pin = "1234" }, "32 bytes"},
		{"two certificates", func(f *trustFixture) {
			setBundle(f.t, f, append(append([]byte(nil), f.pem...), pem.EncodeToMemory(other)...))
		}, "exactly one"},
		{"not a CA", func(f *trustFixture) { setBundle(f.t, f, selfSigned(f.t, base(false))) }, "not a CA"},
		{"not self-signed", func(f *trustFixture) {
			ca, caKey := setupRoot(f.t)
			parent, _ := x509.ParseCertificate(ca.Bytes)
			der, certErr := x509.CreateCertificate(rand.Reader, base(true), parent, &leafKey.PublicKey, caKey)
			if certErr != nil {
				f.t.Fatal(certErr)
			}
			setBundle(f.t, f, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		}, "not self-signed"},
		{"not root", func(f *trustFixture) { f.env.EUID = func() int { return 1000 } }, "must run as root"},
		{"unsupported family", func(f *trustFixture) {
			f.writeAt("/etc/os-release", "ID=\"sles\"\nID_LIKE=\"suse opensuse\"\n")
		}, "Debian-family"},
		{"no os-release", func(f *trustFixture) { _ = os.Remove(f.env.path("/etc/os-release")) }, "os-release"},
		{"directory missing", func(f *trustFixture) { _ = os.RemoveAll(f.env.path(f.family.Dir)) }, "does not exist"},
		{"ca_bundle missing", func(f *trustFixture) { _ = os.Remove(f.caBundle) }, "ca_bundle"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newTrustFixture(t, osReleaseDebian)
			config := f.read(f.config)
			tt.mutate(f)
			err := f.install()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
			if f.exists(f.target()) || len(f.runner.calls) != 0 || f.read(f.config) != config {
				t.Fatalf("a refused install changed something (calls %v)", f.runner.calls)
			}
		})
	}
}

func firstDER(t *testing.T, data []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM")
	}
	return block.Bytes
}

func TestInstallRefusesSymbolicLinks(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"ca_bundle", "target", "directory"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			f := newTrustFixture(t, osReleaseDebian)
			real := filepath.Join(f.dir, "real")
			switch kind {
			case "ca_bundle":
				writeTestFile(t, real, f.pem, 0o600)
				_ = os.Remove(f.caBundle)
				symlinkOrSkip(t, real, f.caBundle)
			case "target":
				writeTestFile(t, real, []byte("elsewhere\n"), 0o644)
				symlinkOrSkip(t, real, f.target())
			case "directory":
				mkdirAll(t, real)
				_ = os.RemoveAll(f.env.path(f.family.Dir))
				symlinkOrSkip(t, real, f.env.path(f.family.Dir))
			}
			config := f.read(f.config)
			if err := f.install(); err == nil {
				t.Fatal("a symbolic link was accepted")
			}
			if len(f.runner.calls) != 0 || f.read(f.config) != config {
				t.Fatal("a refused install changed something")
			}
			if kind == "target" && f.read(real) != "elsewhere\n" {
				t.Fatal("the file behind the link was written")
			}
		})
	}
}

func symlinkOrSkip(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		t.Skipf("cannot create a symbolic link here: %v", err)
	}
}

func TestInstallNoRecordLeavesAgentYamlAlone(t *testing.T) {
	t.Parallel()
	f := newTrustFixture(t, osReleaseDebian)
	config := f.read(f.config)
	opts := f.opts()
	opts.NoRecord = true
	if err := installTrust(context.Background(), f.env, opts); err != nil {
		t.Fatal(err)
	}
	if f.read(f.config) != config || f.exists(f.config+".bak") {
		t.Error("--no-record changed agent.yaml")
	}
	if len(f.runner.calls) != 1 {
		t.Fatalf("calls = %v", f.runner.calls)
	}
}

func TestInstallWithANewPinReplacesTheKey(t *testing.T) {
	t.Parallel()
	f := newTrustFixture(t, osReleaseDebian)
	old := strings.Repeat("ab", 32)
	f.writeConfig("system_trust:\n  root_sha256: \"" + old + "\"\n")
	if err := f.install(); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(f.config)
	if err != nil || cfg.SystemTrust == nil || cfg.SystemTrust.RootSHA256 != f.pin {
		t.Fatalf("config %+v, err %v", cfg.SystemTrust, err)
	}
	if strings.Contains(f.read(f.config), old) || !strings.Contains(f.read(f.config+".bak"), old) {
		t.Error("the old pin is not only in the .bak file")
	}
}

func TestRemoveDeletesOnlyTheFixedFileAndTheKey(t *testing.T) {
	t.Parallel()
	for name, tt := range map[string]struct {
		osRelease string
		hook      string
	}{
		"debian":  {osReleaseDebian, "/usr/sbin/update-ca-certificates --fresh"},
		"redhat":  {osReleaseRocky, "/usr/bin/update-ca-trust"},
		"ubuntu2": {osReleaseUbuntu, "/usr/sbin/update-ca-certificates --fresh"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newTrustFixture(t, tt.osRelease)
			sibling := filepath.Join(filepath.Dir(f.target()), "other-ca.crt")
			writeTestFile(t, sibling, []byte("not ours\n"), 0o644)
			if err := f.install(); err != nil {
				t.Fatal(err)
			}
			f.runner.calls = nil
			if err := removeTrust(context.Background(), f.env, TrustOptions{ConfigPath: f.config, Stdout: f.stdout}); err != nil {
				t.Fatal(err)
			}
			if f.exists(f.target()) {
				t.Error("the file is still there")
			}
			if f.read(sibling) != "not ours\n" {
				t.Error("another file in the directory was touched")
			}
			if len(f.runner.calls) != 1 || strings.Join(f.runner.calls[0], " ") != tt.hook {
				t.Fatalf("calls = %v, want %s", f.runner.calls, tt.hook)
			}
			if strings.Contains(f.read(f.config), "system_trust") {
				t.Errorf("the key is still in agent.yaml:\n%s", f.read(f.config))
			}
			if _, err := LoadConfig(f.config); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRemoveRefusesAFileThatIsNotThePinnedRoot(t *testing.T) {
	t.Parallel()
	f := newTrustFixture(t, osReleaseDebian)
	other, _ := setupRoot(t)
	writeTestFile(t, f.target(), pem.EncodeToMemory(other), 0o644)
	f.writeConfig("system_trust:\n  root_sha256: \"" + f.pin + "\"\n")
	config := f.read(f.config)
	err := removeTrust(context.Background(), f.env, TrustOptions{ConfigPath: f.config})
	if err == nil || !strings.Contains(err.Error(), "not removing") {
		t.Fatalf("err = %v", err)
	}
	if !f.exists(f.target()) || len(f.runner.calls) != 0 || f.read(f.config) != config {
		t.Fatal("a refused removal changed something")
	}
}

func TestRemoveWithAFailingHookPutsTheFileBack(t *testing.T) {
	t.Parallel()
	f := newTrustFixture(t, osReleaseDebian)
	if err := f.install(); err != nil {
		t.Fatal(err)
	}
	config := f.read(f.config)
	f.runner.err = errors.New("exit status 1")
	f.runner.output = "no way"
	err := removeTrust(context.Background(), f.env, TrustOptions{ConfigPath: f.config})
	if err == nil || !strings.Contains(err.Error(), "put back") {
		t.Fatalf("err = %v", err)
	}
	if f.read(f.target()) != string(f.pem) || f.read(f.config) != config {
		t.Fatal("the state is not as before the failed removal")
	}
}

func TestRemoveNeedsAPinAndRoot(t *testing.T) {
	t.Parallel()
	f := newTrustFixture(t, osReleaseDebian)
	if err := removeTrust(context.Background(), f.env, TrustOptions{ConfigPath: f.config}); err == nil || !strings.Contains(err.Error(), "no pin") {
		t.Fatalf("err = %v", err)
	}
	f.env.EUID = func() int { return 1000 }
	if err := removeTrust(context.Background(), f.env, TrustOptions{ConfigPath: f.config, RootSHA256: f.pin}); err == nil || !strings.Contains(err.Error(), "must run as root") {
		t.Fatalf("err = %v", err)
	}
	// With the pin on the command line and no file: nothing to remove, no hook.
	f.env.EUID = func() int { return 0 }
	if err := removeTrust(context.Background(), f.env, TrustOptions{ConfigPath: f.config, RootSHA256: f.pin, Stdout: f.stdout}); err != nil {
		t.Fatal(err)
	}
	if len(f.runner.calls) != 0 || !strings.Contains(f.stdout.String(), "nothing to remove") {
		t.Fatalf("calls %v, output %q", f.runner.calls, f.stdout.String())
	}
}

func TestStatus(t *testing.T) {
	t.Parallel()
	f := newTrustFixture(t, osReleaseDebian)
	f.env.EUID = func() int { return 1000 } // status needs no root
	status := func(opts TrustOptions) (bool, string) {
		t.Helper()
		var out bytes.Buffer
		opts.ConfigPath, opts.Stdout = f.config, &out
		ok, err := trustStatus(f.env, opts)
		if err != nil {
			t.Fatal(err)
		}
		return ok, out.String()
	}
	if ok, out := status(TrustOptions{}); ok || !strings.Contains(out, "not configured") {
		t.Errorf("without a pin: %v %q", ok, out)
	}
	if ok, out := status(TrustOptions{RootSHA256: f.pin}); ok || !strings.Contains(out, "not installed") || !strings.Contains(out, "trust install --root-sha256 "+f.pin) {
		t.Errorf("not installed: %v %q", ok, out)
	}
	root := f.env
	root.EUID = func() int { return 0 }
	if err := installTrust(context.Background(), root, f.opts()); err != nil {
		t.Fatal(err)
	}
	if ok, out := status(TrustOptions{}); !ok || !strings.Contains(out, "installed: ") {
		t.Errorf("installed (pin from agent.yaml): %v %q", ok, out)
	}
	if ok, out := status(TrustOptions{RootSHA256: strings.ToUpper(f.pin)}); !ok || out == "" {
		t.Errorf("installed (pin given): %v %q", ok, out)
	}
	if ok, out := status(TrustOptions{Quiet: true}); !ok || out != "" {
		t.Errorf("quiet: %v %q", ok, out)
	}
	if ok, out := status(TrustOptions{RootSHA256: strings.Repeat("0", 64)}); ok || !strings.Contains(out, "pin differs") {
		t.Errorf("another pin than agent.yaml: %v %q", ok, out)
	}
	other, _ := setupRoot(t)
	writeTestFile(t, f.target(), pem.EncodeToMemory(other), 0o644)
	if ok, out := status(TrustOptions{}); ok || !strings.Contains(out, "differs") {
		t.Errorf("another certificate in the file: %v %q", ok, out)
	}
	if ok, out := status(TrustOptions{Quiet: true}); ok || out != "" {
		t.Errorf("quiet and differs: %v %q", ok, out)
	}
	if len(f.runner.calls) != 1 {
		t.Errorf("status ran a hook: %v", f.runner.calls)
	}
	f.writeAt("/etc/os-release", "ID=arch\n")
	if ok, out := status(TrustOptions{}); ok || !strings.Contains(out, "Debian-family") {
		t.Errorf("unsupported: %v %q", ok, out)
	}
}

func TestSystemTrustCheck(t *testing.T) {
	t.Parallel()
	f := newTrustFixture(t, osReleaseDebian)
	load := func() *Config {
		t.Helper()
		cfg, err := LoadConfig(f.config)
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	check := func() (string, bool) { return systemTrustCheck(f.env, load()) }
	if text, ok := check(); !ok || text != "  system trust  off\n" {
		t.Errorf("off: %v %q", ok, text)
	}
	f.writeConfig("system_trust:\n  root_sha256: \"" + f.pin + "\"\n")
	if text, ok := check(); !ok || !strings.Contains(text, "not installed") || !strings.Contains(text, "trust install --root-sha256 "+f.pin) {
		t.Errorf("missing: %v %q", ok, text)
	}
	if err := f.install(); err != nil {
		t.Fatal(err)
	}
	if text, ok := check(); !ok || !strings.Contains(text, "installed: "+f.target()) {
		t.Errorf("installed: %v %q", ok, text)
	}
	other, _ := setupRoot(t)
	writeTestFile(t, f.target(), pem.EncodeToMemory(other), 0o644)
	if text, ok := check(); !ok || !strings.Contains(text, "differs") {
		t.Errorf("differs: %v %q", ok, text)
	}
	// A pin that does not match the root in ca_bundle is the one failure.
	f.writeConfig("system_trust:\n  root_sha256: \"" + strings.Repeat("0", 64) + "\"\n")
	if text, ok := check(); ok || !strings.Contains(text, "pin differs from ca_bundle") {
		t.Errorf("pin mismatch: %v %q", ok, text)
	}
	f.writeConfig("system_trust:\n  root_sha256: \"" + f.pin + "\"\n")
	_ = os.Remove(f.caBundle) // a laptop without the root: information only
	f.writeAt("/etc/os-release", "ID=\"sles\"\n")
	if text, ok := check(); !ok || !strings.Contains(text, "configured") || !strings.Contains(text, "Debian-family") {
		t.Errorf("unsupported: %v %q", ok, text)
	}
}

func TestParseOSReleaseAndFamilies(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		id, like string
		want     string
	}{
		{"debian", "", "Debian"}, {"ubuntu", "debian", "Debian"}, {"raspbian", "debian", "Debian"},
		{"rhel", "fedora", "RedHat"}, {"rocky", "rhel centos fedora", "RedHat"}, {"fedora", "", "RedHat"},
		{"centos", "rhel fedora", "RedHat"}, {"amzn", "fedora", "RedHat"},
		{"sles", "suse opensuse", ""}, {"arch", "", ""}, {"alpine", "", ""}, {"", "", ""},
	} {
		fam, err := familyOf(tt.id, tt.like)
		switch {
		case tt.want == "" && err == nil:
			t.Errorf("%q %q accepted as %s", tt.id, tt.like, fam.Name)
		case tt.want != "" && (err != nil || fam.Name != tt.want):
			t.Errorf("%q %q: %v %v", tt.id, tt.like, fam, err)
		}
	}
	id, like := parseOSRelease([]byte("NAME=\"x\"\nID='rocky'\nID_LIKE=\"rhel fedora\"\n# comment\nbroken\n"))
	if id != "rocky" || like != "rhel fedora" {
		t.Errorf("parsed %q %q", id, like)
	}
	if _, err := familyOf("evil\x1b[31m"+strings.Repeat("a", 500), ""); err == nil || strings.ContainsRune(err.Error(), 0x1b) || len(err.Error()) > 400 {
		t.Errorf("the refusal repeats unbounded or raw os-release text: %v", err)
	}
}

func TestSystemTrustConfigValidation(t *testing.T) {
	t.Parallel()
	pin := strings.Repeat("0123456789abcdef", 4)
	parse := func(extra string) (*Config, error) {
		return ParseConfig("agent.yaml", []byte("server: https://pki.homelab.lan:8444\nca_bundle: "+yamlQuote(filepath.Join(t.TempDir(), "root.pem"))+
			"\nhostname: proxy1.homelab.lan\nstate_dir: "+yamlQuote(filepath.Join(t.TempDir(), "state"))+"\n"+extra))
	}
	if cfg, err := parse(""); err != nil || cfg.SystemTrust != nil {
		t.Fatalf("an agent.yaml of 0.3.8: %v %+v", err, cfg)
	}
	if cfg, err := parse("system_trust:\n"); err != nil || cfg.SystemTrust != nil {
		t.Fatalf("an empty key is off: %v %+v", err, cfg)
	}
	if cfg, err := parse("system_trust:\n  root_sha256: " + strings.ToUpper(pin) + "\n"); err != nil || cfg.SystemTrust.RootSHA256 != pin {
		t.Fatalf("upper case is normalized: %v %+v", err, cfg)
	}
	for name, extra := range map[string]string{
		"empty":       "system_trust:\n  root_sha256: \"\"\n",
		"short":       "system_trust:\n  root_sha256: abcd\n",
		"colons":      "system_trust:\n  root_sha256: \"" + strings.TrimSuffix(strings.Repeat("01:", 32), ":") + "\"\n",
		"not hex":     "system_trust:\n  root_sha256: \"" + strings.Repeat("z", 64) + "\"\n",
		"unknown key": "system_trust:\n  root_sha256: " + pin + "\n  force: true\n",
		"a boolean":   "system_trust: true\n",
		"a string":    "system_trust: " + pin + "\n",
		"no pin":      "system_trust: {}\n",
	} {
		if _, err := parse(extra); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOnlyTheTrustCommandsReachTheTrustStore(t *testing.T) {
	t.Parallel()
	// "run" and everything the service runs never touch the trust store: the
	// sandbox of the unit stays as it is because no running code path needs more.
	allowed := map[string]bool{"trust_store.go": true, "trust_cli.go": true, "setup.go": true}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") || allowed[name] {
			continue
		}
		data, readErr := os.ReadFile(name)
		if readErr != nil {
			t.Fatal(readErr)
		}
		for _, banned := range []string{"trustHost", "installTrust", "removeTrust", "trustEnv", "TrustInstall", "TrustRemove", "update-ca-certificates", "update-ca-trust"} {
			if strings.Contains(string(data), banned) {
				t.Errorf("%s mentions %s: the service must not reach the trust store", name, banned)
			}
		}
	}
}

func TestTrustFilesAreFixedConstants(t *testing.T) {
	t.Parallel()
	for _, fam := range []trustFamily{trustDebian, trustRedHat} {
		for _, argv := range [][]string{fam.Install, fam.Remove} {
			if !strings.HasPrefix(argv[0], "/usr/") || strings.ContainsAny(strings.Join(argv, ""), "$`;|&<>*") {
				t.Errorf("%s: unexpected argument vector %v", fam.Name, argv)
			}
		}
		if filepath.Base(fam.File) != fam.File || strings.ContainsAny(fam.File, " /\\") {
			t.Errorf("%s: file name %q", fam.Name, fam.File)
		}
	}
}
