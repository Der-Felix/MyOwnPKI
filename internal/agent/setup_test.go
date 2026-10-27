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
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/deploy"
	agentv1 "github.com/Der-Felix/MyOwnPKI/internal/gen/myownpki/agent/v1"
)

type fakeSetupAgent struct {
	status      Status
	result      *Result
	enrollCalls int
	pollCalls   int
	token       string
}

func (f *fakeSetupAgent) Enroll(_ context.Context, token string) (*Result, error) {
	f.enrollCalls++
	f.token = token
	return f.result, nil
}

func (f *fakeSetupAgent) Poll(context.Context) (*Result, error) {
	f.pollCalls++
	return f.result, nil
}

func (f *fakeSetupAgent) Status() Status { return f.status }

type fakeSetupRunner struct{ calls []string }

func (f *fakeSetupRunner) Run(_ context.Context, args ...string) error {
	f.calls = append(f.calls, strings.Join(args, " "))
	return nil
}

func TestNormalizeRootSHA256(t *testing.T) {
	t.Parallel()
	raw := bytes.Repeat([]byte{0xab}, sha256.Size)
	plain := hex.EncodeToString(raw)
	colon := strings.ToUpper(strings.Join(strings.Split(plain, ""), ":"))
	for _, value := range []string{plain, colon} {
		got, err := normalizeRootSHA256(value)
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("normalizeRootSHA256(%q) = %x, %v", value, got, err)
		}
	}
	for _, value := range []string{"", "abcd", strings.Repeat("g", 64)} {
		if _, err := normalizeRootSHA256(value); err == nil {
			t.Errorf("normalizeRootSHA256(%q) succeeded", value)
		}
	}
}

func TestVerifiedRootExactlyOneAndFingerprint(t *testing.T) {
	t.Parallel()
	root, _ := setupRoot(t)
	cert, _ := x509.ParseCertificate(root.Bytes)
	sum := sha256.Sum256(cert.Raw)
	if _, err := verifiedRoot(pem.EncodeToMemory(root), sum[:]); err != nil {
		t.Fatal(err)
	}
	wrong := bytes.Repeat([]byte{1}, sha256.Size)
	if _, err := verifiedRoot(pem.EncodeToMemory(root), wrong); err == nil {
		t.Fatal("wrong fingerprint accepted")
	}
	double := append(pem.EncodeToMemory(root), pem.EncodeToMemory(root)...)
	if _, err := verifiedRoot(double, sum[:]); err == nil {
		t.Fatal("two certificates accepted")
	}
	if _, err := verifiedRoot(append(pem.EncodeToMemory(root), []byte("junk")...), sum[:]); err == nil {
		t.Fatal("trailing data accepted")
	}
}

func TestSetupAdmissionPendingAndTokenLifecycle(t *testing.T) {
	for _, tt := range []struct {
		name         string
		status       Status
		state        agentv1.EnrollState
		wantEnroll   int
		wantPoll     int
		wantToken    bool
		wantLastCall string
		wantOutput   string
	}{
		{name: "newly admitted consumes token", state: agentv1.EnrollState_ENROLL_STATE_ADMITTED, wantEnroll: 1, wantLastCall: "restart myownpki-agent.service", wantOutput: "enabled and running"},
		{name: "pending keeps token and service disabled", state: agentv1.EnrollState_ENROLL_STATE_PENDING_APPROVAL, wantEnroll: 1, wantToken: true, wantLastCall: "disable myownpki-agent.service", wantOutput: "systemctl enable --now"},
		{name: "pending poll keeps token", status: Status{Enrollment: "request"}, state: agentv1.EnrollState_ENROLL_STATE_ADMITTED, wantPoll: 1, wantToken: true, wantLastCall: "restart myownpki-agent.service"},
		{name: "already enrolled does not consume token", status: Status{Enrolled: true, AgentID: "agent"}, state: agentv1.EnrollState_ENROLL_STATE_ADMITTED, wantToken: true, wantLastCall: "restart myownpki-agent.service"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newSetupFixture(t, tt.state)
			fixture.agent.status = tt.status
			tokenFile := filepath.Join(fixture.dir, "join-token")
			if err := os.WriteFile(tokenFile, []byte("secret-token\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			fixture.opts.TokenFile = tokenFile
			if err := Setup(context.Background(), fixture.opts); err != nil {
				t.Fatal(err)
			}
			if fixture.agent.enrollCalls != tt.wantEnroll || fixture.agent.pollCalls != tt.wantPoll {
				t.Fatalf("enroll=%d poll=%d", fixture.agent.enrollCalls, fixture.agent.pollCalls)
			}
			_, err := os.Stat(tokenFile)
			if tt.wantToken && err != nil {
				t.Fatalf("token removed: %v", err)
			}
			if !tt.wantToken && !os.IsNotExist(err) {
				t.Fatalf("token was not consumed: %v", err)
			}
			calls := fixture.runner.calls
			if len(calls) == 0 || calls[len(calls)-1] != tt.wantLastCall {
				t.Fatalf("systemctl calls: %v", calls)
			}
			if !strings.Contains(fixture.stdout.String(), tt.wantOutput) && tt.wantOutput != "" {
				t.Fatalf("output %q lacks %q", fixture.stdout.String(), tt.wantOutput)
			}
			if strings.Contains(fixture.stdout.String()+fixture.stderr.String(), "secret-token") {
				t.Fatal("token was logged")
			}
		})
	}
}

func TestSetupPreservesConfigAndReplacesPristineExampleOnce(t *testing.T) {
	fixture := newSetupFixture(t, agentv1.EnrollState_ENROLL_STATE_PENDING_APPROVAL)
	example, err := deploy.AgentExample("agent.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G306 -- test the packaged world-readable conffile mode.
	if err = os.WriteFile(fixture.opts.ConfigPath, example, 0o644); err != nil {
		t.Fatal(err)
	}
	if err = Setup(context.Background(), fixture.opts); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(fixture.opts.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, example) || !bytes.Contains(first, []byte("hostname: \"proxy1.homelab.lan\"")) {
		t.Fatalf("pristine example was not replaced:\n%s", first)
	}
	custom := bytes.Replace(first, []byte(`log_level: "info"`), []byte(`log_level: "debug"`), 1)
	// #nosec G306 G703 -- verify that a custom conffile and its contents are preserved.
	if err = os.WriteFile(fixture.opts.ConfigPath, custom, 0o640); err != nil {
		t.Fatal(err)
	}
	fixture.agent.status = Status{Enrolled: true}
	fixture.opts.Server = "https://changed.homelab.lan:8444"
	if err = Setup(context.Background(), fixture.opts); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(fixture.opts.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, custom) {
		t.Fatalf("custom configuration changed:\n%s", got)
	}
}

func TestSetupWebrootStandaloneModesAndAssets(t *testing.T) {
	for _, tt := range []struct {
		name       string
		webroot    bool
		lowPorts   bool
		wantLow    bool
		wantConfig string
	}{
		{name: "standalone", wantLow: true, wantConfig: `challenge: "standalone"`},
		{name: "webroot", webroot: true, wantConfig: `challenge: "webroot"`},
		{name: "webroot low ports", webroot: true, lowPorts: true, wantLow: true, wantConfig: `challenge: "webroot"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newSetupFixture(t, agentv1.EnrollState_ENROLL_STATE_PENDING_APPROVAL)
			fixture.opts.LowPorts = tt.lowPorts
			if tt.webroot {
				fixture.opts.Webroot = filepath.Join(fixture.dir, "www")
				// #nosec G301 -- test the conventional webroot directory mode.
				if err := os.Mkdir(fixture.opts.Webroot, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := Setup(context.Background(), fixture.opts); err != nil {
				t.Fatal(err)
			}
			config, err := os.ReadFile(fixture.opts.ConfigPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(config, []byte(tt.wantConfig)) {
				t.Fatalf("config lacks %q:\n%s", tt.wantConfig, config)
			}
			_, err = os.Stat(filepath.Join(fixture.opts.DropinDir, "20-low-ports.conf"))
			if tt.wantLow != (err == nil) {
				t.Fatalf("low-ports presence error = %v, want %v", err, tt.wantLow)
			}
			paths, err := os.ReadFile(filepath.Join(fixture.opts.DropinDir, "10-paths.conf"))
			if err != nil {
				t.Fatal(err)
			}
			if tt.webroot && !bytes.Contains(paths, []byte(fixture.opts.Webroot)) {
				t.Fatalf("webroot not writable: %s", paths)
			}
			if runtime.GOOS != "windows" {
				for path, want := range map[string]os.FileMode{fixture.opts.ConfigPath: 0o644, fixture.opts.StateDir: 0o700, filepath.Join(filepath.Dir(fixture.opts.ConfigPath), "root.pem"): 0o600, fixture.opts.UnitPath: 0o644} {
					st, err := os.Stat(path)
					if err != nil || st.Mode().Perm() != want {
						t.Errorf("%s mode = %v, %v; want %o", path, st.Mode(), err, want)
					}
				}
			}
		})
	}
}

func TestSetupPreflightAndTokenValidationChangeNothing(t *testing.T) {
	fixture := newSetupFixture(t, agentv1.EnrollState_ENROLL_STATE_PENDING_APPROVAL)
	fixture.opts.RootSHA256 = strings.Repeat("00", 32)
	if err := Setup(context.Background(), fixture.opts); err == nil {
		t.Fatal("wrong root fingerprint accepted")
	}
	if _, err := os.Stat(fixture.opts.ConfigPath); !os.IsNotExist(err) {
		t.Fatalf("config created during failed preflight: %v", err)
	}
	if len(fixture.runner.calls) != 0 {
		t.Fatalf("systemd called during preflight: %v", fixture.runner.calls)
	}
	fixture = newSetupFixture(t, agentv1.EnrollState_ENROLL_STATE_PENDING_APPROVAL)
	tokenFile := filepath.Join(fixture.dir, "token")
	// #nosec G306 -- deliberately insecure mode must be rejected on Unix.
	if err := os.WriteFile(tokenFile, []byte("not-a-token"), 0o644); err != nil {
		t.Fatal(err)
	}
	fixture.opts.TokenFile = tokenFile
	if runtime.GOOS != "windows" {
		if err := Setup(context.Background(), fixture.opts); err == nil || !strings.Contains(err.Error(), "0600") {
			t.Fatalf("insecure token mode accepted: %v", err)
		}
	}
}

func TestSetupRejectsNonFQDNAndUnsafeTokenFiles(t *testing.T) {
	fixture := newSetupFixture(t, agentv1.EnrollState_ENROLL_STATE_PENDING_APPROVAL)
	fixture.opts.Hostname = "proxy1"
	if err := Setup(context.Background(), fixture.opts); err == nil || !strings.Contains(err.Error(), "not fully qualified") {
		t.Fatalf("non-FQDN accepted: %v", err)
	}
	if _, err := os.Stat(fixture.opts.ConfigPath); !os.IsNotExist(err) {
		t.Fatalf("config created for non-FQDN: %v", err)
	}

	fixture = newSetupFixture(t, agentv1.EnrollState_ENROLL_STATE_PENDING_APPROVAL)
	fixture.opts.TokenFile = fixture.dir
	if err := Setup(context.Background(), fixture.opts); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory accepted as token: %v", err)
	}

	fixture = newSetupFixture(t, agentv1.EnrollState_ENROLL_STATE_PENDING_APPROVAL)
	tokenFile := filepath.Join(fixture.dir, "large-token")
	if err := os.WriteFile(tokenFile, bytes.Repeat([]byte("x"), maxSetupTokenSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.opts.TokenFile = tokenFile
	if err := Setup(context.Background(), fixture.opts); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized token accepted: %v", err)
	}
}

func TestSetupPackagedAndTarballAssetsAreIdentical(t *testing.T) {
	t.Parallel()
	for name, path := range map[string]string{"agent.yaml": "agent.example.yaml", "unit": "systemd/myownpki-agent.service", "low-ports": "systemd/agent-low-ports.conf"} {
		embedded, err := deploy.AgentExample(name)
		if err != nil {
			t.Fatal(err)
		}
		disk, err := os.ReadFile(filepath.Join("..", "..", "deploy", filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(embedded, disk) {
			t.Errorf("%s differs between embedded package and tarball sources", name)
		}
	}
}

type setupFixture struct {
	dir    string
	opts   SetupOptions
	agent  *fakeSetupAgent
	runner *fakeSetupRunner
	stdout *bytes.Buffer
	stderr *bytes.Buffer
}

func newSetupFixture(t *testing.T, state agentv1.EnrollState) *setupFixture {
	t.Helper()
	dir := t.TempDir()
	// #nosec G301 -- temporary test configuration directory.
	if err := os.MkdirAll(filepath.Join(dir, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	root, _ := setupRoot(t)
	cert, err := x509.ParseCertificate(root.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(dir, "source-root.pem")
	if err := os.WriteFile(rootPath, pem.EncodeToMemory(root), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.Raw)
	fake := &fakeSetupAgent{result: &Result{State: state, AgentID: "agent-1", Message: "waiting"}}
	runner := &fakeSetupRunner{}
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	f := &setupFixture{dir: dir, agent: fake, runner: runner, stdout: stdout, stderr: stderr}
	f.opts = SetupOptions{Server: "https://pki.homelab.lan:8444", CABundle: rootPath, RootSHA256: hex.EncodeToString(sum[:]),
		Hostname: "proxy1.homelab.lan", ConfigPath: filepath.Join(dir, "etc", "agent.yaml"), StateDir: filepath.Join(dir, "state"),
		UnitPath: filepath.Join(dir, "systemd", "myownpki-agent.service"), DropinDir: filepath.Join(dir, "systemd", "myownpki-agent.service.d"),
		Stdout: stdout, Stderr: stderr}
	oldCheck, oldRunner, oldNew := setupPlatformCheck, setupSystemd, setupNewAgent
	setupPlatformCheck = func() error { return nil }
	setupSystemd = runner
	setupNewAgent = func(*Config, io.Writer, string) (setupAgent, error) { return fake, nil }
	t.Cleanup(func() { setupPlatformCheck, setupSystemd, setupNewAgent = oldCheck, oldRunner, oldNew })
	return f
}

func setupRoot(t *testing.T) (*pem.Block, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Setup test root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &pem.Block{Type: "CERTIFICATE", Bytes: der}, key
}
