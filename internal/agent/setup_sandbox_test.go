package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentv1 "github.com/Der-Felix/MyOwnPKI/internal/gen/myownpki/agent/v1"
)

// The three bugs of docs/PHASE3.md §11 that setup had before v0.3.5. Each
// test uses a host as an older release left it (a hand-edited drop-in, a
// configuration with a deployment) and runs setup again, as "Update agent"
// does.

func webrootFixture(t *testing.T) *setupFixture {
	t.Helper()
	fixture := newSetupFixture(t, agentv1.EnrollState_ENROLL_STATE_PENDING_APPROVAL)
	fixture.opts.Webroot = filepath.Join(fixture.dir, "www")
	// #nosec G301 -- test webroot directory.
	if err := os.Mkdir(fixture.opts.Webroot, 0o755); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func readDropin(t *testing.T, fixture *setupFixture, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixture.opts.DropinDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// Bug 1: setup rewrote 10-paths.conf from state_dir and paths on every run
// and dropped what the operator had added (OPERATIONS §12.3: /var/log/nginx).
func TestSetupKeepsHandMadeReadWritePaths(t *testing.T) {
	fixture := webrootFixture(t)
	if err := Setup(context.Background(), fixture.opts); err != nil {
		t.Fatal(err)
	}
	manual := filepath.Join(fixture.dir, "log", "nginx")
	pathsFile := filepath.Join(fixture.opts.DropinDir, "10-paths.conf")
	// #nosec G306 -- systemd drop-in mode.
	if err := os.WriteFile(pathsFile, []byte(strings.TrimRight(readDropin(t, fixture, "10-paths.conf"), "\n")+" "+manual+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if err := Setup(context.Background(), fixture.opts); err != nil {
			t.Fatalf("run %d: %v", i+2, err)
		}
		if got := readDropin(t, fixture, "10-paths.conf"); !strings.Contains(got, manual) || !strings.Contains(got, fixture.opts.Webroot) {
			t.Fatalf("run %d lost an entry:\n%s", i+2, got)
		}
	}
}

// Bug 2: setup removed 20-low-ports.conf whenever enrollment was not
// standalone, but nginx hooks need it in webroot mode too (OPERATIONS §12.3).
func TestSetupKeepsLowPortsDropinInWebrootMode(t *testing.T) {
	fixture := webrootFixture(t)
	if err := Setup(context.Background(), fixture.opts); err != nil {
		t.Fatal(err)
	}
	lowPorts := filepath.Join(fixture.opts.DropinDir, "20-low-ports.conf")
	if _, err := os.Stat(lowPorts); !os.IsNotExist(err) {
		t.Fatalf("webroot mode wrote the drop-in by itself: %v", err)
	}
	asset, err := os.ReadFile(filepath.Join("..", "..", "deploy", "systemd", "agent-low-ports.conf"))
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G306 G703 -- test drop-in in a temporary directory.
	if err = os.WriteFile(lowPorts, asset, 0o644); err != nil {
		t.Fatal(err)
	}
	if err = Setup(context.Background(), fixture.opts); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(lowPorts); err != nil {
		t.Fatalf("setup removed the low-ports drop-in the operator installed: %v", err)
	}
}

// Bug 2b: needLowPort looked only at the enrollment challenge, so a
// deployment that answers http-01 standalone never got the capability.
func TestSetupLowPortsForStandaloneDeployment(t *testing.T) {
	fixture := webrootFixture(t)
	if err := Setup(context.Background(), fixture.opts); err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(fixture.opts.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	ssl := filepath.Join(fixture.dir, "ssl")
	// #nosec G301 -- test certificate directory.
	if err = os.Mkdir(ssl, 0o755); err != nil {
		t.Fatal(err)
	}
	withDeployment := strings.Replace(string(config), "paths: [", "acme_directory: \"https://pki.homelab.lan/acme/directory\"\npaths: ["+yamlPath(ssl)+", ", 1)
	withDeployment = strings.Replace(withDeployment, "deployments: []", "deployments:\n  - name: proxy\n    profile: nginx\n    names: [proxy1.homelab.lan]\n    challenge: standalone\n    dir: "+yamlPath(filepath.Join(ssl, "proxy"))+"\n", 1)
	// #nosec G306 G703 -- configuration file in a temporary directory.
	if err = os.WriteFile(fixture.opts.ConfigPath, []byte(withDeployment), 0o644); err != nil {
		t.Fatal(err)
	}
	if err = Setup(context.Background(), fixture.opts); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(fixture.opts.DropinDir, "20-low-ports.conf")); err != nil {
		t.Fatalf("a standalone deployment needs CAP_NET_BIND_SERVICE: %v", err)
	}
}

// Bug 3: a fresh agent.yaml had no acme_directory, which Validate requires as
// soon as a deployment exists. setup --acme-directory writes it.
func TestSetupWritesACMEDirectoryIntoNewConfig(t *testing.T) {
	fixture := newSetupFixture(t, agentv1.EnrollState_ENROLL_STATE_PENDING_APPROVAL)
	fixture.opts.ACMEDirectory = "https://pki.homelab.lan/acme/directory"
	if err := Setup(context.Background(), fixture.opts); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(fixture.opts.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfig(fixture.opts.ConfigPath, data)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ACMEDirectory != fixture.opts.ACMEDirectory {
		t.Fatalf("acme_directory = %q", cfg.ACMEDirectory)
	}
}

// A host as v0.3.4 left it: the drop-in written by setup plus the nginx log
// directory (OPERATIONS §12.3), and the low-ports drop-in installed by hand
// for "nginx -t" in webroot mode. An update runs setup again; the second and
// third run must not change a byte, and the operator is told what was kept.
func TestSetupOnAnExistingHostKeepsAndIsIdempotent(t *testing.T) {
	fixture := webrootFixture(t)
	if err := Setup(context.Background(), fixture.opts); err != nil {
		t.Fatal(err)
	}
	logs := filepath.Join(fixture.dir, "var-log-nginx")
	pathsFile := filepath.Join(fixture.opts.DropinDir, "10-paths.conf")
	lowPorts := filepath.Join(fixture.opts.DropinDir, "20-low-ports.conf")
	// #nosec G306 -- systemd drop-in mode.
	if err := os.WriteFile(pathsFile, []byte("[Service]\nReadWritePaths="+fixture.opts.StateDir+" "+fixture.opts.Webroot+" "+logs+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// #nosec G306 -- systemd drop-in mode.
	if err := os.WriteFile(lowPorts, []byte("# installed by hand\n[Service]\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshot := func() map[string]string {
		out := map[string]string{}
		for _, p := range []string{pathsFile, lowPorts, fixture.opts.ConfigPath, fixture.opts.UnitPath} {
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			out[p] = string(data)
		}
		return out
	}
	before := snapshot()
	fixture.stdout.Reset()
	for i := range 3 {
		if err := Setup(context.Background(), fixture.opts); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
		after := snapshot()
		for p, want := range before {
			if after[p] != want {
				t.Fatalf("run %d changed %s:\n%s\nwant:\n%s", i+1, p, after[p], want)
			}
		}
	}
	if out := fixture.stdout.String(); !strings.Contains(out, "Kept in 10-paths.conf") || !strings.Contains(out, logs) || strings.Contains(out, "Removed") {
		t.Fatalf("operator output:\n%s", out)
	}
}

// What the operator did not ask for is not added: a run over a drop-in that
// holds only the entries of agent.yaml adds nothing.
func TestSetupAddsOnlyWhatAgentYamlImplies(t *testing.T) {
	fixture := webrootFixture(t)
	if err := Setup(context.Background(), fixture.opts); err != nil {
		t.Fatal(err)
	}
	pathsFile := filepath.Join(fixture.opts.DropinDir, "10-paths.conf")
	// An older release wrote only the state directory when paths was empty.
	// #nosec G306 -- systemd drop-in mode.
	if err := os.WriteFile(pathsFile, []byte("[Service]\nReadWritePaths="+fixture.opts.StateDir+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fixture.stdout.Reset()
	if err := Setup(context.Background(), fixture.opts); err != nil {
		t.Fatal(err)
	}
	got := readDropin(t, fixture, "10-paths.conf")
	if want := "[Service]\nReadWritePaths=" + fixture.opts.StateDir + " " + fixture.opts.Webroot + "\n"; got != want {
		t.Fatalf("drop-in:\n%s\nwant:\n%s", got, want)
	}
	if !strings.Contains(fixture.stdout.String(), "Added to 10-paths.conf: "+fixture.opts.Webroot) {
		t.Fatalf("the addition was not reported:\n%s", fixture.stdout.String())
	}
}

func TestSetupLowPortsFlagAndExplicitFalse(t *testing.T) {
	fixture := webrootFixture(t)
	fixture.opts.LowPorts = true
	if err := Setup(context.Background(), fixture.opts); err != nil {
		t.Fatal(err)
	}
	lowPorts := filepath.Join(fixture.opts.DropinDir, "20-low-ports.conf")
	if _, err := os.Stat(lowPorts); err != nil {
		t.Fatalf("--low-ports did not write the drop-in: %v", err)
	}
	// Without the flag the file stays (left as found).
	fixture.opts.LowPorts = false
	if err := Setup(context.Background(), fixture.opts); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(lowPorts); err != nil {
		t.Fatalf("a run without the flag removed the drop-in: %v", err)
	}
	// Only an explicit sandbox.low_ports: false removes it.
	config, err := os.ReadFile(fixture.opts.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G306 G703 -- configuration file in a temporary directory.
	if err = os.WriteFile(fixture.opts.ConfigPath, append(config, []byte("sandbox:\n  low_ports: false\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	fixture.stdout.Reset()
	if err = Setup(context.Background(), fixture.opts); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(lowPorts); !os.IsNotExist(err) {
		t.Fatalf("sandbox.low_ports: false left the drop-in: %v", err)
	}
	if !strings.Contains(fixture.stdout.String(), "Removed 20-low-ports.conf") {
		t.Fatalf("the removal was not reported:\n%s", fixture.stdout.String())
	}
	// The flag against the explicit false is a conflict and changes nothing.
	fixture.opts.LowPorts = true
	if err = Setup(context.Background(), fixture.opts); err == nil || !strings.Contains(err.Error(), "sandbox.low_ports") {
		t.Fatalf("flag against low_ports: false: %v", err)
	}
}

func TestSetupRefusesAPathSystemdWouldSplitBeforeChangingAnything(t *testing.T) {
	fixture := webrootFixture(t)
	fixture.opts.StateDir = filepath.Join(fixture.dir, "state dir")
	if err := Setup(context.Background(), fixture.opts); err == nil || !strings.Contains(err.Error(), "drop-in") {
		t.Fatalf("a state directory with a space was accepted: %v", err)
	}
	if _, err := os.Stat(fixture.opts.UnitPath); !os.IsNotExist(err) {
		t.Fatalf("setup wrote the unit before refusing: %v", err)
	}
	if len(fixture.runner.calls) != 0 {
		t.Fatalf("systemd was called: %v", fixture.runner.calls)
	}
}

func TestSetupACMEDirectoryValidationAndExistingConfig(t *testing.T) {
	fixture := newSetupFixture(t, agentv1.EnrollState_ENROLL_STATE_PENDING_APPROVAL)
	fixture.opts.ACMEDirectory = "http://pki.homelab.lan/acme/directory"
	if err := Setup(context.Background(), fixture.opts); err == nil || !strings.Contains(err.Error(), "--acme-directory") {
		t.Fatalf("plain http accepted: %v", err)
	}
	if _, err := os.Stat(fixture.opts.ConfigPath); !os.IsNotExist(err) {
		t.Fatalf("config written by a refused run: %v", err)
	}
	fixture.opts.ACMEDirectory = ""
	if err := Setup(context.Background(), fixture.opts); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(fixture.opts.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	fixture.opts.ACMEDirectory = "https://pki.homelab.lan/acme/directory"
	fixture.stderr.Reset()
	if err = Setup(context.Background(), fixture.opts); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(fixture.opts.ConfigPath)
	if err != nil || string(after) != string(before) {
		t.Fatalf("an existing agent.yaml was changed: %v\n%s", err, after)
	}
	if !strings.Contains(fixture.stderr.String(), "acme_directory") {
		t.Fatalf("no notice about the preserved file: %q", fixture.stderr.String())
	}
}
