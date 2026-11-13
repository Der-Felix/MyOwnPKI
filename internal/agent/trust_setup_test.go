package agent

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	agentv1 "github.com/Der-Felix/MyOwnPKI/internal/gen/myownpki/agent/v1"
)

// trustHostFor replaces the host of the trust commands for one test: a fake
// file system root with the anchors directory of a Debian host and a fake runner.
func trustHostFor(t *testing.T, dir, osRelease string) (*fakeTrustRunner, trustEnv) {
	t.Helper()
	runner := &fakeTrustRunner{}
	env := trustEnv{Root: filepath.Join(dir, "root"), Runner: runner, EUID: func() int { return 0 }}
	mkdirAll(t, env.path("/etc"))
	writeTestFile(t, env.path("/etc/os-release"), []byte(osRelease), 0o644)
	mkdirAll(t, env.path(trustDebian.Dir))
	old := trustHost
	trustHost = func() trustEnv { return env }
	t.Cleanup(func() { trustHost = old })
	return runner, env
}

func TestSetupSystemTrust(t *testing.T) {
	for _, tt := range []struct {
		name  string
		state agentv1.EnrollState
	}{
		{"admitted", agentv1.EnrollState_ENROLL_STATE_ADMITTED},
		{"waiting for approval", agentv1.EnrollState_ENROLL_STATE_PENDING_APPROVAL},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newSetupFixture(t, tt.state)
			runner, env := trustHostFor(t, fixture.dir, osReleaseDebian)
			fixture.opts.SystemTrust = true
			if err := Setup(context.Background(), fixture.opts); err != nil {
				t.Fatal(err)
			}
			if len(runner.calls) != 1 || strings.Join(runner.calls[0], " ") != "/usr/sbin/update-ca-certificates" {
				t.Fatalf("hook calls = %v", runner.calls)
			}
			target := filepath.Join(env.path(trustDebian.Dir), trustDebian.File)
			installed, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			rootCopy, err := os.ReadFile(filepath.Join(fixture.dir, "etc", "root.pem"))
			if err != nil || string(installed) != string(rootCopy) {
				t.Fatalf("the installed root is not the verified ca_bundle (%v)", err)
			}
			cfg, err := LoadConfig(fixture.opts.ConfigPath)
			if err != nil || cfg.SystemTrust == nil || cfg.SystemTrust.RootSHA256 != strings.ToLower(fixture.opts.RootSHA256) {
				t.Fatalf("recorded key: %+v, %v", cfg, err)
			}
			if !strings.Contains(fixture.stdout.String(), target) {
				t.Errorf("output lacks the file: %q", fixture.stdout.String())
			}
		})
	}
}

func TestSetupWithoutSystemTrustNeverTouchesTheTrustStore(t *testing.T) {
	fixture := newSetupFixture(t, agentv1.EnrollState_ENROLL_STATE_ADMITTED)
	old := trustHost
	trustHost = func() trustEnv {
		t.Error("setup without --system-trust reached the trust store")
		return defaultTrustEnv()
	}
	t.Cleanup(func() { trustHost = old })
	if err := Setup(context.Background(), fixture.opts); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(fixture.opts.ConfigPath)
	if err != nil || cfg.SystemTrust != nil {
		t.Fatalf("system_trust is off by default: %+v, %v", cfg, err)
	}
}

func TestSetupSystemTrustRefusesAnUnsupportedHostBeforeAnyChange(t *testing.T) {
	fixture := newSetupFixture(t, agentv1.EnrollState_ENROLL_STATE_ADMITTED)
	runner, _ := trustHostFor(t, fixture.dir, "ID=\"sles\"\nID_LIKE=\"suse opensuse\"\n")
	fixture.opts.SystemTrust = true
	err := Setup(context.Background(), fixture.opts)
	if err == nil || !strings.Contains(err.Error(), "--system-trust") || !strings.Contains(err.Error(), "Debian-family") {
		t.Fatalf("err = %v", err)
	}
	if _, statErr := os.Stat(fixture.opts.ConfigPath); !os.IsNotExist(statErr) {
		t.Error("agent.yaml was written")
	}
	if len(fixture.runner.calls) != 0 || len(runner.calls) != 0 {
		t.Errorf("something ran: %v %v", fixture.runner.calls, runner.calls)
	}
}

func TestSetupSystemTrustNotForADeniedHostAndAFailedHookIsReported(t *testing.T) {
	denied := newSetupFixture(t, agentv1.EnrollState_ENROLL_STATE_DENIED)
	runner, _ := trustHostFor(t, denied.dir, osReleaseDebian)
	denied.opts.SystemTrust = true
	if err := Setup(context.Background(), denied.opts); err == nil {
		t.Fatal("a denied enrollment was reported as success")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("a denied host reached the trust store: %v", runner.calls)
	}

	failing := newSetupFixture(t, agentv1.EnrollState_ENROLL_STATE_ADMITTED)
	runner, env := trustHostFor(t, failing.dir, osReleaseDebian)
	runner.err = os.ErrPermission
	failing.opts.SystemTrust = true
	err := Setup(context.Background(), failing.opts)
	if err == nil || !strings.Contains(err.Error(), "setup is done, but --system-trust failed") {
		t.Fatalf("err = %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(env.path(trustDebian.Dir), trustDebian.File)); !os.IsNotExist(statErr) {
		t.Error("the file stayed after a failed hook")
	}
	if calls := failing.runner.calls; len(calls) == 0 || calls[len(calls)-1] != "restart myownpki-agent.service" {
		t.Errorf("the host is not enrolled and running although only the trust store failed: %v", calls)
	}
}

// The unit and the drop-ins are the same with and without --system-trust: the
// confined process gets no new write access (docs/PHASE3.md §15, decision 4).
func TestSetupSystemTrustLeavesUnitAndDropinsUnchanged(t *testing.T) {
	snapshot := func(systemTrust bool) map[string]string {
		fixture := newSetupFixture(t, agentv1.EnrollState_ENROLL_STATE_ADMITTED)
		trustHostFor(t, fixture.dir, osReleaseDebian)
		fixture.opts.SystemTrust = systemTrust
		if err := Setup(context.Background(), fixture.opts); err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		read := func(path string) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			got[filepath.Base(path)] = strings.ReplaceAll(string(data), fixture.dir, "<dir>")
		}
		read(fixture.opts.UnitPath)
		entries, err := os.ReadDir(fixture.opts.DropinDir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			read(filepath.Join(fixture.opts.DropinDir, e.Name()))
		}
		return got
	}
	without, with := snapshot(false), snapshot(true)
	var names []string
	for name := range without {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 || len(with) != len(without) {
		t.Fatalf("files: %v vs %v", names, with)
	}
	for _, name := range names {
		if with[name] != without[name] {
			t.Errorf("%s differs with --system-trust:\n%s\nvs\n%s", name, with[name], without[name])
		}
	}
	for name, content := range with {
		if strings.Contains(content, "/etc/ssl") || strings.Contains(content, "/etc/pki") || strings.Contains(content, "/usr/local/share") {
			t.Errorf("%s widens the sandbox to a trust store path", name)
		}
	}
}
