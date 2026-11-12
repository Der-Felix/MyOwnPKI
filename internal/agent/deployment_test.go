package agent

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite the golden files of testdata/edit")

// editFixture is a host in a temporary directory: agent.yaml, the unit and
// its drop-in directory, the directories agent.yaml mentions, a recorder for
// systemctl and no root check.
type editFixture struct {
	t       *testing.T
	root    string
	config  string
	unit    string
	dropins string
	runner  *fakeSetupRunner
	stdout  *bytes.Buffer
	stderr  *bytes.Buffer
}

func newEditFixture(t *testing.T, input string) *editFixture {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"etc", "state", "www", "ssl", "bin", "systemd", "log-a", "mail"} {
		// #nosec G301 -- test directories.
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f := &editFixture{t: t, root: root, config: filepath.Join(root, "etc", "agent.yaml"), unit: filepath.Join(root, "systemd", "myownpki-agent.service"),
		runner: &fakeSetupRunner{}, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	f.dropins = f.unit + ".d"
	f.write(f.config, strings.ReplaceAll(input, "@ROOT@", filepath.ToSlash(root)))
	f.write(f.unit, "[Unit]\n")
	oldCheck, oldRunner, oldWrite := editPlatformCheck, setupSystemd, editWriteFile
	editPlatformCheck = func(string) error { return nil }
	setupSystemd = f.runner
	t.Cleanup(func() { editPlatformCheck, setupSystemd, editWriteFile = oldCheck, oldRunner, oldWrite })
	return f
}

func (f *editFixture) write(path, content string) {
	f.t.Helper()
	// #nosec G301 G306 G703 -- test files in a temporary directory.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		f.t.Fatal(err)
	}
	// #nosec G306 G703 -- test files in a temporary directory.
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
}

func (f *editFixture) read(path string) string {
	f.t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		f.t.Fatal(err)
	}
	return string(data)
}

func (f *editFixture) p(parts ...string) string {
	return filepath.Join(append([]string{f.root}, parts...)...)
}

func (f *editFixture) edit() EditOptions {
	f.stdout.Reset()
	f.stderr.Reset()
	return EditOptions{ConfigPath: f.config, UnitPath: f.unit, Stdout: f.stdout, Stderr: f.stderr}
}

func (f *editFixture) dry() EditOptions {
	e := f.edit()
	e.DryRun = true
	return e
}

// normalize makes output comparable across systems: the temporary root
// becomes @ROOT@ and YAML-escaped backslashes become slashes.
func (f *editFixture) normalize(s string) string {
	s = strings.ReplaceAll(s, strings.ReplaceAll(f.root, `\`, `\\`), "@ROOT@")
	s = strings.ReplaceAll(s, `\\`, "/")
	s = strings.ReplaceAll(s, filepath.ToSlash(f.root), "@ROOT@")
	s = strings.ReplaceAll(s, f.root, "@ROOT@")
	return strings.ReplaceAll(s, `\`, "/")
}

// tree is every file below the root with its content and mode, to prove that
// a command changed nothing.
func (f *editFixture) tree() map[string]string {
	f.t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(f.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(f.root, path)
		if d.Type()&fs.ModeSymlink != 0 {
			out[rel] = "symlink"
			return nil
		}
		if d.IsDir() {
			out[rel] = "dir"
			return nil
		}
		// #nosec G122 -- test helper over a private temporary directory.
		data, err := os.ReadFile(path)
		out[rel] = string(data)
		return err
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "edit", name)
	if *updateGolden {
		// #nosec G306 G703 -- golden file in the source tree.
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != strings.ReplaceAll(string(want), "\r\n", "\n") {
		t.Errorf("%s differs:\n%s\nwant:\n%s", name, got, want)
	}
}

func (f *editFixture) nginxHooks() []HookSpec {
	return []HookSpec{{Name: "nginx-test", Command: []string{f.p("bin", "nginx"), "-t"}},
		{Name: "nginx-reload", Command: []string{f.p("bin", "systemctl"), "reload", "nginx"}}}
}

// --- golden: what an edit does to the file -----------------------------------

func TestEditGolden(t *testing.T) {
	const acme = "https://pki.homelab.lan/acme/directory"
	tests := []struct {
		name  string
		input string
		add   func(f *editFixture) AddOptions
		// remove
		remove     string
		prunePaths bool
		golden     string
	}{
		{name: "fresh file from setup, first nginx deployment", input: "fresh.in.yaml", golden: "fresh.out.yaml",
			add: func(f *editFixture) AddOptions {
				return AddOptions{Spec: DeploymentSpec{Name: "proxy", Dir: f.p("ssl", "proxy"), Hooks: f.nginxHooks(), TestHook: "nginx-test", ReloadHook: "nginx-reload",
					Check: "127.0.0.1:443", SandboxWrite: []string{f.p("log-a")}, LowPorts: true, ACMEDirectory: acme}}
			}},
		{name: "comments and blank lines, a second deployment shares the hooks", input: "commented.in.yaml", golden: "commented.out.yaml",
			add: func(f *editFixture) AddOptions {
				return AddOptions{Spec: DeploymentSpec{Name: "api", Names: []string{"API.homelab.lan."}, Dir: f.p("ssl", "api"),
					// the same command lines under the same and under a new name
					Hooks:    []HookSpec{{Name: "nginx-test", Command: []string{filepath.ToSlash(f.p("bin", "nginx")), "-t"}}, {Name: "nginx-reload-api", Command: []string{filepath.ToSlash(f.p("bin", "systemctl")), "reload", "nginx"}}},
					TestHook: "nginx-test", ReloadHook: "nginx-reload-api", Check: "127.0.0.1:443"}}
			}},
		{name: "block lists stay block lists", input: "blocklists.in.yaml", golden: "blocklists.out.yaml",
			add: func(f *editFixture) AddOptions {
				return AddOptions{CreateDirs: true, Spec: DeploymentSpec{Name: "imap", Profile: ProfileFile, Files: Files{Fullchain: f.p("mail", "imap", "fullchain.pem"), Key: f.p("mail", "imap", "privkey.pem")},
					Hooks: []HookSpec{{Name: "imap-reload", Command: []string{f.p("bin", "systemctl"), "reload", "dovecot"}}}, ReloadHook: "imap-reload", Challenge: ChallengeStandalone,
					Owner: "root", Group: "root", KeyMode: "0640", SandboxWrite: []string{f.p("log-b"), f.p("log-a")}, LowPorts: true}}
			}},
		{name: "empty hooks, paths and deployments", input: "nulls.in.yaml", golden: "nulls.out.yaml",
			add: func(f *editFixture) AddOptions {
				return AddOptions{Spec: DeploymentSpec{Name: "proxy", Dir: f.p("ssl", "proxy"), Challenge: ChallengeStandalone, Hooks: f.nginxHooks()[:1], TestHook: "nginx-test", ACMEDirectory: acme}}
			}},
		{name: "remove keeps paths", input: "commented.in.yaml", remove: "site", golden: "remove.out.yaml"},
		{name: "remove with prune-paths", input: "commented.in.yaml", remove: "site", prunePaths: true, golden: "remove-prune.out.yaml"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "edit", tt.input))
			if err != nil {
				t.Fatal(err)
			}
			f := newEditFixture(t, string(raw))
			if tt.remove != "" {
				err = RemoveDeployment(context.Background(), RemoveOptions{EditOptions: f.edit(), Name: tt.remove, PrunePaths: tt.prunePaths})
			} else {
				opts := tt.add(f)
				opts.EditOptions = f.edit()
				err = AddDeployment(context.Background(), opts)
			}
			if err != nil {
				t.Fatal(err)
			}
			golden(t, tt.golden, f.normalize(f.read(f.config)))
			// The result is what the loader of "run" accepts, and a backup holds the old file.
			if _, err = LoadConfig(f.config); err != nil {
				t.Fatal(err)
			}
			if f.read(f.config+".bak") != strings.ReplaceAll(string(raw), "@ROOT@", filepath.ToSlash(f.root)) {
				t.Error("agent.yaml.bak is not the previous file")
			}
		})
	}
}

// A second run of the same command is refused and changes nothing; a rewrite
// of the result by "sandbox sync" is a no-op.
func TestAddTwiceIsRefusedAndSyncIsIdempotent(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "edit", "fresh.in.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	f := newEditFixture(t, string(raw))
	add := func() error {
		return AddDeployment(context.Background(), AddOptions{EditOptions: f.edit(), Spec: DeploymentSpec{Name: "proxy", Dir: f.p("ssl", "proxy"), Hooks: f.nginxHooks(),
			TestHook: "nginx-test", ReloadHook: "nginx-reload", SandboxWrite: []string{f.p("log-a")}, LowPorts: true, ACMEDirectory: "https://pki.homelab.lan/acme/directory"}})
	}
	if err = add(); err != nil {
		t.Fatal(err)
	}
	before := f.tree()
	err = add()
	if err == nil || err.Error() != `deployment "proxy" exists – pick another name or run "deployment remove proxy" first` {
		t.Fatalf("second add: %v", err)
	}
	if !sameTree(before, f.tree()) {
		t.Error("a refused add changed the host")
	}
	if err = SyncSandbox(context.Background(), SyncOptions{EditOptions: f.edit()}); err != nil {
		t.Fatal(err)
	}
	if !sameTree(before, f.tree()) {
		t.Error("sandbox sync after add changed the host")
	}
	if !strings.Contains(f.stdout.String(), "nothing to do") {
		t.Errorf("sync output: %s", f.stdout.String())
	}
}

func sameTree(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// --- the commands: what is written, in which order, and what is refused ------

func TestAddWritesDropinsAndReloadsButDoesNotRestart(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "edit", "fresh.in.yaml"))
	f := newEditFixture(t, string(raw))
	opts := AddOptions{EditOptions: f.edit(), Spec: DeploymentSpec{Name: "proxy", Dir: f.p("ssl", "proxy"), Hooks: f.nginxHooks(), TestHook: "nginx-test", ReloadHook: "nginx-reload",
		SandboxWrite: []string{f.p("log-a")}, LowPorts: true, ACMEDirectory: "https://pki.homelab.lan/acme/directory"}}
	if err := AddDeployment(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	paths := f.read(filepath.Join(f.dropins, "10-paths.conf"))
	for _, want := range []string{f.p("state"), f.p("www"), f.p("ssl"), f.p("log-a")} {
		if !strings.Contains(paths, want) {
			t.Errorf("10-paths.conf lacks %s:\n%s", want, paths)
		}
	}
	if _, err := os.Stat(filepath.Join(f.dropins, "20-low-ports.conf")); err != nil {
		t.Errorf("--low-ports: %v", err)
	}
	if got := strings.Join(f.runner.calls, ";"); got != "daemon-reload" {
		t.Errorf("systemctl calls = %q, want only daemon-reload", got)
	}
	if !strings.Contains(f.stdout.String(), "systemctl restart myownpki-agent") {
		t.Errorf("the restart command is not printed:\n%s", f.stdout.String())
	}
	// --restart does it.
	f.runner.calls = nil
	if err := RemoveDeployment(context.Background(), RemoveOptions{EditOptions: EditOptions{ConfigPath: f.config, UnitPath: f.unit, Restart: true}, Name: "proxy"}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.runner.calls, ";"); got != "restart myownpki-agent.service" {
		t.Errorf("remove --restart calls = %q", got)
	}
}

func TestAddWithoutUnitSkipsSystemctl(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "edit", "fresh.in.yaml"))
	f := newEditFixture(t, string(raw))
	if err := os.Remove(f.unit); err != nil {
		t.Fatal(err)
	}
	opts := AddOptions{EditOptions: f.edit(), Spec: DeploymentSpec{Name: "proxy", Dir: f.p("ssl", "proxy"), ACMEDirectory: "https://pki.homelab.lan/acme/directory"}}
	if err := AddDeployment(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if len(f.runner.calls) != 0 || !strings.Contains(f.stdout.String(), "The unit is not installed (run setup first) – files written, systemctl skipped.") {
		t.Errorf("calls %v, output:\n%s", f.runner.calls, f.stdout.String())
	}
}

func TestDryRunWritesNothingAndShowsTheDiff(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "edit", "fresh.in.yaml"))
	f := newEditFixture(t, string(raw))
	before := f.tree()
	opts := AddOptions{EditOptions: f.dry(), CreateDirs: true, Spec: DeploymentSpec{Name: "proxy", Dir: f.p("ssl", "new", "proxy"), Hooks: f.nginxHooks(), TestHook: "nginx-test", ReloadHook: "nginx-reload",
		SandboxWrite: []string{f.p("log-a")}, LowPorts: true, ACMEDirectory: "https://pki.homelab.lan/acme/directory"}}
	if err := AddDeployment(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if !sameTree(before, f.tree()) || len(f.runner.calls) != 0 {
		t.Fatalf("a dry run changed the host (calls %v)", f.runner.calls)
	}
	out := f.normalize(f.stdout.String())
	for _, want := range []string{"Dry run: nothing was written.", "--- a/agent.yaml", "+++ b/agent.yaml", "+  - name: \"proxy\"", "--- /dev/null", "+++ b/10-paths.conf", "+++ b/20-low-ports.conf", "Would create directory @ROOT@/ssl/new"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run lacks %q:\n%s", want, out)
		}
	}
}

func TestFailureOfTheSecondWriteRestoresTheDropins(t *testing.T) {
	// An existing host: a drop-in the operator edited, no low-ports drop-in.
	raw, _ := os.ReadFile(filepath.Join("testdata", "edit", "fresh.in.yaml"))
	f := newEditFixture(t, string(raw))
	oldDropin := "[Service]\nReadWritePaths=" + f.p("state") + " " + f.p("www") + " " + f.p("mine") + "\n"
	f.write(filepath.Join(f.dropins, "10-paths.conf"), oldDropin)
	before := f.tree()
	editWriteFile = func(path string, data []byte, mode os.FileMode) error {
		if filepath.Base(path) == "agent.yaml" {
			return errors.New("injected: disk full")
		}
		return atomicSetupFile(path, data, mode)
	}
	opts := AddOptions{EditOptions: f.edit(), Spec: DeploymentSpec{Name: "proxy", Dir: f.p("ssl", "proxy"), LowPorts: true, ACMEDirectory: "https://pki.homelab.lan/acme/directory"}}
	err := AddDeployment(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "injected") || !strings.Contains(err.Error(), "restored") {
		t.Fatalf("error = %v", err)
	}
	after := f.tree()
	delete(after, filepath.Join("etc", "agent.yaml.bak")) // written before the failing write; it equals agent.yaml
	if !sameTree(before, after) {
		t.Errorf("the host changed:\nbefore %v\nafter  %v", before, after)
	}
	if len(f.runner.calls) != 0 {
		t.Errorf("systemctl ran: %v", f.runner.calls)
	}
}

func TestAddRefusalsLeaveTheHostUntouched(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "edit", "fresh.in.yaml"))
	const acme = "https://pki.homelab.lan/acme/directory"
	tests := []struct {
		name string
		spec func(f *editFixture) DeploymentSpec
		want string // substring of the message, @ROOT@ expanded
	}{
		{name: "no ACME directory", spec: func(f *editFixture) DeploymentSpec { return DeploymentSpec{Name: "p", Dir: f.p("ssl", "p")} },
			want: "agent.yaml has no acme_directory – pass --acme-directory https://pki.homelab.lan/acme/directory"},
		{name: "http ACME directory", spec: func(f *editFixture) DeploymentSpec {
			return DeploymentSpec{Name: "p", Dir: f.p("ssl", "p"), ACMEDirectory: "http://pki.homelab.lan/acme/directory"}
		}, want: "--acme-directory"},
		{name: "bad name", spec: func(f *editFixture) DeploymentSpec {
			return DeploymentSpec{Name: "Proxy 1", Dir: f.p("ssl", "p"), ACMEDirectory: acme}
		}, want: "lower case letters, digits and '-'"},
		{name: "dir /etc", spec: func(f *editFixture) DeploymentSpec {
			return DeploymentSpec{Name: "p", Dir: "/etc", ACMEDirectory: acme}
		}, want: `--dir /etc: too broad – the agent may write only where "paths" allows; use a subdirectory such as /etc/ssl/myownpki`},
		{name: "dir /", spec: func(f *editFixture) DeploymentSpec {
			return DeploymentSpec{Name: "p", Dir: "/", ACMEDirectory: acme}
		}, want: "--dir /: too broad"},
		{name: "dir whose parent is /etc", spec: func(f *editFixture) DeploymentSpec {
			return DeploymentSpec{Name: "p", Dir: "/etc/certs", ACMEDirectory: acme}
		}, want: "--dir /etc/certs: its directory /etc is too broad"},
		{name: "key in /usr", spec: func(f *editFixture) DeploymentSpec {
			return DeploymentSpec{Name: "p", Files: Files{Fullchain: "/usr/fullchain.pem", Key: "/usr/key.pem"}, ACMEDirectory: acme}
		}, want: "its directory /usr is too broad"},
		{name: "webroot /var", spec: func(f *editFixture) DeploymentSpec {
			return DeploymentSpec{Name: "p", Dir: f.p("ssl", "p"), Challenge: ChallengeWebroot, Webroot: "/var", ACMEDirectory: acme}
		}, want: "--webroot /var: too broad"},
		{name: "sandbox-write /root", spec: func(f *editFixture) DeploymentSpec {
			return DeploymentSpec{Name: "p", Dir: f.p("ssl", "p"), SandboxWrite: []string{"/root"}, ACMEDirectory: acme}
		}, want: "--sandbox-write /root: too broad"},
		{name: "sandbox-write /home", spec: func(f *editFixture) DeploymentSpec {
			return DeploymentSpec{Name: "p", Dir: f.p("ssl", "p"), SandboxWrite: []string{"/home"}, ACMEDirectory: acme}
		}, want: "--sandbox-write /home: too broad"},
		{name: "dir below /proc", spec: func(f *editFixture) DeploymentSpec {
			return DeploymentSpec{Name: "p", Dir: "/proc/1/x/y", ACMEDirectory: acme}
		}, want: "too broad"},
		{name: "relative dir", spec: func(f *editFixture) DeploymentSpec {
			return DeploymentSpec{Name: "p", Dir: "ssl/p", ACMEDirectory: acme}
		}, want: "--dir ssl/p: an absolute path"},
		{name: "dotdot", spec: func(f *editFixture) DeploymentSpec {
			return DeploymentSpec{Name: "p", Dir: f.p("ssl") + "/../etc/p", ACMEDirectory: acme}
		}, want: "no .. path segments"},
		{name: "directory missing", spec: func(f *editFixture) DeploymentSpec {
			return DeploymentSpec{Name: "p", Files: Files{Fullchain: f.p("nope", "f.pem"), Key: f.p("nope", "k.pem")}, ACMEDirectory: acme}
		}, want: "@ROOT@/nope does not exist – create it, or pass --create-dirs"},
		{name: "sandbox directory missing", spec: func(f *editFixture) DeploymentSpec {
			return DeploymentSpec{Name: "p", Dir: f.p("ssl", "p"), SandboxWrite: []string{f.p("nolog")}, ACMEDirectory: acme}
		}, want: "@ROOT@/nolog does not exist – create it, or pass --create-dirs"},
		{name: "relative hook", spec: func(f *editFixture) DeploymentSpec {
			return DeploymentSpec{Name: "p", Dir: f.p("ssl", "p"), ACMEDirectory: acme, Hooks: []HookSpec{{Name: "nginx-test", Command: []string{"nginx", "-t"}}}}
		}, want: `hook "nginx-test": the first element must be an absolute path`},
		{name: "unknown reload hook", spec: func(f *editFixture) DeploymentSpec {
			return DeploymentSpec{Name: "p", Dir: f.p("ssl", "p"), ACMEDirectory: acme, ReloadHook: "nope"}
		}, want: `hook "nope" is not defined`},
		{name: "key mode for others", spec: func(f *editFixture) DeploymentSpec {
			return DeploymentSpec{Name: "p", Dir: f.p("ssl", "p"), ACMEDirectory: acme, KeyMode: "0644"}
		}, want: "key_mode"},
		{name: "name that is not a FQDN", spec: func(f *editFixture) DeploymentSpec {
			return DeploymentSpec{Name: "p", Dir: f.p("ssl", "p"), ACMEDirectory: acme, Names: []string{"proxy"}}
		}, want: "not fully qualified"},
		{name: "ip address", spec: func(f *editFixture) DeploymentSpec {
			return DeploymentSpec{Name: "p", Dir: f.p("ssl", "p"), ACMEDirectory: acme, Names: []string{"192.0.2.10"}}
		}, want: "IP identifiers"},
		{name: "profile needs more", spec: func(f *editFixture) DeploymentSpec {
			return DeploymentSpec{Name: "p", ACMEDirectory: acme}
		}, want: "pick a profile"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newEditFixture(t, string(raw))
			before := f.tree()
			err := AddDeployment(context.Background(), AddOptions{EditOptions: f.edit(), Spec: tt.spec(f)})
			want := strings.ReplaceAll(tt.want, "@ROOT@/", f.root+string(filepath.Separator))
			if want == "" {
				t.Fatal("a refusal needs a message")
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("error = %v, want %q", err, want)
			}
			if !sameTree(before, f.tree()) || len(f.runner.calls) != 0 {
				t.Errorf("a refused add changed the host (calls %v)", f.runner.calls)
			}
		})
	}
}

func TestAddRefusesWhatTheEditorCannotKeep(t *testing.T) {
	for _, name := range []string{"anchors", "twodocs", "mergekey"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "edit", name+".in.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			f := newEditFixture(t, string(raw))
			before := f.tree()
			err = AddDeployment(context.Background(), AddOptions{EditOptions: f.edit(), Spec: DeploymentSpec{Name: "p", Dir: f.p("ssl", "p"), ACMEDirectory: "https://pki.homelab.lan/acme/directory"}})
			if name == "twodocs" {
				// The loader reads only the first document, the editor must not touch the rest.
				if err == nil || !strings.Contains(err.Error(), "several documents") {
					t.Fatalf("error = %v", err)
				}
			} else if err == nil || err.Error() != "agent.yaml uses anchors, aliases or several documents – edit it by hand and run config check" {
				t.Fatalf("error = %v", err)
			}
			if !sameTree(before, f.tree()) {
				t.Error("the host changed")
			}
		})
	}
}

func TestAddRefusesAnInvalidFileAndANonRootRun(t *testing.T) {
	f := newEditFixture(t, "server: http://pki.homelab.lan\n")
	before := f.tree()
	err := AddDeployment(context.Background(), AddOptions{EditOptions: f.edit(), Spec: DeploymentSpec{Name: "p"}})
	if err == nil || err.Error() != `agent.yaml is not valid yet – run "myownpki-agent config check" and fix it first; nothing was changed` {
		t.Fatalf("invalid file: %v", err)
	}
	editPlatformCheck = rootRequiredError
	err = AddDeployment(context.Background(), AddOptions{EditOptions: f.edit(), Spec: DeploymentSpec{Name: "p"}})
	if err == nil || err.Error() != "deployment add must run as root; nothing was changed" {
		t.Fatalf("non-root: %v", err)
	}
	for _, run := range []func() error{
		func() error {
			return RemoveDeployment(context.Background(), RemoveOptions{EditOptions: f.edit(), Name: "p"})
		},
		func() error { return SyncSandbox(context.Background(), SyncOptions{EditOptions: f.edit()}) },
	} {
		if err = run(); err == nil || !strings.Contains(err.Error(), "must run as root") {
			t.Fatalf("non-root: %v", err)
		}
	}
	if !sameTree(before, f.tree()) {
		t.Error("the host changed")
	}
}

func TestAddRefusesASymlinkOnTheWay(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "edit", "fresh.in.yaml"))
	f := newEditFixture(t, string(raw))
	elsewhere := t.TempDir()
	link := f.p("ssl", "link")
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	for name, spec := range map[string]DeploymentSpec{
		"nginx dir below a link": {Name: "p", Dir: filepath.Join(link, "p"), ACMEDirectory: "https://pki.homelab.lan/acme/directory"},
		"file target below link": {Name: "p", Files: Files{Fullchain: filepath.Join(link, "f.pem"), Key: filepath.Join(link, "k.pem")}, ACMEDirectory: "https://pki.homelab.lan/acme/directory"},
		"sandbox dir is a link":  {Name: "p", Dir: f.p("ssl", "p"), SandboxWrite: []string{link}, ACMEDirectory: "https://pki.homelab.lan/acme/directory"},
	} {
		before := f.tree()
		err := AddDeployment(context.Background(), AddOptions{EditOptions: f.edit(), Spec: spec})
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !sameTree(before, f.tree()) {
			t.Errorf("%s: the host changed", name)
		}
	}
	// A link below an existing paths entry that leads out is caught by the loader's own check.
	f2 := newEditFixture(t, strings.Replace(string(raw), `paths: ["@ROOT@/www"]`, `paths: ["@ROOT@/www", "@ROOT@/ssl"]`, 1))
	if err := os.Symlink(elsewhere, f2.p("ssl", "link")); err != nil {
		t.Skip(err)
	}
	err := AddDeployment(context.Background(), AddOptions{EditOptions: f2.edit(), Spec: DeploymentSpec{Name: "p", Dir: f2.p("ssl", "link", "p"), ACMEDirectory: "https://pki.homelab.lan/acme/directory"}})
	if err == nil || !strings.Contains(err.Error(), "not under paths") {
		t.Errorf("link out of a covered path: %v", err)
	}
}

// --- remove, list, sandbox sync ------------------------------------------------

func TestRemoveUnknownAndList(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "edit", "commented.in.yaml"))
	f := newEditFixture(t, string(raw))
	err := RemoveDeployment(context.Background(), RemoveOptions{EditOptions: f.edit(), Name: "nope"})
	if err == nil || !strings.Contains(err.Error(), `deployment "nope" does not exist (known: site)`) {
		t.Fatalf("error = %v", err)
	}
	var out bytes.Buffer
	if err = ListDeployments(&out, f.config); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"NAME", "site", "nginx", "site.homelab.lan", "test=nginx-test reload=nginx-reload", "127.0.0.1:443"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("list lacks %q:\n%s", want, out.String())
		}
	}
	if err = RemoveDeployment(context.Background(), RemoveOptions{EditOptions: f.edit(), Name: "site"}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err = ListDeployments(&out, f.config); err != nil || !strings.Contains(out.String(), "No deployments.") {
		t.Fatalf("%q, %v", out.String(), err)
	}
	if !strings.Contains(f.stdout.String(), "Deployed files and the agent's state are not touched") {
		t.Errorf("output: %s", f.stdout.String())
	}
}

func TestRemoveWritesTheConfigurationBeforeTheDropins(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "edit", "commented.in.yaml"))
	f := newEditFixture(t, string(raw))
	f.write(filepath.Join(f.dropins, "10-paths.conf"), "[Service]\nReadWritePaths="+f.p("state")+" "+f.p("www")+" "+f.p("ssl")+"\n")
	var order []string
	editWriteFile = func(path string, data []byte, mode os.FileMode) error {
		order = append(order, filepath.Base(path))
		return atomicSetupFile(path, data, mode)
	}
	if err := RemoveDeployment(context.Background(), RemoveOptions{EditOptions: f.edit(), Name: "site", PrunePaths: true}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(order, ","); got != "agent.yaml.bak,agent.yaml,10-paths.conf" {
		t.Errorf("write order = %s", got)
	}
	if got := f.read(filepath.Join(f.dropins, "10-paths.conf")); strings.Contains(got, f.p("ssl")) || !strings.Contains(got, f.p("www")) {
		t.Errorf("10-paths.conf after prune:\n%s", got)
	}
}

func TestAddWritesTheDropinsBeforeTheConfiguration(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "edit", "fresh.in.yaml"))
	f := newEditFixture(t, string(raw))
	var order []string
	editWriteFile = func(path string, data []byte, mode os.FileMode) error {
		order = append(order, filepath.Base(path))
		return atomicSetupFile(path, data, mode)
	}
	if err := AddDeployment(context.Background(), AddOptions{EditOptions: f.edit(), Spec: DeploymentSpec{Name: "p", Dir: f.p("ssl", "p"), LowPorts: true, ACMEDirectory: "https://pki.homelab.lan/acme/directory"}}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(order, ","); got != "10-paths.conf,20-low-ports.conf,agent.yaml.bak,agent.yaml" {
		t.Errorf("write order = %s", got)
	}
}

// A host as v0.3.4 left it keeps its hand-made entries through setup, sandbox
// sync and deployment add (docs/PHASE3.md §11.1 "setup regression").
func TestPreV035HostKeepsItsEntriesThroughEveryCommand(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "edit", "fresh.in.yaml"))
	f := newEditFixture(t, string(raw))
	logs := f.p("log-nginx")
	pathsFile := filepath.Join(f.dropins, "10-paths.conf")
	lowFile := filepath.Join(f.dropins, "20-low-ports.conf")
	f.write(pathsFile, "[Service]\nReadWritePaths="+f.p("state")+" "+f.p("www")+" "+logs+"\n")
	f.write(lowFile, "# by hand\n[Service]\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n")
	keeps := func(step string) {
		t.Helper()
		if got := f.read(pathsFile); !strings.Contains(got, logs) {
			t.Fatalf("%s lost the hand-made entry:\n%s", step, got)
		}
		if got := f.read(lowFile); got != "# by hand\n[Service]\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n" {
			t.Fatalf("%s changed the low-ports drop-in:\n%s", step, got)
		}
	}
	if err := SyncSandbox(context.Background(), SyncOptions{EditOptions: f.edit()}); err != nil {
		t.Fatal(err)
	}
	keeps("sandbox sync")
	if !strings.Contains(f.stdout.String(), logs) {
		t.Errorf("the kept entry is not reported:\n%s", f.stdout.String())
	}
	if err := AddDeployment(context.Background(), AddOptions{EditOptions: f.edit(), Spec: DeploymentSpec{Name: "p", Dir: f.p("ssl", "p"), ACMEDirectory: "https://pki.homelab.lan/acme/directory"}}); err != nil {
		t.Fatal(err)
	}
	keeps("deployment add")
	if !strings.Contains(f.read(pathsFile), f.p("ssl")) {
		t.Errorf("the new path is missing:\n%s", f.read(pathsFile))
	}
	if err := RemoveDeployment(context.Background(), RemoveOptions{EditOptions: f.edit(), Name: "p", PrunePaths: true}); err != nil {
		t.Fatal(err)
	}
	keeps("deployment remove --prune-paths")
	// --adopt records the entry, then --prune has nothing left to drop.
	if err := SyncSandbox(context.Background(), SyncOptions{EditOptions: f.edit(), Adopt: true}); err != nil {
		t.Fatal(err)
	}
	keeps("sandbox sync --adopt")
	if cfg, err := LoadConfig(f.config); err != nil || !slices.Contains(cfg.Sandbox.Write, logs) {
		t.Fatalf("adopt did not record %s: %+v, %v", logs, cfg, err)
	}
	before := f.tree()
	if err := SyncSandbox(context.Background(), SyncOptions{EditOptions: f.edit(), Prune: true}); err != nil {
		t.Fatal(err)
	}
	if !sameTree(before, f.tree()) {
		t.Error("--prune after --adopt changed something")
	}
}

func TestSyncSandboxPruneAddsAndRemoves(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "edit", "fresh.in.yaml"))
	f := newEditFixture(t, string(raw))
	pathsFile := filepath.Join(f.dropins, "10-paths.conf")
	f.write(pathsFile, "[Service]\nReadWritePaths="+f.p("state")+" "+f.p("old")+"\n")
	if err := SyncSandbox(context.Background(), SyncOptions{EditOptions: f.dry(), Prune: true}); err != nil {
		t.Fatal(err)
	}
	if got := f.read(pathsFile); !strings.Contains(got, f.p("old")) {
		t.Fatal("--dry-run wrote")
	}
	if err := SyncSandbox(context.Background(), SyncOptions{EditOptions: f.edit(), Prune: true}); err != nil {
		t.Fatal(err)
	}
	if got, want := f.read(pathsFile), "[Service]\nReadWritePaths="+f.p("state")+" "+f.p("www")+"\n"; got != want {
		t.Errorf("after --prune:\n%s\nwant:\n%s", got, want)
	}
	if err := SyncSandbox(context.Background(), SyncOptions{EditOptions: f.edit(), Adopt: true, Prune: true}); err == nil {
		t.Error("--adopt and --prune together were accepted")
	}
}

func TestSyncSandboxRemovesLowPortsOnlyForAnExplicitFalse(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "edit", "fresh.in.yaml"))
	f := newEditFixture(t, string(raw)+"sandbox:\n  low_ports: false\n")
	lowFile := filepath.Join(f.dropins, "20-low-ports.conf")
	f.write(lowFile, "[Service]\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n")
	if err := SyncSandbox(context.Background(), SyncOptions{EditOptions: f.edit()}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(lowFile); !os.IsNotExist(err) {
		t.Errorf("sandbox.low_ports: false left the drop-in: %v", err)
	}
	if got := strings.Join(f.runner.calls, ";"); got != "daemon-reload" {
		t.Errorf("calls = %q", got)
	}
}

// --- helpers -------------------------------------------------------------------

func TestSplitCommand(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    []string
		wantErr bool
	}{
		{in: "/usr/sbin/nginx -t", want: []string{"/usr/sbin/nginx", "-t"}},
		{in: "  /usr/bin/systemctl   reload  nginx ", want: []string{"/usr/bin/systemctl", "reload", "nginx"}},
		{in: `/usr/bin/pvenode cert set '/etc/ssl/my pve/fullchain.pem' "/etc/ssl/my pve/privkey.pem" --force 1`,
			want: []string{"/usr/bin/pvenode", "cert", "set", "/etc/ssl/my pve/fullchain.pem", "/etc/ssl/my pve/privkey.pem", "--force", "1"}},
		{in: `/bin/x "a \"quoted\" word" 'single \ stays'`, want: []string{"/bin/x", `a "quoted" word`, `single \ stays`}},
		{in: `/bin/x ''`, want: []string{"/bin/x", ""}},
		{in: `/bin/x $(reboot); id | cat`, want: []string{"/bin/x", "$(reboot);", "id", "|", "cat"}}, // no shell: these are plain words
		{in: "/bin/x 'unterminated", wantErr: true},
		{in: `/bin/x "unterminated`, wantErr: true},
		{in: "/bin/x\nreboot", wantErr: true},
		{in: "", want: nil},
	}
	for _, tt := range tests {
		got, err := SplitCommand(tt.in)
		if (err != nil) != tt.wantErr || !slices.Equal(got, tt.want) {
			t.Errorf("SplitCommand(%q) = %q, %v; want %q (error %v)", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestParseHookFlag(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	exe := filepath.Join(dir, "nginx")
	if h, err := ParseHookFlag("nginx-test=" + exe + " -t"); err != nil || h.Name != "nginx-test" || !slices.Equal(h.Command, []string{exe, "-t"}) {
		t.Errorf("good hook: %+v, %v", h, err)
	}
	for _, bad := range []string{"nginx-test", "=nginx -t", "nginx-test=nginx -t", "nginx-test=", "nginx-test='" + exe} {
		if _, err := ParseHookFlag(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := ParseHookFlag("nginx-test=nginx -t"); err == nil || err.Error() != `hook "nginx-test": the first element must be an absolute path` {
		t.Errorf("relative first element: %v", err)
	}
}

func TestBroadAndWideDirs(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"/", "/etc", "/etc/", "/usr", "/var", "/boot", "/dev", "/proc", "/sys", "/run", "/root", "/home", "/tmp", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/srv", "/mnt",
		"/proc/self", "/sys/kernel", "/dev/shm"} {
		if !broadDir(p) {
			t.Errorf("%s is not broad", p)
		}
	}
	for _, p := range []string{"/etc/ssl/myownpki", "/var/www/html", "/var/lib/myownpki-agent", "/srv/www", "/opt/app/certs", "/home/user/certs"} {
		if broadDir(p) {
			t.Errorf("%s is broad", p)
		}
	}
	for _, p := range []string{"/etc/nginx", "/etc/ssl", "/var/lib", "/var/log", "/usr/share"} {
		if !wideDir(p) {
			t.Errorf("%s is not wide", p)
		}
	}
	for _, p := range []string{"/etc/nginx/myownpki", "/var/log/nginx", "/var/www/html"} {
		if wideDir(p) {
			t.Errorf("%s is wide", p)
		}
	}
	cfg := &Config{Paths: []string{"/etc/nginx", "/var/www/html"}, Sandbox: Sandbox{Write: []string{"/var/log"}}}
	if w := cfg.Warnings(); len(w) != 2 || !strings.Contains(w[0], "/etc/nginx/myownpki") {
		t.Errorf("warnings = %q", w)
	}
}

func TestUnifiedDiff(t *testing.T) {
	t.Parallel()
	old := "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\n"
	updated := "a\nb\nc\nd\nE\nf\ng\nh\ni\nj\nk\n"
	// The two changes are 5 lines apart, so they share one hunk.
	want := "--- a/x\n+++ b/x\n@@ -2,9 +2,10 @@\n b\n c\n d\n-e\n+E\n f\n g\n h\n i\n j\n+k\n"
	if got := unifiedDiff("x", []byte(old), true, []byte(updated)); got != want {
		t.Errorf("diff:\n%s\nwant:\n%s", got, want)
	}
	if got := unifiedDiff("x", []byte(old), true, []byte(old)); got != "" {
		t.Errorf("equal files: %q", got)
	}
	if got, want := unifiedDiff("n", nil, false, []byte("one\ntwo\n")), "--- /dev/null\n+++ b/n\n@@ -0,0 +1,2 @@\n+one\n+two\n"; got != want {
		t.Errorf("new file:\n%s\nwant:\n%s", got, want)
	}
	far := strings.Repeat("x\n", 20)
	two := unifiedDiff("y", []byte("A\n"+far+"B\n"), true, []byte("a\n"+far+"b\n"))
	if strings.Count(two, "@@ -") != 2 {
		t.Errorf("distant changes should be two hunks:\n%s", two)
	}
}

func TestResolveHooks(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	systemctl, nginx, postfix, truth := filepath.Join(dir, "systemctl"), filepath.Join(dir, "nginx"), filepath.Join(dir, "postfix"), filepath.Join(dir, "true")
	exeA, exeB := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	existing := map[string][]string{"nginx-reload": {systemctl, "reload", "nginx"}, "other": {truth}}
	add, reuse, err := resolveHooks(existing, []HookSpec{
		{Name: "nginx-reload", Command: []string{systemctl, "reload", "nginx"}}, // same name, same command: reused as is
		{Name: "web-reload", Command: []string{systemctl, "reload", "nginx"}},   // new name, known command: alias
		{Name: "nginx-test", Command: []string{nginx, "-t"}},                    // new
		{Name: "postfix-test", Command: []string{postfix, "check"}},             // new
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(add) != 2 || add[0].Name != "nginx-test" || add[1].Name != "postfix-test" {
		t.Errorf("new hooks = %+v", add)
	}
	if len(reuse) != 1 || reuse["web-reload"] != "nginx-reload" {
		t.Errorf("aliases = %v", reuse)
	}
	for name, wanted := range map[string][]HookSpec{
		"same name, other command": {{Name: "nginx-reload", Command: []string{systemctl, "restart", "nginx"}}},
		"twice":                    {{Name: "a", Command: []string{exeA}}, {Name: "a", Command: []string{exeB}}},
		"bad name":                 {{Name: "a b", Command: []string{exeA}}},
		"no command":               {{Name: "a"}},
	} {
		if _, _, err := resolveHooks(existing, wanted); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Hostile text in the flags ends in a refusal or in plain text, never in a
// command: there is no shell anywhere on this path.
func TestAddHostileInput(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "edit", "fresh.in.yaml"))
	for name, spec := range map[string]func(f *editFixture) DeploymentSpec{
		"command substitution in a name": func(f *editFixture) DeploymentSpec {
			return DeploymentSpec{Name: "p", Dir: f.p("ssl", "p"), Names: []string{"$(reboot).homelab.lan"}}
		},
		"newline in a name": func(f *editFixture) DeploymentSpec {
			return DeploymentSpec{Name: "p", Dir: f.p("ssl", "p"), Names: []string{"a.homelab.lan\nserver: x"}}
		},
		"quote in the check": func(f *editFixture) DeploymentSpec {
			return DeploymentSpec{Name: "p", Dir: f.p("ssl", "p"), Check: `127.0.0.1:443"; reboot`}
		},
		"newline in the name of the deployment": func(f *editFixture) DeploymentSpec {
			return DeploymentSpec{Name: "p\nhooks: x", Dir: f.p("ssl", "p")}
		},
	} {
		f := newEditFixture(t, string(raw))
		before := f.tree()
		s := spec(f)
		s.ACMEDirectory = "https://pki.homelab.lan/acme/directory"
		if err := AddDeployment(context.Background(), AddOptions{EditOptions: f.edit(), Spec: s}); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if !sameTree(before, f.tree()) {
			t.Errorf("%s: the host changed", name)
		}
	}
	// Owner and group are free text for the YAML; they must come out quoted and as one value.
	f := newEditFixture(t, string(raw))
	err := AddDeployment(context.Background(), AddOptions{EditOptions: f.edit(), Spec: DeploymentSpec{Name: "p", Dir: f.p("ssl", "p"), Owner: "root\nhooks: {x: [/bin/x]}",
		ACMEDirectory: "https://pki.homelab.lan/acme/directory"}})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(f.config)
	if err != nil || len(cfg.Hooks) != 0 || cfg.Deployments[0].Owner != "root\nhooks: {x: [/bin/x]}" {
		t.Errorf("owner text escaped its value: %+v, %v", cfg, err)
	}
}
