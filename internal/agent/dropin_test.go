package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func sandboxConfig(dir string, mutate func(*Config)) *Config {
	cfg := &Config{StateDir: filepath.Join(dir, "state"), Paths: []string{filepath.Join(dir, "www"), filepath.Join(dir, "ssl")},
		Enrollment: Enrollment{Challenge: ChallengeWebroot, Webroot: filepath.Join(dir, "www")}}
	if mutate != nil {
		mutate(cfg)
	}
	return cfg
}

func boolPtr(b bool) *bool { return &b }

func TestRenderDropinsPathsTable(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	state, www, ssl := filepath.Join(dir, "state"), filepath.Join(dir, "www"), filepath.Join(dir, "ssl")
	logs := filepath.Join(dir, "log", "nginx")
	derivedLine := "ReadWritePaths=" + state + " " + www + " " + ssl
	tests := []struct {
		name        string
		existing    string // "" = no file
		have        bool
		cfg         func(*Config)
		opts        DropinOptions
		want        string // exact content; "=" = unchanged
		wantAdded   []string
		wantRemoved []string
		wantKept    []string
	}{
		{name: "fresh file", want: dropinHeader + "[Service]\n" + derivedLine + "\n", wantAdded: nil},
		{name: "as an older setup wrote it", have: true, existing: "[Service]\n" + derivedLine + "\n", want: "="},
		{name: "hand-made entry on the line is kept", have: true, existing: "[Service]\n" + derivedLine + " " + logs + "\n", want: "=", wantKept: []string{logs}},
		{name: "hand-made entry on its own line is kept", have: true, existing: "[Service]\n" + derivedLine + "\nReadWritePaths=" + logs + "\n", want: "=", wantKept: []string{logs}},
		{name: "comments and other directives are kept", have: true, existing: "# mine\n[Service]\nPrivateTmp=yes\n" + derivedLine + "\n# end\n", want: "="},
		{name: "a missing entry is appended to the last line", have: true, existing: "# mine\n[Service]\nReadWritePaths=" + state + " " + logs + "\n# end\n",
			want:      "# mine\n[Service]\nReadWritePaths=" + state + " " + logs + " " + www + " " + ssl + "\n# end\n",
			wantAdded: []string{www, ssl}, wantKept: []string{logs}},
		{name: "a new sandbox.write entry is added", have: true, existing: "[Service]\n" + derivedLine + "\n",
			cfg:  func(c *Config) { c.Sandbox.Write = []string{logs} },
			want: "[Service]\n" + derivedLine + " " + logs + "\n", wantAdded: []string{logs}},
		{name: "sandbox.write explains the entry, so nothing is kept", have: true, existing: "[Service]\n" + derivedLine + " " + logs + "\n",
			cfg: func(c *Config) { c.Sandbox.Write = []string{logs} }, want: "="},
		{name: "the dash prefix and a trailing slash still count as present", have: true, existing: "[Service]\nReadWritePaths=-" + state + " " + www + "/ " + ssl + "\n", want: "="},
		{name: "no Service section: one is appended", have: true, existing: "[Unit]\nDescription=x\n",
			want: "[Unit]\nDescription=x\n\n[Service]\n" + derivedLine + "\n", wantAdded: []string{state, www, ssl}},
		{name: "an empty file", have: true, existing: "", want: "\n[Service]\n" + derivedLine + "\n", wantAdded: []string{state, www, ssl}},
		{name: "Service section followed by another one", have: true, existing: "[Service]\nPrivateTmp=yes\n[Install]\nWantedBy=multi-user.target\n",
			want:      "[Service]\nPrivateTmp=yes\n" + derivedLine + "\n[Install]\nWantedBy=multi-user.target\n",
			wantAdded: []string{state, www, ssl}},
		{name: "a continuation line is read as one", have: true, existing: "[Service]\nReadWritePaths=" + state + " \\\n" + www + " " + ssl + " \\\n" + logs + "\n", want: "=", wantKept: []string{logs}},
		{name: "a reset hides what came before", have: true, existing: "[Service]\nReadWritePaths=" + state + " " + www + " " + ssl + "\nReadWritePaths=\nReadWritePaths=" + state + "\n",
			want:      "[Service]\nReadWritePaths=" + state + " " + www + " " + ssl + "\nReadWritePaths=\nReadWritePaths=" + state + " " + www + " " + ssl + "\n",
			wantAdded: []string{www, ssl}},
		{name: "prune drops what agent.yaml does not explain", have: true, existing: "# mine\n[Service]\n" + derivedLine + " " + logs + "\n",
			opts: DropinOptions{Prune: true}, want: "# mine\n[Service]\n" + derivedLine + "\n", wantRemoved: []string{logs}},
		{name: "prune removes a line that would be empty", have: true, existing: "[Service]\n" + derivedLine + "\nReadWritePaths=" + logs + "\n",
			opts: DropinOptions{Prune: true}, want: "[Service]\n" + derivedLine + "\n", wantRemoved: []string{logs}},
		{name: "drop removes only the named entry", have: true, existing: "[Service]\n" + derivedLine + " " + logs + " " + filepath.Join(dir, "other") + "\n",
			opts: DropinOptions{Drop: []string{logs}}, want: "[Service]\n" + derivedLine + " " + filepath.Join(dir, "other") + "\n",
			wantRemoved: []string{logs}, wantKept: []string{filepath.Join(dir, "other")}},
		{name: "drop never removes a derived entry", have: true, existing: "[Service]\n" + derivedLine + "\n",
			opts: DropinOptions{Drop: []string{www}}, want: "="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := sandboxConfig(dir, tt.cfg)
			plan, err := RenderDropins(cfg, DropinState{Paths: []byte(tt.existing), HavePaths: tt.have}, []byte("low"), tt.opts)
			if err != nil {
				t.Fatal(err)
			}
			want := tt.want
			if want == "=" {
				want = tt.existing
			}
			if string(plan.Paths) != want {
				t.Errorf("content:\n%s\nwant:\n%s", plan.Paths, want)
			}
			if tt.have && plan.PathsChanged != (want != tt.existing) {
				t.Errorf("PathsChanged = %v", plan.PathsChanged)
			}
			wantAdded := tt.wantAdded
			if !tt.have {
				wantAdded = []string{state, www, ssl}
			}
			if !slices.Equal(plan.Added, wantAdded) || !slices.Equal(plan.Removed, tt.wantRemoved) || !slices.Equal(plan.Kept, tt.wantKept) {
				t.Errorf("added %v removed %v kept %v; want %v %v %v", plan.Added, plan.Removed, plan.Kept, wantAdded, tt.wantRemoved, tt.wantKept)
			}
			// A second pass over the result changes nothing (idempotence).
			again, err := RenderDropins(cfg, DropinState{Paths: plan.Paths, HavePaths: true}, []byte("low"), tt.opts)
			if err != nil {
				t.Fatal(err)
			}
			if again.PathsChanged || !bytes.Equal(again.Paths, plan.Paths) {
				t.Errorf("second pass changed the file:\n%s", again.Paths)
			}
		})
	}
}

// The bug of v0.3.4 and before, as a model test: an entry that agent.yaml
// does not explain is never dropped by an ordinary run.
func TestRenderDropinsNeverWidensBeyondConfiguration(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := sandboxConfig(dir, nil)
	plan, err := RenderDropins(cfg, DropinState{}, []byte("low"), DropinOptions{})
	if err != nil {
		t.Fatal(err)
	}
	words := strings.Fields(strings.SplitN(strings.Split(string(plan.Paths), "ReadWritePaths=")[1], "\n", 2)[0])
	want := []string{cfg.StateDir, cfg.Paths[0], cfg.Paths[1]}
	if !slices.Equal(words, want) {
		t.Fatalf("a fresh drop-in has %v, want exactly %v", words, want)
	}
}

func TestRenderDropinsRefusesEntriesSystemdWouldSplit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for name, mutate := range map[string]func(*Config){
		"space in paths":       func(c *Config) { c.Paths = append(c.Paths, filepath.Join(dir, "my certs")) },
		"specifier in state":   func(c *Config) { c.StateDir = filepath.Join(dir, "%h") },
		"quote in sandbox":     func(c *Config) { c.Sandbox.Write = []string{filepath.Join(dir, `a"b`)} },
		"newline in sandbox":   func(c *Config) { c.Sandbox.Write = []string{filepath.Join(dir, "a\nb")} },
		"tab in paths":         func(c *Config) { c.Paths = append(c.Paths, filepath.Join(dir, "a\tb")) },
		"apostrophe in sandbx": func(c *Config) { c.Sandbox.Write = []string{filepath.Join(dir, "it's")} },
	} {
		if _, err := RenderDropins(sandboxConfig(dir, mutate), DropinState{}, nil, DropinOptions{}); err == nil || !strings.Contains(err.Error(), "drop-in") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRenderDropinsLowPorts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	asset := []byte("[Service]\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n")
	standaloneDeployment := func(c *Config) {
		c.Deployments = []Deployment{{Name: "proxy", Challenge: ChallengeStandalone}}
	}
	tests := []struct {
		name  string
		cfg   func(*Config)
		flag  bool
		file  []byte // nil = absent
		want  LowPortsAction
		notes int
	}{
		{name: "webroot, nothing asked, no file: stays absent", want: LowPortsKeep},
		{name: "webroot, nothing asked, file there: left as found", file: asset, want: LowPortsKeep},
		{name: "webroot, file there but edited: left as found", file: []byte("# mine\n"), want: LowPortsKeep},
		{name: "standalone enrollment writes it", cfg: func(c *Config) { c.Enrollment = Enrollment{Challenge: ChallengeStandalone} }, want: LowPortsWrite},
		{name: "standalone enrollment, file there", cfg: func(c *Config) { c.Enrollment = Enrollment{Challenge: ChallengeStandalone} }, file: asset, want: LowPortsKeep},
		{name: "standalone enrollment, edited file is not overwritten", cfg: func(c *Config) { c.Enrollment = Enrollment{Challenge: ChallengeStandalone} }, file: []byte("# mine\n"), want: LowPortsKeep, notes: 1},
		{name: "a standalone deployment writes it", cfg: standaloneDeployment, want: LowPortsWrite},
		{name: "the flag writes it", flag: true, want: LowPortsWrite},
		{name: "low_ports true writes it", cfg: func(c *Config) { c.Sandbox.LowPorts = boolPtr(true) }, want: LowPortsWrite},
		{name: "low_ports false removes it", cfg: func(c *Config) { c.Sandbox.LowPorts = boolPtr(false) }, file: asset, want: LowPortsRemove},
		{name: "low_ports false, no file: nothing to do", cfg: func(c *Config) { c.Sandbox.LowPorts = boolPtr(false) }, want: LowPortsKeep},
		{name: "low_ports false beats a standalone challenge", cfg: func(c *Config) { c.Sandbox.LowPorts = boolPtr(false); standaloneDeployment(c) }, file: asset, want: LowPortsRemove},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			state := DropinState{LowPorts: tt.file, HaveLowPorts: tt.file != nil}
			plan, err := RenderDropins(sandboxConfig(dir, tt.cfg), state, asset, DropinOptions{LowPorts: tt.flag})
			if err != nil {
				t.Fatal(err)
			}
			if plan.LowPorts != tt.want || len(plan.Notes) != tt.notes {
				t.Errorf("action %v notes %v; want %v and %d notes", plan.LowPorts, plan.Notes, tt.want, tt.notes)
			}
			if tt.want == LowPortsWrite && !bytes.Equal(plan.LowPortsData, asset) {
				t.Errorf("data = %q", plan.LowPortsData)
			}
		})
	}
	if _, err := RenderDropins(sandboxConfig(dir, func(c *Config) { c.Sandbox.LowPorts = boolPtr(false) }), DropinState{}, asset, DropinOptions{LowPorts: true}); err == nil {
		t.Error("--low-ports against sandbox.low_ports: false was accepted")
	}
}

func TestSandboxBlockIsValidated(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good := "server: https://pki.homelab.lan:8444\nca_bundle: " + yamlPath(filepath.Join(dir, "root.pem")) + "\nhostname: proxy1.homelab.lan\nstate_dir: " + yamlPath(filepath.Join(dir, "state")) + "\n"
	cfg, err := ParseConfig("good", []byte(good+"sandbox:\n  write: ["+yamlPath(filepath.Join(dir, "log"))+"]\n  low_ports: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sandbox.LowPorts == nil || *cfg.Sandbox.LowPorts || len(cfg.Sandbox.Write) != 1 {
		t.Errorf("sandbox = %+v", cfg.Sandbox)
	}
	for name, tc := range map[string]struct{ yaml, want string }{
		"relative":       {"sandbox:\n  write: [var/log/nginx]\n", "sandbox.write"},
		"dotdot":         {"sandbox:\n  write: [" + yamlPath(dir+string(filepath.Separator)+"a"+string(filepath.Separator)+".."+string(filepath.Separator)+"b") + "]\n", "without .."},
		"space":          {"sandbox:\n  write: [" + yamlPath(filepath.Join(dir, "a b")) + "]\n", "drop-in"},
		"unknown key":    {"sandbox:\n  read: [/x]\n", "field read not found"},
		"wrong low type": {"sandbox:\n  low_ports: maybe\n", "cannot unmarshal"},
	} {
		if _, err := ParseConfig(name, []byte(good+tc.yaml)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestDescribeDropins(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := sandboxConfig(dir, nil)
	dropins := filepath.Join(dir, "unit.d")
	got, err := DescribeDropins(cfg, dropins)
	if err != nil || !strings.Contains(got, "not installed") {
		t.Fatalf("%q, %v", got, err)
	}
	plan, err := RenderDropins(cfg, DropinState{}, nil, DropinOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err = writeDropins(dropins, plan); err != nil {
		t.Fatal(err)
	}
	if got, err = DescribeDropins(cfg, dropins); err != nil || !strings.Contains(got, "match agent.yaml") {
		t.Fatalf("%q, %v", got, err)
	}
	cfg.Sandbox.Write = []string{filepath.Join(dir, "log")}
	if got, err = DescribeDropins(cfg, dropins); err != nil || !strings.Contains(got, "differ") || !strings.Contains(got, "sandbox sync") {
		t.Fatalf("%q, %v", got, err)
	}
	if err = os.WriteFile(filepath.Join(dropins, dropinPathsName), append(plan.Paths, []byte("ReadWritePaths="+filepath.Join(dir, "mine")+"\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err = DescribeDropins(sandboxConfig(dir, nil), dropins); err != nil || !strings.Contains(got, "does not explain") {
		t.Fatalf("%q, %v", got, err)
	}
}
