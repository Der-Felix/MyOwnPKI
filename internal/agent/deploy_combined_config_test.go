package agent

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The validation of files.combined: alone it is valid, with any of the four
// other targets it is not, and it must obey the rules every target obeys.
func TestCombinedConfigMatrix(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		build func(dir string, cfg *Config, d *Deployment)
		want  string // "" = valid; else a text of the refusal
	}{
		{"combined alone", func(string, *Config, *Deployment) {}, ""},
		{"with key", func(dir string, _ *Config, d *Deployment) { d.Files.Key = filepath.Join(dir, "ssl", "k.pem") }, "not together"},
		{"with fullchain", func(dir string, _ *Config, d *Deployment) { d.Files.Fullchain = filepath.Join(dir, "ssl", "f.pem") }, "not together"},
		{"with certificate", func(dir string, _ *Config, d *Deployment) { d.Files.Certificate = filepath.Join(dir, "ssl", "c.pem") }, "not together"},
		{"with chain", func(dir string, _ *Config, d *Deployment) { d.Files.Chain = filepath.Join(dir, "ssl", "ch.pem") }, "not together"},
		{"relative", func(_ string, _ *Config, d *Deployment) { d.Files.Combined = "ssl/www.pem" }, "an absolute path"},
		{"dotdot", func(dir string, _ *Config, d *Deployment) {
			d.Files.Combined = filepath.Join(dir, "ssl") + string(filepath.Separator) + ".." + string(filepath.Separator) + "www.pem"
		}, "no .. path segments"},
		{"outside paths", func(_ string, _ *Config, d *Deployment) { d.Files.Combined = filepath.Join(t.TempDir(), "www.pem") }, "not under one of paths"},
		{"state_dir", func(_ string, cfg *Config, d *Deployment) { d.Files.Combined = filepath.Join(cfg.StateDir, "www.pem") }, "state_dir"},
		{"ca_bundle", func(_ string, cfg *Config, d *Deployment) { d.Files.Combined = cfg.CABundle }, "overlaps state_dir or ca_bundle"},
		{"mode 0644", func(_ string, _ *Config, d *Deployment) { d.KeyMode = "0644" }, "key_mode"},
		{"another deployment's combined file", func(_ string, cfg *Config, d *Deployment) {
			other := *d
			other.Name = "other"
			cfg.Deployments = append(cfg.Deployments, other)
		}, "also used by"},
		{"another deployment's key file", func(_ string, cfg *Config, d *Deployment) {
			other := *d
			other.Name = "other"
			other.Files = Files{Fullchain: filepath.Join(filepath.Dir(d.Files.Combined), "x.pem"), Key: d.Files.Combined}
			cfg.Deployments = append(cfg.Deployments, other)
		}, "also used by"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := realTempDir(t)
			cfg := &Config{Server: "https://pki.homelab.lan:8444", CABundle: filepath.Join(dir, "root.pem"), Hostname: "proxy1.homelab.lan", StateDir: filepath.Join(dir, "state"),
				LogLevel: "info", ACMEDirectory: "https://pki.homelab.lan/acme/directory", Enrollment: Enrollment{Challenge: ChallengeStandalone}, Paths: []string{dir}}
			d := Deployment{Name: "proxy", Profile: ProfileFile, Names: []string{"proxy1.homelab.lan"}, Challenge: ChallengeStandalone,
				Files: Files{Combined: filepath.Join(dir, "ssl", "www.pem")}}
			tc.build(dir, cfg, &d)
			cfg.Deployments = append([]Deployment{d}, cfg.Deployments...)
			err := cfg.Validate()
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case tc.want != "" && (!errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

// A file profile without any target still says what is missing.
func TestFileProfileNeedsATarget(t *testing.T) {
	t.Parallel()
	dir := realTempDir(t)
	cfg := &Config{Server: "https://pki.homelab.lan:8444", CABundle: filepath.Join(dir, "root.pem"), Hostname: "proxy1.homelab.lan", StateDir: filepath.Join(dir, "state"),
		LogLevel: "info", ACMEDirectory: "https://pki.homelab.lan/acme/directory", Enrollment: Enrollment{Challenge: ChallengeStandalone}, Paths: []string{dir},
		Deployments: []Deployment{{Name: "proxy", Profile: ProfileFile, Names: []string{"proxy1.homelab.lan"}, Challenge: ChallengeStandalone,
			Files: Files{Key: filepath.Join(dir, "ssl", "k.pem")}}}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "key and certificate or fullchain at least") {
		t.Errorf("error = %v", err)
	}
}

// An agent.yaml written by 0.3.10 has no combined key and parses to the same
// Config as before; a combined key is read and written back by name.
func TestAgentYAMLOfTheOlderReleaseParsesUnchanged(t *testing.T) {
	t.Parallel()
	f := newEditFixture(t, `server: "https://pki.homelab.lan:8444"
ca_bundle: "@ROOT@/etc/root.pem"
hostname: "proxy1.homelab.lan"
acme_directory: "https://pki.homelab.lan/acme/directory"
state_dir: "@ROOT@/state"
log_level: "info"
enrollment:
  challenge: "standalone"
paths: ["@ROOT@/ssl"]
deployments:
  - name: "mail"
    profile: "file"
    names: ["mail.homelab.lan"]
    challenge: "standalone"
    files:
      fullchain: "@ROOT@/ssl/fullchain.pem"
      key: "@ROOT@/ssl/privkey.pem"
`)
	cfg, err := LoadConfig(f.config)
	if err != nil {
		t.Fatal(err)
	}
	want := Files{Fullchain: filepath.ToSlash(f.p("ssl", "fullchain.pem")), Key: filepath.ToSlash(f.p("ssl", "privkey.pem"))}
	if cfg.Deployments[0].Files != want {
		t.Errorf("files = %+v, want %+v", cfg.Deployments[0].Files, want)
	}
	// An unknown key stays an error (an older agent refuses combined this way).
	bad := strings.Replace(f.read(f.config), "fullchain:", "bogus:", 1)
	f.write(f.config, bad)
	if _, err = LoadConfig(f.config); err == nil {
		t.Error("an unknown files key was accepted")
	}
}

// deployment add with a combined file writes one key, list names the file,
// the dry run shows it, remove names it as the deployment's footprint.
func TestCombinedAddListRemove(t *testing.T) {
	f := freshFixture(t)
	combined := f.p("ssl", "haproxy", "www.pem")
	spec := DeploymentSpec{Name: "ha", Names: []string{"www.homelab.lan"}, Files: Files{Combined: combined}, ACMEDirectory: recipeACME}
	before := f.tree()
	if err := AddDeployment(context.Background(), AddOptions{EditOptions: f.dry(), Spec: spec, CreateDirs: true}); err != nil {
		t.Fatal(err)
	}
	if !sameTree(before, f.tree()) || !strings.Contains(f.normalize(f.stdout.String()), "combined:") {
		t.Errorf("dry run changed the host or hides the file:\n%s", f.stdout.String())
	}
	if err := AddDeployment(context.Background(), AddOptions{EditOptions: f.edit(), Spec: spec, CreateDirs: true}); err != nil {
		t.Fatal(err)
	}
	written := f.normalize(f.read(f.config))
	for _, want := range []string{`    profile: "file"`, "    files:\n", `      combined: "@ROOT@/ssl/haproxy/www.pem"`} {
		if !strings.Contains(written, want) {
			t.Errorf("agent.yaml lacks %q:\n%s", want, written)
		}
	}
	for _, other := range []string{"certificate:", "fullchain:", "      key:", "chain:"} {
		if strings.Contains(written, other) {
			t.Errorf("agent.yaml names %q for a combined file:\n%s", other, written)
		}
	}
	cfg, err := LoadConfig(f.config)
	if err != nil || cfg.Deployments[0].Files != (Files{Combined: combined}) {
		t.Fatalf("reloaded files: %+v, %v", cfg.Deployments, err)
	}
	var out bytes.Buffer
	if err = ListDeployments(&out, f.config); err != nil || !strings.Contains(out.String(), combined) {
		t.Errorf("list: %v\n%s", err, out.String())
	}
	if got := footprint(cfg.Deployments[0]); !slices.Contains(got, combined) {
		t.Errorf("footprint = %v", got)
	}
	// Remove takes the entry out of agent.yaml; --prune-paths also drops the
	// directories only this deployment used.
	if err = RemoveDeployment(context.Background(), RemoveOptions{EditOptions: f.edit(), Name: "ha", PrunePaths: true}); err != nil {
		t.Fatal(err)
	}
	if cfg, err = LoadConfig(f.config); err != nil || len(cfg.Deployments) != 0 {
		t.Errorf("after remove: %+v, %v", cfg, err)
	}
}

// The flags and the completion of the spec refuse a mix of the one-file form
// and the others, and name --combined where the profile choice is explained.
func TestCombinedFlagAndSpecRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		spec DeploymentSpec
		want string
	}{
		"with key":       {DeploymentSpec{Name: "p", Files: Files{Combined: "/c.pem", Key: "/k.pem"}}, "use it alone"},
		"with fullchain": {DeploymentSpec{Name: "p", Files: Files{Combined: "/c.pem", Fullchain: "/f.pem"}}, "use it alone"},
		"with a dir":     {DeploymentSpec{Name: "p", Profile: ProfileFile, Dir: "/d", Files: Files{Combined: "/c.pem"}}, "takes no --dir"},
		"nginx profile":  {DeploymentSpec{Name: "p", Profile: ProfileNginx, Dir: "/d", Files: Files{Combined: "/c.pem"}}, "--combined"},
	} {
		t.Run(name, func(t *testing.T) {
			f := freshFixture(t)
			tc.spec.ACMEDirectory = recipeACME
			before := f.tree()
			err := AddDeployment(context.Background(), AddOptions{EditOptions: f.edit(), Spec: tc.spec})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want %q", err, tc.want)
			}
			if !sameTree(before, f.tree()) {
				t.Error("a refused add changed the host")
			}
		})
	}
}

// The flag is parsed, and the dry run maps the one file below the test root
// like every other target and writes nothing.
func TestCombinedFlagAndDryRun(t *testing.T) {
	f := freshFixture(t)
	editPlatformCheck = rootRequiredError
	host := DryRunHost{Root: f.root, ConfigPath: f.config, UnitPath: f.unit}
	if err := os.MkdirAll(filepath.Join(f.root, "etc", "ssl", "myownpki"), 0o750); err != nil {
		t.Fatal(err)
	}
	fs := flag.NewFlagSet("deployment add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	config := fs.String("config", f.config, "")
	cmd, err := ParseDeploymentAdd(fs, config, []string{"ha", "--combined", "/etc/ssl/myownpki/ha.pem", "--name", "www.homelab.lan",
		"--challenge", "standalone", "--acme-directory", recipeACME})
	if err != nil || cmd.Spec.Files != (Files{Combined: "/etc/ssl/myownpki/ha.pem"}) {
		t.Fatalf("parse: %+v, %v", cmd.Spec.Files, err)
	}
	before := f.tree()
	out, err := DryRunDeploymentAdd(context.Background(), cmd, host)
	if err != nil {
		t.Fatalf("dry run: %v\n%s", err, out)
	}
	if want := "combined:"; !strings.Contains(out, want) || strings.Contains(out, "fullchain:") {
		t.Errorf("output:\n%s", out)
	}
	if !sameTree(before, f.tree()) {
		t.Error("the dry run changed the host")
	}
}
