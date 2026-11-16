package agent

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Der-Felix/MyOwnPKI/internal/recipe"
)

const recipeACME = "https://pki.homelab.lan/acme/directory"

func freshFixture(t *testing.T) *editFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "edit", "fresh.in.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return newEditFixture(t, string(raw))
}

// Every recipe renders a deployment that passes the configuration validation
// (the loader of "run" and "config check"), and produces the drop-in entries
// of the table in docs/PHASE3.md §11.2 – in a temporary root.
func TestEveryRecipeRendersAValidDeployment(t *testing.T) {
	for _, name := range recipe.Names() {
		t.Run(name, func(t *testing.T) {
			f := freshFixture(t)
			spec := DeploymentSpec{Name: "svc", ACMEDirectory: recipeACME}
			if err := applyRecipe(&spec, name, f.root); err != nil {
				t.Fatal(err)
			}
			// The dry run first: it expands the recipe and writes nothing.
			before := f.tree()
			if err := AddDeployment(context.Background(), AddOptions{EditOptions: f.dry(), Spec: spec, CreateDirs: true}); err != nil {
				t.Fatal(err)
			}
			if !sameTree(before, f.tree()) {
				t.Fatal("the dry run changed the host")
			}
			dry := f.stdout.String()
			wantNote := name != "nginx"
			if got := strings.Contains(dry, "example recipe, test on a non-production host"); got != wantNote {
				t.Errorf("example wording present = %v, want %v:\n%s", got, wantNote, dry)
			}
			if wantNote && !strings.Contains(dry, "verify:") {
				t.Errorf("the dry run does not say what to verify:\n%s", dry)
			}
			if err := AddDeployment(context.Background(), AddOptions{EditOptions: f.edit(), Spec: spec, CreateDirs: true}); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(f.config)
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.Deployments) != 1 || cfg.Deployments[0].Name != "svc" || !slices.Equal(cfg.Deployments[0].Names, []string{"proxy1.homelab.lan"}) {
				t.Fatalf("deployments = %+v", cfg.Deployments)
			}
			r, _ := recipe.Get(name)
			d := cfg.Deployments[0]
			if d.Profile != r.Profile || d.Check != r.Check || d.Owner != r.Owner || d.Group != r.Group || d.KeyMode != r.KeyMode || d.ReloadHook == "" {
				t.Errorf("deployment = %+v", d)
			}
			// The drop-ins match the configuration, with the recipe's sandbox entries.
			described, err := DescribeDropins(cfg, f.dropins)
			if err != nil || !strings.Contains(described, "match agent.yaml") {
				t.Errorf("drop-ins do not match:\n%s\n%v", described, err)
			}
			paths := f.read(filepath.Join(f.dropins, "10-paths.conf"))
			for _, dir := range r.SandboxWrite {
				if !strings.Contains(paths, filepath.Join(f.root, filepath.FromSlash(dir))) {
					t.Errorf("10-paths.conf lacks the sandbox directory %s:\n%s", dir, paths)
				}
			}
			_, lowErr := os.Stat(filepath.Join(f.dropins, "20-low-ports.conf"))
			if r.LowPorts != (lowErr == nil) {
				t.Errorf("recipe low ports = %v, drop-in error = %v", r.LowPorts, lowErr)
			}
			// A second run of the same recipe is refused, the host stays as it is.
			after := f.tree()
			if err = AddDeployment(context.Background(), AddOptions{EditOptions: f.edit(), Spec: spec, CreateDirs: true}); err == nil || !strings.Contains(err.Error(), `deployment "svc" exists`) {
				t.Errorf("second run: %v", err)
			}
			if !sameTree(after, f.tree()) {
				t.Error("the refused second run changed the host")
			}
		})
	}
}

// The configuration a recipe writes, byte for byte. Only nginx is a recipe
// that ran on a live host; the others say so in their dry run.
func TestRecipeGolden(t *testing.T) {
	for _, name := range []string{"nginx", "apache2", "httpd", "haproxy"} {
		t.Run(name, func(t *testing.T) {
			f := freshFixture(t)
			spec := DeploymentSpec{Name: "test", Names: []string{"proxy.homelab.lan"}, ACMEDirectory: recipeACME}
			if err := applyRecipe(&spec, name, f.root); err != nil {
				t.Fatal(err)
			}
			if err := AddDeployment(context.Background(), AddOptions{EditOptions: f.edit(), Spec: spec, CreateDirs: true}); err != nil {
				t.Fatal(err)
			}
			golden(t, "recipe-"+name+".out.yaml", f.normalize(f.read(f.config)))
			if got := strings.Contains(f.stdout.String(), "example recipe"); got != (name != "nginx") {
				t.Errorf("example wording present = %v:\n%s", got, f.stdout.String())
			}
		})
	}
}

func TestRecipeExplicitFlagsWin(t *testing.T) {
	f := freshFixture(t)
	f.write(f.p("etc", "extra"), "")
	own := f.p("ssl", "own")
	mine := f.p("bin", "mine")
	spec := DeploymentSpec{Name: "test", Dir: own, Check: "127.0.0.1:8443", KeyMode: "0640", Group: "ssl-cert", ReloadHook: "my-reload",
		Hooks:        []HookSpec{{Name: "my-reload", Command: []string{mine, "--reload"}}},
		SandboxWrite: []string{f.p("log-a")}, ACMEDirectory: recipeACME}
	if err := applyRecipe(&spec, "nginx", f.root); err != nil {
		t.Fatal(err)
	}
	if err := AddDeployment(context.Background(), AddOptions{EditOptions: f.edit(), Spec: spec, CreateDirs: true}); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(f.config)
	if err != nil {
		t.Fatal(err)
	}
	d := cfg.Deployments[0]
	if d.Dir != own || d.Check != "127.0.0.1:8443" || d.KeyMode != "0640" || d.Group != "ssl-cert" || d.ReloadHook != "my-reload" || d.TestHook != "nginx-test" {
		t.Errorf("deployment = %+v", d)
	}
	// The recipe's reload hook is not defined when nothing refers to it.
	if _, ok := cfg.Hooks["nginx-reload"]; ok || cfg.Hooks["my-reload"] == nil || cfg.Hooks["nginx-test"] == nil {
		t.Errorf("hooks = %v", cfg.Hooks)
	}
	// Sandbox directories are added to the recipe's, low ports come from the recipe.
	if len(cfg.Sandbox.Write) != 2 || cfg.Sandbox.LowPorts == nil || !*cfg.Sandbox.LowPorts {
		t.Errorf("sandbox = %+v", cfg.Sandbox)
	}
}

// Two nginx deployments from the recipe share one test and one reload hook, so
// they are one rollback group.
func TestRecipeDeploymentsShareTheirHooks(t *testing.T) {
	f := freshFixture(t)
	for _, name := range []string{"first", "second"} {
		spec := DeploymentSpec{Name: name, ACMEDirectory: recipeACME}
		if err := applyRecipe(&spec, "nginx", f.root); err != nil {
			t.Fatal(err)
		}
		if err := AddDeployment(context.Background(), AddOptions{EditOptions: f.edit(), Spec: spec, CreateDirs: true}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	cfg, err := LoadConfig(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Hooks) != 2 || len(cfg.Deployments) != 2 || cfg.Deployments[0].ReloadHook != cfg.Deployments[1].ReloadHook {
		t.Errorf("hooks %v deployments %+v", cfg.Hooks, cfg.Deployments)
	}
	if len(cfg.Sandbox.Write) != 1 {
		t.Errorf("sandbox.write = %v", cfg.Sandbox.Write)
	}
}

func TestRecipeUnknownNameListsTheKnownOnes(t *testing.T) {
	t.Parallel()
	err := ApplyRecipe(&DeploymentSpec{Name: "x"}, "lighttpd")
	if err == nil || err.Error() != `unknown recipe "lighttpd" – known: apache2, dovecot, haproxy, httpd, nginx, postfix, proxmox` {
		t.Errorf("error = %v", err)
	}
}

// A recipe the operator overrides with a different profile does not push its
// own location in.
func TestRecipeKeepsTheOperatorsLocation(t *testing.T) {
	t.Parallel()
	spec := DeploymentSpec{Name: "x", Files: Files{Fullchain: "/srv/x/f.pem", Key: "/srv/x/k.pem"}}
	if err := ApplyRecipe(&spec, "nginx"); err != nil {
		t.Fatal(err)
	}
	if spec.Dir != "" || spec.Files.Fullchain != "/srv/x/f.pem" || spec.Profile != "" {
		t.Errorf("spec = %+v", spec)
	}
}

// DryRunDeploymentAdd is the entry the tests of other packages use: it needs no
// root, writes nothing, maps absolute paths below the root and reports the same
// refusals as the command.
func TestDryRunDeploymentAddNeedsNoRootAndWritesNothing(t *testing.T) {
	f := freshFixture(t)
	editPlatformCheck = rootRequiredError // a development machine: not root
	host := DryRunHost{Root: f.root, ConfigPath: f.config, UnitPath: f.unit}
	parse := func(args ...string) DeploymentAddCommand {
		t.Helper()
		fs := flag.NewFlagSet("deployment add", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		config := fs.String("config", f.config, "")
		cmd, err := ParseDeploymentAdd(fs, config, args)
		if err != nil {
			t.Fatalf("parse %v: %v", args, err)
		}
		return cmd
	}
	for _, d := range []string{"etc/ssl/myownpki", "var/log/nginx", "var/www/acme"} {
		if err := os.MkdirAll(filepath.Join(f.root, filepath.FromSlash(d)), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	cmd := parse("nginx", "--recipe", "nginx", "--name", "proxy1.homelab.lan", "--challenge", "webroot", "--webroot", "/var/www/acme", "--acme-directory", recipeACME)
	before := f.tree()
	out, err := DryRunDeploymentAdd(context.Background(), cmd, host)
	if err != nil {
		t.Fatalf("dry run: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Dry run: nothing was written.") || !strings.Contains(out, "nginx") {
		t.Errorf("output:\n%s", out)
	}
	if !sameTree(before, f.tree()) {
		t.Error("the dry run changed the host")
	}
	// The same arguments through the real command still need root.
	if err = AddDeployment(context.Background(), AddOptions{EditOptions: f.edit(), Spec: cmd.Spec}); err == nil || !strings.Contains(err.Error(), "must run as root") {
		t.Errorf("AddDeployment without root: %v", err)
	}
	// The refusals are those of the command; a ".." survives the mapping. (The
	// system-root rule works on the text of the path, so it is not tried on a
	// mapped root; internal/agentpath has its own table.)
	for args, want := range map[string]string{
		"--webroot var/www --challenge webroot":            "an absolute path",
		"--webroot /var/www/../../etc --challenge webroot": "no .. path segments",
	} {
		c := parse(append([]string{"nginx", "--recipe", "nginx", "--acme-directory", recipeACME}, strings.Fields(args)...)...)
		if _, err = DryRunDeploymentAdd(context.Background(), c, host); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", args, err, want)
		}
	}
	// A usage error is told apart from a refusal.
	fs := flag.NewFlagSet("deployment add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	config := fs.String("config", "", "")
	var usage *UsageError
	if _, err = ParseDeploymentAdd(fs, config, []string{"one", "two"}); !errors.As(err, &usage) || usage.Message == "" {
		t.Errorf("two names: %v", err)
	}
}

// HAProxy usually serves many certificates: two deployments from the recipe
// get a file each, do not collide, and share one test and one reload hook, so
// they are one reload group.
func TestHAProxyRecipeTwoDeploymentsShareOneReloadGroup(t *testing.T) {
	f := freshFixture(t)
	for _, name := range []string{"www", "api"} {
		spec := DeploymentSpec{Name: name, Names: []string{name + ".homelab.lan"}, ACMEDirectory: recipeACME}
		if err := applyRecipe(&spec, "haproxy", f.root); err != nil {
			t.Fatal(err)
		}
		if err := AddDeployment(context.Background(), AddOptions{EditOptions: f.edit(), Spec: spec, CreateDirs: true}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	cfg, err := LoadConfig(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Deployments) != 2 || len(cfg.Hooks) != 2 || cfg.Deployments[0].ReloadHook != cfg.Deployments[1].ReloadHook {
		t.Fatalf("hooks %v deployments %+v", cfg.Hooks, cfg.Deployments)
	}
	want := []string{f.p("etc", "ssl", "myownpki", "haproxy", "www.pem"), f.p("etc", "ssl", "myownpki", "haproxy", "api.pem")}
	for i, d := range cfg.Deployments {
		if filepath.FromSlash(d.Files.Combined) != want[i] || d.Files.Key != "" || d.Files.Fullchain != "" {
			t.Errorf("deployment %s: files %+v, want combined %s", d.Name, d.Files, want[i])
		}
	}
	if grouped := groups(cfg.Deployments); len(grouped) != 1 || len(grouped[0].deployments) != 2 {
		t.Errorf("groups = %+v, want one group of both", grouped)
	}
	if len(cfg.Sandbox.Write) != 0 || (cfg.Sandbox.LowPorts != nil && *cfg.Sandbox.LowPorts) {
		t.Errorf("the HAProxy recipe widens the sandbox: %+v", cfg.Sandbox)
	}
	// A third deployment under the same name is refused, the file stays unique.
	spec := DeploymentSpec{Name: "www", ACMEDirectory: recipeACME}
	if err = applyRecipe(&spec, "haproxy", f.root); err != nil {
		t.Fatal(err)
	}
	if err = AddDeployment(context.Background(), AddOptions{EditOptions: f.edit(), Spec: spec, CreateDirs: true}); err == nil || !strings.Contains(err.Error(), `deployment "www" exists`) {
		t.Errorf("second www: %v", err)
	}
}

// {name} becomes a path segment, so only a name the agent accepts gets in: a
// "/" or ".." never reaches a path, whatever the recipe (the name is checked
// again when the deployment is added).
func TestRecipeNameCannotReachAPath(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"../etc", "a/b", "..", "a..b/c", `a\b`, "A", "a b", "a\nb", "", ".", "-a", "a/../../etc/cron.d/x", "%2e%2e"} {
		for _, rc := range []string{"nginx", "apache2", "httpd", "haproxy"} {
			spec := DeploymentSpec{Name: name}
			err := applyRecipe(&spec, rc, "")
			if err == nil {
				t.Errorf("%s with name %q was accepted: dir %q files %+v", rc, name, spec.Dir, spec.Files)
				continue
			}
			if spec.Dir != "" || spec.Files != (Files{}) {
				t.Errorf("%s with name %q: an error, but a path was set: %q %+v", rc, name, spec.Dir, spec.Files)
			}
		}
	}
	// Recipes without {name} in a path do not need a name for it.
	spec := DeploymentSpec{Name: "x/y"}
	if err := applyRecipe(&spec, "postfix", ""); err != nil || spec.Files.Fullchain != "/etc/ssl/myownpki/postfix/fullchain.pem" {
		t.Errorf("postfix: %v %+v", err, spec.Files)
	}
}
