package agent

import (
	"context"
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

func TestRecipeNginxGolden(t *testing.T) {
	f := freshFixture(t)
	spec := DeploymentSpec{Name: "test", Names: []string{"proxy.homelab.lan"}, ACMEDirectory: recipeACME}
	if err := applyRecipe(&spec, "nginx", f.root); err != nil {
		t.Fatal(err)
	}
	if err := AddDeployment(context.Background(), AddOptions{EditOptions: f.edit(), Spec: spec, CreateDirs: true}); err != nil {
		t.Fatal(err)
	}
	golden(t, "recipe-nginx.out.yaml", f.normalize(f.read(f.config)))
	if strings.Contains(f.stdout.String(), "example recipe") {
		t.Error("nginx is not an example recipe")
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
	err := ApplyRecipe(&DeploymentSpec{Name: "x"}, "apache")
	if err == nil || err.Error() != `unknown recipe "apache" – known: dovecot, nginx, postfix, proxmox` {
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
