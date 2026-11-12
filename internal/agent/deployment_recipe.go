package agent

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/recipe"
)

// ApplyRecipe fills the empty fields of spec from the recipe called name
// (docs/PHASE3.md §11.2): what the operator set explicitly wins. Lists are
// added to (sandbox directories), a hook of the recipe is defined only when
// the deployment ends up referencing it, and --low-ports is on when either
// the recipe or the operator wants it.
func ApplyRecipe(spec *DeploymentSpec, name string) error { return applyRecipe(spec, name, "") }

// applyRecipe: root is a test seam, put in front of every path the recipe brings.
func applyRecipe(spec *DeploymentSpec, name, root string) error {
	r, ok := recipe.Get(name)
	if !ok {
		return fmt.Errorf("unknown recipe %q – known: %s", name, strings.Join(recipe.Names(), ", "))
	}
	path := func(p string) string {
		if root == "" || p == "" {
			return p
		}
		return filepath.Join(root, filepath.FromSlash(p))
	}
	arg := func(a string) string {
		if strings.HasPrefix(a, "/") {
			return path(a)
		}
		return a
	}
	spec.Recipe, spec.recipeExample, spec.recipeNotes = r.Name, r.Example, r.Notes

	ownLocation := spec.Dir != "" || spec.Files != (Files{})
	if !ownLocation && (spec.Profile == "" || spec.Profile == r.Profile) {
		spec.Profile = r.Profile
		if r.Profile == ProfileNginx {
			spec.Dir = path(strings.ReplaceAll(r.Dir, "{name}", spec.Name))
		} else {
			spec.Files = Files{Certificate: path(r.Certificate), Chain: path(r.Chain), Fullchain: path(r.Fullchain), Key: path(r.Key)}
		}
	}
	for _, f := range []struct {
		field *string
		value string
	}{{&spec.Owner, r.Owner}, {&spec.Group, r.Group}, {&spec.KeyMode, r.KeyMode}, {&spec.Check, r.Check}} {
		if *f.field == "" {
			*f.field = f.value
		}
	}
	if spec.TestHook == "" {
		spec.TestHook = r.TestHook
	}
	if spec.ReloadHook == "" {
		spec.ReloadHook = r.ReloadHook
	}
	for _, h := range r.Hooks {
		if h.Name != spec.TestHook && h.Name != spec.ReloadHook || slices.ContainsFunc(spec.Hooks, func(own HookSpec) bool { return own.Name == h.Name }) {
			continue
		}
		command := make([]string, len(h.Command))
		for i, a := range h.Command {
			command[i] = arg(a)
		}
		spec.Hooks = append(spec.Hooks, HookSpec{Name: h.Name, Command: command})
	}
	for _, dir := range r.SandboxWrite {
		dir = path(dir)
		spec.recipeWrites = append(spec.recipeWrites, dir)
		if !slices.Contains(spec.SandboxWrite, dir) {
			spec.SandboxWrite = append(spec.SandboxWrite, dir)
		}
	}
	spec.LowPorts = spec.LowPorts || r.LowPorts
	return nil
}
