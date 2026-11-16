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

	// {name} is replaced in every path of the recipe, and only in paths. The
	// name becomes a path segment, so it must be a name the agent accepts
	// (lower case letters, digits, "-"): no "/", no "..".
	expand := func(p string) (string, error) {
		if strings.Contains(p, "{name}") && !nameRE.MatchString(spec.Name) {
			return "", fmt.Errorf("deployment name %q: lower case letters, digits and '-', e.g. proxy (the recipe %s puts it into a path)", spec.Name, r.Name)
		}
		return path(strings.ReplaceAll(p, "{name}", spec.Name)), nil
	}
	ownLocation := spec.Dir != "" || spec.Files != (Files{})
	if !ownLocation && (spec.Profile == "" || spec.Profile == r.Profile) {
		spec.Profile = r.Profile
		var err error
		if r.Profile == ProfileNginx {
			spec.Dir, err = expand(r.Dir)
		} else {
			spec.Files, err = recipeFiles(r, expand)
		}
		if err != nil {
			return err
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

// recipeFiles maps the file targets of a recipe through expand.
func recipeFiles(r recipe.Recipe, expand func(string) (string, error)) (Files, error) {
	var f Files
	for _, field := range []struct {
		to   *string
		from string
	}{{&f.Certificate, r.Certificate}, {&f.Chain, r.Chain}, {&f.Fullchain, r.Fullchain}, {&f.Key, r.Key}, {&f.Combined, r.Combined}} {
		p, err := expand(field.from)
		if err != nil {
			return Files{}, err
		}
		*field.to = p
	}
	return f, nil
}
