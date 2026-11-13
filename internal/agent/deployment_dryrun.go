package agent

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"strings"
)

// DryRunHost describes the host a parsed "deployment add" is tried on. It
// exists for the tests of the Add host assistant (and any other generator of
// command lines): they must prove that a line they print is accepted by the
// agent and means what the page says, on a development machine that is not a
// Linux host and is not root.
type DryRunHost struct {
	// Root is a directory that stands for "/": every absolute path of the
	// command (directories, files, hook commands) is looked for below it.
	Root string
	// ConfigPath and UnitPath are the real files of the host, already below
	// Root (agent.yaml and the unit; the drop-ins are the unit's .d directory).
	ConfigPath string
	UnitPath   string
	// Stderr receives warnings and hints; nil discards them.
	Stderr io.Writer
}

// DryRunDeploymentAdd runs a parsed "deployment add" through AddDeployment as a
// dry run: the same validation as the command, against the files in host, and
// it writes nothing. It skips only the root check, which is meaningless for a
// run that cannot write, and it maps absolute paths below host.Root (a ".."
// stays visible, so the check that refuses it still sees it). It returns what
// the command would print.
func DryRunDeploymentAdd(ctx context.Context, cmd DeploymentAddCommand, host DryRunHost) (string, error) {
	var out bytes.Buffer
	stderr := host.Stderr
	if stderr == nil {
		stderr = io.Discard
	}
	spec := cmd.Spec
	spec.under(host.Root)
	err := AddDeployment(ctx, AddOptions{
		EditOptions: EditOptions{ConfigPath: host.ConfigPath, UnitPath: host.UnitPath, DryRun: true, Restart: cmd.Restart,
			Stdout: &out, Stderr: stderr, skipPreflight: true},
		Spec: spec, CreateDirs: cmd.CreateDirs,
	})
	if err != nil {
		return out.String(), err
	}
	return out.String(), nil
}

// under maps every absolute path of the spec below root. It joins the text
// without cleaning it.
func (s *DeploymentSpec) under(root string) {
	if root == "" {
		return
	}
	m := func(p string) string {
		if !strings.HasPrefix(p, "/") {
			return p
		}
		return root + string(filepath.Separator) + strings.TrimPrefix(filepath.FromSlash(p), string(filepath.Separator))
	}
	s.Webroot, s.Dir, s.DNSCredentials = m(s.Webroot), m(s.Dir), m(s.DNSCredentials)
	s.Files = Files{Certificate: m(s.Files.Certificate), Chain: m(s.Files.Chain), Fullchain: m(s.Files.Fullchain), Key: m(s.Files.Key)}
	mapAll := func(dirs []string) []string {
		out := make([]string, len(dirs))
		for i, dir := range dirs {
			out[i] = m(dir)
		}
		return out
	}
	s.SandboxWrite, s.recipeWrites = mapAll(s.SandboxWrite), mapAll(s.recipeWrites)
	hooks := make([]HookSpec, len(s.Hooks))
	for i, h := range s.Hooks {
		command := make([]string, len(h.Command))
		for j, a := range h.Command {
			command[j] = m(a)
		}
		hooks[i] = HookSpec{Name: h.Name, Command: command}
	}
	s.Hooks = hooks
}
