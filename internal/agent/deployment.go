package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
)

// "myownpki-agent deployment add|list|remove" and "sandbox sync"
// (docs/PHASE3.md §11.2). They change agent.yaml through the yaml.Node
// editor and the systemd drop-ins through RenderDropins, and check the result
// with ParseConfig – the loader of "run" and "config check" – before a byte
// is written.

// editWriteFile writes one file atomically; tests replace it to inject a failure.
var editWriteFile = atomicSetupFile

// editPlatformCheck refuses a non-Linux host and a non-root run.
var editPlatformCheck = platformEditPreflight

func rootRequiredError(command string) error {
	return fmt.Errorf("%s must run as root; nothing was changed", command)
}

// EditOptions are the inputs every editing command shares.
type EditOptions struct {
	ConfigPath string
	UnitPath   string
	DropinDir  string
	ExampleDir string
	DryRun     bool
	Restart    bool
	Stdout     io.Writer
	Stderr     io.Writer
}

// HookSpec is one hook a deployment brings: a name and an argument vector.
type HookSpec struct {
	Name    string
	Command []string
}

// DeploymentSpec is what "deployment add" asks for, before defaults.
type DeploymentSpec struct {
	Name          string
	Profile       string
	Names         []string
	Challenge     string
	Webroot       string
	Dir           string
	Files         Files
	Owner         string
	Group         string
	KeyMode       string
	Hooks         []HookSpec
	TestHook      string
	ReloadHook    string
	Check         string
	SandboxWrite  []string
	LowPorts      bool
	ACMEDirectory string

	// Recipe names the recipe the spec was filled from ("" = none); it only
	// changes what the dry run prints.
	Recipe string
}

// AddOptions are the inputs of AddDeployment.
type AddOptions struct {
	EditOptions
	Spec       DeploymentSpec
	CreateDirs bool
}

// RemoveOptions are the inputs of RemoveDeployment.
type RemoveOptions struct {
	EditOptions
	Name       string
	PrunePaths bool
}

// SyncOptions are the inputs of SyncSandbox.
type SyncOptions struct {
	EditOptions
	Adopt bool
	Prune bool
}

// editSession is agent.yaml and the drop-ins as found.
type editSession struct {
	opts      EditOptions
	command   string
	cfg       *Config
	editor    *yamlEditor
	data      []byte
	mode      os.FileMode
	unitPath  string
	dropinDir string
	state     DropinState
	lowPorts  []byte
	out       io.Writer
}

func openEditSession(opts EditOptions, command string, forEdit bool) (*editSession, error) {
	if opts.Stdout == nil {
		opts.Stdout = io.Discard
	}
	if opts.Stderr == nil {
		opts.Stderr = io.Discard
	}
	if err := editPlatformCheck(command); err != nil {
		return nil, err
	}
	if opts.ConfigPath == "" {
		opts.ConfigPath = DefaultConfigPath
	}
	s := &editSession{opts: opts, command: command, out: opts.Stdout}
	data, err := readSetupRegular(opts.ConfigPath, maxConfigSize, false)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", opts.ConfigPath, err)
	}
	st, err := os.Stat(opts.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", opts.ConfigPath, err)
	}
	s.data, s.mode = data, st.Mode().Perm()
	if s.cfg, err = ParseConfig(opts.ConfigPath, data); err != nil {
		return nil, errors.New("agent.yaml is not valid yet – run \"myownpki-agent config check\" and fix it first; nothing was changed")
	}
	if forEdit {
		if s.editor, err = openYAMLEditor(data); err != nil {
			return nil, err
		}
	}
	s.unitPath, s.dropinDir = unitPaths(opts.UnitPath, opts.DropinDir)
	if s.state, err = ReadDropins(s.dropinDir); err != nil {
		return nil, err
	}
	if s.lowPorts, err = setupAsset(opts.ExampleDir, "low-ports", "agent-low-ports.conf"); err != nil {
		return nil, err
	}
	return s, nil
}

// result parses the edited YAML with the loader of "run" and refuses an
// invalid result.
func (s *editSession) result() ([]byte, *Config, error) {
	data, err := s.editor.bytes()
	if err != nil {
		return nil, nil, err
	}
	cfg, err := ParseConfig(s.opts.ConfigPath, data)
	if err != nil {
		return nil, nil, fmt.Errorf("the change would make agent.yaml invalid; nothing was changed:\n%w", err)
	}
	return data, cfg, nil
}

type changeSet struct {
	config  []byte
	plan    *DropinPlan
	newDirs []string
	// yamlFirst: removal writes agent.yaml before the drop-ins, so that a
	// crash in between leaves a wider sandbox, never a missing one.
	yamlFirst bool
}

func (c changeSet) configChanged(s *editSession) bool { return string(c.config) != string(s.data) }

// apply prints the dry run, or writes: directories, then the files in the
// order that never leaves a missing entry, then daemon-reload.
func (s *editSession) apply(ctx context.Context, c changeSet) error {
	if s.opts.DryRun {
		s.printDryRun(c)
		return nil
	}
	for _, dir := range c.newDirs {
		// #nosec G301 G703 -- the directory was checked: not a system root, no symlink on the way, a parent of a configured target.
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		_, _ = fmt.Fprintf(s.out, "Created directory %s.\n", dir)
	}
	dropinsChanged := c.plan.PathsChanged || c.plan.LowPorts != LowPortsKeep
	var undo func() error
	writeDropins := func() error {
		var err error
		undo, err = s.writeDropinFiles(c.plan)
		return err
	}
	writeConfig := func() error {
		if !c.configChanged(s) {
			return nil
		}
		if err := editWriteFile(s.opts.ConfigPath+".bak", s.data, s.mode); err != nil {
			return err
		}
		return editWriteFile(s.opts.ConfigPath, c.config, s.mode)
	}
	if c.yamlFirst {
		if err := writeConfig(); err != nil {
			return err
		}
		if err := writeDropins(); err != nil {
			return fmt.Errorf("%w (agent.yaml was already changed)", err)
		}
	} else {
		if err := writeDropins(); err != nil {
			return err
		}
		if err := writeConfig(); err != nil {
			if undo != nil {
				if undoErr := undo(); undoErr != nil {
					return fmt.Errorf("%w; restoring the systemd drop-ins failed too, check %s: %w", err, s.dropinDir, undoErr)
				}
			}
			return fmt.Errorf("%w (the systemd drop-ins were restored)", err)
		}
	}
	if c.configChanged(s) {
		_, _ = fmt.Fprintf(s.out, "Wrote %s (previous file: %s.bak).\n", s.opts.ConfigPath, filepath.Base(s.opts.ConfigPath))
	}
	reportDropins(s.out, c.plan, s.state.HavePaths)
	return s.reload(ctx, dropinsChanged, c.configChanged(s))
}

// writeDropinFiles writes what the plan changes and returns a function that
// puts the previous bytes back.
func (s *editSession) writeDropinFiles(plan *DropinPlan) (func() error, error) {
	pathsFile := filepath.Join(s.dropinDir, dropinPathsName)
	lowFile := filepath.Join(s.dropinDir, dropinLowPortsName)
	var undos []func() error
	undo := func() error {
		var errs []error
		for i := len(undos) - 1; i >= 0; i-- {
			errs = append(errs, undos[i]())
		}
		return errors.Join(errs...)
	}
	restore := func(file string, have bool, data []byte) func() error {
		return func() error {
			if have {
				return atomicSetupFile(file, data, 0o644)
			}
			if err := os.Remove(file); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			return nil
		}
	}
	if plan.PathsChanged {
		if err := editWriteFile(pathsFile, plan.Paths, 0o644); err != nil {
			return undo, err
		}
		undos = append(undos, restore(pathsFile, s.state.HavePaths, s.state.Paths))
	}
	switch plan.LowPorts {
	case LowPortsWrite:
		if err := editWriteFile(lowFile, plan.LowPortsData, 0o644); err != nil {
			return undo, errors.Join(err, undo())
		}
		undos = append(undos, restore(lowFile, s.state.HaveLowPorts, s.state.LowPorts))
	case LowPortsRemove:
		if err := os.Remove(lowFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return undo, errors.Join(err, undo())
		}
		undos = append(undos, restore(lowFile, s.state.HaveLowPorts, s.state.LowPorts))
	case LowPortsKeep:
	}
	return undo, nil
}

// reload runs daemon-reload when a drop-in changed and the restart the
// operator asked for; otherwise it prints the one command that is left.
func (s *editSession) reload(ctx context.Context, dropinsChanged, configChanged bool) error {
	if !dropinsChanged && !configChanged {
		return nil
	}
	if _, err := os.Stat(s.unitPath); errors.Is(err, os.ErrNotExist) {
		_, _ = fmt.Fprintln(s.out, "The unit is not installed (run setup first) – files written, systemctl skipped.")
		return nil
	} else if err != nil {
		return err
	}
	if dropinsChanged {
		if err := setupSystemd.Run(ctx, "daemon-reload"); err != nil {
			return err
		}
		_, _ = fmt.Fprintln(s.out, "Ran systemctl daemon-reload.")
	}
	if s.opts.Restart {
		if err := setupSystemd.Run(ctx, "restart", "myownpki-agent.service"); err != nil {
			return err
		}
		_, _ = fmt.Fprintln(s.out, "Restarted myownpki-agent.")
		return nil
	}
	_, _ = fmt.Fprintln(s.out, "Apply it with: systemctl restart myownpki-agent")
	return nil
}

func (s *editSession) printDryRun(c changeSet) {
	_, _ = fmt.Fprintln(s.out, "Dry run: nothing was written.")
	if d := unifiedDiff(filepath.Base(s.opts.ConfigPath), s.data, true, c.config); d != "" {
		_, _ = fmt.Fprint(s.out, d)
	}
	if d := unifiedDiff(dropinPathsName, s.state.Paths, s.state.HavePaths, c.plan.Paths); d != "" {
		_, _ = fmt.Fprint(s.out, d)
	}
	switch c.plan.LowPorts {
	case LowPortsWrite:
		_, _ = fmt.Fprint(s.out, unifiedDiff(dropinLowPortsName, nil, false, c.plan.LowPortsData))
	case LowPortsRemove:
		_, _ = fmt.Fprintf(s.out, "%s would be removed (sandbox.low_ports: false).\n", dropinLowPortsName)
	case LowPortsKeep:
	}
	for _, dir := range c.newDirs {
		_, _ = fmt.Fprintf(s.out, "Would create directory %s.\n", dir)
	}
	if len(c.plan.Kept) > 0 {
		_, _ = fmt.Fprintf(s.out, "Kept in %s (agent.yaml does not explain them): %s\n", dropinPathsName, strings.Join(c.plan.Kept, " "))
	}
	for _, n := range c.plan.Notes {
		_, _ = fmt.Fprintln(s.out, n)
	}
	if !c.configChanged(s) && c.plan.InSync() {
		_, _ = fmt.Fprintln(s.out, "No change.")
	}
}

// --- deployment add ----------------------------------------------------------

// AddDeployment adds one deployment to agent.yaml and makes the systemd
// sandbox match, in this order: validate everything, write the drop-ins, keep
// agent.yaml.bak, write agent.yaml. It never restarts the agent unless asked.
func AddDeployment(ctx context.Context, opts AddOptions) error {
	s, err := openEditSession(opts.EditOptions, "deployment add", true)
	if err != nil {
		return err
	}
	spec := opts.Spec
	if !nameRE.MatchString(spec.Name) {
		return fmt.Errorf("deployment name %q: lower case letters, digits and '-', e.g. proxy", spec.Name)
	}
	for _, d := range s.cfg.Deployments {
		if d.Name == spec.Name {
			return fmt.Errorf("deployment %q exists – pick another name or run \"deployment remove %s\" first", spec.Name, spec.Name)
		}
	}
	d, err := s.completeSpec(&spec)
	if err != nil {
		return err
	}
	hooks, reuse, err := resolveHooks(s.cfg.Hooks, spec.Hooks)
	if err != nil {
		return err
	}
	d.TestHook = aliasOr(reuse, d.TestHook)
	d.ReloadHook = aliasOr(reuse, d.ReloadHook)
	for _, name := range []string{d.TestHook, d.ReloadHook} {
		if _, known := s.cfg.Hooks[name]; name != "" && !known && !slices.ContainsFunc(hooks, func(h HookSpec) bool { return h.Name == name }) {
			return fmt.Errorf("hook %q is not defined – pass --hook %s='/path/to/command args' or name an existing hook", name, name)
		}
	}
	dirs, err := s.neededDirs(d)
	if err != nil {
		return err
	}
	writeDirs, err := s.checkSandboxDirs(spec.SandboxWrite)
	if err != nil {
		return err
	}
	var missing []string
	for _, nd := range append(slices.Clone(dirs), writeDirs...) {
		switch st, statErr := os.Stat(nd.path); {
		case statErr == nil && !st.IsDir():
			return fmt.Errorf("%s is not a directory", nd.path)
		case errors.Is(statErr, os.ErrNotExist):
			if !opts.CreateDirs {
				return fmt.Errorf("%s does not exist – create it, or pass --create-dirs", nd.path)
			}
			missing = append(missing, nd.path)
		case statErr != nil:
			return fmt.Errorf("%s: %w", nd.path, statErr)
		}
	}
	for _, nd := range append(slices.Clone(dirs), writeDirs...) {
		if nd.warn != "" {
			_, _ = fmt.Fprintln(s.opts.Stderr, "warning:", nd.warn)
		}
	}

	if err = s.editAdd(d, hooks, dirs, writeDirs, spec); err != nil {
		return err
	}
	data, cfg, err := s.result()
	if err != nil {
		return err
	}
	plan, err := RenderDropins(cfg, s.state, s.lowPorts, DropinOptions{})
	if err != nil {
		return err
	}
	if spec.Recipe != "" {
		_, _ = fmt.Fprintf(s.out, "Recipe %s is an example written from the documentation of the service – test it on a non-production host.\n", spec.Recipe)
	}
	for name, with := range reuse {
		_, _ = fmt.Fprintf(s.out, "Hook %q: the identical hook %q exists; reusing it, so both deployments share one reload.\n", name, with)
	}
	if err = s.apply(ctx, changeSet{config: data, plan: plan, newDirs: missing}); err != nil {
		return err
	}
	s.hint(d, cfg, plan)
	return nil
}

func aliasOr(reuse map[string]string, name string) string {
	if with, ok := reuse[name]; ok {
		return with
	}
	return name
}

// completeSpec fills the defaults and checks the flags against each other.
func (s *editSession) completeSpec(spec *DeploymentSpec) (Deployment, error) {
	d := Deployment{Name: spec.Name, Profile: spec.Profile, Dir: spec.Dir, Files: spec.Files, Owner: spec.Owner, Group: spec.Group,
		KeyMode: spec.KeyMode, TestHook: spec.TestHook, ReloadHook: spec.ReloadHook, Check: spec.Check}
	for _, n := range spec.Names {
		d.Names = append(d.Names, strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), "."))
	}
	if len(d.Names) == 0 {
		d.Names = []string{s.cfg.Hostname}
	}
	hasFiles := d.Files != (Files{})
	switch {
	case d.Profile == "" && d.Dir != "" && !hasFiles:
		d.Profile = ProfileNginx
	case d.Profile == "" && d.Dir == "" && hasFiles:
		d.Profile = ProfileFile
	case d.Profile == "":
		return d, errors.New("pick a profile: --recipe, --profile, --dir (nginx profile) or --certificate/--fullchain/--key (file profile)")
	}
	switch d.Profile {
	case ProfileNginx:
		if d.Dir == "" || hasFiles {
			return d, errors.New("profile nginx needs --dir and takes no --certificate, --chain, --fullchain or --key")
		}
	case ProfileFile:
		if d.Dir != "" || d.Files.Key == "" || d.Files.Certificate == "" && d.Files.Fullchain == "" {
			return d, errors.New("profile file needs --key and --fullchain or --certificate, and takes no --dir")
		}
	default:
		return d, errors.New("--profile: nginx or file")
	}
	d.Challenge, d.Webroot = spec.Challenge, spec.Webroot
	if d.Challenge == "" {
		d.Challenge = s.cfg.Enrollment.Challenge
		if d.Webroot != "" {
			d.Challenge = ChallengeWebroot
		}
	}
	switch d.Challenge {
	case ChallengeWebroot:
		if d.Webroot == "" {
			d.Webroot = s.cfg.Enrollment.Webroot
		}
		if d.Webroot == "" {
			return d, errors.New("--challenge webroot needs --webroot DIR (enrollment uses standalone)")
		}
	case ChallengeStandalone:
		if d.Webroot != "" {
			return d, errors.New("--webroot belongs to --challenge webroot")
		}
	default:
		return d, errors.New("--challenge: standalone or webroot")
	}
	switch {
	case spec.ACMEDirectory != "":
		if err := checkACMEDirectory(spec.ACMEDirectory); err != nil {
			return d, fmt.Errorf("--acme-directory: %w", err)
		}
		if s.cfg.ACMEDirectory != "" && s.cfg.ACMEDirectory != spec.ACMEDirectory {
			return d, fmt.Errorf("agent.yaml already has acme_directory %s – edit it by hand to change it", s.cfg.ACMEDirectory)
		}
	case s.cfg.ACMEDirectory == "":
		return d, errors.New("agent.yaml has no acme_directory – pass --acme-directory https://pki.homelab.lan/acme/directory")
	}
	if spec.LowPorts && s.cfg.Sandbox.LowPorts != nil && !*s.cfg.Sandbox.LowPorts {
		return d, errors.New("--low-ports conflicts with sandbox.low_ports: false in agent.yaml – change one of them")
	}
	return d, nil
}

// neededDir is a directory a deployment adds to paths or sandbox.write.
type neededDir struct {
	path string
	warn string
}

// neededDirs are the directories the new deployment needs in paths and that
// paths does not cover yet: the webroot, and the parent of each target (for
// the nginx profile the parent of dir, which the agent creates).
func (s *editSession) neededDirs(d Deployment) ([]neededDir, error) {
	type want struct{ flag, value, dir string }
	var wants []want
	if d.Challenge == ChallengeWebroot {
		wants = append(wants, want{"--webroot", d.Webroot, d.Webroot})
	}
	if d.Profile == ProfileNginx {
		wants = append(wants, want{"--dir", d.Dir, filepath.Dir(d.Dir)})
	} else {
		for _, f := range []struct{ flag, value string }{{"--certificate", d.Files.Certificate}, {"--chain", d.Files.Chain},
			{"--fullchain", d.Files.Fullchain}, {"--key", d.Files.Key}} {
			if f.value != "" {
				wants = append(wants, want{f.flag, f.value, filepath.Dir(f.value)})
			}
		}
	}
	var out []neededDir
	for _, w := range wants {
		if err := checkDotDot(w.flag, w.value); err != nil {
			return nil, err
		}
		// The directory flags must not themselves name a system root, and the
		// directory that becomes writable must not be one. (Text checks first:
		// they do not depend on the host's idea of an absolute path.)
		if (w.flag == "--webroot" || w.flag == "--dir") && broadDir(w.value) {
			return nil, fmt.Errorf("%s %s: %s", w.flag, w.value, tooBroadMessage(w.value))
		}
		covered := Under(s.cfg.Paths, w.dir)
		if !covered && broadDir(w.dir) {
			return nil, fmt.Errorf("%s %s: its directory %s is %s", w.flag, w.value, filepath.ToSlash(w.dir), tooBroadMessage(w.dir))
		}
		if !filepath.IsAbs(w.value) {
			return nil, fmt.Errorf("%s %s: an absolute path", w.flag, w.value)
		}
		if covered {
			continue
		}
		dir := filepath.Clean(w.dir)
		if slices.ContainsFunc(out, func(n neededDir) bool { return Under([]string{n.path}, dir) }) {
			continue
		}
		out = slices.DeleteFunc(out, func(n neededDir) bool { return Under([]string{dir}, n.path) })
		if err := checkNoSymlink(dir); err != nil {
			return nil, fmt.Errorf("%s %s: %w", w.flag, w.value, err)
		}
		nd := neededDir{path: dir}
		if wideDir(dir) {
			nd.warn = fmt.Sprintf("%s is wider than needed – prefer a subdirectory such as %s", dir, narrowerThan(dir))
		}
		out = append(out, nd)
	}
	return out, nil
}

// checkSandboxDirs validates --sandbox-write: absolute, not a system root, no symlink.
func (s *editSession) checkSandboxDirs(dirs []string) ([]neededDir, error) {
	var out []neededDir
	for _, p := range dirs {
		if err := checkDotDot("--sandbox-write", p); err != nil {
			return nil, err
		}
		if broadDir(p) {
			return nil, fmt.Errorf("--sandbox-write %s: %s", p, tooBroadMessage(p))
		}
		if !filepath.IsAbs(p) {
			return nil, fmt.Errorf("--sandbox-write %s: an absolute path", p)
		}
		dir := filepath.Clean(p)
		if slices.Contains(s.cfg.Sandbox.Write, dir) || slices.ContainsFunc(out, func(n neededDir) bool { return n.path == dir }) {
			continue
		}
		if err := checkNoSymlink(dir); err != nil {
			return nil, fmt.Errorf("--sandbox-write %s: %w", p, err)
		}
		nd := neededDir{path: dir}
		if wideDir(dir) {
			nd.warn = fmt.Sprintf("%s is wider than needed – prefer a subdirectory such as %s", dir, narrowerThan(dir))
		}
		out = append(out, nd)
	}
	return out, nil
}

// checkDotDot refuses a path with a .. segment: it would be checked as
// written and used as resolved.
func checkDotDot(flag, value string) error {
	if slices.Contains(strings.Split(filepath.ToSlash(value), "/"), "..") {
		return fmt.Errorf("%s %s: no .. path segments", flag, value)
	}
	return nil
}

// checkNoSymlink refuses a path with a symbolic link on its way: ReadWritePaths
// and the agent's own checks follow links, so a link would make something
// else writable than the path says.
func checkNoSymlink(p string) error {
	p = filepath.Clean(p)
	vol := filepath.VolumeName(p)
	rest := strings.TrimPrefix(p, vol)
	cur := vol + string(filepath.Separator)
	for _, part := range strings.Split(rest, string(filepath.Separator)) {
		if part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		st, err := os.Lstat(cur)
		switch {
		case errors.Is(err, os.ErrNotExist):
			return nil // the rest will be created below a real directory
		case err != nil:
			return err
		case st.Mode()&os.ModeSymlink != 0:
			target, _ := filepath.EvalSymlinks(cur)
			return fmt.Errorf("%s is a symbolic link (to %s) – use the real directory", cur, target)
		}
	}
	return nil
}

// editAdd applies the change to the YAML tree.
func (s *editSession) editAdd(d Deployment, hooks []HookSpec, dirs, writeDirs []neededDir, spec DeploymentSpec) error {
	ed := s.editor
	if s.cfg.ACMEDirectory == "" {
		ed.setScalar("acme_directory", spec.ACMEDirectory)
	}
	for _, h := range hooks {
		if err := ed.addHook(h.Name, h.Command); err != nil {
			return err
		}
	}
	var paths, writes []string
	for _, nd := range dirs {
		paths = append(paths, nd.path)
	}
	for _, nd := range writeDirs {
		writes = append(writes, nd.path)
	}
	if err := ed.addPaths(paths...); err != nil {
		return err
	}
	if err := ed.addSandboxWrite(writes...); err != nil {
		return err
	}
	if spec.LowPorts {
		if err := ed.setLowPortsTrue(); err != nil {
			return err
		}
	}
	return ed.addDeployment(d)
}

// hint prints what a hook that is known to need more sandbox will miss.
func (s *editSession) hint(d Deployment, cfg *Config, plan *DropinPlan) {
	for _, name := range []string{d.TestHook, d.ReloadHook} {
		cmd := cfg.Hooks[name]
		if len(cmd) == 0 {
			continue
		}
		switch filepath.Base(cmd[0]) {
		case "nginx", "apachectl", "apache2ctl", "haproxy":
			if len(cfg.Sandbox.Write) == 0 {
				_, _ = fmt.Fprintf(s.opts.Stderr, "hint: hook %q runs %s, which writes its log files; if it fails with \"Read-only file system\" add its log directory with --sandbox-write (for nginx: /var/log/nginx).\n", name, filepath.Base(cmd[0]))
			}
			if lowPortsWanted(cfg, false) != lowPortsYes && !s.state.HaveLowPorts && plan.LowPorts == LowPortsKeep {
				_, _ = fmt.Fprintf(s.opts.Stderr, "hint: hook %q runs %s, which opens its listen sockets; if it fails with \"Permission denied\" on port 80 or 443 add --low-ports.\n", name, filepath.Base(cmd[0]))
			}
		}
	}
}

// resolveHooks decides which of the wanted hooks are new. A hook name that
// exists with the same command is reused; one that exists with another
// command is an error; a new name whose command line exists under another
// name is an alias of that hook, so deployments of one service share one
// reload (and one rollback group).
func resolveHooks(existing map[string][]string, wanted []HookSpec) ([]HookSpec, map[string]string, error) {
	var add []HookSpec
	reuse := map[string]string{}
	for _, h := range wanted {
		if !hookRE.MatchString(h.Name) {
			return nil, nil, fmt.Errorf("hook %q: a name of letters, digits, '.', '_', '-'", h.Name)
		}
		if len(h.Command) == 0 || !filepath.IsAbs(h.Command[0]) {
			return nil, nil, fmt.Errorf("hook %q: the first element must be an absolute path", h.Name)
		}
		if cur, ok := existing[h.Name]; ok {
			if !slices.Equal(cur, h.Command) {
				return nil, nil, fmt.Errorf("hook %q exists with another command (%s) – pick another name or edit agent.yaml", h.Name, strings.Join(cur, " "))
			}
			continue
		}
		if slices.ContainsFunc(add, func(a HookSpec) bool { return a.Name == h.Name }) {
			return nil, nil, fmt.Errorf("hook %q is given twice", h.Name)
		}
		same := ""
		for name, cmd := range existing {
			if slices.Equal(cmd, h.Command) && (same == "" || name < same) {
				same = name
			}
		}
		if same != "" {
			reuse[h.Name] = same
			continue
		}
		add = append(add, h)
	}
	return add, reuse, nil
}

// SplitCommand splits "CMD ARG ..." into an argument vector: white space
// separates, single quotes keep everything, double quotes keep everything
// except \" and \\. There is no shell: no expansion, no pipes, no variables.
func SplitCommand(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	inWord := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c < 0x20 && c != '\t' || c == 0x7f:
			return nil, errors.New("control characters are not allowed")
		case c == ' ' || c == '\t':
			if inWord {
				out = append(out, cur.String())
				cur.Reset()
				inWord = false
			}
		case c == '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				return nil, errors.New("unterminated single quote")
			}
			cur.WriteString(s[i+1 : i+1+end])
			i += end + 1
			inWord = true
		case c == '"':
			inWord = true
			closed := false
			for i++; i < len(s); i++ {
				if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
					i++
					cur.WriteByte(s[i])
					continue
				}
				if s[i] == '"' {
					closed = true
					break
				}
				cur.WriteByte(s[i])
			}
			if !closed {
				return nil, errors.New("unterminated double quote")
			}
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		out = append(out, cur.String())
	}
	return out, nil
}

// ParseHookFlag parses NAME='CMD ARGS'.
func ParseHookFlag(v string) (HookSpec, error) {
	name, cmd, ok := strings.Cut(v, "=")
	if !ok || name == "" {
		return HookSpec{}, fmt.Errorf("--hook %q: want NAME='/path/to/command args'", v)
	}
	argv, err := SplitCommand(cmd)
	if err != nil {
		return HookSpec{}, fmt.Errorf("--hook %s: %w", name, err)
	}
	if len(argv) == 0 || !filepath.IsAbs(argv[0]) {
		return HookSpec{}, fmt.Errorf("hook %q: the first element must be an absolute path", name)
	}
	return HookSpec{Name: name, Command: argv}, nil
}

// --- deployment remove -------------------------------------------------------

// footprint are the places a deployment writes: its webroot and its targets.
func footprint(d Deployment) []string {
	var out []string
	if d.Challenge == ChallengeWebroot {
		out = append(out, d.Webroot)
	}
	if d.Profile == ProfileNginx {
		return append(out, d.Dir)
	}
	for _, p := range []string{d.Files.Certificate, d.Files.Chain, d.Files.Fullchain, d.Files.Key} {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// prunablePaths are the paths entries that only the removed deployment used.
func prunablePaths(cfg *Config, removed Deployment) []string {
	var others []string
	if cfg.Enrollment.Challenge == ChallengeWebroot {
		others = append(others, cfg.Enrollment.Webroot)
	}
	for _, d := range cfg.Deployments {
		if d.Name != removed.Name {
			others = append(others, footprint(d)...)
		}
	}
	var out []string
	for _, p := range cfg.Paths {
		usedByRemoved := slices.ContainsFunc(footprint(removed), func(f string) bool { return Under([]string{p}, f) })
		usedByOthers := slices.ContainsFunc(others, func(f string) bool { return Under([]string{p}, f) })
		if usedByRemoved && !usedByOthers {
			out = append(out, p)
		}
	}
	return out
}

// RemoveDeployment removes one deployment from agent.yaml. It keeps paths
// unless PrunePaths is set and never touches deployed files or the state.
func RemoveDeployment(ctx context.Context, opts RemoveOptions) error {
	s, err := openEditSession(opts.EditOptions, "deployment remove", true)
	if err != nil {
		return err
	}
	var removed *Deployment
	var names []string
	for i, d := range s.cfg.Deployments {
		names = append(names, d.Name)
		if d.Name == opts.Name {
			removed = &s.cfg.Deployments[i]
		}
	}
	if removed == nil {
		known := "there are none"
		if len(names) > 0 {
			known = "known: " + strings.Join(names, ", ")
		}
		return fmt.Errorf("deployment %q does not exist (%s)", opts.Name, known)
	}
	if !s.editor.removeDeployment(opts.Name) {
		return errors.New("agent.yaml: the deployment is not a plain entry of the deployments list – edit it by hand")
	}
	var drop []string
	if opts.PrunePaths {
		drop = prunablePaths(s.cfg, *removed)
		s.editor.removePaths(drop...)
	}
	data, cfg, err := s.result()
	if err != nil {
		return err
	}
	plan, err := RenderDropins(cfg, s.state, s.lowPorts, DropinOptions{Drop: drop})
	if err != nil {
		return err
	}
	if err = s.apply(ctx, changeSet{config: data, plan: plan, yamlFirst: true}); err != nil {
		return err
	}
	if !s.opts.DryRun {
		_, _ = fmt.Fprintln(s.out, "Deployed files and the agent's state are not touched; delete them by hand if they are not needed.")
	}
	return nil
}

// --- deployment list ---------------------------------------------------------

// ListDeployments prints the deployments of agent.yaml. It reads only, so it
// also runs without root and on hosts that are not Linux.
func ListDeployments(w io.Writer, configPath string) error {
	if configPath == "" {
		configPath = DefaultConfigPath
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return err
	}
	if len(cfg.Deployments) == 0 {
		_, err = fmt.Fprintln(w, "No deployments.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tPROFILE\tNAMES\tTARGETS\tHOOKS\tCHECK")
	for _, d := range cfg.Deployments {
		targets := d.Dir
		if d.Profile == ProfileFile {
			var parts []string
			for _, p := range []string{d.Files.Certificate, d.Files.Chain, d.Files.Fullchain, d.Files.Key} {
				if p != "" {
					parts = append(parts, p)
				}
			}
			targets = strings.Join(parts, ",")
		}
		var hooks []string
		if d.TestHook != "" {
			hooks = append(hooks, "test="+d.TestHook)
		}
		if d.ReloadHook != "" {
			hooks = append(hooks, "reload="+d.ReloadHook)
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", d.Name, d.Profile, strings.Join(d.Names, ","), targets, orDash(strings.Join(hooks, " ")), orDash(d.Check))
	}
	return tw.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// --- sandbox sync ------------------------------------------------------------

// SyncSandbox recomputes both drop-ins from agent.yaml (what a Salt run calls
// after it rendered the file). Entries the file does not explain are kept and
// reported; Adopt records them under sandbox.write, Prune drops them.
func SyncSandbox(ctx context.Context, opts SyncOptions) error {
	if opts.Adopt && opts.Prune {
		return errors.New("--adopt and --prune exclude each other")
	}
	s, err := openEditSession(opts.EditOptions, "sandbox sync", opts.Adopt)
	if err != nil {
		return err
	}
	cfg := s.cfg
	data := s.data
	if opts.Adopt {
		first, firstErr := RenderDropins(cfg, s.state, s.lowPorts, DropinOptions{})
		if firstErr != nil {
			return firstErr
		}
		var adopt []string
		for _, t := range first.Kept {
			if filepath.IsAbs(t) && unitPathSafe(t) && !broadDir(t) {
				adopt = append(adopt, filepath.Clean(t))
				continue
			}
			_, _ = fmt.Fprintf(s.opts.Stderr, "warning: cannot adopt %q (not a plain absolute directory) – edit agent.yaml by hand\n", t)
		}
		if err = s.editor.addSandboxWrite(adopt...); err != nil {
			return err
		}
		if data, cfg, err = s.result(); err != nil {
			return err
		}
		if len(adopt) > 0 {
			_, _ = fmt.Fprintf(s.out, "Adopted into sandbox.write: %s\n", strings.Join(adopt, " "))
		}
	}
	plan, err := RenderDropins(cfg, s.state, s.lowPorts, DropinOptions{Prune: opts.Prune})
	if err != nil {
		return err
	}
	if string(data) == string(s.data) && plan.InSync() {
		if len(plan.Kept) > 0 {
			_, _ = fmt.Fprintf(s.out, "Kept in %s (agent.yaml does not explain them): %s\n  \"sandbox sync --adopt\" records them under sandbox.write, \"sandbox sync --prune\" drops them.\n", dropinPathsName, strings.Join(plan.Kept, " "))
		}
		_, _ = fmt.Fprintln(s.out, "The drop-ins already match agent.yaml; nothing to do.")
		return nil
	}
	return s.apply(ctx, changeSet{config: data, plan: plan})
}
