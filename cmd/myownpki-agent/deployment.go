package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/agent"
)

// listFlag is a flag that may be given several times.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// parseArgs parses flags that may stand before and after the positional
// arguments (deployment add NAME --dir X, or --dir X NAME).
func parseArgs(fs *flag.FlagSet, args []string) ([]string, bool) {
	var positional []string
	for {
		if fs.Parse(args) != nil {
			return nil, false
		}
		if fs.NArg() == 0 {
			return positional, true
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

type editFlags struct {
	configPath *string
	dryRun     *bool
	restart    *bool
}

func addEditFlags(fs *flag.FlagSet, configPath *string, restart bool) editFlags {
	f := editFlags{configPath: configPath, dryRun: fs.Bool("dry-run", false, "show a diff of agent.yaml and the drop-ins; write nothing")}
	if restart {
		f.restart = fs.Bool("restart", false, "restart myownpki-agent afterwards (default: print the command)")
	}
	return f
}

func (f editFlags) options(stdout, stderr io.Writer) agent.EditOptions {
	o := agent.EditOptions{ConfigPath: *f.configPath, DryRun: *f.dryRun, Stdout: stdout, Stderr: stderr}
	if f.restart != nil {
		o.Restart = *f.restart
	}
	return o
}

func cmdDeploymentAdd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs, configPath := subFlags("deployment add", stderr)
	ef := addEditFlags(fs, configPath, true)
	var spec agent.DeploymentSpec
	var names, hooks, sandboxWrite listFlag
	fs.StringVar(&spec.Profile, "profile", "", "nginx or file (default: from --dir or the file flags)")
	fs.Var(&names, "name", "certificate name, a FQDN; repeat for more (default: the host name)")
	fs.StringVar(&spec.Challenge, "challenge", "", "webroot or standalone (default: as enrollment)")
	fs.StringVar(&spec.Webroot, "webroot", "", "webroot directory for --challenge webroot (default: as enrollment)")
	fs.StringVar(&spec.Dir, "dir", "", "nginx profile: directory for fullchain.pem and privkey.pem")
	fs.StringVar(&spec.Files.Certificate, "certificate", "", "file profile: certificate file")
	fs.StringVar(&spec.Files.Chain, "chain", "", "file profile: chain file")
	fs.StringVar(&spec.Files.Fullchain, "fullchain", "", "file profile: certificate and chain in one file")
	fs.StringVar(&spec.Files.Key, "key", "", "file profile: private key file")
	fs.StringVar(&spec.Owner, "owner", "", "owner of the files")
	fs.StringVar(&spec.Group, "group", "", "group of the files")
	fs.StringVar(&spec.KeyMode, "key-mode", "", "mode of the key, without rights for others (default 0600)")
	fs.Var(&hooks, "hook", "define a hook NAME='/absolute/command args' (no shell); repeat for more")
	fs.StringVar(&spec.TestHook, "test-hook", "", "hook that tests the configuration before a reload")
	fs.StringVar(&spec.ReloadHook, "reload-hook", "", "hook that reloads the service")
	fs.StringVar(&spec.Check, "check", "", "local TLS check HOST:PORT (implicit TLS only)")
	fs.Var(&sandboxWrite, "sandbox-write", "directory that hooks may write, e.g. /var/log/nginx; repeat for more")
	fs.BoolVar(&spec.LowPorts, "low-ports", false, "let hooks bind ports below 1024 (CAP_NET_BIND_SERVICE)")
	fs.StringVar(&spec.ACMEDirectory, "acme-directory", "", "ACME directory URL, required when agent.yaml has none")
	createDirs := fs.Bool("create-dirs", false, "create missing directories instead of stopping")
	positional, ok := parseArgs(fs, args)
	if !ok || len(positional) != 1 {
		if ok {
			_, _ = fmt.Fprintln(stderr, "usage: myownpki-agent deployment add NAME [flags]")
		}
		return 2
	}
	spec.Name, spec.Names, spec.SandboxWrite = positional[0], names, sandboxWrite
	for _, h := range hooks {
		hook, err := agent.ParseHookFlag(h)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		spec.Hooks = append(spec.Hooks, hook)
	}
	if err := agent.AddDeployment(ctx, agent.AddOptions{EditOptions: ef.options(stdout, stderr), Spec: spec, CreateDirs: *createDirs}); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func cmdDeploymentList(args []string, stdout, stderr io.Writer) int {
	fs, configPath := subFlags("deployment list", stderr)
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return 2
	}
	if err := agent.ListDeployments(stdout, *configPath); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func cmdDeploymentRemove(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs, configPath := subFlags("deployment remove", stderr)
	ef := addEditFlags(fs, configPath, true)
	prune := fs.Bool("prune-paths", false, "also remove the paths entries that only this deployment used")
	positional, ok := parseArgs(fs, args)
	if !ok || len(positional) != 1 {
		if ok {
			_, _ = fmt.Fprintln(stderr, "usage: myownpki-agent deployment remove NAME [--prune-paths] [--dry-run] [--restart]")
		}
		return 2
	}
	if err := agent.RemoveDeployment(ctx, agent.RemoveOptions{EditOptions: ef.options(stdout, stderr), Name: positional[0], PrunePaths: *prune}); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func cmdSandboxSync(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs, configPath := subFlags("sandbox sync", stderr)
	ef := addEditFlags(fs, configPath, false)
	adopt := fs.Bool("adopt", false, "record drop-in entries agent.yaml does not explain under sandbox.write")
	prune := fs.Bool("prune", false, "drop drop-in entries agent.yaml does not explain")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return 2
	}
	if err := agent.SyncSandbox(ctx, agent.SyncOptions{EditOptions: ef.options(stdout, stderr), Adopt: *adopt, Prune: *prune}); err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}
