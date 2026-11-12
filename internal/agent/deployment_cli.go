package agent

import (
	"flag"
	"strings"
)

// UsageError is a command line that could not be used. Message is "" when the
// flag package has already said why.
type UsageError struct{ Message string }

func (e *UsageError) Error() string {
	if e.Message == "" {
		return "usage error"
	}
	return e.Message
}

// listFlag is a flag that may be given several times.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// ParseFlagsAnywhere parses flags that may stand before and after the
// positional arguments (deployment add NAME --dir X, or --dir X NAME).
func ParseFlagsAnywhere(fs *flag.FlagSet, args []string) ([]string, bool) {
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

// DeploymentAddCommand is a parsed "myownpki-agent deployment add": the
// options of AddDeployment, with the recipe already applied.
type DeploymentAddCommand struct {
	ConfigPath string
	DryRun     bool
	Restart    bool
	CreateDirs bool
	Spec       DeploymentSpec
}

// ParseDeploymentAdd defines the flags of "deployment add" on fs and parses
// args with them. It is the one place that knows the flags: the command and
// the tests of the Add host assistant (which must prove that a generated line
// means what the page says) both call it. configPath is the --config flag the
// caller defined on fs. A failure to parse is a *UsageError.
func ParseDeploymentAdd(fs *flag.FlagSet, configPath *string, args []string) (DeploymentAddCommand, error) {
	dryRun := fs.Bool("dry-run", false, "show a diff of agent.yaml and the drop-ins; write nothing")
	restart := fs.Bool("restart", false, "restart myownpki-agent afterwards (default: print the command)")
	var spec DeploymentSpec
	var names, hooks, sandboxWrite listFlag
	var recipeName string
	fs.StringVar(&recipeName, "recipe", "", "fill defaults for nginx, postfix, dovecot or proxmox (explicit flags win)")
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
	positional, ok := ParseFlagsAnywhere(fs, args)
	if !ok {
		return DeploymentAddCommand{}, &UsageError{}
	}
	if len(positional) != 1 {
		return DeploymentAddCommand{}, &UsageError{Message: "usage: myownpki-agent deployment add NAME [flags]"}
	}
	spec.Name, spec.Names, spec.SandboxWrite = positional[0], names, sandboxWrite
	for _, h := range hooks {
		hook, err := ParseHookFlag(h)
		if err != nil {
			return DeploymentAddCommand{}, err
		}
		spec.Hooks = append(spec.Hooks, hook)
	}
	if recipeName != "" {
		if err := ApplyRecipe(&spec, recipeName); err != nil {
			return DeploymentAddCommand{}, err
		}
	}
	return DeploymentAddCommand{ConfigPath: *configPath, DryRun: *dryRun, Restart: *restart, CreateDirs: *createDirs, Spec: spec}, nil
}
