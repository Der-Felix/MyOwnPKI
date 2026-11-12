package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/Der-Felix/MyOwnPKI/internal/agent"
)

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
	cmd, err := agent.ParseDeploymentAdd(fs, configPath, args)
	if err != nil {
		var usage *agent.UsageError
		if errors.As(err, &usage) {
			if usage.Message != "" {
				_, _ = fmt.Fprintln(stderr, usage.Message)
			}
			return 2
		}
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	opts := agent.AddOptions{EditOptions: agent.EditOptions{ConfigPath: cmd.ConfigPath, DryRun: cmd.DryRun, Restart: cmd.Restart, Stdout: stdout, Stderr: stderr},
		Spec: cmd.Spec, CreateDirs: cmd.CreateDirs}
	if err := agent.AddDeployment(ctx, opts); err != nil {
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
	positional, ok := agent.ParseFlagsAnywhere(fs, args)
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
