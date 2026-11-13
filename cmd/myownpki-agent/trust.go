package main

import (
	"context"
	"fmt"
	"io"

	"github.com/Der-Felix/MyOwnPKI/internal/agent"
)

const trustUsage = "usage: myownpki-agent trust install --root-sha256 HEX [--no-record] [--config FILE]\n" +
	"       myownpki-agent trust remove [--root-sha256 HEX] [--config FILE]\n" +
	"       myownpki-agent trust status [--quiet] [--root-sha256 HEX] [--config FILE]\n"

// cmdTrust is "trust install|remove|status": the root of this PKI in the
// system trust store of the host (docs/PHASE3.md §15). install and remove need
// root; status only reads. "run" never calls any of this.
func cmdTrust(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, trustUsage)
		return 2
	}
	name := "trust " + args[0]
	fs, configPath := subFlags(name, stderr)
	opts := agent.TrustOptions{Stdout: stdout, Stderr: stderr}
	fs.StringVar(&opts.RootSHA256, "root-sha256", "", "SHA-256 of the root certificate DER, 64 hexadecimal digits")
	switch args[0] {
	case "install":
		fs.BoolVar(&opts.NoRecord, "no-record", false, "do not write system_trust into agent.yaml (a file another tool owns)")
	case "remove":
	case "status":
		fs.BoolVar(&opts.Quiet, "quiet", false, "print nothing; the exit code is 0 only when the pinned root is installed")
	default:
		_, _ = fmt.Fprint(stderr, trustUsage)
		return 2
	}
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 {
		return 2
	}
	opts.ConfigPath = *configPath
	switch args[0] {
	case "install":
		if opts.RootSHA256 == "" {
			_, _ = fmt.Fprintln(stderr, "trust install: --root-sha256 is required (the SHA-256 of the root, as shown in the admin UI)")
			return 2
		}
		if err := agent.TrustInstall(ctx, opts); err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
	case "remove":
		if err := agent.TrustRemove(ctx, opts); err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
	default:
		installed, err := agent.TrustStatus(opts)
		if err != nil {
			_, _ = fmt.Fprintln(stderr, err)
			return 1
		}
		if !installed {
			return 1
		}
	}
	return 0
}
