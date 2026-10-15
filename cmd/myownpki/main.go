// Command myownpki is the MyOwnPKI server: web UI, REST API, ACME server and CA engine.
//
// Commands so far: --version, `config check`, `db status`/`db migrate`,
// `audit verify`, `init`, `ca list`/`ca show`, `user unlock`/`user reset-2fa` and `serve --dev` (UI prototype).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/Der-Felix/MyOwnPKI/internal/version"
)

const binary = "myownpki"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

// run dispatches the command line and returns the process exit code
// (0 success, 1 runtime error, 2 usage error).
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(binary, flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print version information and exit")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(fs.Output(), "Usage:\n  %s --version\n  %s config check [--config FILE]\n  %s init [--config FILE] [--stdin|--demo] [--with-ca --ca-base-url URL] [...]\n  %s db status|migrate [--config FILE]\n  %s audit verify [--config FILE] [--scope S] [--expect-head SEQ:HASH] [--checkpoint-key FP]\n  %s ca list [--config FILE]\n  %s ca show NAME [--config FILE]\n  %s user unlock|reset-2fa NAME [--config FILE] [...]\n  %s serve --dev [--listen 127.0.0.1:9443]\n\nFlags:\n", binary, binary, binary, binary, binary, binary, binary, binary, binary)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *showVersion {
		_, _ = fmt.Fprintln(stdout, version.Get().String(binary))
		return 0
	}

	switch fs.Arg(0) {
	case "init":
		return runInit(ctx, fs.Args()[1:], stdout, stderr)
	case "user":
		return runUser(ctx, fs.Args()[1:], stdout, stderr)
	case "ca":
		return runCA(ctx, fs.Args()[1:], stdout, stderr)
	case "audit":
		return runAudit(ctx, fs.Args()[1:], stdout, stderr)
	case "db":
		return runDB(ctx, fs.Args()[1:], stdout, stderr)
	case "config":
		return runConfig(fs.Args()[1:], stdout, stderr)
	case "serve":
		return runServe(ctx, fs.Args()[1:], stderr)
	case "":
		_, _ = fmt.Fprintf(stderr, "%s: no command given\n", binary)
	default:
		_, _ = fmt.Fprintf(stderr, "%s: unknown command %q\n", binary, fs.Arg(0))
	}
	fs.Usage()
	return 2
}
