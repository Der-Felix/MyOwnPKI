// Command myownpki is the MyOwnPKI server: web UI, REST API, ACME server and CA engine.
//
// Phase 0: only --version is implemented.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Der-Felix/MyOwnPKI/internal/version"
)

const binary = "myownpki"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run parses the arguments and returns the process exit code
// (0 success, 2 usage error).
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(binary, flag.ContinueOnError)
	fs.SetOutput(stderr)
	showVersion := fs.Bool("version", false, "print version information and exit")
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

	_, _ = fmt.Fprintf(stderr, "%s: no command given (phase 0 only supports --version)\n", binary)
	fs.Usage()
	return 2
}
