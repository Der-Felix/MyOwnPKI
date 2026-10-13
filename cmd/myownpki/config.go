package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/config"
)

// runConfig handles `myownpki config <subcommand>`.
func runConfig(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "check" {
		_, _ = fmt.Fprintf(stderr, "Usage:\n  %s config check [--config FILE]\n", binary)
		if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
			return 2
		}
		_, _ = fmt.Fprintf(stderr, "%s config: unknown subcommand %q\n", binary, args[0])
		return 2
	}
	return runConfigCheck(args[1:], os.Environ(), stdout, stderr)
}

// runConfigCheck loads and validates the configuration exactly like the
// server will and prints the effective values with their source. Exit code
// 0 = valid, 1 = invalid, 2 = usage error.
func runConfigCheck(args, environ []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(binary+" config check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("config", "", "config file (default: $"+config.EnvConfigFile+", then "+
		config.DefaultPath(runtime.GOOS, os.Getenv)+")")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "%s config check: unexpected argument %q\n", binary, fs.Arg(0))
		return 2
	}
	if *path == "" {
		*path = lookupEnv(environ, config.EnvConfigFile)
	}
	if *path == "" {
		*path = config.DefaultPath(runtime.GOOS, os.Getenv)
	}

	cfg, src, err := config.Load(*path, environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}
	printConfig(stdout, cfg, src)
	return 0
}

func lookupEnv(environ []string, name string) string {
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			return v
		}
	}
	return ""
}

// printConfig shows the effective configuration; values set by an
// environment variable are marked, so an admin sees why a value differs
// from the file.
func printConfig(w io.Writer, cfg config.Config, src config.Source) {
	from := func(env string) string {
		if slices.Contains(src.Env, env) {
			return "   (from " + env + ")"
		}
		return ""
	}
	tls := "self-signed bootstrap certificate"
	if cfg.Admin.TLSCertFile != "" {
		tls = cfg.Admin.TLSCertFile + " + " + cfg.Admin.TLSKeyFile
	}
	public := cfg.Public.Listen
	if public == "" {
		public = "disabled"
	}
	rows := [][2]string{
		{"data_dir", cfg.DataDir + from("MYOWNPKI_DATA_DIR")},
		{"log.level", cfg.Log.Level + from("MYOWNPKI_LOG_LEVEL")},
		{"log.format", cfg.Log.Format + from("MYOWNPKI_LOG_FORMAT")},
		{"admin.listen", cfg.Admin.Listen + from("MYOWNPKI_ADMIN_LISTEN")},
		{"admin.tls", tls + from("MYOWNPKI_ADMIN_TLS_CERT_FILE") + from("MYOWNPKI_ADMIN_TLS_KEY_FILE")},
		{"public.listen", public + from("MYOWNPKI_PUBLIC_LISTEN")},
	}
	_, _ = fmt.Fprintf(w, "Config file: %s\n\n", src.File)
	for _, r := range rows {
		_, _ = fmt.Fprintf(w, "  %-14s %s\n", r[0], r[1])
	}
	_, _ = fmt.Fprintln(w, "\nConfiguration is valid.")
}
