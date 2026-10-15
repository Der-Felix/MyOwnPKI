package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/setup"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
)

// Exit codes of `db status`, for scripts and monitoring.
const (
	exitOK      = 0
	exitProblem = 1 // wrong file type, modified or newer migrations, unreadable file
	exitUsage   = 2
	exitPending = 3 // files missing or migrations pending: run `db migrate`
)

// runDB handles `myownpki db <status|migrate>`.
func runDB(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	usage := func() {
		_, _ = fmt.Fprintf(stderr, "Usage:\n  %s db status [--config FILE]\n  %s db migrate [--config FILE]\n", binary, binary)
	}
	if len(args) == 0 {
		usage()
		return exitUsage
	}
	switch args[0] {
	case "status":
		return runDBStatus(ctx, args[1:], os.Environ(), stdout, stderr)
	case "migrate":
		return runDBMigrate(ctx, args[1:], os.Environ(), stdout, stderr)
	case "-h", "--help":
		usage()
		return exitOK
	}
	_, _ = fmt.Fprintf(stderr, "%s db: unknown subcommand %q\n", binary, args[0])
	usage()
	return exitUsage
}

// loadForDB parses the flags of a db subcommand and loads the configuration.
func loadForDB(name string, args, environ []string, stderr io.Writer) (config.Config, int) {
	fs := flag.NewFlagSet(binary+" db "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := configFlag(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return config.Config{}, exitOK
		}
		return config.Config{}, exitUsage
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "%s db %s: unexpected argument %q\n", binary, name, fs.Arg(0))
		return config.Config{}, exitUsage
	}
	cfg, _, err := config.Load(configPath(*path, environ), environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return config.Config{}, exitProblem
	}
	return cfg, -1
}

// runDBStatus shows every database file without creating or changing anything.
func runDBStatus(ctx context.Context, args, environ []string, stdout, stderr io.Writer) int {
	cfg, code := loadForDB("status", args, environ, stderr)
	if code >= 0 {
		return code
	}
	l := store.Layout{DataDir: cfg.DataDir}
	sts, err := store.Status(ctx, l, store.DefaultTenant)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return exitProblem
	}
	_, _ = fmt.Fprintf(stdout, "Data directory: %s\n\n", cfg.DataDir)
	var problem, pending bool
	for _, st := range sts {
		rel, _ := filepath.Rel(cfg.DataDir, st.Path)
		var line string
		switch {
		case st.Err != nil:
			line = "PROBLEM: " + st.Err.Error()
			problem = true
		case !st.Exists:
			line = "not created yet"
			pending = true
		case st.Report.Pending() > 0:
			line = fmt.Sprintf("%d migration(s) pending – version %d of %d", st.Report.Pending(), st.Report.Version(), st.Available)
			pending = true
		default:
			line = fmt.Sprintf("up to date – version %d of %d, journal %s", st.Report.Version(), st.Available, st.JournalMode)
		}
		_, _ = fmt.Fprintf(stdout, "  %-28s %s\n", filepath.ToSlash(rel), line)
	}
	if sys := sts[0]; sys.Kind == store.KindSystem && sys.Exists && sys.Err == nil && sys.Report.Pending() == 0 {
		tenants, err := store.Tenants(ctx, l)
		if err != nil {
			_, _ = fmt.Fprintf(stdout, "\n  tenants: PROBLEM: %v\n", err)
			problem = true
		} else {
			names := make([]string, len(tenants))
			for i, t := range tenants {
				names[i] = t.ID
			}
			_, _ = fmt.Fprintf(stdout, "\n  Tenants in system.db: %s\n", strings.Join(names, ", "))
		}
		printInstance(ctx, stdout, sys.Path)
	}
	for _, st := range sts {
		if st.Kind == store.KindPKI && st.Exists && st.Err == nil && st.Report.Pending() == 0 {
			printCRLStatus(ctx, stdout, st.Path)
		}
	}
	// A problem outranks pending migrations: migrating would not fix it.
	switch {
	case problem:
		_, _ = fmt.Fprintln(stdout, "\nThe server will refuse to start until the problem is solved – usually by restoring a backup.")
		return exitProblem
	case pending:
		_, _ = fmt.Fprintf(stdout, "\nRun `%s db migrate` to create missing files and apply pending migrations.\n", binary)
		return exitPending
	}
	return exitOK
}

// runDBMigrate creates missing directories and database files and applies
// pending migrations. The server does the same at start-up.
func runDBMigrate(ctx context.Context, args, environ []string, stdout, stderr io.Writer) int {
	cfg, code := loadForDB("migrate", args, environ, stderr)
	if code >= 0 {
		return code
	}
	applied, err := store.Migrate(ctx, store.Layout{DataDir: cfg.DataDir}, store.DefaultTenant, clock.System{}.Now)
	for _, a := range applied {
		rel, _ := filepath.Rel(cfg.DataDir, a.Path)
		what := "already up to date"
		if len(a.Versions) > 0 {
			what = fmt.Sprintf("applied %d migration(s), now version %d", len(a.Versions), a.Versions[len(a.Versions)-1])
		}
		_, _ = fmt.Fprintf(stdout, "  %-28s %s\n", filepath.ToSlash(rel), what)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return exitProblem
	}
	return exitOK
}

// printInstance says whether init ran – and warns about a demo instance.
func printInstance(ctx context.Context, stdout io.Writer, path string) {
	db, err := store.OpenReadOnly(ctx, path)
	if err != nil {
		_, _ = fmt.Fprintf(stdout, "  Instance: PROBLEM: %v\n", err)
		return
	}
	defer func() { _ = db.Close() }()
	inst, err := setup.ReadInstance(ctx, db.Read)
	switch {
	case err != nil:
		_, _ = fmt.Fprintf(stdout, "  Instance: PROBLEM: %v\n", err)
	case !inst.Initialized:
		_, _ = fmt.Fprintf(stdout, "  Instance: not initialized yet – run `%s init`\n", binary)
	case inst.Demo:
		_, _ = fmt.Fprintf(stdout, "  Instance: initialized %s\n  WARNING: %s\n", inst.InitializedAt, setup.DemoWarning)
	default:
		_, _ = fmt.Fprintf(stdout, "  Instance: initialized %s\n", inst.InitializedAt)
	}
}
