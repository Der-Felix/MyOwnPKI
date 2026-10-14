package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
)

// runCA handles `myownpki ca list|show` – read-only views of the CAs.
// Creating and renewing CAs comes with the API and the UI (PHASE1 13/18/19).
func runCA(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	usage := func() {
		_, _ = fmt.Fprintf(stderr, "Usage:\n  %s ca list [--config FILE]\n  %s ca show NAME [--config FILE]\n", binary, binary)
	}
	if len(args) == 0 {
		usage()
		return exitUsage
	}
	switch args[0] {
	case "list":
		return runCAList(ctx, args[1:], os.Environ(), stdout, stderr)
	case "show":
		return runCAShow(ctx, args[1:], os.Environ(), stdout, stderr)
	case "-h", "--help":
		usage()
		return exitOK
	}
	_, _ = fmt.Fprintf(stderr, "%s ca: unknown subcommand %q\n", binary, args[0])
	usage()
	return exitUsage
}

// loadCAs parses the flags, opens the tenant's pki.db read-only and reads
// every CA. positional are the expected arguments after the flags.
func loadCAs(ctx context.Context, name string, args, environ []string, positional int, stdout, stderr io.Writer) ([]ca.CAInfo, []string, int) {
	fset := flag.NewFlagSet(binary+" ca "+name, flag.ContinueOnError)
	fset.SetOutput(stderr)
	path := configFlag(fset)
	// Allow "ca show NAME --config FILE" as well as flags first.
	var rest []string
	for len(args) > 0 {
		if err := fset.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, nil, exitOK
			}
			return nil, nil, exitUsage
		}
		args = fset.Args()
		if len(args) > 0 {
			rest = append(rest, args[0])
			args = args[1:]
		}
	}
	if len(rest) != positional {
		_, _ = fmt.Fprintf(stderr, "%s ca %s: want %d argument(s), got %d\n", binary, name, positional, len(rest))
		return nil, nil, exitUsage
	}
	cfg, _, err := config.Load(configPath(*path, environ), environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return nil, nil, exitProblem
	}
	file, err := store.Layout{DataDir: cfg.DataDir}.TenantDB(store.DefaultTenant, store.KindPKI)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return nil, nil, exitProblem
	}
	if _, serr := os.Stat(file); errors.Is(serr, fs.ErrNotExist) {
		_, _ = fmt.Fprintf(stdout, "The CA database doesn't exist yet (run `%s db migrate`).\n", binary)
		return nil, nil, exitPending
	}
	db, err := store.OpenReadOnly(ctx, file)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return nil, nil, exitProblem
	}
	defer func() { _ = db.Close() }()
	cas, err := ca.ListCAs(ctx, db.Read)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "read CAs: %v (run `%s db status`)\n", err, binary)
		return nil, nil, exitProblem
	}
	return cas, rest, -1
}

func runCAList(ctx context.Context, args, environ []string, stdout, stderr io.Writer) int {
	cas, _, code := loadCAs(ctx, "list", args, environ, 0, stdout, stderr)
	if code >= 0 {
		return code
	}
	if len(cas) == 0 {
		_, _ = fmt.Fprintln(stdout, "No CAs yet.")
		return exitOK
	}
	w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "NAME\tKIND\tSTATUS\tKEY\tGENERATION\tVALID UNTIL\tPARENT\tNOTE")
	for _, c := range cas {
		gen, until, note := "-", "-", ""
		for _, g := range c.Generations {
			if len(g.Warnings) > 0 {
				note = "WARNING – see ca show"
			}
			if g.Current {
				gen, until = fmt.Sprint(g.Generation), dateOnly(g.NotAfter)
			}
			if g.Pending {
				gen += fmt.Sprintf(" (%d pending)", g.Generation)
			}
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", c.Name, c.Kind, c.Status, c.KeyMode, gen, until, orDash(c.Parent), note)
	}
	_ = w.Flush()
	return exitOK
}

func runCAShow(ctx context.Context, args, environ []string, stdout, stderr io.Writer) int {
	cas, rest, code := loadCAs(ctx, "show", args, environ, 1, stdout, stderr)
	if code >= 0 {
		return code
	}
	for _, c := range cas {
		if c.Name == rest[0] {
			showCA(stdout, c)
			return exitOK
		}
	}
	_, _ = fmt.Fprintf(stderr, "%s ca show: there is no CA named %q\n", binary, rest[0])
	return exitProblem
}

func showCA(out io.Writer, c ca.CAInfo) {
	p := func(label, value string) { _, _ = fmt.Fprintf(out, "  %-20s %s\n", label+":", value) }
	_, _ = fmt.Fprintf(out, "CA %s (%s, %s)\n", c.Name, c.Kind, c.Status)
	p("Parent", orDash(c.Parent))
	p("Key mode", c.KeyMode)
	p("Public base URL", c.BaseURL)
	if c.PathLen != nil {
		p("Path length", fmt.Sprint(*c.PathLen))
	}
	if len(c.NameConstraints) > 0 {
		crit := "critical"
		if !c.NameConstraintsCritical {
			crit = "NOT critical (compatibility switch)"
		}
		p("Name constraints", strings.Join(c.NameConstraints, "; ")+" – "+crit)
	}
	if len(c.EKULimit) > 0 {
		p("EKU limit", strings.Join(c.EKULimit, ", "))
	}
	p("CRL validity", fmt.Sprintf("%d days", c.CRLDays))
	p("Max. validity", fmt.Sprintf("%d days for issued certificates", c.MaxValidityDays))
	_, _ = fmt.Fprintln(out, "  Generations:")
	for _, g := range c.Generations {
		state := "previous"
		switch {
		case g.Pending:
			state = "waiting for its offline signature"
		case g.Current:
			state = "current"
		}
		_, _ = fmt.Fprintf(out, "    %d  %s, %s, %s\n", g.Generation, state, g.KeyAlgorithm, g.Subject)
		if !g.Pending {
			_, _ = fmt.Fprintf(out, "       valid %s to %s, serial %s\n", dateOnly(g.NotBefore), dateOnly(g.NotAfter), g.Serial)
			_, _ = fmt.Fprintf(out, "       SHA-256 %s\n", g.Fingerprint)
		}
		if g.Issuer != "" {
			_, _ = fmt.Fprintf(out, "       issued by %s\n", g.Issuer)
		}
		_, _ = fmt.Fprintf(out, "       published at %s and %s\n", g.CertURL, g.CRLURL)
		for _, w := range g.Warnings {
			_, _ = fmt.Fprintf(out, "       WARNING: %s\n", w)
		}
	}
}

func dateOnly(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return orDash(s)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
