package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
)

// runAudit handles `myownpki audit verify`.
func runAudit(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	usage := func() {
		_, _ = fmt.Fprintf(stderr, "Usage:\n  %s audit verify [--config FILE] [--scope instance|tenant:default] [--expect-head SEQ:HASH]\n", binary)
	}
	if len(args) == 0 || args[0] != "verify" {
		usage()
		if len(args) > 0 && args[0] != "-h" && args[0] != "--help" {
			_, _ = fmt.Fprintf(stderr, "%s audit: unknown subcommand %q\n", binary, args[0])
		}
		return exitUsage
	}
	return runAuditVerify(ctx, args[1:], os.Environ(), stdout, stderr)
}

// runAuditVerify walks every audit chain (read-only). Exit codes as for
// `db status`: 0 intact, 1 broken or unreadable, 3 a log doesn't exist yet.
func runAuditVerify(ctx context.Context, args, environ []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(binary+" audit verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := configFlag(fs)
	scope := fs.String("scope", "", "verify only this log: instance or tenant:<id> (default: all)")
	expect := fs.String("expect-head", "", "SEQ:HASH noted earlier (process log, backup manifest); needs --scope")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "%s audit verify: unexpected argument %q\n", binary, fs.Arg(0))
		return exitUsage
	}
	var want *audit.Head
	if *expect != "" {
		if *scope == "" {
			_, _ = fmt.Fprintf(stderr, "%s audit verify: --expect-head needs --scope (a head belongs to one log)\n", binary)
			return exitUsage
		}
		h, err := audit.ParseHead(*expect)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "%s audit verify: --expect-head: %v\n", binary, err)
			return exitUsage
		}
		want = &h
	}

	cfg, _, err := config.Load(configPath(*path, environ), environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return exitProblem
	}
	logs, err := store.Layout{DataDir: cfg.DataDir}.AuditLogs(store.DefaultTenant)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return exitProblem
	}

	result, matched := exitOK, false
	for _, log := range logs {
		if *scope != "" && log.Scope != *scope {
			continue
		}
		matched = true
		line, code := verifyLog(ctx, log, want)
		_, _ = fmt.Fprintf(stdout, "  %-16s %s\n", log.Scope, line)
		if code == exitProblem || (code == exitPending && result == exitOK) {
			result = code
		}
	}
	if !matched {
		_, _ = fmt.Fprintf(stderr, "%s audit verify: no audit log with scope %q\n", binary, *scope)
		return exitUsage
	}
	if result == exitProblem {
		_, _ = fmt.Fprintln(stdout, "\nThe audit log was changed outside MyOwnPKI. Keep the file for investigation and compare with a backup.")
	}
	return result
}

func verifyLog(ctx context.Context, log store.AuditLog, want *audit.Head) (string, int) {
	if _, err := os.Stat(log.Path); errors.Is(err, fs.ErrNotExist) {
		return "not created yet (run `" + binary + " db migrate`)", exitPending
	}
	db, err := store.OpenAuditLog(ctx, log)
	if err != nil {
		return "PROBLEM: " + err.Error(), exitProblem
	}
	defer func() { _ = db.Close() }()
	rep, err := audit.Verify(ctx, db.Read, log.Scope)
	switch {
	case err != nil:
		return "PROBLEM: " + err.Error(), exitProblem
	case rep.Break != nil:
		return fmt.Sprintf("BROKEN at seq %d – %s", rep.Break.Seq, rep.Break.Reason), exitProblem
	}
	if want != nil {
		if err := audit.CheckHead(ctx, db.Read, *want); err != nil {
			return "BROKEN – " + err.Error(), exitProblem
		}
	}
	line := fmt.Sprintf("OK – %d entries, head %s", rep.Entries, rep.Head)
	if want != nil {
		line += fmt.Sprintf(" (contains expected head %d)", want.Seq)
	}
	return line, exitOK
}
