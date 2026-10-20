package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Der-Felix/MyOwnPKI/internal/backup"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
)

// runBackup handles `myownpki backup DIR` and `myownpki backup verify DIR`
// (PHASE1 step 16).
func runBackup(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	usage := func() {
		_, _ = fmt.Fprintf(stderr, "Usage:\n  %s backup DIR [--config FILE]          copy every database into the new directory DIR (also while the server runs)\n"+
			"  %s backup verify DIR [--checkpoint-key FP]  run every restore check on DIR, write nothing\n"+
			"  %s restore DIR [--config FILE] [--checkpoint-key FP]  restore into the (empty) data directory\n", binary, binary, binary)
	}
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		usage()
		if len(args) == 0 {
			return exitUsage
		}
		return exitOK
	}
	if args[0] == "verify" {
		return runBackupVerify(ctx, args[1:], stdout, stderr)
	}
	fset := flag.NewFlagSet(binary+" backup", flag.ContinueOnError)
	fset.SetOutput(stderr)
	path := configFlag(fset)
	dir, code := parseUserArgs(fset, args, stderr)
	if code >= 0 {
		return code
	}
	cfg, code := loadConfig(*path, os.Environ(), stderr)
	if code >= 0 {
		return code
	}
	m, err := backup.Create(ctx, dir, backup.Options{Layout: store.Layout{DataDir: cfg.DataDir}, AuthKeyFile: cfg.AuthKeyFile(), Clock: clock.System{}, Who: consoleWho()})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return exitProblem
	}
	_, _ = fmt.Fprintf(stdout, "Backup written to %s: %d files, tenants %v.\n", dir, len(m.Files), m.Tenants)
	for _, lg := range m.Audit {
		_, _ = fmt.Fprintf(stdout, "  audit %-16s head %s (%d entries)\n", lg.Scope, lg.Head, lg.Entries)
	}
	if m.CheckpointKey != "" {
		_, _ = fmt.Fprintf(stdout, "  checkpoint key %s – the same as noted at init?\n", m.CheckpointKey)
	}
	if m.AuthKey {
		_, _ = fmt.Fprintln(stdout, "  auth.key is in the backup (it lives in the data directory).")
	} else if _, serr := os.Stat(cfg.AuthKeyFile()); serr != nil {
		_, _ = fmt.Fprintf(stdout, "  auth.key: %s doesn't exist (yet) – nothing to back up.\n", cfg.AuthKeyFile())
	} else {
		_, _ = fmt.Fprintf(stdout, "  auth.key is NOT in the backup (%s is outside the data directory) – back it up separately,\n  or every user needs `%s user reset-2fa` after a restore.\n", cfg.AuthKeyFile(), binary)
	}
	_, _ = fmt.Fprintf(stdout, "\nWARNING: %s\nCheck the backup now and then: %s backup verify %s\n", backup.Warning, binary, dir)
	return exitOK
}

func runBackupVerify(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet(binary+" backup verify", flag.ContinueOnError)
	fset.SetOutput(stderr)
	pin := fset.String("checkpoint-key", "", "fingerprint of the checkpoint key noted at init (recommended)")
	dir, code := parseUserArgs(fset, args, stderr)
	if code >= 0 {
		return code
	}
	rep, err := backup.Verify(ctx, dir, *pin)
	printBackupReport(stdout, rep, *pin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return exitProblem
	}
	_, _ = fmt.Fprintln(stdout, "The backup passed every check of a restore.")
	return exitOK
}

// runRestore handles `myownpki restore DIR`.
func runRestore(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet(binary+" restore", flag.ContinueOnError)
	fset.SetOutput(stderr)
	path := configFlag(fset)
	pin := fset.String("checkpoint-key", "", "fingerprint of the checkpoint key noted at init (recommended)")
	dir, code := parseUserArgs(fset, args, stderr)
	if code >= 0 {
		return code
	}
	cfg, code := loadConfig(*path, os.Environ(), stderr)
	if code >= 0 {
		return code
	}
	rep, err := backup.Restore(ctx, dir, *pin, backup.Options{Layout: store.Layout{DataDir: cfg.DataDir}, AuthKeyFile: cfg.AuthKeyFile(), Clock: clock.System{}, Who: consoleWho()})
	printBackupReport(stdout, rep, *pin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		if errors.Is(err, backup.ErrRefused) {
			_, _ = fmt.Fprintln(stderr, "Nothing was restored.")
		}
		return exitProblem
	}
	_, _ = fmt.Fprintf(stdout, "Restored into %s. Start the server and unseal it with the passphrase of the backed-up instance.\n", cfg.DataDir)
	return exitOK
}

func printBackupReport(w io.Writer, rep *backup.Report, pin string) {
	if rep == nil || rep.Manifest == nil {
		return
	}
	m := rep.Manifest
	_, _ = fmt.Fprintf(w, "Backup of %s (MyOwnPKI %s), tenants %v, %d files.\n", m.CreatedAt, m.Version, m.Tenants, len(m.Files))
	if m.CheckpointKey != "" && pin == "" {
		_, _ = fmt.Fprintf(w, "Checkpoint key %s – compare it with the one noted at init (or pass --checkpoint-key).\n", m.CheckpointKey)
	}
	if rep.Certificates > 0 {
		_, _ = fmt.Fprintf(w, "Name index checked for %d certificates.\n", rep.Certificates)
	}
	for _, n := range rep.Notes {
		_, _ = fmt.Fprintf(w, "note: %s\n", n)
	}
	for _, p := range rep.Problems {
		_, _ = fmt.Fprintf(w, "problem: %s\n", p)
	}
}

// loadConfig reads the configuration for a console command.
func loadConfig(path string, environ []string, stderr io.Writer) (config.Config, int) {
	cfg, _, err := config.Load(configPath(path, environ), environ)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return config.Config{}, exitProblem
	}
	return cfg, -1
}
