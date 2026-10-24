package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/authz"
	"github.com/Der-Felix/MyOwnPKI/internal/backup"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/config"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
)

// runBackup handles `myownpki backup DIR` and `myownpki backup verify DIR`
// (PHASE1 step 16).
func runBackup(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	usage := func() {
		_, _ = fmt.Fprintf(stderr, "Usage:\n  %s backup DIR [--config FILE]          copy every database into the new directory DIR (also while the server runs)\n"+
			"  %s backup verify DIR [--checkpoint-key FP]  run every restore check on DIR, write nothing\n"+
			"  %s backup scheduled DIR --keep 14 [--config FILE]  the timer's run: DIR/<UTC time>, verify, then prune\n"+
			"  %s backup prune DIR --keep 14 [--dry-run]  keep the newest N scheduled backups in DIR, delete older ones\n"+
			"  %s restore DIR [--config FILE] [--checkpoint-key FP]  restore into the (empty) data directory\n", binary, binary, binary, binary, binary)
	}
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		usage()
		if len(args) == 0 {
			return exitUsage
		}
		return exitOK
	}
	switch args[0] {
	case "verify":
		return runBackupVerify(ctx, args[1:], stdout, stderr)
	case "scheduled":
		return runBackupScheduled(ctx, args[1:], stdout, stderr)
	case "prune":
		return runBackupPrune(args[1:], stdout, stderr)
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

// scheduledWho is the actor of a backup the timer makes (v0.2.2): the
// system, not a person at the console.
var scheduledWho = keys.Who{Actor: audit.Actor{Type: audit.ActorSystem, Name: "backup-timer"}, Principal: authz.System("backup-timer")}

// runBackupScheduled is what myownpki-backup.service runs (v0.2.2): a backup
// into DIR/<UTC time>, every restore check on it, then the prune – only when
// the check passed. A backup that fails its check is renamed to
// <time>-unverified: kept for a look, never pruned, never counted as one of
// the kept backups. Any failure ends with exit 1, so systemd marks the run
// as failed (systemctl --failed, the journal).
func runBackupScheduled(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet(binary+" backup scheduled", flag.ContinueOnError)
	fset.SetOutput(stderr)
	path := configFlag(fset)
	keep := fset.Int("keep", 0, "how many scheduled backups to keep (1-"+strconv.Itoa(backup.MaxKeep)+")")
	parent, code := parseUserArgs(fset, args, stderr)
	if code >= 0 {
		return code
	}
	if *keep < 1 || *keep > backup.MaxKeep {
		_, _ = fmt.Fprintf(stderr, "%s: --keep must be 1 to %d\n", fset.Name(), backup.MaxKeep)
		return exitUsage
	}
	cfg, code := loadConfig(*path, os.Environ(), stderr)
	if code >= 0 {
		return code
	}
	if st, err := os.Stat(parent); err != nil || !st.IsDir() {
		_, _ = fmt.Fprintf(stderr, "%s is not a directory – create it (install.sh does: 0700, owned by the service user)\n", parent)
		return exitProblem
	}
	clk := clock.System{}
	dir := filepath.Join(parent, backup.ScheduledName(clk.Now()))
	m, err := backup.Create(ctx, dir, backup.Options{Layout: store.Layout{DataDir: cfg.DataDir}, AuthKeyFile: cfg.AuthKeyFile(), Clock: clk, Who: scheduledWho})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "backup failed: %v\n", err)
		return exitProblem
	}
	_, _ = fmt.Fprintf(stdout, "Backup written to %s: %d files, tenants %v.\n", dir, len(m.Files), m.Tenants)
	rep, err := backup.Verify(ctx, dir, "")
	if err != nil {
		for _, p := range problems(rep) {
			_, _ = fmt.Fprintf(stderr, "problem: %s\n", p)
		}
		bad := dir + backup.UnverifiedSuffix
		if rerr := os.Rename(dir, bad); rerr != nil {
			bad = dir
		}
		_, _ = fmt.Fprintf(stderr, "backup verify failed: %v – kept as %s, nothing pruned\n", err, bad)
		return exitProblem
	}
	_, _ = fmt.Fprintln(stdout, "Verified: the backup passed every check of a restore.")
	res, err := backup.Prune(parent, *keep, false)
	if res != nil {
		printPrune(stdout, parent, res, false)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "prune: %v\n", err)
		return exitProblem
	}
	return exitOK
}

// runBackupPrune handles `myownpki backup prune DIR --keep 14 [--dry-run]`.
// It needs no config: it reads only DIR.
func runBackupPrune(args []string, stdout, stderr io.Writer) int {
	fset := flag.NewFlagSet(binary+" backup prune", flag.ContinueOnError)
	fset.SetOutput(stderr)
	keep := fset.Int("keep", 0, "how many scheduled backups to keep (1-"+strconv.Itoa(backup.MaxKeep)+")")
	dry := fset.Bool("dry-run", false, "only show what would be deleted")
	parent, code := parseUserArgs(fset, args, stderr)
	if code >= 0 {
		return code
	}
	if *keep < 1 || *keep > backup.MaxKeep {
		_, _ = fmt.Fprintf(stderr, "%s: --keep must be 1 to %d\n", fset.Name(), backup.MaxKeep)
		return exitUsage
	}
	res, err := backup.Prune(parent, *keep, *dry)
	if res != nil {
		printPrune(stdout, parent, res, *dry)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%v\n", err)
		return exitProblem
	}
	return exitOK
}

func printPrune(w io.Writer, parent string, res *backup.PruneResult, dry bool) {
	verb := "Deleted"
	if dry {
		verb = "Would delete"
	}
	for _, n := range res.Deleted {
		_, _ = fmt.Fprintf(w, "%s %s\n", verb, filepath.Join(parent, n))
	}
	for _, s := range res.Skipped {
		_, _ = fmt.Fprintf(w, "Left alone %s: %s\n", filepath.Join(parent, s.Name), s.Reason)
	}
	_, _ = fmt.Fprintf(w, "Scheduled backups in %s: %s. Only scheduled backups (named like 20261025T031500Z) are ever deleted.\n", parent, res)
}

func problems(rep *backup.Report) []string {
	if rep == nil {
		return nil
	}
	return rep.Problems
}
