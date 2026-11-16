package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBackupCommands: backup, verify and restore from the console; the
// restore refuses a data directory that is in use.
func TestBackupCommands(t *testing.T) {
	t.Parallel()
	cfg, dataDir := dbConfig(t)
	var buf bytes.Buffer
	if code := runDBMigrate(t.Context(), []string{"--config", cfg}, nil, &buf, &buf); code != exitOK {
		t.Fatal(buf.String())
	}
	dir := filepath.Join(t.TempDir(), "backup")
	var out bytes.Buffer
	if code := runBackup(t.Context(), []string{dir, "--config", cfg}, &out, &out); code != exitOK ||
		!strings.Contains(out.String(), "WARNING: This backup holds") || !strings.Contains(out.String(), "auth.key: ") {
		t.Fatalf("backup: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := runBackup(t.Context(), []string{"verify", dir}, &out, &out); code != exitOK || !strings.Contains(out.String(), "passed every check") {
		t.Fatalf("verify: %d\n%s", code, out.String())
	}
	out.Reset()
	if code := runRestore(t.Context(), []string{dir, "--config", cfg}, &out, &out); code != exitProblem || !strings.Contains(out.String(), "not empty") {
		t.Errorf("restore over the data directory: %d\n%s", code, out.String())
	}
	other, otherData := dbConfig(t)
	out.Reset()
	if code := runRestore(t.Context(), []string{dir, "--config", other}, &out, &out); code != exitOK || !strings.Contains(out.String(), "Restored into") {
		t.Fatalf("restore: %d\n%s", code, out.String())
	}
	if _, err := os.Stat(filepath.Join(otherData, "system.db")); err != nil {
		t.Error(err)
	}
	_ = dataDir
}

// TestBackupScheduled: the timer's run writes <parent>/<UTC time>, verifies
// it and keeps the newest --keep scheduled backups; prune --dry-run only
// reports, and nothing that isn't a scheduled backup is touched.
func TestBackupScheduled(t *testing.T) {
	t.Parallel()
	cfg, _ := dbConfig(t)
	var out bytes.Buffer
	if code := runDBMigrate(t.Context(), []string{"--config", cfg}, nil, &out, &out); code != exitOK {
		t.Fatal(out.String())
	}
	parent := t.TempDir()
	for _, args := range [][]string{
		{"scheduled", parent, "--config", cfg}, // no --keep
		{"scheduled", parent, "--keep", "0", "--config", cfg},
		{"prune", parent},
		{"prune", parent, "--keep", "1001"},
	} {
		out.Reset()
		if code := runBackup(t.Context(), args, &out, &out); code != exitUsage {
			t.Errorf("%v: %d %s", args, code, out.String())
		}
	}
	out.Reset()
	if code := runBackup(t.Context(), []string{"scheduled", filepath.Join(parent, "missing"), "--keep", "2", "--config", cfg}, &out, &out); code != exitProblem || !strings.Contains(out.String(), "is not a directory") {
		t.Errorf("missing parent: %d %s", code, out.String())
	}
	// Three older scheduled backups and an update backup of install.sh.
	seed := filepath.Join(t.TempDir(), "seed")
	out.Reset()
	if code := runBackup(t.Context(), []string{seed, "--config", cfg}, &out, &out); code != exitOK {
		t.Fatal(out.String())
	}
	older := []string{"20200101T000000Z", "20200102T000000Z", "20200103T000000Z", "20200101T000000Z-v0.2.1"}
	for _, n := range older {
		if err := os.CopyFS(filepath.Join(parent, n), os.DirFS(seed)); err != nil {
			t.Fatal(err)
		}
	}
	out.Reset()
	if code := runBackup(t.Context(), []string{"prune", parent, "--keep", "2", "--dry-run"}, &out, &out); code != exitOK ||
		!strings.Contains(out.String(), "Would delete "+filepath.Join(parent, "20200101T000000Z")+"\n") {
		t.Errorf("dry run: %d %s", code, out.String())
	}
	out.Reset()
	if code := runBackup(t.Context(), []string{"scheduled", parent, "--keep", "2", "--config", cfg}, &out, &out); code != exitOK ||
		!strings.Contains(out.String(), "Verified: the backup passed every check") || !strings.Contains(out.String(), "kept 2, deleted 2 (20200101T000000Z, 20200102T000000Z)") {
		t.Fatalf("scheduled: %d\n%s", code, out.String())
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, e := range entries {
		left = append(left, e.Name())
	}
	if len(left) != 3 || left[0] != "20200101T000000Z-v0.2.1" || left[1] != "20200103T000000Z" || len(left[2]) != len("20261025T031500Z") {
		t.Errorf("left: %v", left)
	}
}

// fingerprintIn finds "SHA256:<32 hex digits>" in text.
func fingerprintIn(t *testing.T, text string) string {
	t.Helper()
	i := strings.Index(text, "SHA256:")
	if i < 0 || len(text) < i+7+32 {
		t.Fatalf("no key fingerprint in\n%s", text)
	}
	return text[i : i+7+32]
}

// TestBackupSignatureCommands: the backup key, what verify says about a
// signed backup, a wrong pin, a backup of a version before 0.9.0, and a
// restore on a host that has no key.
func TestBackupSignatureCommands(t *testing.T) {
	t.Parallel()
	cfg, dataDir := dbConfig(t)
	var out bytes.Buffer
	if code := runDBMigrate(t.Context(), []string{"--config", cfg}, nil, &out, &out); code != exitOK {
		t.Fatal(out.String())
	}
	run := func(fn func(context.Context, []string, io.Writer, io.Writer) int, args ...string) (int, string) {
		t.Helper()
		out.Reset()
		code := fn(t.Context(), args, &out, &out)
		return code, out.String()
	}
	dir := filepath.Join(t.TempDir(), "backup")
	code, text := run(runBackup, dir, "--config", cfg)
	if code != exitOK || !strings.Contains(text, "backup key SHA256:") || !strings.Contains(text, "This key was made now") {
		t.Fatalf("first backup: %d\n%s", code, text)
	}
	fp := fingerprintIn(t, text)
	if _, err := os.Stat(filepath.Join(dataDir, "backup-signing.key")); err != nil {
		t.Fatal(err)
	}
	if code, text = run(runBackup, filepath.Join(t.TempDir(), "second"), "--config", cfg); code != exitOK ||
		!strings.Contains(text, "backup key "+fp) || strings.Contains(text, "This key was made now") {
		t.Fatalf("second backup: %d\n%s", code, text)
	}

	// verify with the configuration: this host's key is the expected one.
	if code, text = run(runBackup, "verify", dir, "--config", cfg); code != exitOK ||
		!strings.Contains(text, "Signature valid: made by key "+fp+", the backup key of this host.") || !strings.Contains(text, "passed every check") {
		t.Fatalf("verify on the host: %d\n%s", code, text)
	}
	// verify on a machine that knows nothing: signed, by a key nobody vouched for.
	if code, text = run(runBackup, "verify", dir); code != exitOK ||
		!strings.Contains(text, "a key nobody has vouched for yet") || !strings.Contains(text, "note: signed by key "+fp) {
		t.Fatalf("verify without a key: %d\n%s", code, text)
	}
	if code, text = run(runBackup, "verify", dir, "--backup-key", fp); code != exitOK || !strings.Contains(text, "the key you named") {
		t.Fatalf("verify with the pin: %d\n%s", code, text)
	}
	if code, text = run(runBackup, "verify", dir, "--backup-key", "SHA256:00000000000000000000000000000000"); code != exitProblem ||
		!strings.Contains(text, "not by the expected key") || strings.Contains(text, "passed every check") {
		t.Fatalf("verify with a wrong pin: %d\n%s", code, text)
	}
	if code, text = run(runBackup, "verify", dir, "--backup-key", "abc"); code != exitProblem || !strings.Contains(text, "backup key") {
		t.Fatalf("verify with a malformed pin: %d\n%s", code, text)
	}

	// The timer's run signs with the same key and checks that it did.
	parent := t.TempDir()
	if code, text = run(runBackup, "scheduled", parent, "--keep", "2", "--config", cfg); code != exitOK ||
		!strings.Contains(text, "backup key "+fp) || !strings.Contains(text, "Verified: the backup passed every check") {
		t.Fatalf("scheduled: %d\n%s", code, text)
	}

	// Restore on a host without the key: works with the fingerprint, says that
	// the new instance has no key.
	other, otherData := dbConfig(t)
	if code, text = run(runRestore, dir, "--config", other, "--backup-key", fp); code != exitOK ||
		!strings.Contains(text, "Restored into") || !strings.Contains(text, "never part of a backup") {
		t.Fatalf("restore: %d\n%s", code, text)
	}
	if _, err := os.Stat(filepath.Join(otherData, "backup-signing.key")); !os.IsNotExist(err) {
		t.Errorf("the key was restored: %v", err)
	}

	// A backup of a version before 0.9.0.
	old := filepath.Join(t.TempDir(), "old")
	if err := os.CopyFS(old, os.DirFS(dir)); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(old, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest = bytes.Replace(manifest, []byte("myownpki-backup/2"), []byte("myownpki-backup/1"), 1)
	if err := os.WriteFile(filepath.Join(old, "manifest.json"), manifest, 0o600); err != nil { // #nosec G703 -- the test's own backup copy
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(old, "manifest.sig")); err != nil {
		t.Fatal(err)
	}
	if code, text = run(runBackup, "verify", old); code != exitOK ||
		!strings.Contains(text, "unauthenticated") || !strings.Contains(text, "no signature (made before 0.9.0)") {
		t.Fatalf("verify of a format 1 backup: %d\n%s", code, text)
	}
	if code, text = run(runBackup, "verify", old, "--backup-key", fp); code != exitProblem || !strings.Contains(text, "has no signature") {
		t.Fatalf("format 1 with a pin: %d\n%s", code, text)
	}
	// The host's own key is a pin too: no --backup-key needed to refuse it.
	if code, text = run(runBackup, "verify", old, "--config", cfg); code != exitProblem || !strings.Contains(text, "has no signature") {
		t.Fatalf("format 1 on the host: %d\n%s", code, text)
	}
	if code, text = run(runBackup, "verify", old, "--config", cfg, "--allow-unsigned"); code != exitOK || !strings.Contains(text, "unauthenticated") {
		t.Fatalf("format 1 with --allow-unsigned: %d\n%s", code, text)
	}
	another, _ := dbConfig(t)
	if code, text = run(runRestore, old, "--config", another, "--backup-key", fp, "--allow-unsigned"); code != exitOK || !strings.Contains(text, "unauthenticated") {
		t.Fatalf("restore of a format 1 backup: %d\n%s", code, text)
	}
}
