package main

import (
	"bytes"
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
