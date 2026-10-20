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
