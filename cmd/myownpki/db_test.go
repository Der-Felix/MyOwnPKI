package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// dbConfig writes a config file whose data_dir is a fresh temp directory.
func dbConfig(t *testing.T) (configFile, dataDir string) {
	t.Helper()
	dataDir = filepath.Join(t.TempDir(), "data")
	configFile = filepath.Join(t.TempDir(), "config.yaml")
	content := "data_dir: \"" + strings.ReplaceAll(dataDir, `\`, `\\`) + "\"\n"
	if err := os.WriteFile(configFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return configFile, dataDir
}

func TestDBStatusAndMigrate(t *testing.T) {
	t.Parallel()
	cfg, dataDir := dbConfig(t)
	var stdout, stderr bytes.Buffer

	// Before: nothing exists, status says so and creates nothing.
	if code := runDBStatus(t.Context(), []string{"--config", cfg}, nil, &stdout, &stderr); code != exitPending {
		t.Fatalf("status before migrate: exit %d, want %d\n%s%s", code, exitPending, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "system.db") || !strings.Contains(stdout.String(), "not created yet") ||
		!strings.Contains(stdout.String(), "tenants/default/pki.db") {
		t.Errorf("status output:\n%s", stdout.String())
	}
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Error("db status created the data directory")
	}

	stdout.Reset()
	if code := runDBMigrate(t.Context(), []string{"--config", cfg}, nil, &stdout, &stderr); code != exitOK {
		t.Fatalf("migrate: exit %d\n%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "applied 1 migration(s)") {
		t.Errorf("migrate output:\n%s", stdout.String())
	}

	stdout.Reset()
	if code := runDBStatus(t.Context(), []string{"--config", cfg}, nil, &stdout, &stderr); code != exitOK {
		t.Fatalf("status after migrate: exit %d\n%s", code, stdout.String())
	}
	if strings.Count(stdout.String(), "up to date") != 3 || !strings.Contains(stdout.String(), "journal wal") {
		t.Errorf("status output:\n%s", stdout.String())
	}

	stdout.Reset()
	if code := runDBMigrate(t.Context(), []string{"--config", cfg}, nil, &stdout, &stderr); code != exitOK ||
		strings.Count(stdout.String(), "already up to date") != 3 {
		t.Errorf("second migrate: exit %d\n%s", code, stdout.String())
	}
}

func TestDBStatusProblemOutranksPending(t *testing.T) {
	t.Parallel()
	cfg, dataDir := dbConfig(t)
	var out bytes.Buffer
	if code := runDBMigrate(t.Context(), []string{"--config", cfg}, nil, &out, &out); code != exitOK {
		t.Fatal(out.String())
	}
	// audit.db over pki.db (wrong type) and system.db removed (pending).
	tenant := filepath.Join(dataDir, "tenants", "default")
	data, err := os.ReadFile(filepath.Join(tenant, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(tenant, "pki.db"), data, 0o600); err != nil { //nolint:gosec // temp dir of the test
		t.Fatal(err)
	}
	for _, f := range []string{"system.db", "system.db-wal", "system.db-shm"} {
		_ = os.Remove(filepath.Join(dataDir, f))
	}

	out.Reset()
	if code := runDBStatus(t.Context(), []string{"--config", cfg}, nil, &out, &out); code != exitProblem {
		t.Errorf("exit %d, want %d (a problem must not be reported as merely pending)\n%s", code, exitProblem, out.String())
	}
	if !strings.Contains(out.String(), "PROBLEM: database file has the wrong type") {
		t.Errorf("output:\n%s", out.String())
	}
}

func TestDBUsage(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{{"db"}, {"db", "drop"}} {
		var stdout, stderr bytes.Buffer
		if code := run(t.Context(), args, &stdout, &stderr); code != exitUsage || !strings.Contains(stderr.String(), "db status") {
			t.Errorf("%v: exit %d\n%s", args, code, stderr.String())
		}
	}
}
