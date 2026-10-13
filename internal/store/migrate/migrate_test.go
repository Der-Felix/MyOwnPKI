package migrate_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/store/migrate"
)

var now = time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)

func files(m map[string]string) fstest.MapFS {
	fsys := fstest.MapFS{}
	for name, content := range m {
		fsys[name] = &fstest.MapFile{Data: []byte(content)}
	}
	return fsys
}

func mustLoad(t *testing.T, m map[string]string) []migrate.Migration {
	t.Helper()
	set, err := migrate.Load(files(m))
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func tableExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var n int
	if err := db.QueryRowContext(t.Context(), `SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?`, name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

func TestLoad(t *testing.T) {
	t.Parallel()
	set := mustLoad(t, map[string]string{
		"0002_second.sql": "CREATE TABLE b (x);",
		"0001_first.sql":  "CREATE TABLE a (x);",
		"README.md":       "ignored",
	})
	if len(set) != 2 || set[0].Version != 1 || set[0].Name != "first" || set[1].Version != 2 {
		t.Fatalf("set = %+v", set)
	}

	crlf := mustLoad(t, map[string]string{"0001_first.sql": "CREATE TABLE a (x);\r\nCREATE TABLE c (y);\r\n"})
	lf := mustLoad(t, map[string]string{"0001_first.sql": "CREATE TABLE a (x);\nCREATE TABLE c (y);\n"})
	if crlf[0].Checksum != lf[0].Checksum {
		t.Error("checksum depends on line endings – Windows and Linux builds would disagree")
	}
}

func TestLoadRejectsBadSets(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		files   map[string]string
		wantErr string
	}{
		{"gap", map[string]string{"0001_a.sql": "SELECT 1;", "0003_c.sql": "SELECT 1;"}, "expected version 0002"},
		{"duplicate", map[string]string{"0001_a.sql": "SELECT 1;", "0001_b.sql": "SELECT 1;"}, "expected version 0002"},
		{"not starting at 1", map[string]string{"0002_b.sql": "SELECT 1;"}, "expected version 0001"},
		{"bad name", map[string]string{"1_init.sql": "SELECT 1;"}, "want NNNN_lower_case_name.sql"},
		{"upper case", map[string]string{"0001_Init.sql": "SELECT 1;"}, "want NNNN_lower_case_name.sql"},
		{"empty", map[string]string{"0001_a.sql": "  \n"}, "is empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := migrate.Load(files(tt.files))
			if !errors.Is(err, migrate.ErrInvalidSet) || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want ErrInvalidSet containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestApply(t *testing.T) {
	t.Parallel()
	db := openDB(t)
	set := mustLoad(t, map[string]string{
		"0001_a.sql": "CREATE TABLE a (x INTEGER);",
		"0002_b.sql": "CREATE TABLE b (x INTEGER); INSERT INTO b VALUES (1);",
	})
	clk := clock.NewFake(now)

	done, err := migrate.Apply(t.Context(), db, set, clk.Now)
	if err != nil || !slices.Equal(done, []int{1, 2}) {
		t.Fatalf("Apply = %v, %v", done, err)
	}
	report, err := migrate.Check(t.Context(), db, set)
	if err != nil || report.Pending() != 0 || report.Version() != 2 {
		t.Fatalf("Check = %+v, %v", report, err)
	}
	if got := report.Migrations[0].AppliedAt; got != "2026-10-13T08:00:00Z" {
		t.Errorf("applied_at = %q, want UTC from the injected clock", got)
	}

	clk.Advance(time.Hour)
	done, err = migrate.Apply(t.Context(), db, set, clk.Now)
	if err != nil || len(done) != 0 {
		t.Errorf("second Apply = %v, %v; want nothing to do", done, err)
	}

	// A third migration in a newer binary is applied on top.
	set3 := mustLoad(t, map[string]string{
		"0001_a.sql": "CREATE TABLE a (x INTEGER);",
		"0002_b.sql": "CREATE TABLE b (x INTEGER); INSERT INTO b VALUES (1);",
		"0003_c.sql": "CREATE TABLE c (x INTEGER);",
	})
	if done, err := migrate.Apply(t.Context(), db, set3, clk.Now); err != nil || !slices.Equal(done, []int{3}) {
		t.Errorf("upgrade = %v, %v", done, err)
	}
}

func TestFailedMigrationLeavesNothingBehind(t *testing.T) {
	t.Parallel()
	db := openDB(t)
	set := mustLoad(t, map[string]string{
		"0001_ok.sql":     "CREATE TABLE a (x INTEGER);",
		"0002_broken.sql": "CREATE TABLE half (x INTEGER);\nINSERT INTO missing_table VALUES (1);",
	})
	done, err := migrate.Apply(t.Context(), db, set, clock.NewFake(now).Now)
	if err == nil || !strings.Contains(err.Error(), "0002_broken") {
		t.Fatalf("err = %v, want failure in 0002_broken", err)
	}
	if !slices.Equal(done, []int{1}) {
		t.Errorf("applied = %v, want [1]", done)
	}
	if tableExists(t, db, "half") {
		t.Error("table from the failed migration exists – the migration was not atomic")
	}
	report, err := migrate.Check(t.Context(), db, set)
	if err != nil || report.Version() != 1 || report.Pending() != 1 {
		t.Errorf("after failure: %+v, %v", report, err)
	}
}

func TestModifiedMigrationIsRejected(t *testing.T) {
	t.Parallel()
	db := openDB(t)
	original := mustLoad(t, map[string]string{"0001_a.sql": "CREATE TABLE a (x INTEGER);"})
	if _, err := migrate.Apply(t.Context(), db, original, clock.NewFake(now).Now); err != nil {
		t.Fatal(err)
	}
	changed := mustLoad(t, map[string]string{"0001_a.sql": "CREATE TABLE a (x INTEGER, y TEXT);"})
	for name, call := range map[string]func() error{
		"Check": func() error { _, err := migrate.Check(t.Context(), db, changed); return err },
		"Apply": func() error { _, err := migrate.Apply(t.Context(), db, changed, clock.NewFake(now).Now); return err },
	} {
		if err := call(); !errors.Is(err, migrate.ErrModified) || !strings.Contains(err.Error(), "0001_a.sql") {
			t.Errorf("%s: err = %v, want ErrModified naming the file", name, err)
		}
	}
}

func TestNewerDatabaseIsRejected(t *testing.T) {
	t.Parallel()
	db := openDB(t)
	newer := mustLoad(t, map[string]string{"0001_a.sql": "CREATE TABLE a (x);", "0002_b.sql": "CREATE TABLE b (x);"})
	if _, err := migrate.Apply(t.Context(), db, newer, clock.NewFake(now).Now); err != nil {
		t.Fatal(err)
	}
	older := newer[:1]
	_, err := migrate.Apply(context.Background(), db, older, clock.NewFake(now).Now)
	if !errors.Is(err, migrate.ErrNewer) || !strings.Contains(err.Error(), "0002_b") {
		t.Errorf("err = %v, want ErrNewer naming 0002_b", err)
	}
}

func TestCheckOnEmptyDatabase(t *testing.T) {
	t.Parallel()
	db := openDB(t)
	set := mustLoad(t, map[string]string{"0001_a.sql": "CREATE TABLE a (x);"})
	report, err := migrate.Check(t.Context(), db, set)
	if err != nil || report.Pending() != 1 || report.Version() != 0 {
		t.Errorf("Check = %+v, %v", report, err)
	}
	if tableExists(t, db, "schema_migrations") {
		t.Error("Check created the bookkeeping table – it must not write")
	}
}
