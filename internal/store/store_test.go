package store

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/clock"
)

var now = clock.NewFake(time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)).Now

func TestTenantIDs(t *testing.T) {
	t.Parallel()
	l := Layout{DataDir: t.TempDir()}
	for _, ok := range []string{"default", "lab-2", "a", strings.Repeat("a", 63)} {
		if _, err := l.TenantDir(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "..", "../x", "a/b", `a\b`, "Default", "-x", "a.b", "a b", strings.Repeat("a", 64)} {
		if _, err := l.TenantDir(bad); err == nil {
			t.Errorf("%q accepted – it could escape or collide in the tenants directory", bad)
		}
	}
	if _, err := l.TenantDB(DefaultTenant, KindSystem); err == nil {
		t.Error("system.db accepted as a tenant database")
	}
	p, _ := l.TenantDB(DefaultTenant, KindAudit)
	if want := filepath.Join(l.DataDir, "tenants", "default", "audit.db"); p != want {
		t.Errorf("audit path = %s, want %s", p, want)
	}
}

func TestMigrationSetsLoad(t *testing.T) {
	t.Parallel()
	for _, k := range Kinds {
		set, err := Migrations(k)
		if err != nil || len(set) == 0 {
			t.Errorf("%s: %d migrations, %v", k, len(set), err)
		}
	}
}

func TestMigrateAndStatus(t *testing.T) {
	t.Parallel()
	l := Layout{DataDir: t.TempDir()}

	// Status never creates anything.
	before, err := Status(t.Context(), l, DefaultTenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range before {
		if st.Exists || st.Err != nil {
			t.Errorf("%s before migrate: %+v", st.Kind, st)
		}
	}
	if entries, _ := os.ReadDir(l.DataDir); len(entries) != 0 {
		t.Errorf("Status created files: %v", entries)
	}

	applied, err := Migrate(t.Context(), l, DefaultTenant, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 4 {
		t.Fatalf("applied to %d files, want 4 (system, instance audit, tenant pki, tenant audit)", len(applied))
	}
	for _, a := range applied {
		if len(a.Versions) == 0 {
			t.Errorf("%s: nothing applied", a.Kind)
		}
	}

	after, err := Status(t.Context(), l, DefaultTenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range after {
		if !st.Exists || st.Err != nil || st.Report.Pending() != 0 || st.Report.Version() != st.Available || st.JournalMode != "wal" {
			t.Errorf("%s after migrate: exists=%v err=%v pending=%d version=%d/%d journal=%q",
				st.Kind, st.Exists, st.Err, st.Report.Pending(), st.Report.Version(), st.Available, st.JournalMode)
		}
	}

	again, err := Migrate(t.Context(), l, DefaultTenant, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range again {
		if len(a.Versions) != 0 {
			t.Errorf("%s: second run applied %v", a.Kind, a.Versions)
		}
	}
}

func TestSwappedFileIsRejected(t *testing.T) {
	t.Parallel()
	l := Layout{DataDir: t.TempDir()}
	if _, err := Migrate(t.Context(), l, DefaultTenant, now); err != nil {
		t.Fatal(err)
	}
	pki, _ := l.TenantDB(DefaultTenant, KindPKI)
	audit, _ := l.TenantDB(DefaultTenant, KindAudit)
	data, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(pki, data, 0o600); err != nil { //nolint:gosec // path from the test's temp layout
		t.Fatal(err)
	}

	if _, err = Migrate(t.Context(), l, DefaultTenant, now); !errors.Is(err, ErrWrongKind) {
		t.Errorf("Migrate: err = %v, want ErrWrongKind", err)
	}
	sts, err := Status(t.Context(), l, DefaultTenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range sts {
		if st.Kind == KindPKI && !errors.Is(st.Err, ErrWrongKind) {
			t.Errorf("Status of pki.db: err = %v, want ErrWrongKind", st.Err)
		}
	}
}

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(t.Context(), filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestOneWriterSerializesConcurrentWrites(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	if _, err := db.Write.ExecContext(t.Context(), `CREATE TABLE n (i INTEGER)`); err != nil {
		t.Fatal(err)
	}
	const writers = 50
	var wg sync.WaitGroup
	errs := make(chan error, writers*2)
	for i := range writers {
		wg.Go(func() {
			tx, err := db.Write.BeginTx(t.Context(), nil)
			if err != nil {
				errs <- err
				return
			}
			if _, err := tx.ExecContext(t.Context(), `INSERT INTO n VALUES (?)`, i); err != nil {
				_ = tx.Rollback()
				errs <- err
				return
			}
			errs <- tx.Commit()
		})
		wg.Go(func() {
			var c int
			errs <- db.Read.QueryRowContext(t.Context(), `SELECT count(*) FROM n`).Scan(&c)
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent access failed: %v", err)
		}
	}
	var c int
	if err := db.Read.QueryRowContext(t.Context(), `SELECT count(*) FROM n`).Scan(&c); err != nil || c != writers {
		t.Errorf("rows = %d, %v; want %d", c, err, writers)
	}
}

func TestReadPoolIsReadOnly(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	if _, err := db.Write.ExecContext(t.Context(), `CREATE TABLE r (i INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Read.ExecContext(t.Context(), `INSERT INTO r VALUES (1)`); err == nil {
		t.Error("write through the read pool succeeded")
	}
}

func TestForeignKeysAreEnforced(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	for _, q := range []string{
		`CREATE TABLE parent (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE child (parent_id INTEGER NOT NULL REFERENCES parent (id))`,
	} {
		if _, err := db.Write.ExecContext(t.Context(), q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Write.ExecContext(t.Context(), `INSERT INTO child VALUES (42)`); err == nil {
		t.Error("foreign key not enforced")
	}
}

func TestOpenRejectsQueryCharacters(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"a?b.db", "a#b.db"} {
		path := filepath.Join(t.TempDir(), p)
		if _, err := Open(t.Context(), path); err == nil {
			t.Errorf("%s accepted", p)
		}
		if _, err := OpenReadOnly(t.Context(), path); err == nil {
			t.Errorf("%s accepted read-only", p)
		}
	}
	if _, err := OpenReadOnly(t.Context(), filepath.Join(t.TempDir(), "missing.db")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
}

func TestMigrateRegistersTenantOnce(t *testing.T) {
	t.Parallel()
	l := Layout{DataDir: t.TempDir()}
	clk := clock.NewFake(time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC))
	if _, err := Migrate(t.Context(), l, DefaultTenant, clk.Now); err != nil {
		t.Fatal(err)
	}
	clk.Advance(24 * time.Hour)
	if _, err := Migrate(t.Context(), l, DefaultTenant, clk.Now); err != nil {
		t.Fatal(err)
	}
	tenants, err := Tenants(t.Context(), l)
	if err != nil {
		t.Fatal(err)
	}
	if len(tenants) != 1 || tenants[0].ID != DefaultTenant || tenants[0].AllowServerKeygen != 1 ||
		tenants[0].CreatedAt != "2026-10-13T08:00:00Z" {
		t.Errorf("tenants = %+v; want one default tenant created at the first run", tenants)
	}
}

func TestTenantIDsAreCheckedInTheSchemaToo(t *testing.T) {
	t.Parallel()
	l := Layout{DataDir: t.TempDir()}
	if _, err := Migrate(t.Context(), l, DefaultTenant, now); err != nil {
		t.Fatal(err)
	}
	db, err := Open(t.Context(), l.SystemDB())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for _, bad := range []string{"../x", "Upper", "-x", ""} {
		_, err := db.Write.ExecContext(t.Context(), `INSERT INTO tenants (id, name, created_at) VALUES (?, 'x', 'x')`, bad)
		if err == nil {
			t.Errorf("tenant id %q accepted by the database", bad)
		}
	}
}

// Every database type has a schema directory and every schema directory
// belongs to a type – adding acme or metrics later can't be half done.
func TestKindsMatchSchemaDirectories(t *testing.T) {
	t.Parallel()
	entries, err := schemaFiles.ReadDir("schema")
	if err != nil {
		t.Fatal(err)
	}
	var dirs []Kind
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, Kind(e.Name()))
		}
	}
	for _, k := range Kinds {
		if !slices.Contains(dirs, k) {
			t.Errorf("kind %s has no schema/%s directory", k, k)
		}
	}
	for _, d := range dirs {
		if !slices.Contains(Kinds, d) {
			t.Errorf("schema/%s has no Kind constant in Kinds", d)
		}
	}
	for _, k := range TenantKinds {
		if !slices.Contains(Kinds, k) || k == KindSystem {
			t.Errorf("tenant kind %s is not a per-tenant entry of Kinds", k)
		}
	}
}

// sqlc 1.31.1 miscounts positions after a multi-byte character in SQLite
// files and cuts statements short, so schema and query files stay ASCII.
func TestSQLFilesAreASCII(t *testing.T) {
	t.Parallel()
	for _, root := range []string{"schema", "queries"} {
		err := fs.WalkDir(os.DirFS(root), ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || filepath.Ext(p) != ".sql" {
				return err
			}
			data, err := fs.ReadFile(os.DirFS(root), p)
			if err != nil {
				return err
			}
			for i, line := range strings.Split(string(data), "\n") {
				for _, r := range line {
					if r > 127 {
						t.Errorf("%s/%s:%d: non-ASCII character %q", root, p, i+1, r)
						break
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestSwappedAuditScopeIsRejected(t *testing.T) {
	t.Parallel()
	l := Layout{DataDir: t.TempDir()}
	if _, err := Migrate(t.Context(), l, DefaultTenant, now); err != nil {
		t.Fatal(err)
	}
	tenantAudit, _ := l.TenantDB(DefaultTenant, KindAudit)
	data, err := os.ReadFile(tenantAudit)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(l.InstanceAuditDB(), data, 0o600); err != nil { //nolint:gosec // temp dir of the test
		t.Fatal(err)
	}
	if _, err = Migrate(t.Context(), l, DefaultTenant, now); !errors.Is(err, ErrWrongScope) {
		t.Errorf("Migrate: err = %v, want ErrWrongScope", err)
	}
	sts, err := Status(t.Context(), l, DefaultTenant)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(sts[1].Err, ErrWrongScope) {
		t.Errorf("Status of %s: err = %v, want ErrWrongScope", sts[1].Path, sts[1].Err)
	}
}
