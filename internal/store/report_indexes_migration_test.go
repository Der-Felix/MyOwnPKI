package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/store/migrate"
)

// TestReportIndexesMigrationAddsIndexesOnly: migration 0020 (docs/PHASE3.md
// section 14.1) creates exactly two indexes. No table, column, trigger or
// other index changes, so nothing about the data can change either.
func TestReportIndexesMigrationAddsIndexesOnly(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	path, err := Layout{DataDir: t.TempDir()}.TenantDB(DefaultTenant, KindPKI)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	set, err := Migrations(KindPKI)
	if err != nil {
		t.Fatal(err)
	}
	if len(set) < 20 || set[18].Version != 19 || set[19].Version != 20 {
		t.Fatalf("the migration set is not 0019 followed by 0020: %d migrations", len(set))
	}
	now := func() time.Time { return time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC) }
	if _, err = migrate.Apply(ctx, db.Write, set[:19], now); err != nil {
		t.Fatal(err)
	}
	before := schemaObjects(t, db.Write)
	if _, err = migrate.Apply(ctx, db.Write, set[:20], now); err != nil {
		t.Fatal(err)
	}
	after := schemaObjects(t, db.Write)

	var added []string
	for k, v := range after {
		old, existed := before[k]
		switch {
		case !existed:
			added = append(added, k)
		case old != v:
			t.Errorf("%s changed", k)
		}
	}
	for k := range before {
		if _, ok := after[k]; !ok {
			t.Errorf("%s vanished", k)
		}
	}
	slices.Sort(added)
	if want := []string{"index acme_orders_certificate on acme_orders", "index certificates_created_at on certificates"}; !slices.Equal(added, want) {
		t.Errorf("0020 added %v, want %v", added, want)
	}
}

// schemaObjects maps "type name on table" to the SQL of every schema object.
func schemaObjects(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), `SELECT type, name, tbl_name, coalesce(sql, '') FROM sqlite_master`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var typ, name, table, ddl string
		if err = rows.Scan(&typ, &name, &table, &ddl); err != nil {
			t.Fatal(err)
		}
		out[typ+" "+name+" on "+table] = ddl
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
