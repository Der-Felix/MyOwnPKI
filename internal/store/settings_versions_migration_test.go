package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/store/migrate"
)

// TestSettingsVersionsMigrations: pki.db 0021 and system.db 0015 (docs/PHASE3.md
// section 16.1, step 61) add the append-only table settings_versions and
// nothing else; existing rows are untouched; the table's own constraints and
// triggers hold.
func TestSettingsVersionsMigrations(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		kind    Kind
		number  int      // the migration under test
		seed    []string // rows that exist before it
		checked string   // a table whose rows must survive
	}{
		{KindPKI, 21, []string{
			`INSERT INTO cas (id, name, kind, status, key_mode, public_base_url, crl_days, max_validity_days, created_at, updated_at)
			 VALUES ('ca_1', 'root', 'root', 'active', 'offline', 'http://pki.example', 7, 3650, '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z')`,
			`INSERT INTO domains (id, name, ca_id, include_subdomains, wildcards, challenge_types, approval, preset, address_policy, ip_ranges, created_at, updated_at)
			 VALUES ('dom_1', 'homelab.example', 'ca_1', 1, 0, '["dns-01"]', 'account', 'server', 'internal', '[]', '2026-11-02T00:00:00Z', '2026-11-02T00:00:00Z')`,
		}, "domains"},
		{KindSystem, 15, []string{
			`INSERT INTO tenants (id, name, created_at, subject_o, acme_orders_per_hour) VALUES ('default', 'default', '2026-11-01T00:00:00Z', 'Homelab', 42)`,
		}, "tenants"},
	} {
		t.Run(string(tc.kind), func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()
			db := openMigrationTestDB(t, tc.kind)
			set, err := Migrations(tc.kind)
			if err != nil {
				t.Fatal(err)
			}
			if len(set) < tc.number || set[tc.number-1].Version != tc.number || set[tc.number-2].Version != tc.number-1 {
				t.Fatalf("the latest migration of %s is not %04d after %04d: %d migrations", tc.kind, tc.number, tc.number-1, len(set))
			}
			now := func() time.Time { return time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC) }
			if _, err = migrate.Apply(ctx, db, set[:tc.number-1], now); err != nil {
				t.Fatal(err)
			}
			for _, q := range tc.seed {
				if _, err = db.ExecContext(ctx, q); err != nil {
					t.Fatal(err)
				}
			}
			before := schemaObjects(t, db)
			rowsBefore := dump(ctx, t, db, tc.checked)
			if _, ok := before["table settings_versions on settings_versions"]; ok {
				t.Fatal("settings_versions exists before its migration")
			}
			if _, err = migrate.Apply(ctx, db, set[:tc.number], now); err != nil {
				t.Fatal(err)
			}
			after := schemaObjects(t, db)

			var added []string
			for k, v := range after {
				if old, existed := before[k]; !existed {
					added = append(added, k)
				} else if old != v {
					t.Errorf("%s changed", k)
				}
			}
			for k := range before {
				if _, ok := after[k]; !ok {
					t.Errorf("%s vanished", k)
				}
			}
			slices.Sort(added)
			want := []string{
				"index sqlite_autoindex_settings_versions_1 on settings_versions",
				"table settings_versions on settings_versions",
				"trigger settings_versions_no_delete on settings_versions",
				"trigger settings_versions_no_replace on settings_versions",
				"trigger settings_versions_no_update on settings_versions",
			}
			if !slices.Equal(added, want) {
				t.Errorf("%04d added %v, want %v", tc.number, added, want)
			}
			if got := dump(ctx, t, db, tc.checked); got != rowsBefore {
				t.Errorf("rows of %s changed:\n%s\nwas\n%s", tc.checked, got, rowsBefore)
			}
			if !strings.Contains(after["table settings_versions on settings_versions"], "STRICT") {
				t.Error("settings_versions is not STRICT")
			}
			checkSettingsVersionsTable(ctx, t, db)
		})
	}
}

// checkSettingsVersionsTable exercises the constraints of the new table.
func checkSettingsVersionsTable(ctx context.Context, t *testing.T, db *sql.DB) {
	t.Helper()
	const cols = `(kind, object_id, version, change, schema, snapshot_json, snapshot_sha256, actor_type, actor_id, actor_name, reason, restored_from, created_at)`
	sha := strings.Repeat("a", 64)
	insert := func(version int, change, snapshot, actor, reason string, restoredFrom any) error {
		_, err := db.ExecContext(ctx, `INSERT INTO settings_versions `+cols+` VALUES ('domain', 'obj1', ?, ?, 1, ?, ?, ?, 'u', 'alice', ?, ?, '2026-11-13T12:00:00Z')`,
			version, change, snapshot, sha, actor, reason, restoredFrom)
		return err
	}
	if err := insert(1, "create", `{}`, "user", "first", nil); err != nil {
		t.Fatalf("a valid row: %v", err)
	}
	if err := insert(2, "restore", `{}`, "user", "", 1); err != nil {
		t.Fatalf("a valid restore row: %v", err)
	}
	for name, err := range map[string]error{
		"duplicate number":       insert(1, "update", `{}`, "user", "", nil),
		"version 0":              insert(0, "update", `{}`, "user", "", nil),
		"unknown change":         insert(3, "edit", `{}`, "user", "", nil),
		"invalid JSON":           insert(3, "update", `{`, "user", "", nil),
		"JSON array":             insert(3, "update", `[]`, "user", "", nil),
		"unknown actor":          insert(3, "update", `{}`, "root", "", nil),
		"reason of 201":          insert(3, "update", `{}`, "user", strings.Repeat("x", 201), nil),
		"restore without source": insert(3, "restore", `{}`, "user", "", nil),
		"source without restore": insert(3, "update", `{}`, "user", "", 1),
		"restored_from 0":        insert(3, "restore", `{}`, "user", "", 0),
		"NULL reason (no default)": func() error {
			_, err := db.ExecContext(ctx, `INSERT INTO settings_versions (kind, object_id, version, change, schema, snapshot_json, snapshot_sha256, actor_type, actor_id, actor_name, created_at)
				VALUES ('domain', 'obj1', 3, 'update', 1, '{}', ?, 'user', 'u', 'a', '2026-11-13T12:00:00Z')`, sha)
			return err
		}(),
	} {
		if err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// The same number of another object, and a reason of exactly 200 characters, are fine.
	if _, err := db.ExecContext(ctx, `INSERT INTO settings_versions `+cols+` VALUES ('domain', 'obj2', 1, 'create', 1, '{}', ?, 'user', 'u', 'a', ?, NULL, '2026-11-13T12:00:00Z')`, sha, strings.Repeat("é", 200)); err != nil {
		t.Errorf("a reason of 200 characters: %v", err)
	}
	// Append-only: UPDATE and DELETE abort, for every row and every column.
	for _, q := range []string{
		`UPDATE settings_versions SET reason = 'edited' WHERE object_id = 'obj1'`,
		`UPDATE settings_versions SET snapshot_json = '{"x":1}'`,
		`UPDATE settings_versions SET object_id = 'x' WHERE version = 99`, // matches no row: the trigger is per row
		`DELETE FROM settings_versions WHERE object_id = 'obj1'`,
		`DELETE FROM settings_versions`,
		`INSERT OR REPLACE INTO settings_versions ` + cols + ` VALUES ('domain', 'obj1', 1, 'update', 1, '{}', '` + sha + `', 'user', 'u', 'a', '', NULL, '2026-11-13T12:00:00Z')`,
	} {
		_, err := db.ExecContext(ctx, q)
		switch {
		case strings.HasPrefix(q, "UPDATE settings_versions SET object_id = 'x' WHERE version = 99"):
			if err != nil {
				t.Errorf("an UPDATE that matches no row failed: %v", err)
			}
		case err == nil:
			t.Errorf("%q was accepted", q)
		case !strings.Contains(err.Error(), "append-only") && !strings.Contains(err.Error(), "UNIQUE"):
			t.Errorf("%q failed for another reason: %v", q, err)
		}
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM settings_versions`).Scan(&n); err != nil || n != 3 {
		t.Errorf("rows after the refused changes: %d, %v, want 3", n, err)
	}
	// Behind the no_replace trigger the UNIQUE constraint holds on its own.
	if _, err := db.ExecContext(ctx, `DROP TRIGGER settings_versions_no_replace`); err != nil {
		t.Fatal(err)
	}
	if err := insert(1, "update", `{}`, "user", "", nil); err == nil || !strings.Contains(err.Error(), "UNIQUE") {
		t.Errorf("a duplicate number without the trigger: %v, want a UNIQUE failure", err)
	}
}

// openMigrationTestDB opens an empty database file of a kind.
func openMigrationTestDB(t *testing.T, kind Kind) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), string(kind)+".db")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db.Write
}

// dump renders every row of a table in a stable order.
func dump(ctx context.Context, t *testing.T, db *sql.DB, table string) string {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT * FROM `+table+` ORDER BY 1`) //nolint:gosec // table is a literal of the calling test
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	cols, _ := rows.Columns()
	var sb strings.Builder
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err = rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		for i, c := range cols {
			sb.WriteString(c + "=")
			sb.WriteString(strings.TrimSpace(strings.ReplaceAll(toString(vals[i]), "\n", " ")))
			sb.WriteString(";")
		}
		sb.WriteString("\n")
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	return sb.String()
}

func toString(v any) string {
	switch x := v.(type) {
	case nil:
		return "NULL"
	case []byte:
		return string(x)
	case string:
		return x
	default:
		return fmt.Sprint(x)
	}
}
