package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/store/migrate"
)

// TestEnrollmentPassMigrationKeepsJoinTokens: migration 0019 is additive.
// Join tokens of a 0018 database become kind "token" with one use; a used
// one has spent it, an unused one has not; the secrets' hashes and the
// "used" record stay as they were.
func TestEnrollmentPassMigrationKeepsJoinTokens(t *testing.T) {
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
	if len(set) < 19 || set[17].Version != 18 || set[18].Version != 19 {
		t.Fatalf("the migration set is not 0018 followed by 0019: %d migrations", len(set))
	}
	now := func() time.Time { return time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC) }
	if _, err = migrate.Apply(ctx, db.Write, set[:18], now); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO join_tokens (id, token_hash, label, name_patterns, expires_at, created_by, created_at)
		 VALUES ('jtk_unused', 'h1', 'unused', '["a.homelab.lan"]', '2027-01-01T00:00:00Z', 'admin', '2026-11-01T00:00:00Z')`,
		`INSERT INTO join_tokens (id, token_hash, label, name_patterns, expires_at, used_at, used_by, created_by, created_at)
		 VALUES ('jtk_used', 'h2', 'used', '["b.homelab.lan"]', '2027-01-01T00:00:00Z', '2026-11-02T00:00:00Z', 'enr_1', 'admin', '2026-11-01T00:00:00Z')`,
	} {
		if _, err = db.Write.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = migrate.Apply(ctx, db.Write, set, now); err != nil {
		t.Fatal(err)
	}
	type row struct {
		kind              string
		maxUses, useCount int
		usedBy            string
		revoked           bool
	}
	got := map[string]row{}
	rows, err := db.Read.QueryContext(ctx, `SELECT id, kind, max_uses, use_count, coalesce(used_by, ''), revoked_at IS NOT NULL FROM join_tokens`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		var r row
		if err = rows.Scan(&id, &r.kind, &r.maxUses, &r.useCount, &r.usedBy, &r.revoked); err != nil {
			t.Fatal(err)
		}
		got[id] = r
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if want := (row{kind: "token", maxUses: 1}); got["jtk_unused"] != want {
		t.Errorf("unused token: %+v, want %+v", got["jtk_unused"], want)
	}
	if want := (row{kind: "token", maxUses: 1, useCount: 1, usedBy: "enr_1"}); got["jtk_used"] != want {
		t.Errorf("used token: %+v, want %+v", got["jtk_used"], want)
	}
}
