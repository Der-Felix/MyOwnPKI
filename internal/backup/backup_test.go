package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

func newInstance(t *testing.T) (*testinstance.Instance, Options) {
	t.Helper()
	v := testinstance.New(t, testinstance.Options{})
	v.Unseal(t)
	return v, Options{Layout: store.Layout{DataDir: v.Config.DataDir}, AuthKeyFile: v.Config.AuthKeyFile(), Clock: v.Clock, Who: testinstance.Console}
}

func issue(t *testing.T, v *testinstance.Instance, name string) *ca.Issued {
	t.Helper()
	out, err := v.Engine.Issue(context.Background(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{name}, Who: testinstance.Console})
	if err != nil {
		t.Fatalf("issue %s: %v", name, err)
	}
	return out
}

// dump reads tables of a database as text, for comparing two copies.
func dump(t *testing.T, path string, tables ...string) string {
	t.Helper()
	db, err := store.OpenReadOnly(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var b strings.Builder
	for _, table := range tables {
		dumpTable(t, db.Read, table, &b)
	}
	return b.String()
}

func dumpTable(t *testing.T, db *sql.DB, table string, b *strings.Builder) {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), "SELECT * FROM "+table+" ORDER BY 1") // #nosec G202 -- table names of the test
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	cols, _ := rows.Columns()
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if serr := rows.Scan(ptrs...); serr != nil {
			t.Fatal(serr)
		}
		fmt.Fprintf(b, "%s %v\n", table, vals)
	}
	if rerr := rows.Err(); rerr != nil {
		t.Fatal(rerr)
	}
}

var pkiTables = []string{"cas", "ca_generations", "certificates", "certificate_sans", "revocations", "crls", "keys", "blocked_keys"}

func TestBackupRestoreRoundTrip(t *testing.T) {
	t.Parallel()
	v, o := newInstance(t)
	nas := issue(t, v, "nas.homelab.lan")
	issue(t, v, "git.homelab.lan")
	if _, err := v.Engine.Revoke(t.Context(), ca.RevokeRequest{CertificateID: nas.ID, Reason: "superseded", Who: testinstance.Console}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "backup")
	m, err := Create(t.Context(), dir, o)
	if err != nil {
		t.Fatal(err)
	}
	if !m.AuthKey || m.CheckpointKey == "" || len(m.Audit) != 2 || len(m.Tenants) != 1 {
		t.Errorf("manifest %+v", m)
	}
	if _, cerr := Create(t.Context(), dir, o); cerr == nil || !strings.Contains(cerr.Error(), "never overwrites") {
		t.Errorf("second backup into the same directory: %v", cerr)
	}
	if fi, serr := os.Stat(filepath.Join(dir, "tenants", "default", "pki.db")); serr != nil || (fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/') {
		t.Errorf("pki.db in the backup: %v", serr)
	}

	rep, err := Verify(t.Context(), dir, "")
	if err != nil {
		t.Fatalf("verify: %v %v", err, rep)
	}
	if rep.Certificates != 2 {
		t.Errorf("SAN index checked for %d certificates", rep.Certificates)
	}

	pkiPath, _ := o.Layout.TenantDB(store.DefaultTenant, store.KindPKI)
	before := dump(t, pkiPath, pkiTables...)
	sysBefore := dump(t, o.Layout.SystemDB(), "users", "role_bindings", "unseal", "instance")

	target := Options{Layout: store.Layout{DataDir: filepath.Join(t.TempDir(), "restored")}, Clock: v.Clock, Who: testinstance.Console}
	target.AuthKeyFile = filepath.Join(target.Layout.DataDir, "auth.key")
	rr, err := Restore(t.Context(), dir, "", target)
	if err != nil {
		t.Fatalf("restore: %v %+v", err, rr)
	}
	restoredPKI, _ := target.Layout.TenantDB(store.DefaultTenant, store.KindPKI)
	if got := dump(t, restoredPKI, pkiTables...); got != before {
		t.Errorf("pki.db differs after the restore")
	}
	if got := dump(t, target.Layout.SystemDB(), "users", "role_bindings", "unseal", "instance"); got != sysBefore {
		t.Errorf("system.db differs after the restore")
	}
	if _, serr := os.Stat(target.AuthKeyFile); serr != nil {
		t.Errorf("auth.key not restored: %v", serr)
	}
	// The instance log has the backup and the restore; both chains verify.
	for _, lg := range []store.AuditLog{{Scope: store.InstanceScope, Path: target.Layout.InstanceAuditDB()}} {
		db, oerr := store.OpenAuditLog(t.Context(), lg)
		if oerr != nil {
			t.Fatal(oerr)
		}
		r, verr := audit.Verify(t.Context(), db.Read, lg.Scope)
		_ = db.Close()
		if verr != nil || r.Break != nil {
			t.Errorf("restored %s log: %v %+v", lg.Scope, verr, r.Break)
		}
	}
	db, err := store.OpenReadOnly(t.Context(), target.Layout.InstanceAuditDB())
	if err != nil {
		t.Fatal(err)
	}
	var n int
	_ = db.Read.QueryRowContext(t.Context(), `SELECT count(*) FROM audit_entries WHERE action IN (?, ?)`, ActionBackup, ActionRestore).Scan(&n)
	_ = db.Close()
	if n != 2 {
		t.Errorf("%d backup/restore audit entries, want 2", n)
	}

	// Only into an empty data directory.
	if _, err := Restore(t.Context(), dir, "", o); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Errorf("restore over the running instance: %v", err)
	}
}

// TestBackupDuringWrites: certificates are issued and the outbox delivered
// while the backup runs; the backup is consistent, and after the restore a
// delivery adds the missing audit entries exactly once.
func TestBackupDuringWrites(t *testing.T) {
	t.Parallel()
	v, o := newInstance(t)
	scope := store.TenantScope(store.DefaultTenant)
	d := &audit.Deliverer{Routes: []audit.Route{{Source: "pki", From: v.PKIDB.Write, To: v.TenantAudit.Write, Scope: scope}}, Clock: v.Clock, Log: slog.New(slog.DiscardHandler)}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	issued := 0
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := v.Engine.Issue(context.Background(), ca.Request{CA: "issuing", Preset: "server", DNSNames: []string{fmt.Sprintf("host%d.homelab.lan", i)}, Who: testinstance.Console}); err != nil {
				t.Error(err)
				return
			}
			if _, err := d.DeliverPending(context.Background()); err != nil {
				t.Error(err)
				return
			}
			issued++
		}
	}()
	time.Sleep(200 * time.Millisecond)
	dir := filepath.Join(t.TempDir(), "backup")
	_, err := Create(t.Context(), dir, o)
	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if issued == 0 {
		t.Fatal("nothing was written during the backup")
	}
	target := Options{Layout: store.Layout{DataDir: filepath.Join(t.TempDir(), "restored")}, Clock: v.Clock, Who: testinstance.Console}
	target.AuthKeyFile = filepath.Join(target.Layout.DataDir, "auth.key")
	if rep, rerr := Restore(t.Context(), dir, "", target); rerr != nil {
		t.Fatalf("restore: %v %+v", rerr, rep)
	}
	pkiPath, _ := target.Layout.TenantDB(store.DefaultTenant, store.KindPKI)
	taPath, _ := target.Layout.TenantDB(store.DefaultTenant, store.KindAudit)
	pki, err := store.Open(t.Context(), pkiPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pki.Close() }()
	ta, err := store.Open(t.Context(), taPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ta.Close() }()
	rd := &audit.Deliverer{Routes: []audit.Route{{Source: "pki", From: pki.Write, To: ta.Write, Scope: scope}}, Clock: v.Clock, Log: slog.New(slog.DiscardHandler)}
	for range 2 { // twice: the second delivery must add nothing
		if _, err := rd.DeliverPending(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	// The audit copy is newer than the pki.db copy (audit last): it may name
	// certificates issued after the pki.db snapshot, but every certificate
	// of the restored pki.db has exactly one issue entry.
	ids := map[string]bool{}
	eachID := func(db *sql.DB, query string, args ...any) []string {
		rows, qerr := db.QueryContext(t.Context(), query, args...)
		if qerr != nil {
			t.Fatal(qerr)
		}
		defer func() { _ = rows.Close() }()
		var out []string
		for rows.Next() {
			var id string
			if serr := rows.Scan(&id); serr != nil {
				t.Fatal(serr)
			}
			out = append(out, id)
		}
		if rerr := rows.Err(); rerr != nil {
			t.Fatal(rerr)
		}
		return out
	}
	entries := eachID(ta.Read, `SELECT target_id FROM audit_entries WHERE action = ?`, ca.ActionIssue)
	for _, id := range entries {
		if ids[id] {
			t.Errorf("certificate %s has two issue entries", id)
		}
		ids[id] = true
	}
	certs := eachID(pki.Read, `SELECT id FROM certificates`)
	for _, id := range certs {
		if !ids[id] {
			t.Errorf("certificate %s has no issue entry after the restore", id)
		}
	}
	if len(certs) == 0 || len(entries) < len(certs) {
		t.Errorf("%d certificates, %d issue entries", len(certs), len(entries))
	}
	if r, err := audit.Verify(t.Context(), ta.Read, scope); err != nil || r.Break != nil {
		t.Errorf("tenant log after the restore: %v %+v", err, r.Break)
	}
}

// TestTamperedBackupRefused: every kind of change is refused before anything
// is written.
func TestTamperedBackupRefused(t *testing.T) {
	t.Parallel()
	v, o := newInstance(t)
	issue(t, v, "nas.homelab.lan")
	orig := filepath.Join(t.TempDir(), "backup")
	if _, err := Create(t.Context(), orig, o); err != nil {
		t.Fatal(err)
	}
	copyBackup := func(t *testing.T) string {
		t.Helper()
		dir := filepath.Join(t.TempDir(), "backup")
		if err := os.CopyFS(dir, os.DirFS(orig)); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	editManifest := func(t *testing.T, dir string, fn func(*Manifest)) {
		t.Helper()
		m, err := readManifest(dir)
		if err != nil {
			t.Fatal(err)
		}
		fn(m)
		if err := os.Remove(filepath.Join(dir, ManifestFile)); err != nil {
			t.Fatal(err)
		}
		if err := writeManifest(dir, m); err != nil {
			t.Fatal(err)
		}
	}
	// rehash fixes the manifest after a change, as a careful attacker would.
	rehash := func(t *testing.T, dir, rel string) {
		t.Helper()
		editManifest(t, dir, func(m *Manifest) {
			for i, f := range m.Files {
				if f.Path == rel {
					m.Files[i].SHA256, m.Files[i].Size, _ = hashFile(filepath.Join(dir, filepath.FromSlash(rel)))
				}
			}
		})
	}
	sqlEdit := func(t *testing.T, path, stmt string) {
		t.Helper()
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.Close() }()
		if _, err := db.ExecContext(t.Context(), stmt); err != nil {
			t.Fatal(err)
		}
	}
	pkiRel := "tenants/default/pki.db"
	for _, tc := range []struct {
		name, want string
		change     func(t *testing.T, dir string)
	}{
		{"changed file", "SHA-256", func(t *testing.T, dir string) {
			t.Helper()
			p := filepath.Join(dir, filepath.FromSlash(pkiRel))
			data, _ := os.ReadFile(p)
			data[len(data)/2] ^= 0xff
			_ = os.WriteFile(p, data, 0o600) // #nosec G703 -- a file of the test's own backup copy
		}},
		{"missing file", "missing", func(_ *testing.T, dir string) { _ = os.Remove(filepath.Join(dir, "audit.db")) }},
		{"extra file", "not in the manifest", func(_ *testing.T, dir string) {
			_ = os.WriteFile(filepath.Join(dir, "tenants", "evil.db"), []byte("x"), 0o600)
		}},
		{"no manifest", "no manifest.json", func(_ *testing.T, dir string) { _ = os.Remove(filepath.Join(dir, ManifestFile)) }},
		{"path outside", "not a path inside", func(t *testing.T, dir string) {
			t.Helper()
			editManifest(t, dir, func(m *Manifest) { m.Files[0].Path = "../system.db" })
		}},
		{"head moved", "cut off or rewritten", func(t *testing.T, dir string) {
			t.Helper()
			editManifest(t, dir, func(m *Manifest) { m.Audit[0].Entries++ })
		}},
		{"audit entry changed", "broken", func(t *testing.T, dir string) {
			t.Helper()
			sqlEdit(t, filepath.Join(dir, "audit.db"), `DROP TRIGGER IF EXISTS audit_entries_no_update; UPDATE audit_entries SET actor_name = 'someone else' WHERE seq = 1`)
			rehash(t, dir, "audit.db")
		}},
		{"SAN index changed", "name index", func(t *testing.T, dir string) {
			t.Helper()
			sqlEdit(t, filepath.Join(dir, filepath.FromSlash(pkiRel)), `DROP TRIGGER certificate_sans_no_update; UPDATE certificate_sans SET value = 'evil.example' WHERE type = 'dns'`)
			rehash(t, dir, pkiRel)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := copyBackup(t)
			tc.change(t, dir)
			target := Options{Layout: store.Layout{DataDir: filepath.Join(t.TempDir(), "restored")}, Clock: v.Clock, Who: testinstance.Console}
			rep, err := Restore(t.Context(), dir, "", target)
			msg := fmt.Sprint(err)
			if rep != nil {
				msg += " " + strings.Join(rep.Problems, " | ")
			}
			if err == nil || !strings.Contains(msg, tc.want) {
				t.Errorf("want a refusal with %q, got %s", tc.want, msg)
			}
			if _, serr := os.Stat(target.Layout.DataDir); !errors.Is(serr, os.ErrNotExist) {
				t.Error("a refused restore created the data directory")
			}
		})
	}
	// The manifest is plain JSON: unknown fields are refused too.
	dir := copyBackup(t)
	data, _ := os.ReadFile(filepath.Join(dir, ManifestFile))
	var raw map[string]any
	_ = json.Unmarshal(data, &raw)
	raw["extra"] = true
	data, _ = json.Marshal(raw)
	_ = os.WriteFile(filepath.Join(dir, ManifestFile), data, 0o600)
	if _, err := Verify(t.Context(), dir, ""); err == nil {
		t.Error("manifest with an unknown field accepted")
	}
}
