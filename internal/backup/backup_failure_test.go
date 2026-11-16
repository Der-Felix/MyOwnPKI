package backup

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/testinstance"
)

const pkiRel = "tenants/default/pki.db"

// tree is the SHA-256 of every file below dir, by slash path.
func tree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	fsys := os.DirFS(dir)
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			out[p+"/"] = ""
			return nil
		}
		data, rerr := fs.ReadFile(fsys, p)
		if rerr != nil {
			return rerr
		}
		sum := sha256.Sum256(data)
		out[p] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func sameTree(t *testing.T, a, b map[string]string) {
	t.Helper()
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			t.Errorf("%s: %q before, %q after", k, v, w)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			t.Errorf("%s appeared", k)
		}
	}
}

// backupCopy returns a fresh copy of a backup directory.
func backupCopy(t *testing.T, src string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "backup")
	if err := os.CopyFS(dir, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	return dir
}

func editManifestOf(t *testing.T, dir string, fn func(*Manifest)) {
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

// rehash writes the file's real hash and size into the manifest, as a careful
// attacker would after changing it.
func rehash(t *testing.T, dir, rel string) {
	t.Helper()
	editManifestOf(t, dir, func(m *Manifest) {
		for i, f := range m.Files {
			if f.Path == rel {
				var err error
				if m.Files[i].SHA256, m.Files[i].Size, err = hashFile(filepath.Join(dir, filepath.FromSlash(rel))); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
}

func execOn(t *testing.T, path, stmt string) {
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

func targetOptions(t *testing.T, v *testinstance.Instance) Options {
	t.Helper()
	o := Options{Layout: store.Layout{DataDir: filepath.Join(t.TempDir(), "restored")}, Clock: v.Clock, Who: testinstance.Console}
	o.AuthKeyFile = filepath.Join(o.Layout.DataDir, "auth.key")
	return o
}

// TestCreateRefusals: a backup never overwrites, never starts without an
// instance, and a refusal before the first byte leaves the target alone.
func TestCreateRefusals(t *testing.T) {
	v, o := newInstance(t)
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "afile"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(base, "taken"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "taken", "precious.txt"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := tree(t, base)
	tests := []struct {
		name string
		dir  string
		opt  Options
		want string
	}{
		{"no instance in the data directory", filepath.Join(t.TempDir(), "b"), Options{Layout: store.Layout{DataDir: t.TempDir()}, Clock: v.Clock}, "no instance at"},
		{"data directory that does not exist", filepath.Join(t.TempDir(), "b"), Options{Layout: store.Layout{DataDir: filepath.Join(t.TempDir(), "nope")}, Clock: v.Clock}, "no instance at"},
		{"target is a directory with files", filepath.Join(base, "taken"), o, "never overwrites"},
		{"target is a file", filepath.Join(base, "afile"), o, ""},
		{"parent of the target is missing", filepath.Join(base, "missing", "deeper", "b"), o, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Create(t.Context(), tc.dir, tc.opt)
			if err == nil || m != nil {
				t.Fatalf("Create = %v, %v, want a refusal", m, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q, want it to contain %q", err, tc.want)
			}
		})
	}
	sameTree(t, before, tree(t, base))
	if _, err := os.Stat(filepath.Join(base, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a refused backup created its parent directory: %v", err)
	}
}

// TestCreateFailureRemovesThePartialBackup: whatever goes wrong half way, no
// directory is left that looks like a backup.
func TestCreateFailureRemovesThePartialBackup(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		break_ func(t *testing.T, o Options)
		want   string
	}{
		{"a tenant database is gone", func(t *testing.T, o Options) {
			t.Helper()
			p, _ := o.Layout.TenantDB(store.DefaultTenant, store.KindPKI)
			// Closed handles of the test instance hold it on Windows; an empty
			// file is as unusable as a missing one.
			if err := os.Truncate(p, 0); err != nil {
				t.Fatal(err)
			}
		}, "the database has no schema"},
		{"the instance audit chain is broken", func(t *testing.T, o Options) {
			t.Helper()
			execOn(t, o.Layout.InstanceAuditDB(), `DROP TRIGGER IF EXISTS audit_entries_no_update; UPDATE audit_entries SET actor_name = 'someone else' WHERE seq = 1`)
		}, "audit.db: the audit chain is broken"},
		{"the tenant audit chain is broken", func(t *testing.T, o Options) {
			t.Helper()
			p, _ := o.Layout.TenantDB(store.DefaultTenant, store.KindAudit)
			execOn(t, p, `DROP TRIGGER IF EXISTS audit_entries_no_update; UPDATE audit_entries SET actor_name = 'someone else' WHERE seq = 1`)
		}, "the audit chain is broken"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, o := newInstance(t)
			issue2 := filepath.Join(t.TempDir(), "backup")
			tc.break_(t, o)
			m, err := Create(t.Context(), issue2, o)
			if err == nil || m != nil {
				t.Fatalf("Create = %v, %v, want an error", m, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q, want it to contain %q", err, tc.want)
			}
			if _, serr := os.Stat(issue2); !errors.Is(serr, fs.ErrNotExist) {
				t.Errorf("the failed backup was left behind: %v", serr)
			}
		})
	}
}

// TestManifestDescribesTheFiles: every number in the manifest is checked
// against the files by a second computation, in the order the restore needs.
func TestManifestDescribesTheFiles(t *testing.T) {
	t.Parallel()
	v, o := newInstance(t)
	issue(t, v, "nas.homelab.lan")
	dir := filepath.Join(t.TempDir(), "backup")
	m, err := Create(t.Context(), dir, o)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != Format || got.Version == "" || got.CreatedAt != v.Clock.Now().UTC().Format(audit.TimeFormat) {
		t.Errorf("manifest header %+v", got)
	}
	if len(got.Tenants) != 1 || got.Tenants[0] != store.DefaultTenant || !got.AuthKey || len(m.Files) != len(got.Files) {
		t.Errorf("manifest %+v", got)
	}
	// Order: system, then the business databases, then the audit logs; the
	// auth key last.
	var order []string
	for _, f := range got.Files {
		order = append(order, f.Path)
	}
	want := []string{"system.db", pkiRel, "audit.db", "tenants/default/audit.db", "auth.key"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("files in the order %v, want %v", order, want)
	}
	for _, f := range got.Files {
		data, rerr := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f.Path)))
		if rerr != nil {
			t.Fatal(rerr)
		}
		sum := sha256.Sum256(data)
		if f.SHA256 != hex.EncodeToString(sum[:]) || f.Size != int64(len(data)) {
			t.Errorf("%s: manifest %s/%d, file %x/%d", f.Path, f.SHA256, f.Size, sum, len(data))
		}
		if runtime.GOOS != "windows" {
			if fi, _ := os.Stat(filepath.Join(dir, filepath.FromSlash(f.Path))); fi.Mode().Perm()&0o077 != 0 {
				t.Errorf("%s is readable by others: %v", f.Path, fi.Mode().Perm())
			}
		}
		if strings.HasSuffix(f.Path, ".db") && f.Migration == 0 {
			t.Errorf("%s has no migration version", f.Path)
		}
	}
	if len(got.Audit) != 2 || got.Audit[0].Scope != store.InstanceScope || got.Audit[1].Scope != store.TenantScope(store.DefaultTenant) {
		t.Fatalf("audit heads %+v", got.Audit)
	}
	for _, lg := range got.Audit {
		if lg.Entries < 1 || !strings.Contains(lg.Head, ":") {
			t.Errorf("audit head %+v", lg)
		}
	}
	// The instance log holds the entry of this very backup.
	if got.Audit[0].Entries != m.Audit[0].Entries {
		t.Errorf("returned and written manifest differ: %d and %d entries", m.Audit[0].Entries, got.Audit[0].Entries)
	}
	if entries, _ := os.ReadDir(dir); len(entries) == 0 || strings.Contains(strings.Join(dirNames(entries), ","), ".tmp") {
		t.Errorf("backup directory: %v", dirNames(entries))
	}
}

func dirNames(es []os.DirEntry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

// TestAuthKeyOutsideTheBackup: an auth key that lives outside the data
// directory, or was removed, is not copied, and the restore says where it
// has to go.
func TestAuthKeyOutsideTheBackup(t *testing.T) {
	t.Parallel()
	v, o := newInstance(t)
	key, err := os.ReadFile(o.AuthKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secrets", "auth.key")
	if err := os.MkdirAll(filepath.Dir(outside), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, key, 0o600); err != nil { // #nosec G703 -- a file of the test's own temp directory
		t.Fatal(err)
	}
	tests := []struct {
		name string
		path string
		note string
	}{
		{"outside the data directory", outside, "auth.key is not in the backup"},
		{"a name in the data directory that does not exist", filepath.Join(o.Layout.DataDir, "missing.key"), "auth.key is not in the backup"},
		{"the data directory itself", o.Layout.DataDir, "auth.key is not in the backup"},
		{"empty", "", "auth.key is not in the backup"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			oo := o
			oo.AuthKeyFile = tc.path
			dir := filepath.Join(t.TempDir(), "backup")
			m, err := Create(t.Context(), dir, oo)
			if err != nil {
				t.Fatal(err)
			}
			if m.AuthKey {
				t.Error("the manifest says the key is in the backup")
			}
			for _, f := range m.Files {
				if f.Kind == KindAuthKey || strings.Contains(f.Path, "auth.key") {
					t.Errorf("the backup lists %s", f.Path)
				}
			}
			if _, serr := os.Stat(filepath.Join(dir, "auth.key")); !errors.Is(serr, fs.ErrNotExist) {
				t.Errorf("auth.key is in the backup directory: %v", serr)
			}
			target := targetOptions(t, v)
			rep, err := Restore(t.Context(), dir, "", target)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(rep.Notes, "\n"), tc.note) || !strings.Contains(strings.Join(rep.Notes, "\n"), "reset-2fa") {
				t.Errorf("notes %q", rep.Notes)
			}
			if _, serr := os.Stat(filepath.Join(target.Layout.DataDir, "auth.key")); !errors.Is(serr, fs.ErrNotExist) {
				t.Errorf("a key that was not in the backup appeared: %v", serr)
			}
		})
	}
	t.Run("restored somewhere else than configured", func(t *testing.T) {
		t.Parallel()
		dir := filepath.Join(t.TempDir(), "backup")
		if _, err := Create(t.Context(), dir, o); err != nil {
			t.Fatal(err)
		}
		target := targetOptions(t, v)
		target.AuthKeyFile = outside
		rep, err := Restore(t.Context(), dir, "", target)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(strings.Join(rep.Notes, "\n"), "the configuration names "+outside) {
			t.Errorf("notes %q", rep.Notes)
		}
		got, rerr := os.ReadFile(filepath.Join(target.Layout.DataDir, "auth.key"))
		if rerr != nil || !bytes.Equal(got, key) {
			t.Errorf("restored key: %v, equal %v", rerr, bytes.Equal(got, key))
		}
	})
}

// TestInside: the rule that decides whether the auth key travels with the
// backup. A sibling with the same name prefix is not inside.
func TestInside(t *testing.T) {
	t.Parallel()
	d := filepath.Join(t.TempDir(), "data")
	tests := []struct {
		name string
		path string
		want string // "" = not inside
	}{
		{"file in the directory", filepath.Join(d, "auth.key"), "auth.key"},
		{"nested file", filepath.Join(d, "keys", "auth.key"), filepath.Join("keys", "auth.key")},
		{"the directory itself", d, ""},
		{"the parent", filepath.Dir(d), ""},
		{"a sibling with the same prefix", d + "-2" + string(filepath.Separator) + "auth.key", ""},
		{"a path that climbs out", filepath.Join(d, "..", "other", "auth.key"), ""},
		{"a path that climbs out and back", filepath.Join(d, "..", "data", "auth.key"), "auth.key"},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rel, ok := inside(d, tc.path)
			if (tc.want != "") != ok || rel != tc.want {
				t.Errorf("inside(%q, %q) = %q, %v, want %q", d, tc.path, rel, ok, tc.want)
			}
		})
	}
}

// TestCopyFileFailures: the helper refuses to overwrite, reports a source
// that can't be read as a file, and never leaves a half-written key readable
// by others.
func TestCopyFileFailures(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "taken"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		src, dst string
	}{
		{"source missing", filepath.Join(dir, "nope"), filepath.Join(dir, "new1")},
		{"destination exists", src, filepath.Join(dir, "taken")},
		{"destination directory missing", src, filepath.Join(dir, "missing", "new2")},
		{"source is a directory", dir, filepath.Join(dir, "new3")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := copyFile(tc.src, tc.dst); err == nil {
				t.Fatal("copyFile succeeded")
			}
		})
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "taken")); string(got) != "old" {
		t.Errorf("an existing file was overwritten: %q", got)
	}
	if err := copyFile(src, filepath.Join(dir, "ok")); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "ok")); string(got) != "secret" {
		t.Errorf("copy: %q", got)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(filepath.Join(dir, "ok")); fi.Mode().Perm() != 0o600 {
			t.Errorf("copy has mode %v", fi.Mode().Perm())
		}
	}
}

// TestRestoreRefusals: where a restore may go, and that a refusal leaves
// neither the backup changed nor a work directory behind.
func TestRestoreRefusals(t *testing.T) {
	t.Parallel()
	v, o := newInstance(t)
	issue(t, v, "nas.homelab.lan")
	good := filepath.Join(t.TempDir(), "backup")
	if _, err := Create(t.Context(), good, o); err != nil {
		t.Fatal(err)
	}
	goodTree := tree(t, good)

	t.Run("target holds a file", func(t *testing.T) {
		t.Parallel()
		parent := t.TempDir()
		target := Options{Layout: store.Layout{DataDir: filepath.Join(parent, "data")}, Clock: v.Clock, Who: testinstance.Console}
		if err := os.MkdirAll(target.Layout.DataDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(target.Layout.DataDir, "keep.txt"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		before := tree(t, parent)
		if _, err := Restore(t.Context(), good, "", target); err == nil || !strings.Contains(err.Error(), "not empty") {
			t.Errorf("restore into a directory with a file: %v", err)
		}
		sameTree(t, before, tree(t, parent))
	})
	t.Run("target is a regular file", func(t *testing.T) {
		t.Parallel()
		parent := t.TempDir()
		target := Options{Layout: store.Layout{DataDir: filepath.Join(parent, "data")}, Clock: v.Clock, Who: testinstance.Console}
		if err := os.WriteFile(target.Layout.DataDir, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		before := tree(t, parent)
		if _, err := Restore(t.Context(), good, "", target); err == nil {
			t.Error("restore over a file")
		}
		sameTree(t, before, tree(t, parent))
	})
	t.Run("an empty target directory and a missing parent are fine", func(t *testing.T) {
		t.Parallel()
		parent := t.TempDir()
		empty := Options{Layout: store.Layout{DataDir: filepath.Join(parent, "empty")}, Clock: v.Clock, Who: testinstance.Console}
		if err := os.Mkdir(empty.Layout.DataDir, 0o700); err != nil {
			t.Fatal(err)
		}
		deep := Options{Layout: store.Layout{DataDir: filepath.Join(parent, "a", "b", "data")}, Clock: v.Clock, Who: testinstance.Console}
		for _, target := range []Options{empty, deep} {
			if _, err := Restore(t.Context(), good, "", target); err != nil {
				t.Fatalf("restore into %s: %v", target.Layout.DataDir, err)
			}
			if _, err := os.Stat(target.Layout.SystemDB()); err != nil {
				t.Errorf("system.db: %v", err)
			}
			if runtime.GOOS != "windows" {
				if fi, _ := os.Stat(target.Layout.DataDir); fi.Mode().Perm() != 0o700 {
					t.Errorf("data directory mode %v", fi.Mode().Perm())
				}
				if fi, _ := os.Stat(target.Layout.SystemDB()); fi.Mode().Perm()&0o077 != 0 {
					t.Errorf("system.db mode %v", fi.Mode().Perm())
				}
			}
		}
		entries, _ := os.ReadDir(parent)
		if got := strings.Join(dirNames(entries), ","); got != "a,empty" {
			t.Errorf("below the parent: %s – a work directory was left behind", got)
		}
	})
	t.Run("a refusal leaves no work directory and the backup unchanged", func(t *testing.T) {
		t.Parallel()
		dir := backupCopy(t, good)
		execOn(t, filepath.Join(dir, "audit.db"), `DROP TRIGGER IF EXISTS audit_entries_no_update; UPDATE audit_entries SET actor_name = 'someone else' WHERE seq = 1`)
		rehash(t, dir, "audit.db")
		before := tree(t, dir)
		parent := t.TempDir()
		target := Options{Layout: store.Layout{DataDir: filepath.Join(parent, "data")}, Clock: v.Clock, Who: testinstance.Console}
		rep, err := Restore(t.Context(), dir, "", target)
		if !errors.Is(err, ErrRefused) || rep == nil || len(rep.Problems) == 0 {
			t.Fatalf("restore of a tampered backup: %v %+v", err, rep)
		}
		if entries, _ := os.ReadDir(parent); len(entries) != 0 {
			t.Errorf("below the parent: %v", dirNames(entries))
		}
		sameTree(t, before, tree(t, dir))
		if _, verr := Verify(t.Context(), dir, ""); !errors.Is(verr, ErrRefused) {
			t.Errorf("verify: %v", verr)
		}
		sameTree(t, before, tree(t, dir))
	})
	t.Run("a good backup is not changed by verify or restore", func(t *testing.T) {
		t.Parallel()
		dir := backupCopy(t, good)
		if _, err := Verify(t.Context(), dir, ""); err != nil {
			t.Fatal(err)
		}
		if _, err := Restore(t.Context(), dir, "", targetOptions(t, v)); err != nil {
			t.Fatal(err)
		}
		sameTree(t, goodTree, tree(t, dir))
	})
	t.Run("no backup at all", func(t *testing.T) {
		t.Parallel()
		for _, dir := range []string{filepath.Join(t.TempDir(), "nope"), t.TempDir()} {
			if _, err := Verify(t.Context(), dir, ""); err == nil || !strings.Contains(err.Error(), "no manifest.json") {
				t.Errorf("verify %s: %v", dir, err)
			}
		}
	})
	t.Run("a checkpoint key that is not the noted one", func(t *testing.T) {
		t.Parallel()
		rep, err := Verify(t.Context(), good, "SHA256:not-the-key-noted-at-init")
		if !errors.Is(err, ErrRefused) || rep == nil || !strings.Contains(strings.Join(rep.Problems, "|"), "audit log") {
			t.Errorf("wrong pin: %v %+v", err, rep)
		}
	})
}

// TestModifiedBackupIsRefused: changes that keep the file hashes consistent
// (a manifest rewritten by someone who changed a database) are still found.
func TestModifiedBackupIsRefused(t *testing.T) {
	t.Parallel()
	v, o := newInstance(t)
	issue(t, v, "nas.homelab.lan")
	good := filepath.Join(t.TempDir(), "backup")
	if _, err := Create(t.Context(), good, o); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		change func(t *testing.T, dir string)
		want   string
	}{
		{"manifest of another format", func(t *testing.T, dir string) {
			t.Helper()
			editManifestOf(t, dir, func(m *Manifest) { m.Format = "myownpki-backup/2" })
		}, `backup format "myownpki-backup/2"`},
		{"manifest without a format", func(t *testing.T, dir string) {
			t.Helper()
			editManifestOf(t, dir, func(m *Manifest) { m.Format = "" })
		}, "backup format"},
		{"manifest with a creation time that is no time", func(t *testing.T, dir string) {
			t.Helper()
			editManifestOf(t, dir, func(m *Manifest) { m.CreatedAt = "yesterday" })
		}, "created_at"},
		{"manifest that is not JSON", func(t *testing.T, dir string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(dir, ManifestFile), []byte("{not json"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "can't be read"},
		{"manifest that is empty", func(t *testing.T, dir string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(dir, ManifestFile), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}, "can't be read"},
		{"manifest larger than the limit", func(t *testing.T, dir string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(dir, ManifestFile), []byte(strings.Repeat(" ", maxManifest+1)), 0o600); err != nil {
				t.Fatal(err)
			}
		}, "is larger than"},
		{"manifest is a directory", func(t *testing.T, dir string) {
			t.Helper()
			if err := os.Remove(filepath.Join(dir, ManifestFile)); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(dir, ManifestFile), 0o700); err != nil {
				t.Fatal(err)
			}
		}, ""},
		{"a file listed twice", func(t *testing.T, dir string) {
			t.Helper()
			editManifestOf(t, dir, func(m *Manifest) { m.Files = append(m.Files, m.Files[0]) })
		}, ""},
		{"absolute path", func(t *testing.T, dir string) {
			t.Helper()
			editManifestOf(t, dir, func(m *Manifest) { m.Files[0].Path = "/etc/passwd" })
		}, "not a path inside the backup"},
		{"path with a backslash", func(t *testing.T, dir string) {
			t.Helper()
			editManifestOf(t, dir, func(m *Manifest) { m.Files[0].Path = `tenants\default\pki.db` })
		}, "not a path inside the backup"},
		{"path that is not clean", func(t *testing.T, dir string) {
			t.Helper()
			editManifestOf(t, dir, func(m *Manifest) { m.Files[0].Path = "tenants/./default/pki.db" })
		}, "not a path inside the backup"},
		{"path that climbs out in the middle", func(t *testing.T, dir string) {
			t.Helper()
			editManifestOf(t, dir, func(m *Manifest) { m.Files[0].Path = "tenants/../../system.db" })
		}, "not a path inside the backup"},
		{"path that is only dots", func(t *testing.T, dir string) {
			t.Helper()
			editManifestOf(t, dir, func(m *Manifest) { m.Files[0].Path = ".." })
		}, "not a path inside the backup"},
		{"the manifest listing itself", func(t *testing.T, dir string) {
			t.Helper()
			editManifestOf(t, dir, func(m *Manifest) { m.Files[0].Path = ManifestFile })
		}, "not a path inside the backup"},
		{"a file of the manifest removed", func(t *testing.T, dir string) {
			t.Helper()
			editManifestOf(t, dir, func(m *Manifest) { m.Files = m.Files[1:] })
		}, "not in the manifest"},
		{"a tenant database swapped for the system database", func(t *testing.T, dir string) {
			t.Helper()
			data, err := os.ReadFile(filepath.Join(dir, "system.db"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(pkiRel)), data, 0o600); err != nil { // #nosec G703 -- a file of the test's own backup copy
				t.Fatal(err)
			}
			rehash(t, dir, pkiRel)
		}, pkiRel},
		{"a database that is not a database", func(t *testing.T, dir string) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(pkiRel)), []byte(strings.Repeat("not sqlite ", 100)), 0o600); err != nil {
				t.Fatal(err)
			}
			rehash(t, dir, pkiRel)
		}, pkiRel},
		{"a database with a wrong migration number in the manifest", func(t *testing.T, dir string) {
			t.Helper()
			editManifestOf(t, dir, func(m *Manifest) {
				for i := range m.Files {
					if m.Files[i].Path == pkiRel {
						m.Files[i].Migration++
					}
				}
			})
		}, "the manifest says"},
		{"a listed tenant that has no files", func(t *testing.T, dir string) {
			t.Helper()
			editManifestOf(t, dir, func(m *Manifest) { m.Tenants = append(m.Tenants, "ghost") })
		}, "ghost"},
		{"a tenant dropped from the list", func(t *testing.T, dir string) {
			t.Helper()
			editManifestOf(t, dir, func(m *Manifest) { m.Tenants = nil })
		}, "belongs to no tenant"},
		{"the head of the instance audit log dropped", func(t *testing.T, dir string) {
			t.Helper()
			editManifestOf(t, dir, func(m *Manifest) { m.Audit = m.Audit[1:] })
		}, "the manifest has no head for the audit log"},
		{"the head of an audit log pointing at an entry that is not there", func(t *testing.T, dir string) {
			t.Helper()
			editManifestOf(t, dir, func(m *Manifest) { m.Audit[0].Head = "9999:" + strings.Repeat("0", 64) })
		}, "audit log"},
		{"audit entries deleted at the end, manifest and hash fixed up", func(t *testing.T, dir string) {
			t.Helper()
			execOn(t, filepath.Join(dir, "audit.db"), `DROP TRIGGER IF EXISTS audit_entries_no_delete; DROP TRIGGER IF EXISTS audit_entries_no_update; DELETE FROM audit_entries WHERE seq = (SELECT max(seq) FROM audit_entries)`)
			rehash(t, dir, "audit.db")
		}, "cut off or rewritten"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := backupCopy(t, good)
			tc.change(t, dir)
			before := tree(t, dir)
			target := targetOptions(t, v)
			rep, err := Restore(t.Context(), dir, "", target)
			if err == nil {
				t.Fatal("the modified backup was restored")
			}
			msg := err.Error()
			if rep != nil {
				msg += " | " + strings.Join(rep.Problems, " | ")
			}
			if !strings.Contains(msg, tc.want) {
				t.Errorf("refusal %q does not contain %q", msg, tc.want)
			}
			if _, serr := os.Stat(target.Layout.DataDir); !errors.Is(serr, fs.ErrNotExist) {
				t.Errorf("a refused restore created the data directory: %v", serr)
			}
			sameTree(t, before, tree(t, dir))
		})
	}
}

// TestRestoredAuditLogContinues: after a restore the log has exactly one
// more entry than the backup (the restore), and the head the manifest names
// is still reachable inside the chain.
func TestRestoredAuditLogContinues(t *testing.T) {
	t.Parallel()
	v, o := newInstance(t)
	dir := filepath.Join(t.TempDir(), "backup")
	m, err := Create(t.Context(), dir, o)
	if err != nil {
		t.Fatal(err)
	}
	target := targetOptions(t, v)
	v.Clock.Advance(time.Hour)
	if _, rerr := Restore(t.Context(), dir, "", target); rerr != nil {
		t.Fatal(rerr)
	}
	db, err := store.OpenAuditLog(t.Context(), store.AuditLog{Scope: store.InstanceScope, Path: target.Layout.InstanceAuditDB()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	r, err := audit.Verify(t.Context(), db.Read, store.InstanceScope)
	if err != nil || r.Break != nil {
		t.Fatalf("verify: %v %+v", err, r.Break)
	}
	if r.Entries != m.Audit[0].Entries+1 {
		t.Errorf("%d entries after the restore, want %d", r.Entries, m.Audit[0].Entries+1)
	}
	head, err := audit.ParseHead(m.Audit[0].Head)
	if err != nil {
		t.Fatal(err)
	}
	if err := audit.CheckHead(t.Context(), db.Read, head); err != nil {
		t.Errorf("the head of the backup is not part of the restored chain: %v", err)
	}
	var last string
	if err := db.Read.QueryRowContext(t.Context(), `SELECT action FROM audit_entries ORDER BY seq DESC LIMIT 1`).Scan(&last); err != nil || last != ActionRestore {
		t.Errorf("last entry %q, %v", last, err)
	}
}
