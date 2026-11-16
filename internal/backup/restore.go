package backup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/backup/backupkey"
	"github.com/Der-Felix/MyOwnPKI/internal/ca"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
)

// Report is the result of checking a backup.
type Report struct {
	Manifest *Manifest
	// Problems refuse a restore.
	Problems []string
	// Certificates whose name index was compared.
	Certificates int
	// Notes are for the operator (auth.key, migrations to apply).
	Notes []string
	// Authenticity says what the signature proves: nothing (format 1), that a
	// key made it (signed), or that the expected key made it (pinned).
	Authenticity Authenticity
	// SigningKey is the fingerprint of the key that signed; "" = unsigned.
	SigningKey string
}

// ErrRefused wraps the problems of a backup that may not be restored.
var ErrRefused = errors.New("the backup is refused")

func (r *Report) problem(format string, a ...any) {
	r.Problems = append(r.Problems, fmt.Sprintf(format, a...))
}

// Verify runs every check of a restore on a copy and writes nothing else.
func Verify(ctx context.Context, dir string, c Check) (*Report, error) {
	c, err := normalizeCheck(c)
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "myownpki-verify-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	return check(ctx, dir, filepath.Join(tmp, "data"), c)
}

// normalizeCheck checks the --backup-key text before anything is read and
// returns c with the fingerprints as lower-case hex digits.
func normalizeCheck(c Check) (Check, error) {
	var err error
	if c.BackupKey != "" {
		if c.BackupKey, err = backupkey.NormalizePin(c.BackupKey); err != nil {
			return c, fmt.Errorf("backup key: %w", err)
		}
	}
	if c.HostKey != "" {
		if c.HostKey, err = backupkey.NormalizePin(c.HostKey); err != nil {
			return c, fmt.Errorf("host backup key: %w", err)
		}
	}
	return c, nil
}

// check copies the backup to work (a new directory) and checks it there:
// the backup itself is never opened as a database. The signature is checked
// first: nothing the manifest says is used before it is known who vouches
// for it.
func check(ctx context.Context, dir, work string, c Check) (*Report, error) {
	pin := c.CheckpointKey
	m, raw, err := loadManifest(dir)
	if err != nil {
		return nil, err
	}
	r := &Report{Manifest: m}
	r.checkSignature(dir, raw, c.BackupKey, c.HostKey, c.AllowUnsigned)
	if len(r.Problems) > 0 {
		return r, fmt.Errorf("%w: %s", ErrRefused, strings.Join(r.Problems, "; "))
	}
	listed := map[string]File{}
	for _, f := range m.Files {
		clean := path.Clean(f.Path)
		if clean != f.Path || strings.HasPrefix(clean, "../") || clean == ".." || path.IsAbs(clean) || strings.Contains(clean, `\`) || clean == ManifestFile || clean == SignatureFile {
			r.problem("the manifest names the file %q – not a path inside the backup", f.Path)
			continue
		}
		listed[clean] = f
	}
	if len(r.Problems) > 0 {
		return r, fmt.Errorf("%w: %s", ErrRefused, strings.Join(r.Problems, "; "))
	}
	// Every file on disk must be in the manifest, and the other way round.
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil || d.IsDir() {
			return werr
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if rel != ManifestFile && (rel != SignatureFile || m.Format != Format) && listed[rel].Path == "" {
			r.problem("%s is not in the manifest – the backup was changed", rel)
		}
		return nil
	})
	if err != nil {
		return r, err
	}
	if err := os.MkdirAll(work, 0o700); err != nil {
		return r, err
	}
	for _, f := range m.Files {
		src := filepath.Join(dir, filepath.FromSlash(f.Path))
		sum, size, herr := hashFile(src)
		switch {
		case errors.Is(herr, fs.ErrNotExist):
			r.problem("%s is missing", f.Path)
			continue
		case herr != nil:
			r.problem("%s: %v", f.Path, herr)
			continue
		case sum != f.SHA256 || size != f.Size:
			r.problem("%s: SHA-256 or size differs from the manifest – the file was changed or damaged", f.Path)
			continue
		}
		dst := filepath.Join(work, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return r, err
		}
		if err := copyFile(src, dst); err != nil {
			return r, err
		}
	}
	if len(r.Problems) > 0 {
		return r, fmt.Errorf("%w: %s", ErrRefused, strings.Join(r.Problems, "; "))
	}

	l := store.Layout{DataDir: work}
	r.checkDatabases(ctx, l, m)
	r.checkAudit(ctx, work, m, pin)
	for _, t := range m.Tenants {
		p, perr := l.TenantDB(t, store.KindPKI)
		if perr != nil {
			r.problem("%v", perr)
			continue
		}
		db, oerr := store.OpenReadOnly(ctx, p)
		if oerr != nil {
			r.problem("tenant %s: %v", t, oerr)
			continue
		}
		problems, n, serr := ca.CheckSANIndex(ctx, db.Read, 20)
		_ = db.Close()
		r.Certificates += n
		if serr != nil {
			r.problem("tenant %s: %v", t, serr)
		}
		for _, pr := range problems {
			r.problem("tenant %s: %s", t, pr)
		}
	}
	if len(r.Problems) > 0 {
		return r, fmt.Errorf("%w: %d problem(s)", ErrRefused, len(r.Problems))
	}
	return r, nil
}

// checkDatabases: integrity, kind and scope, migrations of every database.
func (r *Report) checkDatabases(ctx context.Context, l store.Layout, m *Manifest) {
	want := map[string]File{}
	for _, f := range m.Files {
		want[f.Path] = f
	}
	seen := map[string]bool{}
	for _, t := range m.Tenants {
		sts, err := store.Status(ctx, l, t)
		if err != nil {
			r.problem("tenant %s: %v", t, err)
			continue
		}
		for _, st := range sts {
			rel, _ := filepath.Rel(l.DataDir, st.Path)
			rel = filepath.ToSlash(rel)
			if seen[rel] {
				continue
			}
			seen[rel] = true
			f, listed := want[rel]
			switch {
			case !st.Exists || !listed:
				r.problem("%s is not in the backup", rel)
				continue
			case st.Err != nil:
				r.problem("%s: %v", rel, st.Err)
				continue
			case st.Report.Version() != f.Migration:
				r.problem("%s: migration version %d, the manifest says %d", rel, st.Report.Version(), f.Migration)
			}
			if p := st.Report.Pending(); p > 0 {
				r.Notes = append(r.Notes, fmt.Sprintf("%s: %d migration(s) of this version are applied at the next start", rel, p))
			}
			r.integrity(ctx, st.Path, rel)
		}
	}
	for rel, f := range want {
		if f.Kind != KindAuthKey && !seen[rel] {
			r.problem("%s is in the manifest but belongs to no tenant of the backup", rel)
		}
	}
}

func (r *Report) integrity(ctx context.Context, path, rel string) {
	db, err := store.OpenReadOnly(ctx, path)
	if err != nil {
		r.problem("%s: %v", rel, err)
		return
	}
	defer func() { _ = db.Close() }()
	var res string
	if err := db.Read.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&res); err != nil || res != "ok" {
		r.problem("%s: integrity check failed: %s %v", rel, res, err)
	}
}

// checkAudit: every log intact and ending exactly at the manifest head.
func (r *Report) checkAudit(ctx context.Context, work string, m *Manifest, pin string) {
	if pin == "" {
		pin = m.CheckpointKey
	}
	scopes := []string{store.InstanceScope}
	for _, t := range m.Tenants {
		scopes = append(scopes, store.TenantScope(t))
	}
	for _, scope := range scopes {
		i := slices.IndexFunc(m.Audit, func(lg Log) bool { return lg.Scope == scope })
		if i < 0 {
			r.problem("the manifest has no head for the audit log %s", scope)
			continue
		}
		want := m.Audit[i]
		got, key, err := auditState(ctx, filepath.Join(work, filepath.FromSlash(want.Path)), scope, pin)
		switch {
		case err != nil:
			r.problem("audit log %s: %v", scope, err)
		case got.Head != want.Head || got.Entries != want.Entries:
			r.problem("audit log %s ends at %s (%d entries), the manifest says %s (%d) – entries were cut off or rewritten", scope, got.Head, got.Entries, want.Head, want.Entries)
		case key != "" && m.CheckpointKey != "" && key != m.CheckpointKey:
			r.problem("audit log %s: checkpoints signed with %s, the manifest says %s", scope, key, m.CheckpointKey)
		}
		if head, perr := audit.ParseHead(want.Head); perr == nil {
			r.checkHead(ctx, filepath.Join(work, filepath.FromSlash(want.Path)), scope, head)
		}
	}
}

func (r *Report) checkHead(ctx context.Context, p, scope string, head audit.Head) {
	if head.Seq == 0 {
		return
	}
	db, err := store.OpenAuditLog(ctx, store.AuditLog{Scope: scope, Path: p})
	if err != nil {
		return // reported by auditState
	}
	defer func() { _ = db.Close() }()
	if err := audit.CheckHead(ctx, db.Read, head); err != nil {
		r.problem("audit log %s: %v", scope, err)
	}
}

// Restore checks the backup as Verify does and moves it into the data
// directory of o, which must be empty or missing.
func Restore(ctx context.Context, dir string, c Check, o Options) (*Report, error) {
	c, perr := normalizeCheck(c)
	if perr != nil {
		return nil, perr
	}
	data := o.Layout.DataDir
	// A file is no empty directory (on Windows ReadDir says "not found" for
	// it, and the restore would delete it).
	if fi, err := os.Stat(data); err == nil && !fi.IsDir() {
		return nil, fmt.Errorf("%s is a file, not a directory – restore only into an empty data directory", data)
	}
	if entries, err := os.ReadDir(data); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("%s is not empty – restore only into an empty data directory (stop the server, move the old one away)", data)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	parent := filepath.Dir(data)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, err
	}
	// The work copy lies next to the data directory: one rename moves it.
	tmp, err := os.MkdirTemp(parent, ".myownpki-restore-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	work := filepath.Join(tmp, "data")
	r, err := check(ctx, dir, work, c)
	if err != nil {
		return r, err
	}
	r.noteBackupKey(o.Layout.DataDir)
	if r.Manifest.AuthKey {
		keyRel := ""
		for _, f := range r.Manifest.Files {
			if f.Kind == KindAuthKey {
				keyRel = f.Path
			}
		}
		if rel, ok := inside(data, o.AuthKeyFile); !ok || filepath.ToSlash(rel) != keyRel {
			r.Notes = append(r.Notes, fmt.Sprintf("auth.key is restored to %s, but the configuration names %s – move it there, or every user needs `myownpki user reset-2fa`",
				filepath.Join(data, filepath.FromSlash(keyRel)), o.AuthKeyFile))
		}
	} else {
		r.Notes = append(r.Notes, fmt.Sprintf("auth.key is not in the backup (it lived outside the data directory): put it at %s, or every user needs `myownpki user reset-2fa`", o.AuthKeyFile))
	}

	ia, err := store.Open(ctx, filepath.Join(work, "audit.db"))
	if err != nil {
		return r, err
	}
	_, _, err = audit.Append(ctx, ia.Write, store.InstanceScope, audit.Entry{
		Time: o.Clock.Now().UTC(), Actor: o.Who.Actor, Action: ActionRestore, Target: audit.Target{Type: "instance", ID: "restore"},
		Result: audit.ResultSuccess, SourceIP: o.Who.SourceIP, Details: map[string]any{
			"backup_created_at": r.Manifest.CreatedAt, "backup_version": r.Manifest.Version, "tenants": r.Manifest.Tenants,
		},
	}, "")
	if cerr := ia.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return r, fmt.Errorf("audit entry: %w", err)
	}
	if err := os.Remove(data); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return r, err
	}
	if err := os.Rename(work, data); err != nil {
		return r, fmt.Errorf("move the restored files into %s: %w", data, err)
	}
	return r, nil
}

// noteBackupKey tells what a restore does not bring along: the backup key
// stays with the host that made the backup, so the instance restored here
// has none until its first backup makes a new one.
func (r *Report) noteBackupKey(dataDir string) {
	if exists(backupkey.Path(dataDir)) {
		return
	}
	text := "the backup key (" + backupkey.FileName + ") is never part of a backup: the first backup made here creates a new one – note its fingerprint"
	if r.SigningKey != "" {
		text += "; this backup stays verifiable with --backup-key " + r.SigningKey
	}
	r.Notes = append(r.Notes, text)
}
