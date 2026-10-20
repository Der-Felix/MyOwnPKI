// Package backup makes, checks and restores backups of an instance (PHASE1
// step 16): every database as one consistent copy (VACUUM INTO, also while
// the server runs), the audit databases last, a manifest with SHA-256 per
// file and the head of every audit chain. A restore goes only into an empty
// data directory and only after every check passed.
package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/audit"
	"github.com/Der-Felix/MyOwnPKI/internal/clock"
	"github.com/Der-Felix/MyOwnPKI/internal/keys"
	"github.com/Der-Felix/MyOwnPKI/internal/store"
	"github.com/Der-Felix/MyOwnPKI/internal/store/migrate"
	"github.com/Der-Felix/MyOwnPKI/internal/version"
)

// Format names the layout of a backup directory.
const Format = "myownpki-backup/1"

// ManifestFile is written last: a directory without it is not a backup.
const ManifestFile = "manifest.json"

// Audit actions in the instance log.
const (
	ActionBackup  = "system.backup"
	ActionRestore = "system.restore"
)

// Warning is shown at every backup (owner decision 2).
const Warning = "This backup holds the CA and certificate keys, encrypted with the root key. " +
	"Keep the unseal passphrase and the recovery key apart from it – whoever has both can sign as your CAs."

// Manifest describes a backup.
type Manifest struct {
	Format    string   `json:"format"`
	CreatedAt string   `json:"created_at"`
	Version   string   `json:"version"`
	Tenants   []string `json:"tenants"`
	Files     []File   `json:"files"`
	Audit     []Log    `json:"audit"`
	// CheckpointKey is the fingerprint of the key that signs the audit
	// checkpoints – compare it with the one noted at init.
	CheckpointKey string `json:"checkpoint_key"`
	// AuthKey: auth.key is in the backup (it lived in the data directory).
	AuthKey bool `json:"auth_key_included"`
}

// File is one file of the backup; Path is relative to the data directory.
type File struct {
	Path      string     `json:"path"`
	Kind      store.Kind `json:"kind"` // system, pki, audit; "auth_key"
	Tenant    string     `json:"tenant,omitempty"`
	SHA256    string     `json:"sha256"`
	Size      int64      `json:"size"`
	Migration int        `json:"migration,omitempty"`
}

// Log is the state of one audit log in the backup.
type Log struct {
	Scope          string                `json:"scope"`
	Path           string                `json:"path"`
	Head           string                `json:"head"` // seq:hash
	Entries        int64                 `json:"entries"`
	LastCheckpoint *audit.CheckpointInfo `json:"last_checkpoint,omitempty"`
}

// KindAuthKey marks auth.key in the manifest.
const KindAuthKey store.Kind = "auth_key"

// Options for Create and Restore.
type Options struct {
	Layout      store.Layout
	AuthKeyFile string // config auth.key_file
	Clock       clock.Clock
	Who         keys.Who
}

// source is one file to copy.
type source struct {
	rel, path, tenant, scope string
	kind                     store.Kind
}

// sources lists the databases in backup order: system.db, the tenants'
// business databases, then the audit logs (PHASE1 "Backup consistency").
func sources(l store.Layout, tenants []string) ([]source, error) {
	out := []source{{rel: "system.db", path: l.SystemDB(), kind: store.KindSystem}}
	var audits []source
	audits = append(audits, source{rel: "audit.db", path: l.InstanceAuditDB(), kind: store.KindAudit, scope: store.InstanceScope})
	for _, t := range tenants {
		for _, k := range store.TenantKinds {
			p, err := l.TenantDB(t, k)
			if err != nil {
				return nil, err
			}
			s := source{rel: filepath.ToSlash(filepath.Join("tenants", t, string(k)+".db")), path: p, kind: k, tenant: t}
			if k == store.KindAudit {
				s.scope = store.TenantScope(t)
				audits = append(audits, s)
				continue
			}
			out = append(out, s)
		}
	}
	return append(out, audits...), nil
}

// Create writes a backup into dir, which must not exist yet.
func Create(ctx context.Context, dir string, o Options) (*Manifest, error) {
	l := o.Layout
	if _, err := os.Stat(l.SystemDB()); err != nil {
		return nil, fmt.Errorf("no instance at %s: %w", l.DataDir, err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("%s exists already – a backup never overwrites anything; choose a new directory", dir)
		}
		return nil, err
	}
	m, err := create(ctx, dir, o)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return m, nil
}

func create(ctx context.Context, dir string, o Options) (*Manifest, error) {
	l := o.Layout
	rows, err := store.Tenants(ctx, l)
	if err != nil {
		return nil, err
	}
	now := o.Clock.Now().UTC()
	m := &Manifest{Format: Format, CreatedAt: now.Format(audit.TimeFormat), Version: version.Get().Version, Files: []File{}, Audit: []Log{}}
	for _, t := range rows {
		m.Tenants = append(m.Tenants, t.ID)
	}
	srcs, err := sources(l, m.Tenants)
	if err != nil {
		return nil, err
	}

	// The audit entry first, so the backup holds it.
	ia, err := store.Open(ctx, l.InstanceAuditDB())
	if err != nil {
		return nil, err
	}
	_, _, err = audit.Append(ctx, ia.Write, store.InstanceScope, audit.Entry{
		Time: now, Actor: o.Who.Actor, Action: ActionBackup, Target: audit.Target{Type: "instance", ID: "backup"},
		Result: audit.ResultSuccess, SourceIP: o.Who.SourceIP, Details: map[string]any{"tenants": m.Tenants, "databases": len(srcs)},
	}, "")
	if cerr := ia.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, fmt.Errorf("audit entry: %w", err)
	}

	for _, s := range srcs {
		dst := filepath.Join(dir, filepath.FromSlash(s.rel))
		if merr := os.MkdirAll(filepath.Dir(dst), 0o700); merr != nil {
			return nil, merr
		}
		if verr := vacuumInto(ctx, s.path, dst); verr != nil {
			return nil, fmt.Errorf("copy %s: %w", s.rel, verr)
		}
		f := File{Path: s.rel, Kind: s.kind, Tenant: s.tenant}
		if f.SHA256, f.Size, err = hashFile(dst); err != nil {
			return nil, err
		}
		if f.Migration, err = migrationVersion(ctx, dst, s.kind); err != nil {
			return nil, fmt.Errorf("%s: %w", s.rel, err)
		}
		m.Files = append(m.Files, f)
		if s.kind != store.KindAudit {
			continue
		}
		lg, key, aerr := auditState(ctx, dst, s.scope, "")
		if aerr != nil {
			return nil, fmt.Errorf("%s: %w", s.rel, aerr)
		}
		lg.Path = s.rel
		m.Audit = append(m.Audit, lg)
		switch {
		case key == "":
		case m.CheckpointKey == "":
			m.CheckpointKey = key
		case m.CheckpointKey != key:
			return nil, fmt.Errorf("%s: its checkpoints use key %s, the other logs %s – check the logs with `myownpki audit verify`", s.rel, key, m.CheckpointKey)
		}
	}

	if rel, ok := inside(l.DataDir, o.AuthKeyFile); ok && exists(o.AuthKeyFile) {
		dst := filepath.Join(dir, rel)
		if cerr := copyFile(o.AuthKeyFile, dst); cerr != nil {
			return nil, fmt.Errorf("copy auth.key: %w", cerr)
		}
		f := File{Path: filepath.ToSlash(rel), Kind: KindAuthKey}
		if f.SHA256, f.Size, err = hashFile(dst); err != nil {
			return nil, err
		}
		m.Files = append(m.Files, f)
		m.AuthKey = true
	}
	return m, writeManifest(dir, m)
}

// vacuumInto copies one database as a consistent snapshot.
func vacuumInto(ctx context.Context, src, dst string) error {
	if err := store.Snapshot(ctx, src, dst); err != nil {
		return err
	}
	return os.Chmod(dst, 0o600)
}

func migrationVersion(ctx context.Context, path string, kind store.Kind) (int, error) {
	set, err := store.Migrations(kind)
	if err != nil {
		return 0, err
	}
	db, err := store.OpenReadOnly(ctx, path)
	if err != nil {
		return 0, err
	}
	defer func() { _ = db.Close() }()
	r, err := migrate.Check(ctx, db.Read, set)
	if err != nil {
		return 0, err
	}
	return r.Version(), nil
}

// auditState verifies one log and returns its state and checkpoint key.
func auditState(ctx context.Context, path, scope, pin string) (Log, string, error) {
	db, err := store.OpenAuditLog(ctx, store.AuditLog{Scope: scope, Path: path})
	if err != nil {
		return Log{}, "", err
	}
	defer func() { _ = db.Close() }()
	r, err := audit.VerifyWith(ctx, db.Read, scope, audit.VerifyOptions{CheckpointKey: pin})
	if err != nil {
		return Log{}, "", err
	}
	if r.Break != nil {
		return Log{}, "", fmt.Errorf("the audit chain is broken at seq %d (%s)", r.Break.Seq, r.Break.Reason)
	}
	return Log{Scope: scope, Head: r.Head.String(), Entries: r.Entries, LastCheckpoint: r.LastCheckpoint}, r.CheckpointKey, nil
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path) // #nosec G304 -- a file of the backup being made or checked
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src) // #nosec G304 -- the configured auth key file or a file of the backup
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- inside the new backup or data directory
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// inside reports whether path lies below dir, and its relative path.
func inside(dir, path string) (string, bool) {
	rel, err := filepath.Rel(dir, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false
	}
	return rel, true
}

func writeManifest(dir string, m *Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, ManifestFile+".tmp")
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, ManifestFile))
}

// maxManifest bounds what is read as a manifest.
const maxManifest = 1 << 20

func readManifest(dir string) (*Manifest, error) {
	path := filepath.Join(dir, ManifestFile)
	st, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("%s has no %s – not a MyOwnPKI backup, or an incomplete one", dir, ManifestFile)
	}
	if st.Size() > maxManifest {
		return nil, fmt.Errorf("%s is larger than %d KiB", ManifestFile, maxManifest>>10)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- the manifest of the backup to check
	if err != nil {
		return nil, err
	}
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s can't be read: %w", ManifestFile, err)
	}
	if m.Format != Format {
		return nil, fmt.Errorf("backup format %q is not %q", m.Format, Format)
	}
	if _, err := time.Parse(audit.TimeFormat, m.CreatedAt); err != nil {
		return nil, fmt.Errorf("%s: created_at %q is not a time", ManifestFile, m.CreatedAt)
	}
	return &m, nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
