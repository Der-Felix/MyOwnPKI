package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/Der-Felix/MyOwnPKI/internal/store/auditdb"
	"github.com/Der-Felix/MyOwnPKI/internal/store/migrate"
	"github.com/Der-Felix/MyOwnPKI/internal/store/systemdb"
)

//go:embed schema/*/*.sql
var schemaFiles embed.FS

// ErrWrongKind means a file is a different database kind than its place in
// the layout says, e.g. audit.db copied over pki.db.
var ErrWrongKind = errors.New("database file has the wrong type")

// Migrations returns the migration set of a database kind.
func Migrations(kind Kind) ([]migrate.Migration, error) {
	sub, err := fs.Sub(schemaFiles, "schema/"+string(kind))
	if err != nil {
		return nil, err
	}
	return migrate.Load(sub)
}

// target is one database file, its kind and (for audit logs) its scope.
type target struct {
	Kind  Kind
	Path  string
	Scope string // audit logs only
}

func (l Layout) targets(tenant string) ([]target, error) {
	ts := []target{
		{Kind: KindSystem, Path: l.SystemDB()},
		{Kind: KindAudit, Path: l.InstanceAuditDB(), Scope: InstanceScope},
	}
	for _, k := range TenantKinds {
		p, err := l.TenantDB(tenant, k)
		if err != nil {
			return nil, err
		}
		t := target{Kind: k, Path: p}
		if k == KindAudit {
			t.Scope = TenantScope(tenant)
		}
		ts = append(ts, t)
	}
	return ts, nil
}

// Applied lists the migrations Migrate applied to one file.
type Applied struct {
	Kind     Kind
	Path     string
	Versions []int
}

// Migrate creates missing directories and database files and applies all
// pending migrations to system.db and the databases of tenant. It stops at
// the first file that is of the wrong kind, was changed or is newer.
func Migrate(ctx context.Context, l Layout, tenant string, now func() time.Time) ([]Applied, error) {
	ts, err := l.targets(tenant)
	if err != nil {
		return nil, err
	}
	dir, _ := l.TenantDir(tenant)
	// 0700: the databases hold encrypted keys and the audit log – no other
	// local user needs to list or read them (Windows ignores the mode).
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", dir, err)
	}
	var out []Applied
	for _, t := range ts {
		versions, err := migrateFile(ctx, t, now)
		if err != nil {
			return out, err
		}
		out = append(out, Applied{Kind: t.Kind, Path: t.Path, Versions: versions})
	}
	return out, registerTenant(ctx, l, tenant, now)
}

// registerTenant records the tenant in system.db; an existing row is kept.
func registerTenant(ctx context.Context, l Layout, tenant string, now func() time.Time) error {
	db, err := Open(ctx, l.SystemDB())
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	err = systemdb.New(db.Write).EnsureTenant(ctx, systemdb.EnsureTenantParams{
		ID:        tenant,
		Name:      tenant,
		CreatedAt: now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("register tenant %q: %w", tenant, err)
	}
	return nil
}

// Tenants lists the tenants recorded in system.db without changing anything.
func Tenants(ctx context.Context, l Layout) ([]systemdb.ListTenantsRow, error) {
	db, err := OpenReadOnly(ctx, l.SystemDB())
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	return systemdb.New(db.Read).ListTenants(ctx)
}

func migrateFile(ctx context.Context, t target, now func() time.Time) ([]int, error) {
	set, err := Migrations(t.Kind)
	if err != nil {
		return nil, err
	}
	db, err := Open(ctx, t.Path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	if err = checkKind(ctx, db.Read, t); err != nil {
		return nil, err
	}
	if err = checkScope(ctx, db.Read, t); err != nil {
		return nil, err
	}
	versions, err := migrate.Apply(ctx, db.Write, set, now)
	if err != nil {
		return versions, fmt.Errorf("%s: %w", t.Path, err)
	}
	if err = checkKind(ctx, db.Read, t); err != nil {
		return versions, err
	}
	if t.Scope != "" {
		if err = auditdb.New(db.Write).SetScope(ctx, t.Scope); err != nil {
			return versions, fmt.Errorf("%s: set audit scope: %w", t.Path, err)
		}
	}
	return versions, checkScope(ctx, db.Read, t)
}

// ErrWrongScope means an audit log belongs to another scope than its place
// in the layout, e.g. a tenant's audit.db copied to <data>/audit.db.
var ErrWrongScope = errors.New("audit log has the wrong scope")

// checkScope compares db_info.audit_scope with the expected scope. A log
// whose scope isn't recorded yet (new file) passes.
func checkScope(ctx context.Context, q *sql.DB, t target) error {
	if t.Scope == "" {
		return nil
	}
	var exists int
	if err := q.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'db_info'`).Scan(&exists); err != nil {
		return fmt.Errorf("%s: %w", t.Path, err)
	}
	if exists == 0 {
		return nil
	}
	scope, err := auditdb.New(q).GetScope(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return fmt.Errorf("%s: read audit scope: %w", t.Path, err)
	case scope != t.Scope:
		return fmt.Errorf("%w: %s belongs to %q, expected %q", ErrWrongScope, t.Path, scope, t.Scope)
	}
	return nil
}

// checkKind compares db_info.db_type with the expected kind. A file without
// db_info is new (nothing to compare yet).
func checkKind(ctx context.Context, q *sql.DB, t target) error {
	var exists int
	if err := q.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'db_info'`).Scan(&exists); err != nil {
		return fmt.Errorf("%s: %w", t.Path, err)
	}
	if exists == 0 {
		return nil
	}
	var kind string
	err := q.QueryRowContext(ctx, `SELECT value FROM db_info WHERE key = 'db_type'`).Scan(&kind)
	if err != nil {
		return fmt.Errorf("%s: read db_type: %w", t.Path, err)
	}
	if Kind(kind) != t.Kind {
		return fmt.Errorf("%w: %s is a %q database, expected %q", ErrWrongKind, t.Path, kind, t.Kind)
	}
	return nil
}

// FileStatus is the state of one database file, for `myownpki db status`.
type FileStatus struct {
	Kind        Kind
	Path        string
	Exists      bool
	JournalMode string
	Report      migrate.Report // valid when Err is nil and the file exists
	Available   int            // migrations this binary has for the kind
	Err         error          // wrong kind, modified or newer migrations, unreadable file
}

// Status reports every database of the layout for tenant without creating
// or changing anything.
func Status(ctx context.Context, l Layout, tenant string) ([]FileStatus, error) {
	ts, err := l.targets(tenant)
	if err != nil {
		return nil, err
	}
	out := make([]FileStatus, 0, len(ts))
	for _, t := range ts {
		out = append(out, fileStatus(ctx, t))
	}
	return out, nil
}

func fileStatus(ctx context.Context, t target) FileStatus {
	st := FileStatus{Kind: t.Kind, Path: t.Path}
	set, err := Migrations(t.Kind)
	if err != nil {
		st.Err = err
		return st
	}
	st.Available = len(set)
	if _, statErr := os.Stat(t.Path); errors.Is(statErr, fs.ErrNotExist) {
		return st
	}
	st.Exists = true
	db, err := OpenReadOnly(ctx, t.Path)
	if err != nil {
		st.Err = err
		return st
	}
	defer func() { _ = db.Close() }()
	if st.JournalMode, err = db.JournalMode(ctx); err != nil {
		st.Err = err
		return st
	}
	if err := errors.Join(checkKind(ctx, db.Read, t), checkScope(ctx, db.Read, t)); err != nil {
		st.Err = err
		return st
	}
	st.Report, st.Err = migrate.Check(ctx, db.Read, set)
	return st
}

// OpenAuditLog opens an existing audit log read-only and checks that it is
// an audit database of the expected scope.
func OpenAuditLog(ctx context.Context, log AuditLog) (*DB, error) {
	db, err := OpenReadOnly(ctx, log.Path)
	if err != nil {
		return nil, err
	}
	t := target{Kind: KindAudit, Path: log.Path, Scope: log.Scope}
	if err := errors.Join(checkKind(ctx, db.Read, t), checkScope(ctx, db.Read, t)); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	return db, nil
}
