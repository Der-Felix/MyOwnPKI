// Package migrate applies SQL schema migrations to one SQLite database
// (PLAN §4, decided instead of goose).
//
// Rules:
//   - Files are named NNNN_description.sql; versions start at 1 and have no gaps.
//   - Forward only: there are no down migrations. Going back means restoring a
//     backup (myownpki restore).
//   - Each migration runs in its own transaction together with its bookkeeping
//     row, so a crash leaves it either fully applied or not at all.
//   - The SHA-256 of every applied file is stored. A file that changed after it
//     was applied, or a database migrated by a newer binary, stops everything:
//     the schema history of a CA must not diverge silently.
package migrate

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrInvalidSet is returned for a malformed set of migration files.
	ErrInvalidSet = errors.New("invalid migration set")
	// ErrModified means an applied migration file has changed since.
	ErrModified = errors.New("applied migration was modified")
	// ErrNewer means the database has migrations this binary doesn't know.
	ErrNewer = errors.New("database was migrated by a newer version")
)

// Migration is one SQL file.
type Migration struct {
	Version  int
	Name     string // file name without the version and .sql
	SQL      string
	Checksum string // hex SHA-256 of the file with LF line endings
}

var fileName = regexp.MustCompile(`^([0-9]{4})_([a-z0-9_]+)\.sql$`)

// Load reads all *.sql files of fsys (its root directory), checks names and
// numbering and returns them in order. Other files are ignored.
func Load(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSet, err)
	}
	var out []Migration
	for _, e := range entries {
		if e.IsDir() || path.Ext(e.Name()) != ".sql" {
			continue
		}
		m := fileName.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("%w: %s: want NNNN_lower_case_name.sql", ErrInvalidSet, e.Name())
		}
		data, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidSet, err)
		}
		version, _ := strconv.Atoi(m[1])
		text := strings.ReplaceAll(string(data), "\r\n", "\n")
		sum := sha256.Sum256([]byte(text))
		out = append(out, Migration{Version: version, Name: m[2], SQL: text, Checksum: hex.EncodeToString(sum[:])})
	}
	slices.SortFunc(out, func(a, b Migration) int { return a.Version - b.Version })
	for i, m := range out {
		if m.Version != i+1 {
			return nil, fmt.Errorf("%w: expected version %04d, found %04d_%s.sql (versions start at 1, no gaps or duplicates)",
				ErrInvalidSet, i+1, m.Version, m.Name)
		}
		if strings.TrimSpace(m.SQL) == "" {
			return nil, fmt.Errorf("%w: %04d_%s.sql is empty", ErrInvalidSet, m.Version, m.Name)
		}
	}
	return out, nil
}

// Status describes one migration in a database.
type Status struct {
	Migration
	Applied   bool
	AppliedAt string // RFC 3339 UTC, empty when pending
}

// Report is the migration state of a database.
type Report struct {
	Migrations []Status
}

// Pending returns the number of migrations not applied yet.
func (r Report) Pending() int {
	n := 0
	for _, s := range r.Migrations {
		if !s.Applied {
			n++
		}
	}
	return n
}

// Version returns the highest applied version (0 = none).
func (r Report) Version() int {
	v := 0
	for _, s := range r.Migrations {
		if s.Applied {
			v = s.Version
		}
	}
	return v
}

// Querier is satisfied by *sql.DB and *sql.Tx.
type Querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

const table = "schema_migrations"

const createTable = `CREATE TABLE IF NOT EXISTS ` + table + ` (
	version    INTEGER PRIMARY KEY,
	name       TEXT NOT NULL,
	checksum   TEXT NOT NULL,
	applied_at TEXT NOT NULL
) STRICT`

type applied struct {
	name, checksum, at string
}

// Check compares the database with the migration set without changing
// anything. It returns ErrModified or ErrNewer when they don't fit together.
func Check(ctx context.Context, q Querier, set []Migration) (Report, error) {
	done, err := readApplied(ctx, q)
	if err != nil {
		return Report{}, err
	}
	var r Report
	for _, m := range set {
		a, ok := done[m.Version]
		if ok && a.checksum != m.Checksum {
			return r, fmt.Errorf("%w: %04d_%s.sql (stored SHA-256 %s…, file %s…)",
				ErrModified, m.Version, m.Name, a.checksum[:12], m.Checksum[:12])
		}
		r.Migrations = append(r.Migrations, Status{Migration: m, Applied: ok, AppliedAt: a.at})
		delete(done, m.Version)
	}
	if len(done) > 0 {
		versions := make([]int, 0, len(done))
		for v := range done {
			versions = append(versions, v)
		}
		slices.Sort(versions)
		return r, fmt.Errorf("%w: it has migration %04d_%s, this binary only knows up to %04d",
			ErrNewer, versions[0], done[versions[0]].name, len(set))
	}
	return r, nil
}

func readApplied(ctx context.Context, q Querier) (map[int]applied, error) {
	rows, err := q.QueryContext(ctx, `SELECT name FROM sqlite_schema WHERE type = 'table' AND name = ?`, table)
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	exists := rows.Next()
	if err = errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	done := map[int]applied{}
	if !exists {
		return done, nil
	}
	rows, err = q.QueryContext(ctx, `SELECT version, name, checksum, applied_at FROM `+table)
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			v int
			a applied
		)
		if err := rows.Scan(&v, &a.name, &a.checksum, &a.at); err != nil {
			return nil, fmt.Errorf("read migrations: %w", err)
		}
		done[v] = a
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	return done, nil
}

// Apply runs all pending migrations in order, each in its own transaction,
// and returns the versions it applied. now supplies applied_at (UTC). db must
// be the database's single writer connection.
func Apply(ctx context.Context, db *sql.DB, set []Migration, now func() time.Time) ([]int, error) {
	if _, err := db.ExecContext(ctx, createTable); err != nil {
		return nil, fmt.Errorf("create %s: %w", table, err)
	}
	report, err := Check(ctx, db, set)
	if err != nil {
		return nil, err
	}
	var done []int
	for _, s := range report.Migrations {
		if s.Applied {
			continue
		}
		if err := applyOne(ctx, db, s.Migration, now().UTC()); err != nil {
			return done, err
		}
		done = append(done, s.Version)
	}
	return done, nil
}

func applyOne(ctx context.Context, db *sql.DB, m Migration, at time.Time) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migration %04d_%s: %w", m.Version, m.Name, err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return fmt.Errorf("migration %04d_%s: %w", m.Version, m.Name, err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO `+table+` (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)`,
		m.Version, m.Name, m.Checksum, at.Format(time.RFC3339)); err != nil {
		return fmt.Errorf("migration %04d_%s: record: %w", m.Version, m.Name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migration %04d_%s: commit: %w", m.Version, m.Name, err)
	}
	return nil
}
