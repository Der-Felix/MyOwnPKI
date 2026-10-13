// Package store opens the SQLite databases (ADR-06), keeps their schemas
// migrated and knows where each file lives in the data directory (PLAN §4).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	_ "modernc.org/sqlite" // registers the "sqlite" driver (pure Go)
)

// commonPragmas apply to every connection (go-conventions.md "SQLite"):
// busy_timeout – wait up to 5 s for a lock instead of failing with SQLITE_BUSY;
// foreign_keys – SQLite leaves them off unless asked;
// synchronous=NORMAL – safe with WAL: a power cut can lose the last commits,
// never corrupt the file.
const commonPragmas = "_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"

// DB is one SQLite file with a single writer connection and a read pool.
//
// SQLite allows one writer at a time. Routing every write through one
// connection serializes them inside the process instead of letting them
// collide on the file lock; WAL mode lets readers continue meanwhile.
type DB struct {
	Path  string
	Write *sql.DB // exactly one connection; transactions start IMMEDIATE
	Read  *sql.DB // read-only connections (PRAGMA query_only)
}

// Open opens (and creates, if missing) the database at path. The caller
// decides whether a missing file is acceptable – see OpenExisting.
func Open(ctx context.Context, path string) (*DB, error) {
	if strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("open %s: path must not contain '?' or '#'", path)
	}
	// The writer sets WAL first; journal_mode is stored in the file.
	write, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&"+commonPragmas+"&_txlock=immediate")
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	write.SetMaxOpenConns(1)
	write.SetMaxIdleConns(1)
	write.SetConnMaxLifetime(0)
	if err = write.PingContext(ctx); err != nil {
		_ = write.Close()
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	read, err := openRead(ctx, path)
	if err != nil {
		return nil, errors.Join(err, write.Close())
	}
	return &DB{Path: path, Write: write, Read: read}, nil
}

// OpenReadOnly opens an existing database for reading only: it creates no
// file and has no writer (Write is nil). Used by `myownpki db status`.
func OpenReadOnly(ctx context.Context, path string) (*DB, error) {
	if strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("open %s: path must not contain '?' or '#'", path)
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	read, err := openRead(ctx, path)
	if err != nil {
		return nil, err
	}
	return &DB{Path: path, Read: read}, nil
}

func openRead(ctx context.Context, path string) (*sql.DB, error) {
	read, err := sql.Open("sqlite", path+"?"+commonPragmas+"&_pragma=query_only(1)")
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	read.SetMaxOpenConns(max(4, runtime.NumCPU()))
	if err := read.PingContext(ctx); err != nil {
		return nil, errors.Join(fmt.Errorf("open %s: %w", path, err), read.Close())
	}
	return read, nil
}

// Close closes both handles.
func (d *DB) Close() error {
	var errs []error
	if d.Write != nil {
		errs = append(errs, d.Write.Close())
	}
	return errors.Join(append(errs, d.Read.Close())...)
}

// JournalMode returns the journal mode of the file ("wal" when open via Open).
func (d *DB) JournalMode(ctx context.Context) (string, error) {
	var mode string
	if err := d.Read.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return "", fmt.Errorf("journal mode of %s: %w", d.Path, err)
	}
	return mode, nil
}
