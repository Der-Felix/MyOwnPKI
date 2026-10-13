package store

import (
	"fmt"
	"path/filepath"
	"regexp"
)

// Kind is a database type. Each kind has its own migration set (schema/<kind>).
type Kind string

// Database kinds of phase 1 (PLAN §4; acme and metrics follow later).
const (
	KindSystem Kind = "system" // <data>/system.db
	KindPKI    Kind = "pki"    // <data>/tenants/<tenant>/pki.db
	KindAudit  Kind = "audit"  // <data>/tenants/<tenant>/audit.db
)

// Kinds lists every database type; each has a migration set in schema/<kind>.
// A new type (acme in phase 2, metrics in phase 4) needs: a constant here,
// an entry in Kinds (and TenantKinds for per-tenant files), schema/<kind>/0001_init.sql
// and, once it has queries, a block in sqlc.yaml. The runner itself needs no change.
var Kinds = []Kind{KindSystem, KindPKI, KindAudit}

// TenantKinds are the databases every tenant directory holds.
var TenantKinds = []Kind{KindPKI, KindAudit}

// DefaultTenant is the only tenant of phase 1; every path is tenant-aware
// already, so more tenants (phase 5) need no migration of the layout.
const DefaultTenant = "default"

// tenantID is also a directory name: no dots, slashes or upper case, so it
// can never escape the tenants directory or collide on case-insensitive
// file systems.
var tenantID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Layout maps database kinds to files below the data directory.
type Layout struct {
	DataDir string // absolute, validated by internal/config
}

// SystemDB returns <data>/system.db.
func (l Layout) SystemDB() string {
	return filepath.Join(l.DataDir, "system.db")
}

// InstanceAuditDB returns <data>/audit.db: the audit log of instance events
// (logins, users, unseal). Tenant events go to the tenant's own audit.db.
func (l Layout) InstanceAuditDB() string {
	return filepath.Join(l.DataDir, "audit.db")
}

// InstanceScope is the audit scope of <data>/audit.db.
const InstanceScope = "instance"

// TenantScope is the audit scope of tenants/<tenant>/audit.db.
func TenantScope(tenant string) string { return "tenant:" + tenant }

// AuditLog is one audit database and its scope; the scope is part of the
// chain's starting value, so a log can't be moved to another scope.
type AuditLog struct {
	Scope string
	Path  string
}

// AuditLogs returns the instance log and the log of tenant.
func (l Layout) AuditLogs(tenant string) ([]AuditLog, error) {
	p, err := l.TenantDB(tenant, KindAudit)
	if err != nil {
		return nil, err
	}
	return []AuditLog{{InstanceScope, l.InstanceAuditDB()}, {TenantScope(tenant), p}}, nil
}

// TenantDir returns <data>/tenants/<tenant>.
func (l Layout) TenantDir(tenant string) (string, error) {
	if !tenantID.MatchString(tenant) {
		return "", fmt.Errorf("invalid tenant id %q: want a-z, 0-9 and '-', starting with a letter or digit, at most 63 characters", tenant)
	}
	return filepath.Join(l.DataDir, "tenants", tenant), nil
}

// TenantDB returns the file of a tenant database kind.
func (l Layout) TenantDB(tenant string, kind Kind) (string, error) {
	if kind == KindSystem {
		return "", fmt.Errorf("%s is not a tenant database", kind)
	}
	dir, err := l.TenantDir(tenant)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, string(kind)+".db"), nil
}
