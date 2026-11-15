// Package settingsver is the version history of settings (docs/PHASE3.md
// section 16, step 61).
//
// Every change to a setting that an admin can regret (a domain, the tenant
// settings) appends one row to the append-only table settings_versions of the
// database that owns the setting: who, when, an optional reason, and the full
// state after the change as a typed snapshot. This package holds
//
//   - the closed snapshot types (DomainSnapshot, TenantSnapshot): explicit
//     structs, never maps and never copies of table rows, so a secret cannot
//     enter a snapshot by accident (the guard tests fail until a new field or
//     column is classified);
//   - Diff, a pure function that compares two snapshots field by field;
//   - Append, which numbers a version, writes the baseline of an object that
//     had no history, and checks the optimistic-concurrency number, all inside
//     the caller's transaction (one transaction = one database, ADR-06);
//   - Get, List and DiffVersions for the history and restore API.
//
// The package imports neither ca nor tenant: the writers convert their models
// into snapshots, and restore converts a snapshot back and runs the normal
// writer, so a restore can never do what a normal change would refuse.
package settingsver
