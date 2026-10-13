-- audit.db, migration 0002: the hash-chained audit log (PLAN section 5).
--
-- Instance log (<data>/audit.db) and tenant logs (tenants/<t>/audit.db) share
-- this schema; db_info.audit_scope says which one a file is.
--
-- seq is assigned by the application (head + 1) inside the appending
-- transaction, so there are no gaps. hash = SHA-256 over prev_hash and every
-- column, see internal/audit. Empty strings mean "not applicable"; only
-- outbox_id is NULL for entries that were not delivered through an outbox.
CREATE TABLE audit_entries (
    seq          INTEGER PRIMARY KEY,
    outbox_id    TEXT UNIQUE,
    time         TEXT NOT NULL,
    actor_type   TEXT NOT NULL CHECK (actor_type IN ('user', 'token', 'system', 'acme_account', 'agent')),
    actor_id     TEXT NOT NULL,
    actor_name   TEXT NOT NULL,
    action       TEXT NOT NULL,
    target_type  TEXT NOT NULL,
    target_id    TEXT NOT NULL,
    result       TEXT NOT NULL CHECK (result IN ('success', 'failure', 'denied')),
    source_ip    TEXT NOT NULL,
    details_json TEXT NOT NULL,
    prev_hash    TEXT NOT NULL,
    hash         TEXT NOT NULL UNIQUE
) STRICT;

-- Append-only: the code has no UPDATE or DELETE for this table, and these
-- triggers stop a bug from adding one. Someone editing the file directly is
-- caught by the hash chain instead.
CREATE TRIGGER audit_entries_no_update BEFORE UPDATE ON audit_entries
BEGIN
    SELECT RAISE(ABORT, 'audit log is append-only');
END;

CREATE TRIGGER audit_entries_no_delete BEFORE DELETE ON audit_entries
BEGIN
    SELECT RAISE(ABORT, 'audit log is append-only');
END;
