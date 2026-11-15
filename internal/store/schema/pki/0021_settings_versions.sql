-- pki.db, migration 0021: the version history of settings (docs/PHASE3.md
-- section 16, step 61).
--
-- Every change to a domain appends one row with the full state after the
-- change (snapshot_json: a closed, typed structure, see internal/settingsver;
-- never a copy of a table row). Rows are never edited or removed, so a
-- version number always names the same state. A restore is a new row. The
-- first change to a domain that has no history first appends the state
-- before the change as version 1 with change = 'baseline'.
--
-- kind is not restricted to a list on purpose: a later kind needs no table rebuild (Go
-- allows only the kinds it knows). object_id is the domain ID. reason is
-- the admin's free text, so it lives only here, never in the audit log.
CREATE TABLE settings_versions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    kind            TEXT NOT NULL CHECK (length(kind) BETWEEN 1 AND 64),
    object_id       TEXT NOT NULL CHECK (length(object_id) BETWEEN 1 AND 128),
    version         INTEGER NOT NULL CHECK (version >= 1),
    change          TEXT NOT NULL CHECK (change IN ('create', 'update', 'delete', 'restore', 'baseline')),
    schema          INTEGER NOT NULL CHECK (schema >= 1),
    snapshot_json   TEXT NOT NULL CHECK (json_valid(snapshot_json) AND json_type(snapshot_json) = 'object'),
    snapshot_sha256 TEXT NOT NULL CHECK (length(snapshot_sha256) = 64),
    actor_type      TEXT NOT NULL CHECK (actor_type IN ('user', 'token', 'system', 'acme_account', 'agent')),
    actor_id        TEXT NOT NULL,
    actor_name      TEXT NOT NULL,
    reason          TEXT NOT NULL CHECK (length(reason) <= 200),
    restored_from   INTEGER CHECK (restored_from IS NULL OR restored_from >= 1),
    created_at      TEXT NOT NULL,
    UNIQUE (kind, object_id, version),
    CHECK ((change = 'restore') = (restored_from IS NOT NULL))
) STRICT;

-- Append-only, as audit_entries: the code has no UPDATE or DELETE for this
-- table, and these triggers stop a bug (or a careless script) from adding one.
CREATE TRIGGER settings_versions_no_update BEFORE UPDATE ON settings_versions
BEGIN
    SELECT RAISE(ABORT, 'settings history is append-only');
END;

CREATE TRIGGER settings_versions_no_delete BEFORE DELETE ON settings_versions
BEGIN
    SELECT RAISE(ABORT, 'settings history is append-only');
END;

-- INSERT OR REPLACE deletes the row it replaces without firing the DELETE
-- trigger (SQLite does that only with recursive_triggers on), so an insert
-- that would collide with an existing version or id is refused here, before
-- the conflict handling can remove anything. The UNIQUE constraint stays as
-- the second layer.
CREATE TRIGGER settings_versions_no_replace BEFORE INSERT ON settings_versions
WHEN EXISTS (SELECT 1 FROM settings_versions
             WHERE (kind = NEW.kind AND object_id = NEW.object_id AND version = NEW.version)
                OR (NEW.id IS NOT NULL AND id = NEW.id))
BEGIN
    SELECT RAISE(ABORT, 'settings history is append-only: that version exists');
END;
