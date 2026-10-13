-- system.db, migration 0002: outbox for events that must reach another database
-- (PLAN section 4). A business change and its outbox row are written in the
-- same transaction; a worker delivers the row (topic "audit": to the audit
-- log) and sets delivered_at.
--
-- AUTOINCREMENT: ids are never reused, even after delivered rows are deleted.
-- The audit log deduplicates by "<source>:<id>", so a reused id would hide a
-- new event behind an old one.
CREATE TABLE outbox (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at   TEXT NOT NULL,
    topic        TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    delivered_at TEXT
) STRICT;

CREATE INDEX outbox_pending ON outbox (id) WHERE delivered_at IS NULL;
