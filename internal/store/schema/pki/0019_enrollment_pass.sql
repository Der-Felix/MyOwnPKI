-- pki.db, migration 0019: the enrollment pass (docs/PHASE3.md section 11.2,
-- v0.3.5).
--
-- A pass is a kind of join token: the same table, the same hash lookup and
-- the same Enroll field. It admits up to max_uses hosts (2 to 25; a plain
-- token has exactly one) whose names match its patterns, until it expires
-- or is revoked. Additive: existing rows become kind 'token' with
-- max_uses 1.
--
-- used_at and used_by keep their meaning for a single-use token and are set
-- when the LAST use is taken, so the existing CHECK and every reader of a
-- single-use token keep working. The limits of a pass (2 to 25 uses, 5
-- minutes to 7 days) are enforced in internal/agents, not here: the column
-- only has to hold what the service writes.

ALTER TABLE join_tokens ADD COLUMN kind TEXT NOT NULL DEFAULT 'token' CHECK (kind IN ('token', 'pass'));
ALTER TABLE join_tokens ADD COLUMN max_uses INTEGER NOT NULL DEFAULT 1 CHECK (max_uses BETWEEN 1 AND 25);
ALTER TABLE join_tokens ADD COLUMN use_count INTEGER NOT NULL DEFAULT 0 CHECK (use_count >= 0);
ALTER TABLE join_tokens ADD COLUMN revoked_at TEXT;
ALTER TABLE join_tokens ADD COLUMN revoked_by TEXT;

UPDATE join_tokens SET use_count = 1 WHERE used_at IS NOT NULL;
