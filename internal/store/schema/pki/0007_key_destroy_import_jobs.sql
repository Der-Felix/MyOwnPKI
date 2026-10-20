-- pki.db, migration 0007: destroyed keys and import jobs (PHASE1 step 18).
--
-- A server-generated key can be destroyed after its download ("delete the
-- key from the server"). The row stays - certificates refer to it and are
-- immutable - but the wrapped DEK and the ciphertext are overwritten with
-- one zero byte each (the CHECK of migration 0003 needs non-NULL values).
ALTER TABLE keys ADD COLUMN destroyed_at TEXT;

CREATE TRIGGER keys_destroy_only BEFORE UPDATE ON keys
WHEN OLD.destroyed_at IS NOT NULL
    OR NEW.destroyed_at IS NULL
    OR NEW.wrapped_dek <> x'00' OR NEW.key_ciphertext <> x'00'
    OR NEW.id IS NOT OLD.id OR NEW.purpose IS NOT OLD.purpose OR NEW.algorithm IS NOT OLD.algorithm
BEGIN
    SELECT RAISE(ABORT, 'a key is never changed - it can only be destroyed, once');
END;

CREATE TRIGGER keys_no_delete BEFORE DELETE ON keys
BEGIN
    SELECT RAISE(ABORT, 'keys are destroyed, not deleted');
END;

-- Import jobs (legacy pki.sh archive over the API). The report is JSON; a
-- job is written once when it ends.
CREATE TABLE import_jobs (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL CHECK (kind IN ('legacy')),
    status      TEXT NOT NULL CHECK (status IN ('succeeded', 'failed', 'checked')),
    dry_run     INTEGER NOT NULL CHECK (dry_run IN (0, 1)),
    started_at  TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    started_by  TEXT NOT NULL,
    report_json TEXT NOT NULL CHECK (json_valid(report_json))
) STRICT;

CREATE TRIGGER import_jobs_immutable BEFORE UPDATE ON import_jobs
BEGIN
    SELECT RAISE(ABORT, 'an import job is recorded once');
END;
