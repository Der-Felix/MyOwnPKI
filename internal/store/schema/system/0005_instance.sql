-- system.db, migration 0005: the instance itself (PHASE1 step 11).
--
-- One row, written when myownpki init finishes. demo = 1 marks an instance
-- made by init --demo: all its secrets were written to one file, so it is for
-- trying out only. The mark can't be removed (triggers) - for production,
-- set up a new instance.
CREATE TABLE instance (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    demo           INTEGER NOT NULL CHECK (demo IN (0, 1)),
    initialized_at TEXT NOT NULL
) STRICT;

CREATE TRIGGER instance_no_update BEFORE UPDATE ON instance
BEGIN
    SELECT RAISE(ABORT, 'the instance row never changes - a demo instance stays a demo instance');
END;

CREATE TRIGGER instance_no_delete BEFORE DELETE ON instance
BEGIN
    SELECT RAISE(ABORT, 'the instance row is never deleted');
END;
