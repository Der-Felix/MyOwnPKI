-- system.db, migration 0012: tenant-configurable step-up lifetime.
-- Each session snapshots the setting with every new second-factor proof.
ALTER TABLE tenants ADD COLUMN step_up_minutes INTEGER NOT NULL DEFAULT 5
    CHECK (step_up_minutes IN (5, 10, 15, 30, 60));
ALTER TABLE sessions ADD COLUMN stepup_minutes INTEGER NOT NULL DEFAULT 5
    CHECK (stepup_minutes IN (5, 10, 15, 30, 60));
