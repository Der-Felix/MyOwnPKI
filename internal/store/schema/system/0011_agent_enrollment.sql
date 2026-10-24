-- system.db, migration 0011: how a tenant admits agents (v0.3.0, ADR-18,
-- docs/PHASE3.md section 6.1).
--
-- auto: a valid join token or a passed check admits; verified (default):
-- both are needed, one alone waits for an admin; manual: an admin decides
-- every enrollment.
ALTER TABLE tenants ADD COLUMN agent_enrollment TEXT NOT NULL DEFAULT 'verified'
    CHECK (agent_enrollment IN ('auto', 'verified', 'manual'));
