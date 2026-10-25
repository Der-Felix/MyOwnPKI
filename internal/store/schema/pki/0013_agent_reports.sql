-- Correlate a deployment result with the exact desired-state request.
-- A heartbeat already in flight must not acknowledge a newer request.
ALTER TABLE agent_deployments ADD COLUMN renew_requested_version INTEGER
    CHECK (renew_requested_version IS NULL OR renew_requested_version > 0);

-- An unreported deployment with an open request stays visible until withdrawal.
ALTER TABLE agent_deployments ADD COLUMN reported INTEGER NOT NULL DEFAULT 1
    CHECK (reported IN (0, 1));
