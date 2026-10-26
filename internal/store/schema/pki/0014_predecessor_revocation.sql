-- Mutable predecessor handling lives outside the immutable certificates table.
CREATE TABLE certificate_revocation_plans (
    certificate_id TEXT PRIMARY KEY REFERENCES certificates (id),
    successor_id   TEXT REFERENCES certificates (id),
    planned_at     TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    created_by     TEXT NOT NULL,
    source         TEXT NOT NULL CHECK (source IN ('explicit', 'renewal', 'acme', 'agent'))
) STRICT;

CREATE INDEX certificate_revocation_plans_due ON certificate_revocation_plans (planned_at, certificate_id);
CREATE INDEX certificate_revocation_plans_successor ON certificate_revocation_plans (successor_id, certificate_id);

ALTER TABLE agents ADD COLUMN predecessor_choice TEXT
    CHECK (predecessor_choice IS NULL OR predecessor_choice IN ('now', 'after', 'never'));
ALTER TABLE agents ADD COLUMN predecessor_days INTEGER
    CHECK (predecessor_days IS NULL OR predecessor_days BETWEEN 1 AND 30);

ALTER TABLE agent_deployments ADD COLUMN predecessor_choice TEXT
    CHECK (predecessor_choice IS NULL OR predecessor_choice IN ('now', 'after', 'never'));
ALTER TABLE agent_deployments ADD COLUMN predecessor_days INTEGER
    CHECK (predecessor_days IS NULL OR predecessor_days BETWEEN 1 AND 30);
ALTER TABLE agent_deployments ADD COLUMN renew_predecessor_choice TEXT
    CHECK (renew_predecessor_choice IS NULL OR renew_predecessor_choice IN ('now', 'after', 'never'));
ALTER TABLE agent_deployments ADD COLUMN renew_predecessor_days INTEGER
    CHECK (renew_predecessor_days IS NULL OR renew_predecessor_days BETWEEN 1 AND 30);

-- Server-recorded accepted deployment history; agent timestamps are not used.
CREATE TABLE agent_deployment_certificates (
    agent_id          TEXT NOT NULL REFERENCES agents (id),
    deployment        TEXT NOT NULL,
    certificate_id    TEXT NOT NULL REFERENCES certificates (id),
    first_deployed_at TEXT NOT NULL,
    last_deployed_at  TEXT NOT NULL,
    PRIMARY KEY (agent_id, deployment, certificate_id)
) STRICT;

CREATE INDEX agent_deployment_certificates_cert ON agent_deployment_certificates (certificate_id, agent_id, deployment);
