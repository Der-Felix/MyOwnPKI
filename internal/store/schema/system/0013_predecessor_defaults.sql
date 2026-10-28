-- Independent tenant defaults for confirmed agent deployments and other renewals.
ALTER TABLE tenants ADD COLUMN agent_predecessor_choice TEXT NOT NULL DEFAULT 'now'
    CHECK (agent_predecessor_choice IN ('now', 'after', 'never'));
ALTER TABLE tenants ADD COLUMN agent_predecessor_days INTEGER NOT NULL DEFAULT 7
    CHECK (agent_predecessor_days BETWEEN 1 AND 30);
ALTER TABLE tenants ADD COLUMN other_predecessor_choice TEXT NOT NULL DEFAULT 'after'
    CHECK (other_predecessor_choice IN ('now', 'after', 'never'));
ALTER TABLE tenants ADD COLUMN other_predecessor_days INTEGER NOT NULL DEFAULT 7
    CHECK (other_predecessor_days BETWEEN 1 AND 30);
