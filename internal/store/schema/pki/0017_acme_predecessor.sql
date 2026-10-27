-- Optional per-account predecessor override for ACME without an agent.
ALTER TABLE acme_accounts ADD COLUMN predecessor_choice TEXT
    CHECK (predecessor_choice IS NULL OR predecessor_choice IN ('now', 'after', 'never'));
ALTER TABLE acme_accounts ADD COLUMN predecessor_days INTEGER
    CHECK (predecessor_days IS NULL OR predecessor_days BETWEEN 1 AND 30);
