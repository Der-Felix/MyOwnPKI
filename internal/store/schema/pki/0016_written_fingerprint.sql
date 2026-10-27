-- Additive proof read back after an atomic write; never a TLS-check substitute.
ALTER TABLE agent_deployments ADD COLUMN written_fingerprint TEXT;
ALTER TABLE agent_deployments ADD COLUMN check_configured INTEGER NOT NULL DEFAULT 0
    CHECK (check_configured IN (0, 1));
