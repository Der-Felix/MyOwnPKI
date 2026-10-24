-- One ACME account key and account per agent (docs/PHASE3.md section 6.3).
CREATE UNIQUE INDEX agents_acme_thumbprint ON agents (acme_key_thumbprint)
WHERE acme_key_thumbprint IS NOT NULL;
CREATE UNIQUE INDEX acme_accounts_agent ON acme_accounts (agent_id)
WHERE agent_id IS NOT NULL;
