-- system.db, migration 0008: API tokens and tenant subject defaults
-- (PHASE1 step 18).
--
-- An API token belongs to one user and carries a subset of the user's roles
-- (checked again at every request). Only the SHA-256 of the secret is
-- stored; the secret is shown once. Tokens expire and can be revoked
-- (deleted); the audit log keeps the record.
CREATE TABLE api_tokens (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users (id),
    name         TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    token_hash   TEXT NOT NULL UNIQUE CHECK (length(token_hash) = 64),
    roles_json   TEXT NOT NULL CHECK (json_valid(roles_json) AND json_type(roles_json) = 'array'),
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    last_used_at TEXT
) STRICT;

CREATE INDEX api_tokens_user ON api_tokens (user_id);

-- Subject defaults of a tenant: filled into requests that leave the field
-- empty (and whose CSR has none), like pki.conf of legacy/pki.sh.
ALTER TABLE tenants ADD COLUMN subject_o  TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN subject_ou TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN subject_l  TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN subject_st TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN subject_c  TEXT NOT NULL DEFAULT '' CHECK (subject_c = '' OR (length(subject_c) = 2 AND subject_c NOT GLOB '*[^A-Z]*'));
