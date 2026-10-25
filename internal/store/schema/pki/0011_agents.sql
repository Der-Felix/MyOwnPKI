-- pki.db, migration 0011: the agents (docs/PHASE3.md section 1.1, v0.3.0).
--
-- Everything an agent sends is attacker input: it is stored as data with
-- length limits checked by internal/agents, never used as a path or a
-- command on the server.

-- An admitted agent. Enrollments that are still waiting live in
-- agent_enrollments; only an admitted one becomes an agent, so junk from
-- the unauthenticated Enroll call never creates one.
CREATE TABLE agents (
    id                  TEXT PRIMARY KEY,
    hostname            TEXT NOT NULL,                     -- the FQDN proven at enrollment
    status              TEXT NOT NULL CHECK (status IN ('active', 'disabled', 'revoked')),
    enrollment_mode     TEXT NOT NULL CHECK (enrollment_mode IN ('auto', 'verified', 'manual')),
    proof               TEXT NOT NULL CHECK (json_valid(proof)),  -- what admitted it the last time
    cert_id             TEXT REFERENCES certificates (id), -- its current agent certificate; NULL until issued
    cert_serial         TEXT,
    prev_cert_id        TEXT REFERENCES certificates (id), -- the one before, accepted until it expires
    prev_cert_serial    TEXT,
    acme_key_thumbprint TEXT,                              -- RFC 7638, its ACME account key (step 4)
    os                  TEXT NOT NULL,
    arch                TEXT NOT NULL,
    agent_version       TEXT NOT NULL,
    desired_version     INTEGER NOT NULL DEFAULT 1,        -- +1 on every change of its desired state (step 8a)
    last_seen_at        TEXT,
    created_at          TEXT NOT NULL,
    approved_at         TEXT NOT NULL,
    approved_by         TEXT NOT NULL,                     -- a user, or "auto" / "verified" for the modes
    updated_at          TEXT NOT NULL,
    CHECK ((cert_id IS NULL) = (cert_serial IS NULL)),
    CHECK ((prev_cert_id IS NULL) = (prev_cert_serial IS NULL))
) STRICT;

CREATE INDEX agents_hostname ON agents (hostname);
CREATE UNIQUE INDEX agents_cert_serial ON agents (cert_serial) WHERE cert_serial IS NOT NULL;

-- Join tokens: single-use, short-lived, scoped to name patterns, stored as
-- SHA-256 of the token (it has 256 bits of entropy, so no slow hash).
CREATE TABLE join_tokens (
    id            TEXT PRIMARY KEY,
    token_hash    TEXT NOT NULL UNIQUE,
    label         TEXT NOT NULL,
    name_patterns TEXT NOT NULL CHECK (json_valid(name_patterns)), -- ["proxy1.homelab.lan", "*.homelab.lan"]
    expires_at    TEXT NOT NULL,
    used_at       TEXT,
    used_by       TEXT,                                    -- the enrollment
    created_by    TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    CHECK ((used_at IS NULL) = (used_by IS NULL))
) STRICT;

-- One enrollment attempt (ADR-18) until it is decided or expires.
-- agent_id is set for an admitted one and for a known agent that enrolls
-- again with the key of its last certificate.
CREATE TABLE agent_enrollments (
    id            TEXT PRIMARY KEY,
    agent_id      TEXT REFERENCES agents (id),
    hostname      TEXT NOT NULL,
    csr_der       BLOB NOT NULL,
    spki_sha256   TEXT NOT NULL,                           -- of the CSR's public key: binds the check to the key
    handle_hash   TEXT NOT NULL,                           -- the agent polls with the handle
    check_token   TEXT NOT NULL,
    check_method  TEXT NOT NULL CHECK (check_method IN ('standalone', 'webroot')),
    check_state   TEXT NOT NULL CHECK (check_state IN ('waiting', 'passed', 'failed')),
    check_error   TEXT,
    checked_at    TEXT,
    token_id      TEXT REFERENCES join_tokens (id),
    token_valid   INTEGER NOT NULL CHECK (token_valid IN (0, 1)),
    token_problem TEXT,                                    -- why a given token didn't count
    known_agent   INTEGER NOT NULL CHECK (known_agent IN (0, 1)),
    state         TEXT NOT NULL CHECK (state IN ('waiting_for_check', 'pending_approval', 'admitted', 'denied', 'expired')),
    os            TEXT NOT NULL,
    arch          TEXT NOT NULL,
    agent_version TEXT NOT NULL,
    source_ip     TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    decided_at    TEXT,
    decided_by    TEXT,
    cert_id       TEXT REFERENCES certificates (id)        -- the agent certificate issued for this CSR
) STRICT;

CREATE INDEX agent_enrollments_state ON agent_enrollments (state, expires_at);

-- The names an agent may order (security.md "Agent trust"): exact names
-- or *.suffix patterns.
CREATE TABLE agent_names (
    agent_id TEXT NOT NULL REFERENCES agents (id),
    pattern  TEXT NOT NULL,
    source   TEXT NOT NULL CHECK (source IN ('hostname', 'token', 'admin')),
    added_by TEXT NOT NULL,
    added_at TEXT NOT NULL,
    PRIMARY KEY (agent_id, pattern)
) STRICT;

-- What an agent reports from its agent.yaml (steps 5-8), plus the
-- "Renew now" request (step 8a). Display data only, never a path the
-- server uses.
CREATE TABLE agent_deployments (
    agent_id           TEXT NOT NULL REFERENCES agents (id),
    name               TEXT NOT NULL,
    profile            TEXT NOT NULL,
    names              TEXT NOT NULL CHECK (json_valid(names)),
    challenge          TEXT NOT NULL,
    state              TEXT NOT NULL CHECK (state IN ('pending', 'deployed', 'failed', 'rolled_back')),
    certificate_serial TEXT,
    not_after          TEXT,
    served_fingerprint TEXT,
    deployed_at        TEXT,
    last_error         TEXT,
    last_report_at     TEXT NOT NULL,
    renew_requested_at TEXT,
    renew_requested_by TEXT,
    PRIMARY KEY (agent_id, name),
    CHECK ((renew_requested_at IS NULL) = (renew_requested_by IS NULL))
) STRICT;

-- The ACME account an agent registered over its channel (step 4).
ALTER TABLE acme_accounts ADD COLUMN agent_id TEXT REFERENCES agents (id);
