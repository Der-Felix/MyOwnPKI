-- pki.db, migration 0009: the ACME server (PHASE2 steps 5-9).
--
-- Everything ACME lives in pki.db, so an order and the certificate it
-- produces are written in one transaction (ADR-06). Nonces and rate-limit
-- counters stay in memory.

-- An account is a key (RFC 8555 section 7.3). "approved" is our own: with the
-- approval level "account" an account may order only once an admin approved
-- it or it was bound with an EAB key.
CREATE TABLE acme_accounts (
    id             TEXT PRIMARY KEY,
    key_thumbprint TEXT NOT NULL UNIQUE,                  -- RFC 7638, SHA-256
    jwk            TEXT NOT NULL,                         -- the public key, canonical JSON
    status         TEXT NOT NULL CHECK (status IN ('valid', 'deactivated', 'revoked')),
    contact        TEXT NOT NULL CHECK (json_valid(contact)),
    eab_key_id     TEXT REFERENCES acme_eab_keys (id),
    approved_at    TEXT,
    approved_by    TEXT,
    created_at     TEXT NOT NULL,
    created_ip     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
) STRICT;

-- External account binding keys (RFC 8555 section 7.3.4), made in the UI and
-- shown once. The MAC key is encrypted by the key ring like every key
-- (purpose "acme-eab", bound to this row's ID) and overwritten when it is
-- used: one EAB key, one account. Verifying one needs an unsealed server.
CREATE TABLE acme_eab_keys (
    id               TEXT PRIMARY KEY,
    label            TEXT NOT NULL,
    root_key_version INTEGER NOT NULL,
    wrapped_dek      BLOB NOT NULL,
    mac_ciphertext   BLOB NOT NULL,
    expires_at  TEXT NOT NULL,
    used_at     TEXT,
    used_by     TEXT,                                     -- the account
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL
) STRICT;

CREATE TABLE acme_orders (
    id             TEXT PRIMARY KEY,
    account_id     TEXT NOT NULL REFERENCES acme_accounts (id),
    status         TEXT NOT NULL CHECK (status IN ('pending', 'ready', 'processing', 'valid', 'invalid')),
    identifiers    TEXT NOT NULL CHECK (json_valid(identifiers)),   -- [{"type":"dns","value":"..."}]
    expires_at     TEXT NOT NULL,
    csr_der        BLOB,                                  -- set by finalize; issued at once or at the unseal
    certificate_id TEXT REFERENCES certificates (id),
    error          TEXT CHECK (error IS NULL OR json_valid(error)),
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    CHECK ((status = 'valid') = (certificate_id IS NOT NULL))
) STRICT;

CREATE INDEX acme_orders_status ON acme_orders (status);
CREATE INDEX acme_orders_account ON acme_orders (account_id);

-- One authorization per identifier and account, reused while valid.
CREATE TABLE acme_authzs (
    id               TEXT PRIMARY KEY,
    account_id       TEXT NOT NULL REFERENCES acme_accounts (id),
    identifier_type  TEXT NOT NULL CHECK (identifier_type IN ('dns', 'ip')),
    identifier_value TEXT NOT NULL,
    wildcard         INTEGER NOT NULL CHECK (wildcard IN (0, 1)),
    status           TEXT NOT NULL CHECK (status IN ('pending', 'valid', 'invalid', 'deactivated', 'expired', 'revoked')),
    expires_at       TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
) STRICT;

CREATE INDEX acme_authzs_reuse ON acme_authzs (account_id, identifier_type, identifier_value, wildcard, status);

CREATE TABLE acme_order_authzs (
    order_id TEXT NOT NULL REFERENCES acme_orders (id),
    authz_id TEXT NOT NULL REFERENCES acme_authzs (id),
    PRIMARY KEY (order_id, authz_id)
) STRICT;

CREATE TABLE acme_challenges (
    id           TEXT PRIMARY KEY,
    authz_id     TEXT NOT NULL REFERENCES acme_authzs (id),
    type         TEXT NOT NULL CHECK (type IN ('http-01', 'dns-01')),
    token        TEXT NOT NULL UNIQUE,                    -- 128 random bits, base64url
    status       TEXT NOT NULL CHECK (status IN ('pending', 'processing', 'valid', 'invalid')),
    validated_at TEXT,
    error        TEXT CHECK (error IS NULL OR json_valid(error)),
    updated_at   TEXT NOT NULL
) STRICT;

CREATE INDEX acme_challenges_authz ON acme_challenges (authz_id);

-- Names under the approval level "new_name": a request waits until an admin
-- approves it; approved names are issued without asking again.
CREATE TABLE acme_names (
    name         TEXT PRIMARY KEY,                        -- "dns:nas.homelab.lan", "ip:192.0.2.10"
    status       TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'refused')),
    requested_by TEXT NOT NULL,                           -- the account that asked first
    requested_at TEXT NOT NULL,
    decided_by   TEXT,
    decided_at   TEXT
) STRICT;
