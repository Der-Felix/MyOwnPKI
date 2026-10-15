-- system.db, migration 0004: users, roles and sessions (PHASE1 step 10,
-- security.md "Authentication" and "Authorization").
--
-- Users are instance-wide; what they may do in a tenant comes from
-- role_bindings. No secret is stored in the clear: passwords as Argon2id
-- hashes, TOTP secrets encrypted with the auth key (auth.key_file), recovery
-- codes as HMAC with a key derived from it, sessions as SHA-256 of the
-- cookie value.

CREATE TABLE users (
    id                  TEXT PRIMARY KEY,
    -- Lower case only; anything else is refused, never converted.
    username            TEXT NOT NULL UNIQUE CHECK (length(username) BETWEEN 1 AND 64
                                                    AND username GLOB '[a-z0-9]*'
                                                    AND username NOT GLOB '*[^a-z0-9._@-]*'),
    password_hash       TEXT NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
    password_changed_at TEXT NOT NULL,
    -- Set when the user is created: there is no account without a second
    -- factor. Confirmed by the first valid code (at init or first login).
    totp_secret         BLOB NOT NULL,
    totp_confirmed_at   TEXT,
    -- The last TOTP time step used: a code is valid only once.
    totp_last_step      INTEGER NOT NULL DEFAULT 0,
    -- A new secret while the user changes the authenticator, until confirmed.
    totp_pending        BLOB,
    instance_admin      INTEGER NOT NULL DEFAULT 0 CHECK (instance_admin IN (0, 1)),
    disabled_at         TEXT,
    -- Consecutive failures (password, TOTP, recovery code); at the limit the
    -- account is locked for a while and the counter starts again.
    failed_logins       INTEGER NOT NULL DEFAULT 0 CHECK (failed_logins >= 0),
    locked_until        TEXT,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
) STRICT;

-- User ids are in audit entries: a user is disabled, never deleted.
CREATE TRIGGER users_no_delete BEFORE DELETE ON users
BEGIN
    SELECT RAISE(ABORT, 'users are disabled, never deleted');
END;

CREATE TABLE recovery_codes (
    user_id    TEXT NOT NULL REFERENCES users (id),
    code_hash  TEXT NOT NULL,
    used_at    TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, code_hash)
) STRICT;

-- One role per user, tenant and scope. ca = '' covers the whole tenant;
-- otherwise the name of one CA (CA names never change).
CREATE TABLE role_bindings (
    user_id    TEXT NOT NULL REFERENCES users (id),
    tenant_id  TEXT NOT NULL REFERENCES tenants (id),
    ca         TEXT NOT NULL DEFAULT '',
    role       TEXT NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    PRIMARY KEY (user_id, tenant_id, ca)
) STRICT;

-- id_hash is the SHA-256 of the cookie value: a copy of this table holds no
-- usable session. No IP address here - it is in the audit entry only.
CREATE TABLE sessions (
    id_hash      TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users (id),
    -- password: only the second factor may follow; full: signed in.
    state        TEXT NOT NULL CHECK (state IN ('password', 'full')),
    csrf_token   TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    expires_at   TEXT NOT NULL, -- absolute end
    stepup_at    TEXT           -- last fresh second factor
) STRICT;

CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expires ON sessions (expires_at);
