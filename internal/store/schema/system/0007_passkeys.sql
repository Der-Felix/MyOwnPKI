-- system.db, migration 0007: passkeys (WebAuthn credentials, PHASE1 step 17).
--
-- A passkey is a second factor of one user. credential is the
-- go-webauthn credential as JSON (public key, flags, AAGUID, transports);
-- sign_count is kept apart so a cloned authenticator is noticed. Passkeys
-- can be removed (by the user, or by reset-2fa); the audit log keeps the
-- record.
CREATE TABLE webauthn_credentials (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users (id),
    credential_id BLOB NOT NULL UNIQUE CHECK (length(credential_id) BETWEEN 1 AND 1023),
    credential    TEXT NOT NULL CHECK (json_valid(credential)),
    name          TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    sign_count    INTEGER NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    created_at    TEXT NOT NULL,
    last_used_at  TEXT
) STRICT;

CREATE INDEX webauthn_credentials_user ON webauthn_credentials (user_id);
