-- system.db, migration 0003: the wrapped root key (PLAN section 5, Keys).
--
-- One row per way to unlock the root key: "passphrase" (KEK from Argon2id)
-- and "recovery" (key from HKDF over the recovery key). Each row holds the
-- same root key, encrypted with AES-256-GCM; a successful decryption proves
-- the secret, so there is no separate verifier. No secret is stored here.
CREATE TABLE unseal (
    slot             TEXT PRIMARY KEY CHECK (slot IN ('passphrase', 'recovery')),
    root_key_version INTEGER NOT NULL CHECK (root_key_version >= 1),
    kdf              TEXT NOT NULL CHECK (kdf IN ('argon2id', 'hkdf-sha256')),
    kdf_params       TEXT NOT NULL,
    salt             BLOB NOT NULL,
    wrapped_root_key BLOB NOT NULL,
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
) STRICT;
