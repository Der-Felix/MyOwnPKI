-- pki.db, migration 0003: private keys (PLAN section 4 and 5).
--
-- storage = envelope: the key (PKCS#8) is encrypted with its own DEK, the DEK
-- with the root key (AES-256-GCM). storage = hsm: only a PKCS#11 reference,
-- no key material (hsm build, later).
CREATE TABLE keys (
    id               TEXT PRIMARY KEY,
    purpose          TEXT NOT NULL CHECK (purpose IN ('ca', 'leaf')),
    algorithm        TEXT NOT NULL,
    storage          TEXT NOT NULL CHECK (storage IN ('envelope', 'hsm')),
    root_key_version INTEGER,
    wrapped_dek      BLOB,
    key_ciphertext   BLOB,
    hsm_ref          TEXT,
    created_at       TEXT NOT NULL,
    CHECK (
        (storage = 'envelope' AND root_key_version IS NOT NULL AND wrapped_dek IS NOT NULL
            AND key_ciphertext IS NOT NULL AND hsm_ref IS NULL)
        OR
        (storage = 'hsm' AND hsm_ref IS NOT NULL AND root_key_version IS NULL
            AND wrapped_dek IS NULL AND key_ciphertext IS NULL)
    )
) STRICT;
