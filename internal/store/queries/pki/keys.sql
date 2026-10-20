-- Private keys (ASCII only, see queries/system/tenants.sql).
-- Keys are never updated (a new key gets a new row) - only destroyed once.

-- name: InsertEnvelopeKey :exec
INSERT INTO keys (id, purpose, algorithm, storage, root_key_version, wrapped_dek, key_ciphertext, created_at)
VALUES (?, ?, ?, 'envelope', ?, ?, ?, ?);

-- name: GetKey :one
SELECT id, purpose, algorithm, storage, root_key_version, wrapped_dek, key_ciphertext, hsm_ref, created_at, destroyed_at
FROM keys
WHERE id = ?;

-- Destroys the key material; the trigger allows this once.
-- name: DestroyKey :execrows
UPDATE keys SET wrapped_dek = x'00', key_ciphertext = x'00', destroyed_at = ? WHERE id = ? AND destroyed_at IS NULL;

-- name: KeyDestroyedAt :one
SELECT destroyed_at FROM keys WHERE id = ?;
