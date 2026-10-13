-- Private keys (ASCII only, see queries/system/tenants.sql).
-- Keys are never updated; a new key gets a new row.

-- name: InsertEnvelopeKey :exec
INSERT INTO keys (id, purpose, algorithm, storage, root_key_version, wrapped_dek, key_ciphertext, created_at)
VALUES (?, ?, ?, 'envelope', ?, ?, ?, ?);

-- name: GetKey :one
SELECT id, purpose, algorithm, storage, root_key_version, wrapped_dek, key_ciphertext, hsm_ref, created_at
FROM keys
WHERE id = ?;
