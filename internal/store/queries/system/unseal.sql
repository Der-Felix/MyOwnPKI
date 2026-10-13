-- Unseal slots (ASCII only, see tenants.sql).

-- name: GetUnsealSlot :one
SELECT slot, root_key_version, kdf, kdf_params, salt, wrapped_root_key, created_at, updated_at
FROM unseal
WHERE slot = ?;

-- name: CountUnsealSlots :one
SELECT count(*) FROM unseal;

-- name: InsertUnsealSlot :exec
INSERT INTO unseal (slot, root_key_version, kdf, kdf_params, salt, wrapped_root_key, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateUnsealSlot :execrows
UPDATE unseal
SET kdf = ?, kdf_params = ?, salt = ?, wrapped_root_key = ?, updated_at = ?
WHERE slot = ? AND root_key_version = ?;
