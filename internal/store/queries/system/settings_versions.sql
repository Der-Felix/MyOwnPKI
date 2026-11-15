-- name: InsertSettingsVersion :one
INSERT INTO settings_versions (kind, object_id, version, change, schema, snapshot_json, snapshot_sha256,
    actor_type, actor_id, actor_name, reason, restored_from, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: LatestSettingsVersion :one
SELECT * FROM settings_versions WHERE kind = ? AND object_id = ? ORDER BY version DESC LIMIT 1;

-- name: GetSettingsVersion :one
SELECT * FROM settings_versions WHERE kind = ? AND object_id = ? AND version = ?;

-- name: ListSettingsVersions :many
-- Newest first; before = 0 starts at the newest, otherwise below that number.
SELECT * FROM settings_versions
WHERE kind = sqlc.arg(kind) AND object_id = sqlc.arg(object_id)
  AND (CAST(sqlc.arg(before) AS INTEGER) = 0 OR version < CAST(sqlc.arg(before) AS INTEGER))
ORDER BY version DESC
LIMIT sqlc.arg(row_limit);

-- name: ListLatestSettingsVersions :many
-- The newest version of every object of a kind (a deleted object shows up here
-- with change = 'delete'), ordered by object.
SELECT v.* FROM settings_versions v
WHERE v.kind = ?
  AND v.version = (SELECT max(m.version) FROM settings_versions m WHERE m.kind = v.kind AND m.object_id = v.object_id)
ORDER BY v.object_id;
