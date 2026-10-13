-- Audit log queries (ASCII only, see queries/system/tenants.sql).
-- There is deliberately no UPDATE or DELETE here.

-- name: GetHead :one
SELECT seq, hash FROM audit_entries ORDER BY seq DESC LIMIT 1;

-- name: CountOutboxID :one
SELECT count(*) FROM audit_entries WHERE outbox_id = ?;

-- name: InsertEntry :exec
INSERT INTO audit_entries (
    seq, outbox_id, time, actor_type, actor_id, actor_name, action,
    target_type, target_id, result, source_ip, details_json, prev_hash, hash
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListEntriesFrom :many
SELECT seq, outbox_id, time, actor_type, actor_id, actor_name, action,
       target_type, target_id, result, source_ip, details_json, prev_hash, hash
FROM audit_entries
WHERE seq >= ?
ORDER BY seq
LIMIT ?;

-- name: GetEntry :one
SELECT seq, hash FROM audit_entries WHERE seq = ?;

-- name: GetScope :one
SELECT value FROM db_info WHERE key = 'audit_scope';

-- name: SetScope :exec
INSERT INTO db_info (key, value) VALUES ('audit_scope', ?)
ON CONFLICT (key) DO NOTHING;
