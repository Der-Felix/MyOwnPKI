-- Audit log queries (ASCII only, see queries/system/tenants.sql).
-- There is deliberately no UPDATE or DELETE here.

-- name: GetHead :one
SELECT seq, hash, action FROM audit_entries ORDER BY seq DESC LIMIT 1;

-- name: GetLastCheckpointSeq :one
SELECT seq FROM audit_entries WHERE action = 'audit.checkpoint' ORDER BY seq DESC LIMIT 1;

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

-- One page of the log, newest first (step 18). before = 0 starts at the
-- newest entry; action is a prefix ('' = all), result exact ('' = all),
-- since/until bound the time ('' = open).
-- name: ListEntriesPage :many
SELECT seq, outbox_id, time, actor_type, actor_id, actor_name, action,
       target_type, target_id, result, source_ip, details_json, prev_hash, hash
FROM audit_entries
WHERE (CAST(sqlc.arg(before) AS INTEGER) = 0 OR seq < CAST(sqlc.arg(before) AS INTEGER))
  AND (CAST(sqlc.arg(action) AS TEXT) = '' OR substr(action, 1, length(CAST(sqlc.arg(action) AS TEXT))) = CAST(sqlc.arg(action) AS TEXT))
  AND (CAST(sqlc.arg(result) AS TEXT) = '' OR result = CAST(sqlc.arg(result) AS TEXT))
  AND (CAST(sqlc.arg(since) AS TEXT) = '' OR time >= CAST(sqlc.arg(since) AS TEXT))
  AND (CAST(sqlc.arg(until) AS TEXT) = '' OR time < CAST(sqlc.arg(until) AS TEXT))
ORDER BY seq DESC
LIMIT sqlc.arg(page_size);
