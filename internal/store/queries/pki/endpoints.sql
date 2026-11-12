-- TLS scan endpoints (ASCII only, see queries/system/tenants.sql). What the
-- remote end sent is stored clipped by internal/tlsscan before it gets here.

-- name: CountEndpoints :one
SELECT count(*) FROM endpoints;

-- name: InsertEndpoint :exec
INSERT INTO endpoints (id, host, port, sni, source, created_at, created_by, next_scan_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListEndpoints :many
SELECT * FROM endpoints ORDER BY host, port, coalesce(sni, '');

-- name: GetEndpoint :one
SELECT * FROM endpoints WHERE id = ?;

-- name: DeleteEndpoint :execrows
DELETE FROM endpoints WHERE id = ?;

-- name: ListDueEndpoints :many
SELECT * FROM endpoints WHERE next_scan_at <= ? ORDER BY next_scan_at, id LIMIT ?;

-- A scan is claimed by moving its next time forward; a crash cannot rescan
-- at once. The WHERE makes a concurrent claim lose.
-- name: ClaimEndpoint :execrows
UPDATE endpoints SET next_scan_at = ? WHERE id = ? AND next_scan_at = ?;

-- Scan now: due at once, at most once per 60 seconds (the caller passes the
-- cut-off), kept in the row so a restart does not forget it.
-- name: RequestEndpointScan :execrows
UPDATE endpoints SET scan_requested_at = ?, next_scan_at = ?
WHERE id = ? AND (scan_requested_at IS NULL OR scan_requested_at <= ?);

-- name: RecordScanSuccess :exec
UPDATE endpoints SET last_scan_at = ?, last_ok_at = ?, fail_streak = 0, last_error_kind = NULL, last_error = NULL,
    fingerprint = ?, serial = ?, subject = ?, issuer = ?, not_before = ?, not_after = ?, chain_len = ?, chain_state = ?,
    tls_version = ?, same_count = ?, fingerprint_since = ?, next_scan_at = ?
WHERE id = ?;

-- The served certificate of the last good scan stays: it is what the page
-- shows as the last known state, and a failed scan must not erase it.
-- name: RecordScanFailure :exec
UPDATE endpoints SET last_scan_at = ?, fail_streak = fail_streak + 1, last_error_kind = ?, last_error = ?, next_scan_at = ?
WHERE id = ?;

-- name: FindEndpoint :one
SELECT id FROM endpoints WHERE host = ? AND port = ? AND coalesce(sni, '') = ?;
