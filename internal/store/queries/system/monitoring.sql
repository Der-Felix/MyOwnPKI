-- Monitoring: alerts and notification digests (ASCII only, see tenants.sql).

-- name: ListOpenAlerts :many
SELECT * FROM alerts
WHERE tenant = ? AND resolved_at IS NULL
ORDER BY CASE severity WHEN 'critical' THEN 0 ELSE 1 END, first_seen_at, alert_key;

-- name: ListAlertsSince :many
-- Open alerts and those resolved at or after the given time, newest first.
SELECT * FROM alerts
WHERE tenant = ? AND (resolved_at IS NULL OR resolved_at >= ?)
ORDER BY resolved_at IS NOT NULL, CASE severity WHEN 'critical' THEN 0 ELSE 1 END, first_seen_at DESC, alert_key;

-- name: InsertAlert :exec
INSERT INTO alerts (id, tenant, alert_key, kind, subject, severity, detail, href, first_seen_at, last_seen_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateOpenAlert :exec
UPDATE alerts
SET subject = ?, severity = ?, detail = ?, href = ?, last_seen_at = ?
WHERE id = ? AND resolved_at IS NULL;

-- name: ResolveAlert :exec
UPDATE alerts SET resolved_at = ? WHERE id = ? AND resolved_at IS NULL;

-- name: MarkAlertNotified :exec
UPDATE alerts SET notified_severity = ?, notified_at = ? WHERE id = ?;

-- name: MarkAlertResolveNotified :exec
UPDATE alerts SET resolve_notified = 1 WHERE id = ?;

-- name: ListResolvedUnnotified :many
-- Resolved alerts whose opening was reported but whose end was not yet.
SELECT * FROM alerts
WHERE tenant = ? AND resolved_at IS NOT NULL AND notified_at IS NOT NULL AND resolve_notified = 0
ORDER BY resolved_at, alert_key;

-- name: DeleteResolvedAlertsBefore :execrows
DELETE FROM alerts WHERE resolved_at IS NOT NULL AND resolved_at < ?;

-- name: InsertNotification :one
INSERT INTO notifications (channel, created_at, payload_json, next_attempt_at)
VALUES (?, ?, ?, ?)
RETURNING id;

-- name: ListDueNotifications :many
SELECT * FROM notifications
WHERE sent_at IS NULL AND dropped_at IS NULL AND next_attempt_at <= ?
ORDER BY id
LIMIT 20;

-- name: MarkNotificationSent :exec
UPDATE notifications SET attempts = attempts + 1, sent_at = ?, last_error = NULL WHERE id = ?;

-- name: MarkNotificationRetry :exec
UPDATE notifications SET attempts = attempts + 1, next_attempt_at = ?, last_error = ? WHERE id = ?;

-- name: MarkNotificationDropped :exec
UPDATE notifications SET attempts = attempts + 1, dropped_at = ?, last_error = ? WHERE id = ?;

-- name: DeleteFinishedNotificationsBefore :execrows
DELETE FROM notifications WHERE (sent_at IS NOT NULL AND sent_at < ?) OR (dropped_at IS NOT NULL AND dropped_at < ?);
