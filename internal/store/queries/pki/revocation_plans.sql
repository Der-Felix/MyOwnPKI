-- Planned superseded revocations. Existing rows are never moved implicitly.

-- name: GetRevocationPlan :one
SELECT * FROM certificate_revocation_plans WHERE certificate_id = ?;

-- name: InsertRevocationPlan :execrows
INSERT INTO certificate_revocation_plans (certificate_id, successor_id, planned_at, created_at, created_by, source)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (certificate_id) DO NOTHING;

-- name: DeleteRevocationPlan :execrows
DELETE FROM certificate_revocation_plans WHERE certificate_id = ?;

-- name: ListDueRevocationPlans :many
SELECT p.* FROM certificate_revocation_plans p
JOIN certificates c ON c.id = p.certificate_id
LEFT JOIN revocations r ON r.certificate_id = p.certificate_id
WHERE p.planned_at <= ? AND r.certificate_id IS NULL
ORDER BY p.planned_at, p.certificate_id
LIMIT ?;

-- name: CountRevocationPlansDue :one
SELECT count(*) FROM certificate_revocation_plans
WHERE planned_at > ? AND planned_at <= ?;

-- name: ListRevocationPlansBefore :many
SELECT * FROM certificate_revocation_plans WHERE planned_at <= ? ORDER BY planned_at, certificate_id;

-- name: ListRevocationPlansForAgent :many
SELECT sqlc.embed(p), h.deployment FROM certificate_revocation_plans p
JOIN agent_deployment_certificates h ON h.certificate_id = p.certificate_id
WHERE h.agent_id = ?
ORDER BY p.planned_at, p.certificate_id;

-- name: DeleteRevocationPlansForCertificates :exec
DELETE FROM certificate_revocation_plans
WHERE certificate_id IN (SELECT value FROM json_each(CAST(sqlc.arg(certificate_ids) AS TEXT)));
