-- Exact agent account/order/name mapping and accepted deployment history.

-- name: UpsertAgentDeploymentCertificate :exec
INSERT INTO agent_deployment_certificates (agent_id, deployment, certificate_id, first_deployed_at, last_deployed_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT (agent_id, deployment, certificate_id) DO UPDATE SET last_deployed_at = excluded.last_deployed_at;

-- name: AgentCertificateHistory :one
SELECT * FROM agent_deployment_certificates
WHERE agent_id = ? AND deployment = ? AND certificate_id = ?;

-- name: ListAgentServingCertificateIDs :many
SELECT c.id FROM agent_deployments d
JOIN certificates c ON c.serial_hex = d.certificate_serial
WHERE d.agent_id = ? AND d.state = 'deployed' AND d.reported = 1
  AND d.served_fingerprint IS NOT NULL AND d.served_fingerprint <> ''
  AND lower(d.served_fingerprint) = lower(c.fingerprint_sha256);

-- name: GetACMEAccountByAgentID :one
SELECT * FROM acme_accounts WHERE agent_id = ?;

-- name: ListAgentPredecessorCandidates :many
SELECT c.id, c.serial_hex, c.fingerprint_sha256, c.created_at, o.id AS order_id, o.identifiers
FROM certificates c
JOIN acme_orders o ON o.certificate_id = c.id AND o.status = 'valid'
JOIN acme_accounts a ON a.id = o.account_id
WHERE a.id = ? AND c.created_at < ?
ORDER BY c.created_at, c.id;

-- name: ListAgentCertificateOrders :many
SELECT c.id, c.serial_hex, c.fingerprint_sha256, c.created_at, o.id AS order_id, o.account_id, o.identifiers
FROM certificates c
JOIN acme_orders o ON o.certificate_id = c.id AND o.status = 'valid'
WHERE c.id = ?
LIMIT 2;

-- name: CountAgentDeploymentHistory :one
SELECT count(*) FROM agent_deployment_certificates
WHERE agent_id = ? AND deployment = ? AND certificate_id = ?;

-- name: SetAgentPredecessorPolicy :execrows
UPDATE agents SET predecessor_choice = ?, predecessor_days = ?, updated_at = ? WHERE id = ?;

-- name: SetDeploymentPredecessorPolicy :execrows
UPDATE agent_deployments SET predecessor_choice = ?, predecessor_days = ? WHERE agent_id = ? AND name = ?;
