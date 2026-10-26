-- Reported data is never executable configuration. All keys include agent_id.

-- name: ListAgentDeployments :many
SELECT * FROM agent_deployments WHERE agent_id = ? ORDER BY name;

-- name: GetAgentDeployment :one
SELECT * FROM agent_deployments WHERE agent_id = ? AND name = ?;

-- name: UpdateAgentReport :exec
UPDATE agents SET last_seen_at = ?, os = ?, arch = ?, agent_version = ? WHERE id = ?;

-- name: MarkAgentDeploymentsUnreported :exec
UPDATE agent_deployments SET reported = FALSE WHERE agent_id = ?;

-- name: UpsertAgentDeployment :exec
INSERT INTO agent_deployments (agent_id, name, profile, names, challenge, state, certificate_serial,
    not_after, served_fingerprint, deployed_at, last_error, last_report_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (agent_id, name) DO UPDATE SET profile = excluded.profile, names = excluded.names,
    challenge = excluded.challenge, state = excluded.state, certificate_serial = excluded.certificate_serial,
    not_after = excluded.not_after, served_fingerprint = excluded.served_fingerprint,
    deployed_at = excluded.deployed_at, last_error = excluded.last_error, last_report_at = excluded.last_report_at,
    reported = TRUE;

-- name: ClearDeploymentRenewal :execrows
UPDATE agent_deployments SET renew_requested_at = NULL, renew_requested_by = NULL, renew_requested_version = NULL,
    renew_predecessor_choice = NULL, renew_predecessor_days = NULL
WHERE agent_id = ? AND name = ? AND renew_requested_version = ?;

-- name: RequestDeploymentRenewal :execrows
UPDATE agent_deployments SET renew_requested_at = ?, renew_requested_by = ?, renew_requested_version = ?,
    renew_predecessor_choice = ?, renew_predecessor_days = ?
WHERE agent_id = ? AND name = ? AND renew_requested_at IS NULL;

-- name: WithdrawDeploymentRenewal :execrows
UPDATE agent_deployments SET renew_requested_at = NULL, renew_requested_by = NULL, renew_requested_version = NULL
WHERE agent_id = ? AND name = ? AND renew_requested_at IS NOT NULL;

-- A removed local deployment cannot silently discard an outstanding request.
-- name: DeleteUnreportedDeployments :exec
DELETE FROM agent_deployments WHERE agent_id = ? AND reported = FALSE AND renew_requested_at IS NULL;

-- Never link a reported serial to another account's certificate.
-- name: AgentCertificatesBySerial :many
SELECT c.id FROM certificates c
JOIN acme_orders o ON o.certificate_id = c.id AND o.status = 'valid'
JOIN acme_accounts a ON a.id = o.account_id
WHERE a.agent_id = ? AND c.serial_hex = ? LIMIT 2;
