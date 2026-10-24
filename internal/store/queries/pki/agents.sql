-- Agents, enrollments, join tokens and agent names (v0.3.0, internal/agents).
--
-- Query files must be ASCII only (sqlc 1.31.1, see system/tenants.sql).

-- name: InsertJoinToken :exec
INSERT INTO join_tokens (id, token_hash, label, name_patterns, expires_at, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetJoinToken :one
SELECT * FROM join_tokens WHERE id = ?;

-- name: GetJoinTokenByHash :one
SELECT * FROM join_tokens WHERE token_hash = ?;

-- name: ListJoinTokens :many
SELECT * FROM join_tokens ORDER BY created_at DESC, id;

-- A token is used exactly once: the condition makes a second use a no-op.
-- name: UseJoinToken :execrows
UPDATE join_tokens SET used_at = ?, used_by = ? WHERE id = ? AND used_at IS NULL;

-- Only an unused token can be withdrawn; a used one stays as a record.
-- name: DeleteJoinToken :execrows
DELETE FROM join_tokens WHERE id = ? AND used_at IS NULL;

-- name: InsertEnrollment :exec
INSERT INTO agent_enrollments (id, agent_id, hostname, csr_der, spki_sha256, handle_hash, check_token, check_method,
    check_state, token_id, token_valid, token_problem, known_agent, state, os, arch, agent_version, source_ip,
    created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'waiting', ?, ?, ?, ?, 'waiting_for_check', ?, ?, ?, ?, ?, ?);

-- name: GetEnrollment :one
SELECT * FROM agent_enrollments WHERE id = ?;

-- name: ListEnrollments :many
SELECT * FROM agent_enrollments ORDER BY created_at DESC, id LIMIT ?;

-- name: ListOpenEnrollments :many
SELECT * FROM agent_enrollments
WHERE state IN ('waiting_for_check', 'pending_approval')
ORDER BY created_at, id;

-- The queue limit counts only enrollments that neither a valid join token
-- nor a known agent key stands behind (docs/PHASE3.md section 6.1).
-- name: CountOpenWithoutToken :one
SELECT count(*) FROM agent_enrollments
WHERE state IN ('waiting_for_check', 'pending_approval') AND token_valid = 0 AND known_agent = 0;

-- name: ExpireEnrollments :execrows
UPDATE agent_enrollments SET state = 'expired'
WHERE state IN ('waiting_for_check', 'pending_approval') AND expires_at <= ?;

-- name: SetEnrollmentCheck :exec
UPDATE agent_enrollments SET check_state = ?, check_error = ?, checked_at = ?, expires_at = ?
WHERE id = ?;

-- Decides an open enrollment; a second decision changes nothing.
-- name: DecideEnrollment :execrows
UPDATE agent_enrollments SET state = ?, agent_id = ?, decided_at = ?, decided_by = ?
WHERE id = ? AND state IN ('waiting_for_check', 'pending_approval');

-- name: QueueEnrollment :exec
UPDATE agent_enrollments SET state = 'pending_approval' WHERE id = ? AND state = 'waiting_for_check';

-- name: SetEnrollmentCert :exec
UPDATE agent_enrollments SET cert_id = ? WHERE id = ?;

-- name: InsertAgent :exec
INSERT INTO agents (id, hostname, status, enrollment_mode, proof, os, arch, agent_version, created_at,
    approved_at, approved_by, updated_at)
VALUES (?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetAgent :one
SELECT * FROM agents WHERE id = ?;

-- name: ListAgents :many
SELECT * FROM agents ORDER BY hostname, id;

-- name: ListAgentsByHostname :many
SELECT * FROM agents WHERE hostname = ? ORDER BY created_at, id;

-- name: GetAgentByCertSerial :one
SELECT * FROM agents WHERE cert_serial = sqlc.arg(serial) OR prev_cert_serial = sqlc.arg(serial);

-- The current certificate becomes the previous one, accepted until it
-- expires (a restart between issuance and the agent's switch).
-- name: SetAgentCertificate :exec
UPDATE agents SET prev_cert_id = cert_id, prev_cert_serial = cert_serial, cert_id = ?, cert_serial = ?, updated_at = ?
WHERE id = ?;

-- name: SetAgentStatus :execrows
UPDATE agents SET status = ?, updated_at = ?, desired_version = desired_version + 1 WHERE id = ?;

-- A known agent enrolled again with the key of its last certificate.
-- name: ReadmitAgent :exec
UPDATE agents SET enrollment_mode = ?, proof = ?, os = ?, arch = ?, agent_version = ?, approved_at = ?, approved_by = ?,
    updated_at = ?
WHERE id = ?;

-- name: TouchAgent :exec
UPDATE agents SET last_seen_at = ? WHERE id = ?;

-- name: InsertAgentName :exec
INSERT INTO agent_names (agent_id, pattern, source, added_by, added_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT (agent_id, pattern) DO NOTHING;

-- name: ListAgentNames :many
SELECT * FROM agent_names WHERE agent_id = ? ORDER BY pattern;

-- name: DeleteAgentName :execrows
DELETE FROM agent_names WHERE agent_id = ? AND pattern = ?;

-- name: BumpDesiredVersion :exec
UPDATE agents SET desired_version = desired_version + 1, updated_at = ? WHERE id = ?;
