-- Tenants (PHASE1 section 1.2). The id is also the directory name below
-- <data>/tenants/ and is validated by store.Layout before it gets here.
--
-- Query files must be ASCII only: sqlc 1.31.1 miscounts positions after a
-- multi-byte character in SQLite query files and cuts statements short.

-- name: EnsureTenant :exec
INSERT INTO tenants (id, name, created_at)
VALUES (?, ?, ?)
ON CONFLICT (id) DO NOTHING;

-- name: GetTenant :one
SELECT id, name, allow_server_keygen, created_at
FROM tenants
WHERE id = ?;

-- name: ListTenants :many
SELECT id, name, allow_server_keygen, created_at
FROM tenants
ORDER BY id;

-- Settings of a tenant (step 18): server key generation and subject defaults.
-- name: GetTenantSettings :one
SELECT id, allow_server_keygen, subject_o, subject_ou, subject_l, subject_st, subject_c,
       acme_orders_per_hour, acme_failed_per_name, acme_accounts_per_ip, trust_page, agent_enrollment
FROM tenants
WHERE id = ?;

-- name: SetTenantSettings :execrows
UPDATE tenants
SET allow_server_keygen = ?, subject_o = ?, subject_ou = ?, subject_l = ?, subject_st = ?, subject_c = ?,
    acme_orders_per_hour = ?, acme_failed_per_name = ?, acme_accounts_per_ip = ?, trust_page = ?, agent_enrollment = ?
WHERE id = ?;

-- The public listener asks this for every request to / (v0.2.2).
-- name: GetTrustPage :one
SELECT trust_page FROM tenants WHERE id = ?;

-- The agent listener asks this for every enrollment (v0.3.0).
-- name: GetAgentEnrollment :one
SELECT agent_enrollment FROM tenants WHERE id = ?;
