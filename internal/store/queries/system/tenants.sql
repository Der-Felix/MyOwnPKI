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
