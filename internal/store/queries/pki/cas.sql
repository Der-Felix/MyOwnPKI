-- CAs and their generations (ASCII only, see queries/system/tenants.sql).

-- name: InsertCA :exec
INSERT INTO cas (id, name, kind, parent_id, status, key_mode, path_len, nc_critical, eku_limit,
                 public_base_url, crl_days, max_validity_days, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: SetCurrentGeneration :exec
UPDATE cas SET current_generation = ?, updated_at = ? WHERE id = ?;

-- name: InsertCAGeneration :exec
INSERT INTO ca_generations (ca_id, generation, key_id, key_algorithm, subject_dn, serial_hex, not_before, not_after,
                            cert_der, csr_der, fingerprint_sha256, ski_hex, issuer_ca_id, issuer_generation, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: InsertNameConstraint :exec
INSERT INTO ca_name_constraints (ca_id, kind, value, permitted) VALUES (?, ?, ?, ?);

-- name: GetCAByName :one
SELECT * FROM cas WHERE name = ?;

-- name: GetCA :one
SELECT * FROM cas WHERE id = ?;

-- name: GetCAGeneration :one
SELECT * FROM ca_generations WHERE ca_id = ? AND generation = ?;

-- name: ListNameConstraints :many
SELECT kind, value, permitted FROM ca_name_constraints WHERE ca_id = ? ORDER BY kind, permitted DESC, value;
