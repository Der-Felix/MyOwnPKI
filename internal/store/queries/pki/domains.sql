-- name: InsertDomain :exec
INSERT INTO domains (id, name, ca_id, include_subdomains, wildcards, challenge_types, approval, preset,
    validity_days, address_policy, ip_ranges, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateDomain :exec
UPDATE domains SET ca_id = ?, include_subdomains = ?, wildcards = ?, challenge_types = ?, approval = ?, preset = ?,
    validity_days = ?, address_policy = ?, ip_ranges = ?, updated_at = ?
WHERE id = ?;

-- name: DeleteDomain :exec
DELETE FROM domains WHERE id = ?;

-- name: GetDomain :one
SELECT * FROM domains WHERE id = ?;

-- name: GetDomainByName :one
SELECT * FROM domains WHERE name = ?;

-- name: ListDomains :many
SELECT * FROM domains ORDER BY name;
