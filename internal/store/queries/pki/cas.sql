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

-- name: ListCAs :many
SELECT * FROM cas ORDER BY name;

-- name: ListCAGenerations :many
SELECT * FROM ca_generations WHERE ca_id = ? ORDER BY generation;

-- name: GetPendingGeneration :one
SELECT * FROM ca_generations WHERE ca_id = ? AND cert_der IS NULL ORDER BY generation DESC LIMIT 1;

-- name: MaxGeneration :one
SELECT CAST(coalesce(max(generation), 0) AS INTEGER) AS generation FROM ca_generations WHERE ca_id = ?;

-- Two CAs with the same subject DN confuse chain building in clients;
-- generations of one CA share their DN on purpose.
-- name: CountSubjectElsewhere :one
SELECT count(*) FROM ca_generations WHERE subject_dn = ? AND ca_id <> ?;

-- Issuer name + serial must identify one certificate (RFC 5280): a serial is
-- taken by a leaf of the CA or by a CA certificate the CA signed (also an
-- older certificate of a renewed key, step 15).
-- name: SerialTaken :one
SELECT (SELECT count(*) FROM certificates WHERE certificates.ca_id = sqlc.arg(issuer_id) AND certificates.serial_hex = sqlc.arg(serial_hex))
     + (SELECT count(*) FROM ca_generations WHERE ca_generations.issuer_ca_id = sqlc.arg(issuer_id) AND ca_generations.serial_hex = sqlc.arg(serial_hex))
     + (SELECT count(*) FROM ca_certificate_history h JOIN ca_generations g ON g.ca_id = h.ca_id AND g.generation = h.generation
        WHERE g.issuer_ca_id = sqlc.arg(issuer_id) AND h.serial_hex = sqlc.arg(serial_hex)) AS taken;

-- Sets the certificate of a pending generation (offline signing); a signed
-- generation can't be changed (trigger), the WHERE makes that explicit.
-- name: InstallCAGenerationCert :execrows
UPDATE ca_generations
SET serial_hex = ?, not_before = ?, not_after = ?, cert_der = ?, fingerprint_sha256 = ?, ski_hex = ?
WHERE ca_id = ? AND generation = ? AND cert_der IS NULL;

-- name: SetCAStatus :exec
UPDATE cas SET status = ?, updated_at = ? WHERE id = ?;

-- name: UpdateCALimits :exec
UPDATE cas SET crl_days = ?, max_validity_days = ?, updated_at = ? WHERE id = ?;

-- Set by the legacy importer: serve <base>/<name>.crt|.crl as aliases of
-- generation 1 (step 9).
-- name: SetLegacyURLs :exec
UPDATE cas SET legacy_urls = 1, updated_at = ? WHERE id = ?;

-- name: InsertCAHistory :exec
INSERT INTO ca_certificate_history (ca_id, generation, serial_hex, not_before, not_after, cert_der,
                                    fingerprint_sha256, source, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListCAHistory :many
SELECT * FROM ca_certificate_history WHERE ca_id = ? ORDER BY not_before;
