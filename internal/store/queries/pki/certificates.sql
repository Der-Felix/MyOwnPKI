-- Certificates (ASCII only, see queries/system/tenants.sql).
-- Certificates are never updated; revocation gets its own table (step 9).

-- name: InsertCertificate :exec
INSERT INTO certificates (id, ca_id, ca_generation, source, preset, serial_hex, subject_dn, common_name,
                          not_before, not_after, key_algorithm, key_id, cert_der, fingerprint_sha256,
                          renewal_of, requested_by, custom_ku, custom_eku, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: InsertCertificateSAN :exec
INSERT INTO certificate_sans (certificate_id, type, value) VALUES (?, ?, ?);

-- name: GetCertificate :one
SELECT * FROM certificates WHERE id = ?;

-- name: ListCertificateSANs :many
SELECT type, value FROM certificate_sans WHERE certificate_id = ? ORDER BY type, value;
