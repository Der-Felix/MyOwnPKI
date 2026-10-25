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

-- One page of certificates, newest first: IDs sort by creation time, so the
-- cursor is the last ID of the previous page. Every filter is optional
-- (empty = any). allowed_cas is a JSON array of the CA IDs the caller may read;
-- all_cas = 1 skips it (a tenant-wide role). search is a plain substring of
-- CN, serial or a SAN, compared in lower case with instr(): no wildcards, so
-- percent and underscore match only themselves (sqlc does not parse LIKE ...
-- ESCAPE); the caller passes search in lower case.
-- name: ListCertificates :many
SELECT sqlc.embed(c), r.reason AS revocation_reason, r.revoked_at, r.invalidity_date
FROM certificates c LEFT JOIN revocations r ON r.certificate_id = c.id
WHERE (CAST(sqlc.arg(all_cas) AS INTEGER) = 1 OR c.ca_id IN (SELECT value FROM json_each(CAST(sqlc.arg(allowed_cas) AS TEXT))))
  AND (CAST(sqlc.arg(hide_agents) AS INTEGER) = 0 OR NOT (c.preset = 'client' AND EXISTS (SELECT 1 FROM agents a WHERE a.id = c.requested_by)))
  AND (CAST(sqlc.arg(ca_id) AS TEXT) = '' OR c.ca_id = CAST(sqlc.arg(ca_id) AS TEXT))
  AND (CAST(sqlc.arg(preset) AS TEXT) = '' OR c.preset = CAST(sqlc.arg(preset) AS TEXT))
  AND (CAST(sqlc.arg(status) AS TEXT) = ''
       OR (CAST(sqlc.arg(status) AS TEXT) = 'revoked' AND r.certificate_id IS NOT NULL)
       OR (CAST(sqlc.arg(status) AS TEXT) = 'valid' AND r.certificate_id IS NULL AND c.not_after > sqlc.arg(now))
       OR (CAST(sqlc.arg(status) AS TEXT) = 'expired' AND r.certificate_id IS NULL AND c.not_after <= sqlc.arg(now)))
  AND (CAST(sqlc.arg(expires_before) AS TEXT) = '' OR c.not_after < CAST(sqlc.arg(expires_before) AS TEXT))
  AND (CAST(sqlc.arg(search) AS TEXT) = ''
       OR instr(lower(c.common_name), CAST(sqlc.arg(search) AS TEXT)) > 0
       OR instr(lower(c.serial_hex), CAST(sqlc.arg(search) AS TEXT)) > 0
       OR EXISTS (SELECT 1 FROM certificate_sans s WHERE s.certificate_id = c.id AND instr(lower(s.value), CAST(sqlc.arg(search) AS TEXT)) > 0))
  AND (CAST(sqlc.arg(cursor) AS TEXT) = '' OR c.id < CAST(sqlc.arg(cursor) AS TEXT))
ORDER BY c.id DESC
LIMIT sqlc.arg(page_size);

-- Certificates per issuing CA by state, for the overview: revoked, expired
-- (not revoked, past notAfter), expiring (valid, notAfter before soon) and
-- valid (the rest). The caller drops the CAs the user may not read.
-- name: CountCertificates :many
SELECT c.ca_id,
       CAST(coalesce(sum(CASE WHEN r.certificate_id IS NOT NULL THEN 1 ELSE 0 END), 0) AS INTEGER) AS revoked,
       CAST(coalesce(sum(CASE WHEN r.certificate_id IS NULL AND c.not_after <= CAST(sqlc.arg(now) AS TEXT) THEN 1 ELSE 0 END), 0) AS INTEGER) AS expired,
       CAST(coalesce(sum(CASE WHEN r.certificate_id IS NULL AND c.not_after > CAST(sqlc.arg(now) AS TEXT)
                                   AND c.not_after <= CAST(sqlc.arg(soon) AS TEXT) THEN 1 ELSE 0 END), 0) AS INTEGER) AS expiring,
       CAST(coalesce(sum(CASE WHEN r.certificate_id IS NULL AND c.not_after > CAST(sqlc.arg(soon) AS TEXT) THEN 1 ELSE 0 END), 0) AS INTEGER) AS valid
FROM certificates c LEFT JOIN revocations r ON r.certificate_id = c.id
WHERE CAST(sqlc.arg(hide_agents) AS INTEGER) = 0 OR NOT (c.preset = 'client' AND EXISTS (SELECT 1 FROM agents a WHERE a.id = c.requested_by))
GROUP BY c.ca_id;

-- name: CountFingerprint :one
SELECT count(*) FROM certificates WHERE fingerprint_sha256 = ?;

-- Every certificate in ID order, a page at a time (restore check of the
-- SAN index, step 16).
-- name: ListCertificateDERs :many
SELECT id, serial_hex, cert_der FROM certificates WHERE id > ? ORDER BY id LIMIT ?;

-- ACME revokeCert names a certificate by its DER (RFC 8555 section 7.6).
-- name: GetCertificateByFingerprint :one
SELECT * FROM certificates WHERE fingerprint_sha256 = ?;

-- ACME renewalInfo names a certificate by issuer key ID and serial; the
-- caller compares the key ID (RFC 9773 section 4.1).
-- name: ListCertificatesBySerial :many
SELECT * FROM certificates WHERE serial_hex = ? LIMIT 20;
