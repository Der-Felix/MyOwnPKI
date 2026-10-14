-- Revocation, CRLs and blocked keys (ASCII only, see queries/system/tenants.sql).

-- name: InsertRevocation :exec
INSERT INTO revocations (certificate_id, reason, revoked_at, invalidity_date, revoked_by) VALUES (?, ?, ?, ?, ?);

-- name: GetRevocation :one
SELECT * FROM revocations WHERE certificate_id = ?;

-- name: InsertCARevocation :exec
INSERT INTO ca_revocations (ca_id, generation, reason, revoked_at, invalidity_date, revoked_by, source)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetCARevocation :one
SELECT * FROM ca_revocations WHERE ca_id = ? AND generation = ?;

-- A key may be reported twice (two certificates with one key); the first
-- report stays.
-- name: BlockKey :exec
INSERT INTO blocked_keys (spki_sha256, reason, source_type, source_id, blocked_at, blocked_by)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (spki_sha256) DO NOTHING;

-- name: GetBlockedKey :one
SELECT * FROM blocked_keys WHERE spki_sha256 = ?;

-- Entries of a CRL: revoked leaves of one CA generation. An entry stays
-- until it was on a regular CRL after the certificate expired (RFC 5280
-- section 3.3): the caller passes now minus crl_days as cutoff.
-- name: ListLeafCRLEntries :many
SELECT c.serial_hex, r.reason, r.revoked_at, r.invalidity_date
FROM revocations r JOIN certificates c ON c.id = r.certificate_id
WHERE c.ca_id = ? AND c.ca_generation = ? AND c.not_after > ?
ORDER BY c.serial_hex;

-- name: ListCACRLEntries :many
SELECT g.serial_hex, r.reason, r.revoked_at, r.invalidity_date
FROM ca_revocations r JOIN ca_generations g ON g.ca_id = r.ca_id AND g.generation = r.generation
WHERE g.issuer_ca_id = ? AND g.issuer_generation = ? AND g.not_after > ?
ORDER BY g.serial_hex;

-- name: InsertCRL :exec
INSERT INTO crls (ca_id, generation, number, this_update, next_update, crl_der, source, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetLatestCRL :one
SELECT * FROM crls WHERE ca_id = ? AND generation = ? ORDER BY number DESC LIMIT 1;

-- name: MaxCRLNumber :one
SELECT CAST(coalesce(max(number), 0) AS INTEGER) AS number FROM crls WHERE ca_id = ?;

-- name: SetCRLNumber :exec
UPDATE cas SET crl_number = ?, updated_at = ? WHERE id = ?;

-- name: ListSignedGenerations :many
SELECT g.* FROM ca_generations g WHERE g.cert_der IS NOT NULL ORDER BY g.ca_id, g.generation;

-- name: FindGenerationBySerial :one
SELECT * FROM ca_generations WHERE issuer_ca_id = ? AND serial_hex = ?;

-- The latest notAfter a CA generation signed (leaves and CA certificates).
-- Imported legacy certificates may outlive their CA; the generation needs
-- CRLs until they have expired too. '' = it signed nothing.
-- name: LatestIssuedNotAfter :one
SELECT CAST(coalesce(max(not_after), '') AS TEXT) AS not_after FROM (
    SELECT c.not_after FROM certificates c WHERE c.ca_id = ? AND c.ca_generation = ?
    UNION ALL
    SELECT g.not_after FROM ca_generations g
    WHERE g.issuer_ca_id = ? AND g.issuer_generation = ? AND g.not_after IS NOT NULL
);
