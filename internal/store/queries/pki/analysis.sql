-- Analysis (docs/PHASE3.md section 14, step 46). ASCII only.
-- The queries leave out agent identity certificates (preset 'client' and
-- requested_by an agent, like HideAgentCertificates) and return the CA ID, so
-- the engine can drop the CAs the caller may not read.

-- The DER of every certificate that is valid at now (not revoked, ends after
-- now), for the key size and the signature algorithm. The analysis cache
-- keeps the result of the parsing for a minute. Read in pages by id (keyset):
-- pass the last id of the previous page, the empty string for the first.
-- name: ListValidCertificateDERs :many
SELECT c.id, c.ca_id, c.cert_der
FROM certificates c
WHERE c.not_after > CAST(sqlc.arg(now) AS TEXT)
  AND c.id > CAST(sqlc.arg(after_id) AS TEXT)
  AND NOT EXISTS (SELECT 1 FROM revocations r WHERE r.certificate_id = c.id)
  AND NOT (c.preset = 'client' AND EXISTS (SELECT 1 FROM agents a WHERE a.id = c.requested_by))
ORDER BY c.id
LIMIT sqlc.arg(page_size);

-- Where each issued certificate came from: the account of the ACME order that
-- points at it and that account's agent, both '' if there is none (UI and API
-- issuance). Only source 'issued'; see IssuanceSources for the classes.
-- name: CertificateOrigins :many
SELECT c.id, c.ca_id,
       CAST(coalesce((SELECT o.account_id FROM acme_orders o WHERE o.certificate_id = c.id ORDER BY o.id LIMIT 1), '') AS TEXT) AS account_id,
       CAST(coalesce((SELECT ac.agent_id FROM acme_orders o JOIN acme_accounts ac ON ac.id = o.account_id
                      WHERE o.certificate_id = c.id ORDER BY o.id LIMIT 1), '') AS TEXT) AS agent_id
FROM certificates c
WHERE c.source = 'issued'
  AND NOT (c.preset = 'client' AND EXISTS (SELECT 1 FROM agents a WHERE a.id = c.requested_by))
ORDER BY c.id;

-- Every DNS name and IP any certificate (any status) was issued for, once per
-- CA, for "does a certificate exist under this domain".
-- name: CertificateNames :many
SELECT DISTINCT c.ca_id, s.type, s.value
FROM certificate_sans s JOIN certificates c ON c.id = s.certificate_id
WHERE s.type IN ('dns', 'ip')
  AND NOT (c.preset = 'client' AND EXISTS (SELECT 1 FROM agents a WHERE a.id = c.requested_by))
ORDER BY s.type, s.value;

-- ACME accounts with the time of their newest order ('' = never ordered),
-- newest account first.
-- name: ListACMEAccountActivity :many
SELECT a.id, a.status, a.created_at,
       CAST(coalesce(a.agent_id, '') AS TEXT) AS agent_id,
       CAST(coalesce((SELECT max(o.created_at) FROM acme_orders o WHERE o.account_id = a.id), '') AS TEXT) AS last_order_at
FROM acme_accounts a
ORDER BY a.created_at DESC, a.id
LIMIT ?;
