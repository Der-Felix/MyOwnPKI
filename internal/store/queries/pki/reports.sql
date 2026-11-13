-- Reports (docs/PHASE3.md section 14, step 45). ASCII only.
-- Both queries leave out agent identity certificates (preset 'client' and
-- requested_by an agent, like HideAgentCertificates) and return the CA ID, so
-- the engine can drop the CAs the caller may not read.

-- The end of every certificate that is not revoked and ends in (after, until].
-- Times are in the certificate format (whole seconds, "Z"); not_after uses
-- certificates_not_after.
-- name: ExpiryTimes :many
SELECT c.ca_id, c.not_after
FROM certificates c
WHERE c.not_after > CAST(sqlc.arg(after) AS TEXT) AND c.not_after <= CAST(sqlc.arg(until) AS TEXT)
  AND NOT EXISTS (SELECT 1 FROM revocations r WHERE r.certificate_id = c.id)
  AND NOT (c.preset = 'client' AND EXISTS (SELECT 1 FROM agents a WHERE a.id = c.requested_by))
ORDER BY c.not_after;

-- Every issued certificate created in [since, until) with its source class:
-- 'acme' = an ACME order points at it and the order's account has no agent,
-- 'agent' = the same with an agent-linked account, 'ui' = no order (UI and
-- API issuance share one engine call). Imported and external certificates
-- are no issuances. created_at is stored with milliseconds ("...:00.000Z"),
-- so the bounds must be passed in that format (string comparison).
-- name: IssuanceSources :many
SELECT c.ca_id, c.created_at,
       CAST(CASE
              WHEN EXISTS (SELECT 1 FROM acme_orders o JOIN acme_accounts ac ON ac.id = o.account_id
                           WHERE o.certificate_id = c.id AND ac.agent_id IS NOT NULL) THEN 'agent'
              WHEN EXISTS (SELECT 1 FROM acme_orders o WHERE o.certificate_id = c.id) THEN 'acme'
              ELSE 'ui'
            END AS TEXT) AS source_class
FROM certificates c
WHERE c.source = 'issued' AND c.created_at >= CAST(sqlc.arg(since) AS TEXT) AND c.created_at < CAST(sqlc.arg(until) AS TEXT)
  AND NOT (c.preset = 'client' AND EXISTS (SELECT 1 FROM agents a WHERE a.id = c.requested_by))
ORDER BY c.created_at;
