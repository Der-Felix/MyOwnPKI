-- Accounts

-- name: InsertACMEAccount :exec
INSERT INTO acme_accounts (id, key_thumbprint, jwk, status, contact, eab_key_id, approved_at, approved_by, created_at, created_ip, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetACMEAccount :one
SELECT * FROM acme_accounts WHERE id = ?;

-- name: GetACMEAccountByThumbprint :one
SELECT * FROM acme_accounts WHERE key_thumbprint = ?;

-- name: UpdateACMEAccountContact :exec
UPDATE acme_accounts SET contact = ?, updated_at = ? WHERE id = ?;

-- name: UpdateACMEAccountStatus :exec
UPDATE acme_accounts SET status = ?, updated_at = ? WHERE id = ?;

-- name: UpdateACMEAccountKey :exec
UPDATE acme_accounts SET key_thumbprint = ?, jwk = ?, updated_at = ? WHERE id = ?;

-- name: ApproveACMEAccount :execrows
UPDATE acme_accounts SET approved_at = ?, approved_by = ?, updated_at = ? WHERE id = ? AND approved_at IS NULL;

-- name: ListACMEAccounts :many
SELECT * FROM acme_accounts ORDER BY created_at DESC LIMIT ?;

-- name: CountACMEAccountsWaiting :one
SELECT count(*) FROM acme_accounts WHERE approved_at IS NULL AND status = 'valid';

-- name: BindACMEAccount :exec
UPDATE acme_accounts SET agent_id = ?, approved_at = COALESCE(approved_at, ?),
    approved_by = COALESCE(approved_by, ?), updated_at = ? WHERE id = ?;

-- EAB keys

-- name: InsertACMEEABKey :exec
INSERT INTO acme_eab_keys (id, label, root_key_version, wrapped_dek, mac_ciphertext, expires_at, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetACMEEABKey :one
SELECT * FROM acme_eab_keys WHERE id = ?;

-- name: UseACMEEABKey :execrows
UPDATE acme_eab_keys SET used_at = ?, used_by = ?, wrapped_dek = x'00', mac_ciphertext = x'00'
WHERE id = ? AND used_at IS NULL;

-- name: ListACMEEABKeys :many
SELECT id, label, expires_at, used_at, used_by, created_by, created_at FROM acme_eab_keys ORDER BY created_at DESC LIMIT ?;

-- Orders

-- name: InsertACMEOrder :exec
INSERT INTO acme_orders (id, account_id, status, identifiers, expires_at, replaces, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- RFC 9773: a certificate is replaced by one order at most that is not invalid.
-- name: CountACMEOrdersReplacing :one
SELECT count(*) FROM acme_orders WHERE replaces = ? AND status <> 'invalid';

-- name: GetACMEOrder :one
SELECT * FROM acme_orders WHERE id = ?;

-- name: SetACMEOrderStatus :exec
UPDATE acme_orders SET status = ?, error = ?, updated_at = ? WHERE id = ?;

-- name: SetACMEOrderProcessing :execrows
UPDATE acme_orders SET status = 'processing', csr_der = ?, updated_at = ? WHERE id = ? AND status = 'ready';

-- name: SetACMEOrderValid :execrows
UPDATE acme_orders SET status = 'valid', certificate_id = ?, updated_at = ? WHERE id = ? AND status = 'processing';

-- name: ListACMEOrdersProcessing :many
SELECT * FROM acme_orders WHERE status = 'processing' ORDER BY updated_at LIMIT ?;

-- name: CountACMEOrdersProcessing :one
SELECT count(*) FROM acme_orders WHERE status = 'processing';

-- name: ListACMEOrders :many
SELECT * FROM acme_orders ORDER BY created_at DESC LIMIT ?;

-- name: ExpireACMEOrders :execrows
UPDATE acme_orders SET status = 'invalid', error = ?, updated_at = ?
WHERE status IN ('pending', 'ready') AND expires_at <= ?;

-- name: GetACMEOrderByCertificate :one
SELECT * FROM acme_orders WHERE certificate_id = ?;

-- Authorizations

-- name: InsertACMEAuthz :exec
INSERT INTO acme_authzs (id, account_id, identifier_type, identifier_value, wildcard, status, expires_at, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetACMEAuthz :one
SELECT * FROM acme_authzs WHERE id = ?;

-- name: FindReusableACMEAuthz :one
SELECT * FROM acme_authzs
WHERE account_id = ? AND identifier_type = ? AND identifier_value = ? AND wildcard = ?
  AND status IN ('valid', 'pending') AND expires_at > ?
ORDER BY status = 'valid' DESC, expires_at DESC LIMIT 1;

-- revokeCert: does the account hold a valid authorization for the identifier?
-- name: HasValidACMEAuthz :one
SELECT count(*) FROM acme_authzs
WHERE account_id = ? AND identifier_type = ? AND identifier_value = ? AND wildcard = ?
  AND status = 'valid' AND expires_at > ?;

-- name: SetACMEAuthzStatus :exec
UPDATE acme_authzs SET status = ?, expires_at = ?, updated_at = ? WHERE id = ?;

-- name: ExpireACMEAuthzs :execrows
UPDATE acme_authzs SET status = 'expired', updated_at = ? WHERE status IN ('pending', 'valid') AND expires_at <= ?;

-- name: ListACMEAuthzsOfOrder :many
SELECT a.* FROM acme_authzs a JOIN acme_order_authzs o ON o.authz_id = a.id WHERE o.order_id = ? ORDER BY a.identifier_value;

-- name: LinkACMEOrderAuthz :exec
INSERT INTO acme_order_authzs (order_id, authz_id) VALUES (?, ?);

-- name: ListACMEOrdersOfAuthz :many
SELECT order_id FROM acme_order_authzs WHERE authz_id = ?;

-- name: DeactivateACMEAuthzsOfAccount :execrows
UPDATE acme_authzs SET status = 'deactivated', updated_at = ? WHERE account_id = ? AND status IN ('pending', 'valid');

-- Challenges

-- name: InsertACMEChallenge :exec
INSERT INTO acme_challenges (id, authz_id, type, token, status, updated_at) VALUES (?, ?, ?, ?, ?, ?);

-- name: GetACMEChallenge :one
SELECT * FROM acme_challenges WHERE id = ?;

-- name: ListACMEChallengesOfAuthz :many
SELECT * FROM acme_challenges WHERE authz_id = ? ORDER BY type;

-- name: StartACMEChallenge :execrows
UPDATE acme_challenges SET status = 'processing', updated_at = ? WHERE id = ? AND status = 'pending';

-- name: FinishACMEChallenge :exec
UPDATE acme_challenges SET status = ?, validated_at = ?, error = ?, updated_at = ? WHERE id = ?;

-- Names (approval level new_name)

-- name: GetACMEName :one
SELECT * FROM acme_names WHERE name = ?;

-- name: RequestACMEName :exec
INSERT INTO acme_names (name, status, requested_by, requested_at) VALUES (?, 'pending', ?, ?)
ON CONFLICT (name) DO NOTHING;

-- name: DecideACMEName :execrows
UPDATE acme_names SET status = ?, decided_by = ?, decided_at = ? WHERE name = ? AND status = 'pending';

-- name: ApproveACMENameDirectly :exec
INSERT INTO acme_names (name, status, requested_by, requested_at, decided_by, decided_at)
VALUES (?, 'approved', ?, ?, ?, ?)
ON CONFLICT (name) DO UPDATE SET status = 'approved', decided_by = excluded.decided_by, decided_at = excluded.decided_at;

-- name: ListACMENames :many
SELECT * FROM acme_names ORDER BY status = 'pending' DESC, requested_at DESC LIMIT ?;

-- name: CountACMENamesWaiting :one
SELECT count(*) FROM acme_names WHERE status = 'pending';

-- name: SetACMEPredecessorPolicy :execrows
UPDATE acme_accounts SET predecessor_choice = ?, predecessor_days = ?, updated_at = ? WHERE id = ?;
