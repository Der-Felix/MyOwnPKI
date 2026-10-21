-- Users, roles and sessions (PHASE1 step 10). ASCII only, see tenants.sql.

-- name: InsertUser :exec
INSERT INTO users (id, username, password_hash, password_changed_at, totp_secret, instance_admin, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetUser :one
SELECT * FROM users WHERE id = ?;

-- name: GetUserByName :one
SELECT * FROM users WHERE username = ?;

-- name: ListUsers :many
SELECT * FROM users ORDER BY username;

-- name: CountUsers :one
SELECT count(*) FROM users;

-- name: SetPassword :exec
UPDATE users SET password_hash = ?, password_changed_at = ?, credentials_epoch = credentials_epoch + 1, updated_at = ? WHERE id = ?;

-- The same password with new hash parameters: device cookies stay valid.
-- name: RehashPassword :exec
UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?;

-- A new secret set by an admin: confirmed by the first valid code.
-- name: ResetTOTP :exec
UPDATE users SET totp_secret = ?, totp_confirmed_at = NULL, totp_last_step = 0, totp_pending = NULL,
                 credentials_epoch = credentials_epoch + 1, updated_at = ?
WHERE id = ?;

-- Takes a time step only if it is newer than the last one: a TOTP code is
-- valid once, also when two requests race. 0 rows = replayed code.
-- name: UseTOTPStep :execrows
UPDATE users SET totp_last_step = ?, totp_confirmed_at = coalesce(totp_confirmed_at, ?), updated_at = ?
WHERE id = ? AND totp_last_step < ?;

-- name: SetTOTPPending :exec
UPDATE users SET totp_pending = ?, updated_at = ? WHERE id = ?;

-- name: ApplyTOTPPending :execrows
UPDATE users SET totp_secret = totp_pending, totp_pending = NULL, totp_confirmed_at = ?, totp_last_step = ?,
                 credentials_epoch = credentials_epoch + 1, updated_at = ?
WHERE id = ? AND totp_pending IS NOT NULL;

-- name: SetLoginFailures :exec
UPDATE users SET failed_logins = ?, locked_until = ?, updated_at = ? WHERE id = ?;

-- myownpki user unlock: device cookies issued before are void.
-- name: BumpCredentialsEpoch :exec
UPDATE users SET credentials_epoch = credentials_epoch + 1, updated_at = ? WHERE id = ?;

-- name: SetDisabled :exec
UPDATE users SET disabled_at = ?, updated_at = ? WHERE id = ?;

-- name: InsertRecoveryCode :exec
INSERT INTO recovery_codes (user_id, code_hash, created_at) VALUES (?, ?, ?);

-- name: DeleteRecoveryCodes :exec
DELETE FROM recovery_codes WHERE user_id = ?;

-- 0 rows = unknown or used code.
-- name: UseRecoveryCode :execrows
UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL;

-- name: CountUnusedRecoveryCodes :one
SELECT count(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL;

-- name: SetRoleBinding :exec
INSERT INTO role_bindings (user_id, tenant_id, ca, role, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (user_id, tenant_id, ca) DO UPDATE SET role = excluded.role, created_at = excluded.created_at,
    created_by = excluded.created_by;

-- name: DeleteRoleBinding :execrows
DELETE FROM role_bindings WHERE user_id = ? AND tenant_id = ? AND ca = ?;

-- name: ListRoleBindings :many
SELECT * FROM role_bindings WHERE user_id = ? ORDER BY tenant_id, ca;

-- name: InsertSession :exec
INSERT INTO sessions (id_hash, user_id, state, csrf_token, created_at, last_seen_at, expires_at, stepup_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetSession :one
SELECT * FROM sessions WHERE id_hash = ?;

-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?;

-- name: SetStepUp :exec
UPDATE sessions SET stepup_at = ? WHERE id_hash = ?;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id_hash = ?;

-- name: DeleteUserSessions :execrows
DELETE FROM sessions WHERE user_id = ?;

-- name: DeleteOtherUserSessions :execrows
DELETE FROM sessions WHERE user_id = ? AND id_hash <> ?;

-- name: DeleteExpiredSessions :execrows
DELETE FROM sessions WHERE expires_at <= ? OR (state = 'full' AND last_seen_at <= ?);

-- The last active instance admin and the last active tenant-wide admin of a
-- tenant can't be disabled or lose that role: count the others.
-- name: CountOtherActiveInstanceAdmins :one
SELECT count(*) FROM users WHERE instance_admin = 1 AND disabled_at IS NULL AND id <> ?;

-- name: CountOtherActiveTenantAdmins :one
SELECT count(*) FROM role_bindings b JOIN users u ON u.id = b.user_id
WHERE b.tenant_id = ? AND b.ca = '' AND b.role = 'admin' AND u.disabled_at IS NULL AND b.user_id <> ?;

-- Passkeys (step 17).

-- name: InsertPasskey :exec
INSERT INTO webauthn_credentials (id, user_id, credential_id, credential, name, sign_count, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: ListPasskeys :many
SELECT * FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at, id;

-- name: CountPasskeys :one
SELECT count(*) FROM webauthn_credentials WHERE user_id = ?;

-- A sign-in with a passkey: the counter only moves forward, or stays 0 for
-- authenticators that never count (synced passkeys). The WHERE makes a race
-- between two sign-ins safe.
-- name: UsePasskey :execrows
UPDATE webauthn_credentials
SET credential = sqlc.arg(credential), sign_count = sqlc.arg(sign_count), last_used_at = sqlc.arg(last_used_at)
WHERE id = sqlc.arg(id) AND (sign_count < sqlc.arg(sign_count) OR (sign_count = 0 AND sqlc.arg(sign_count) = 0));

-- name: DeletePasskey :execrows
DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?;

-- name: DeleteUserPasskeys :execrows
DELETE FROM webauthn_credentials WHERE user_id = ?;

-- API tokens (step 18).

-- name: InsertToken :exec
INSERT INTO api_tokens (id, user_id, name, token_hash, roles_json, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: GetTokenByHash :one
SELECT * FROM api_tokens WHERE token_hash = ?;

-- name: ListTokens :many
SELECT * FROM api_tokens WHERE user_id = ? ORDER BY created_at, id;

-- name: CountTokens :one
SELECT count(*) FROM api_tokens WHERE user_id = ?;

-- name: DeleteToken :execrows
DELETE FROM api_tokens WHERE id = ? AND user_id = ?;

-- name: TouchToken :exec
UPDATE api_tokens SET last_used_at = ? WHERE id = ?;

-- name: DeleteUserTokens :execrows
DELETE FROM api_tokens WHERE user_id = ?;
