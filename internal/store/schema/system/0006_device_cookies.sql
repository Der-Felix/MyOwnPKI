-- system.db, migration 0006: credentials epoch (PHASE1 step 13).
--
-- Device cookies (OWASP) carry the epoch of the user's credentials in their
-- HMAC. It rises with a new password, a new or reset second factor and
-- myownpki user unlock, so every device cookie issued before is void.
-- Rehashing a password with new parameters doesn't change it.
ALTER TABLE users ADD COLUMN credentials_epoch INTEGER NOT NULL DEFAULT 0 CHECK (credentials_epoch >= 0);
