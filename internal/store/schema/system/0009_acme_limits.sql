-- system.db, migration 0009: ACME rate limits of a tenant (PHASE2 step 11).
--
-- Per hour: new orders per account, failed validations per name, new
-- accounts per client address (IPv6 counted per /64). The defaults are the
-- values the ACME server used before they became settings.
ALTER TABLE tenants ADD COLUMN acme_orders_per_hour INTEGER NOT NULL DEFAULT 300 CHECK (acme_orders_per_hour BETWEEN 1 AND 10000);
ALTER TABLE tenants ADD COLUMN acme_failed_per_name INTEGER NOT NULL DEFAULT 5 CHECK (acme_failed_per_name BETWEEN 1 AND 100);
ALTER TABLE tenants ADD COLUMN acme_accounts_per_ip INTEGER NOT NULL DEFAULT 10 CHECK (acme_accounts_per_ip BETWEEN 1 AND 1000);
