-- system.db, migration 0010: the public trust page of a tenant (v0.2.2).
--
-- 1: the public listener serves the trust page at / (the CA certificates,
-- their fingerprints, install guides and the Windows helpers); 0: it serves
-- only what certificates point to (CA certificates, CRLs). On by default,
-- also for existing tenants.
ALTER TABLE tenants ADD COLUMN trust_page INTEGER NOT NULL DEFAULT 1 CHECK (trust_page IN (0, 1));
