-- system.db, migration 0001: identify the file.
--
-- db_info lets the server refuse a file that is not a system database (for
-- example a swapped file after a manual restore) before it migrates anything.
CREATE TABLE db_info (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

INSERT INTO db_info (key, value) VALUES ('db_type', 'system');

-- Tenants (PHASE1 section 1.2). Phase 1 has one: "default". The id is also the
-- directory name below <data>/tenants/.
CREATE TABLE tenants (
    id                  TEXT PRIMARY KEY CHECK (id GLOB '[a-z0-9]*' AND id NOT GLOB '*[^a-z0-9-]*' AND length(id) <= 63),
    name                TEXT NOT NULL,
    -- Server-side key generation for leaves; CSR signing is always allowed (PLAN section 5).
    allow_server_keygen INTEGER NOT NULL DEFAULT 1 CHECK (allow_server_keygen IN (0, 1)),
    created_at          TEXT NOT NULL
) STRICT;
