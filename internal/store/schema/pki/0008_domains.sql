-- pki.db, migration 0008: domains (PHASE2 step 1).
--
-- A domain is a name space this tenant issues for automatically (ACME): the
-- CA that signs, which challenges prove control, the approval level, the
-- preset and the validity. A name is served by the most specific domain
-- that covers it; without one, ACME refuses the name.
CREATE TABLE domains (
    id                 TEXT PRIMARY KEY,
    name               TEXT NOT NULL UNIQUE,   -- "homelab.example": punycode, lower case, no trailing dot
    ca_id              TEXT NOT NULL REFERENCES cas (id),
    include_subdomains INTEGER NOT NULL CHECK (include_subdomains IN (0, 1)),
    wildcards          INTEGER NOT NULL CHECK (wildcards IN (0, 1)),
    challenge_types    TEXT NOT NULL CHECK (json_valid(challenge_types)),   -- ["http-01","dns-01"]
    approval           TEXT NOT NULL CHECK (approval IN ('open', 'account', 'new_name')),
    preset             TEXT NOT NULL,
    validity_days      INTEGER CHECK (validity_days IS NULL OR validity_days > 0),   -- NULL = 90
    address_policy     TEXT NOT NULL CHECK (address_policy IN ('internal', 'public')),
    ip_ranges          TEXT NOT NULL CHECK (json_valid(ip_ranges)),   -- ["192.0.2.0/24"]: IP identifiers (http-01 only)
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    CHECK (wildcards = 0 OR include_subdomains = 1)
) STRICT;

CREATE INDEX domains_ca ON domains (ca_id);
