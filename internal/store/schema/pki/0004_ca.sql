-- pki.db, migration 0004: CAs, CA generations and issued certificates
-- (PHASE1 section 1.1, step 7).
--
-- A CA (cas) is what an admin configures: name, parent, name constraints,
-- public base URL, limits. Each key the CA ever had is a generation
-- (ca_generations): renewing a CA with a new key adds generation 2 under the
-- same name, like AD CS "CAName(1).crt". Certificates record the generation
-- that signed them; AIA and CRL URLs contain it, so the chains and CRLs of
-- older certificates keep working after a renewal:
--   <public_base_url>/ca/<name>/<generation>.crt
--   <public_base_url>/crl/<name>/<generation>.crl
--
-- Serials are unique per CA, not per generation: all generations share the
-- issuer name, and issuer name + serial must identify exactly one
-- certificate (RFC 5280 section 4.1.2.2).
CREATE TABLE cas (
    id                 TEXT PRIMARY KEY,
    -- Part of every AIA/CRL URL, so it can never change (trigger below).
    name               TEXT NOT NULL UNIQUE
                       CHECK (length(name) <= 63 AND name GLOB '[a-z0-9]*' AND name NOT GLOB '*[^a-z0-9._-]*'),
    kind               TEXT NOT NULL CHECK (kind IN ('root', 'intermediate')),
    parent_id          TEXT REFERENCES cas (id),
    status             TEXT NOT NULL CHECK (status IN ('active', 'pending_signature', 'retired')),
    key_mode           TEXT NOT NULL CHECK (key_mode IN ('offline', 'online_encrypted', 'hsm')),
    -- The generation that signs new certificates; NULL until the first one exists.
    current_generation INTEGER,
    path_len           INTEGER CHECK (path_len IS NULL OR path_len >= 0),
    -- Name constraints critical (RFC 5280); 0 is a compatibility switch for old clients.
    nc_critical        INTEGER NOT NULL DEFAULT 1 CHECK (nc_critical IN (0, 1)),
    -- JSON array of dotted EKU OIDs this CA may issue (legacy EKU_LIMIT); [] = no limit.
    eku_limit          TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(eku_limit) AND json_type(eku_limit) = 'array'),
    -- Baked into every certificate; immutable once the CA has signed anything (trigger below).
    public_base_url    TEXT NOT NULL
                       CHECK ((public_base_url GLOB 'http://?*' OR public_base_url GLOB 'https://?*')
                              AND public_base_url NOT GLOB '*/'),
    crl_days           INTEGER NOT NULL CHECK (crl_days > 0),
    -- Strictly increasing across all generations; preserved by the importer.
    crl_number         INTEGER NOT NULL DEFAULT 0 CHECK (crl_number >= 0),
    max_validity_days  INTEGER NOT NULL CHECK (max_validity_days > 0),
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    CHECK ((kind = 'root') = (parent_id IS NULL)),
    FOREIGN KEY (id, current_generation) REFERENCES ca_generations (ca_id, generation)
) STRICT;

CREATE TABLE ca_generations (
    ca_id              TEXT NOT NULL REFERENCES cas (id),
    generation         INTEGER NOT NULL CHECK (generation >= 1),
    -- NULL for offline keys: the server only ever holds the certificate (ADR-09).
    key_id             TEXT REFERENCES keys (id),
    key_algorithm      TEXT NOT NULL,
    subject_dn         TEXT NOT NULL,
    -- The fields below are NULL while the certificate is pending (offline signing, step 8).
    serial_hex         TEXT,
    not_before         TEXT,
    not_after          TEXT,
    cert_der           BLOB,
    csr_der            BLOB,
    fingerprint_sha256 TEXT UNIQUE,
    ski_hex            TEXT,
    -- The parent generation that signed this certificate; NULL for a root.
    issuer_ca_id       TEXT,
    issuer_generation  INTEGER,
    created_at         TEXT NOT NULL,
    PRIMARY KEY (ca_id, generation),
    FOREIGN KEY (issuer_ca_id, issuer_generation) REFERENCES ca_generations (ca_id, generation),
    CHECK ((cert_der IS NULL) = (fingerprint_sha256 IS NULL)),
    CHECK (cert_der IS NULL OR (serial_hex IS NOT NULL AND not_before IS NOT NULL
                                AND not_after IS NOT NULL AND ski_hex IS NOT NULL))
) STRICT;

-- Name constraints the CA enforces before signing (and writes into its certificate).
CREATE TABLE ca_name_constraints (
    ca_id     TEXT NOT NULL REFERENCES cas (id),
    kind      TEXT NOT NULL CHECK (kind IN ('dns', 'ip', 'email', 'uri')),
    value     TEXT NOT NULL,
    permitted INTEGER NOT NULL CHECK (permitted IN (0, 1)), -- 1 permitted, 0 excluded
    PRIMARY KEY (ca_id, kind, value, permitted)
) STRICT;

CREATE TABLE certificates (
    id                 TEXT PRIMARY KEY,
    ca_id              TEXT REFERENCES cas (id), -- NULL for external certificates
    ca_generation      INTEGER,
    source             TEXT NOT NULL CHECK (source IN ('issued', 'imported', 'external')),
    preset             TEXT,
    serial_hex         TEXT NOT NULL,
    subject_dn         TEXT NOT NULL,
    common_name        TEXT NOT NULL, -- '' when the certificate has no CN
    not_before         TEXT NOT NULL,
    not_after          TEXT NOT NULL,
    key_algorithm      TEXT NOT NULL,
    key_id             TEXT REFERENCES keys (id), -- only for server-generated keys
    cert_der           BLOB NOT NULL,
    fingerprint_sha256 TEXT NOT NULL UNIQUE,
    renewal_of         TEXT REFERENCES certificates (id),
    requested_by       TEXT NOT NULL, -- display only; the audit log is the record
    custom_ku          TEXT,
    custom_eku         TEXT,
    created_at         TEXT NOT NULL,
    UNIQUE (ca_id, serial_hex),
    FOREIGN KEY (ca_id, ca_generation) REFERENCES ca_generations (ca_id, generation),
    CHECK ((source = 'external') = (ca_id IS NULL)),
    CHECK ((ca_id IS NULL) = (ca_generation IS NULL))
) STRICT;

CREATE INDEX certificates_not_after ON certificates (not_after);

CREATE TABLE certificate_sans (
    certificate_id TEXT NOT NULL REFERENCES certificates (id) ON DELETE CASCADE,
    type           TEXT NOT NULL CHECK (type IN ('dns', 'ip', 'email', 'uri')),
    value          TEXT NOT NULL,
    PRIMARY KEY (certificate_id, type, value)
) STRICT;

CREATE INDEX certificate_sans_value ON certificate_sans (type, value);

-- Immutable facts. A CA name and, once the CA has signed something, its base
-- URL are inside certificates that are already out there.
CREATE TRIGGER cas_name_immutable BEFORE UPDATE OF name ON cas
WHEN NEW.name IS NOT OLD.name
BEGIN
    SELECT RAISE(ABORT, 'a CA name can never change');
END;

CREATE TRIGGER cas_base_url_immutable BEFORE UPDATE OF public_base_url ON cas
WHEN NEW.public_base_url IS NOT OLD.public_base_url
    AND (EXISTS (SELECT 1 FROM certificates WHERE ca_id = OLD.id)
         OR EXISTS (SELECT 1 FROM ca_generations WHERE issuer_ca_id = OLD.id))
BEGIN
    SELECT RAISE(ABORT, 'the public base URL is in certificates already and can never change');
END;

-- A CA certificate is set once (pending -> signed) and then never changed.
CREATE TRIGGER ca_generations_cert_immutable BEFORE UPDATE ON ca_generations
WHEN OLD.cert_der IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'a signed CA generation can never change');
END;

CREATE TRIGGER ca_generations_no_delete BEFORE DELETE ON ca_generations
WHEN OLD.cert_der IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'a signed CA generation can never be deleted');
END;

-- An issued certificate is never changed or deleted: its serial must stay
-- taken forever, and revocation lives in its own table (step 9).
CREATE TRIGGER certificates_no_update BEFORE UPDATE ON certificates
BEGIN
    SELECT RAISE(ABORT, 'certificates are immutable');
END;

CREATE TRIGGER certificates_no_delete BEFORE DELETE ON certificates
WHEN OLD.source <> 'external'
BEGIN
    SELECT RAISE(ABORT, 'issued and imported certificates can never be deleted');
END;

-- The names are a search index of the (immutable) certificate; they may only
-- go together with an external certificate (ON DELETE CASCADE).
CREATE TRIGGER certificate_sans_no_update BEFORE UPDATE ON certificate_sans
BEGIN
    SELECT RAISE(ABORT, 'certificates are immutable');
END;

CREATE TRIGGER certificate_sans_no_delete BEFORE DELETE ON certificate_sans
WHEN (SELECT source FROM certificates WHERE id = OLD.certificate_id) <> 'external'
BEGIN
    SELECT RAISE(ABORT, 'the names of issued and imported certificates can never be deleted');
END;
