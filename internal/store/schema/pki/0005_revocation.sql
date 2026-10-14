-- pki.db, migration 0005: revocation, CRLs and blocked keys (PHASE1 step 9).
--
-- A revocation is final: no certificateHold, rows are never changed or
-- deleted. It takes effect for clients only once a CRL lists it.

-- Revoked end-entity certificates. Reasons per RFC 5280 section 5.3.1,
-- without certificateHold/removeFromCRL (reversible, banned by the CA/B Forum).
CREATE TABLE revocations (
    certificate_id  TEXT PRIMARY KEY REFERENCES certificates (id),
    reason          TEXT NOT NULL CHECK (reason IN ('unspecified', 'keyCompromise', 'affiliationChanged',
                                                    'superseded', 'cessationOfOperation', 'privilegeWithdrawn')),
    revoked_at      TEXT NOT NULL,
    invalidity_date TEXT,
    revoked_by      TEXT NOT NULL
) STRICT;

-- Revoked CA generations. source = server: revoked here (online parent);
-- root_crl: found in an uploaded CRL of an offline root.
CREATE TABLE ca_revocations (
    ca_id           TEXT NOT NULL,
    generation      INTEGER NOT NULL,
    reason          TEXT NOT NULL CHECK (reason IN ('unspecified', 'keyCompromise', 'cACompromise', 'affiliationChanged',
                                                    'superseded', 'cessationOfOperation', 'privilegeWithdrawn')),
    revoked_at      TEXT NOT NULL,
    invalidity_date TEXT,
    revoked_by      TEXT NOT NULL,
    source          TEXT NOT NULL CHECK (source IN ('server', 'root_crl')),
    PRIMARY KEY (ca_id, generation),
    FOREIGN KEY (ca_id, generation) REFERENCES ca_generations (ca_id, generation)
) STRICT;

-- Every CRL ever published. One CRL per CA generation and number; the
-- number rises strictly per CA across all generations (RFC 5280 5.2.3).
-- source = signed: by the server; uploaded: signed offline (offline root).
CREATE TABLE crls (
    ca_id       TEXT NOT NULL REFERENCES cas (id),
    generation  INTEGER NOT NULL,
    number      INTEGER NOT NULL CHECK (number > 0),
    this_update TEXT NOT NULL,
    next_update TEXT NOT NULL,
    crl_der     BLOB NOT NULL,
    source      TEXT NOT NULL CHECK (source IN ('signed', 'uploaded')),
    created_at  TEXT NOT NULL,
    PRIMARY KEY (ca_id, number),
    FOREIGN KEY (ca_id, generation) REFERENCES ca_generations (ca_id, generation)
) STRICT;

CREATE INDEX crls_latest ON crls (ca_id, generation, number);

-- Keys reported compromised (keyCompromise, cACompromise): SHA-256 of the
-- SubjectPublicKeyInfo. The CA engine refuses them for every new
-- certificate and CA of the tenant.
CREATE TABLE blocked_keys (
    spki_sha256 TEXT PRIMARY KEY,
    reason      TEXT NOT NULL CHECK (reason IN ('keyCompromise', 'cACompromise')),
    source_type TEXT NOT NULL CHECK (source_type IN ('certificate', 'ca')),
    source_id   TEXT NOT NULL,
    blocked_at  TEXT NOT NULL,
    blocked_by  TEXT NOT NULL
) STRICT;

-- Imported legacy CAs keep their old URLs (<base>/<name>.crt|.crl) as
-- permanent aliases of generation 1; set by the importer (step 10).
ALTER TABLE cas ADD COLUMN legacy_urls INTEGER NOT NULL DEFAULT 0 CHECK (legacy_urls IN (0, 1));

CREATE TRIGGER revocations_immutable_update BEFORE UPDATE ON revocations
BEGIN
    SELECT RAISE(ABORT, 'a revocation is final');
END;

CREATE TRIGGER revocations_immutable_delete BEFORE DELETE ON revocations
BEGIN
    SELECT RAISE(ABORT, 'a revocation is final');
END;

CREATE TRIGGER ca_revocations_immutable_update BEFORE UPDATE ON ca_revocations
BEGIN
    SELECT RAISE(ABORT, 'a revocation is final');
END;

CREATE TRIGGER ca_revocations_immutable_delete BEFORE DELETE ON ca_revocations
BEGIN
    SELECT RAISE(ABORT, 'a revocation is final');
END;

CREATE TRIGGER crls_immutable_update BEFORE UPDATE ON crls
BEGIN
    SELECT RAISE(ABORT, 'a published CRL is never changed');
END;

CREATE TRIGGER crls_immutable_delete BEFORE DELETE ON crls
BEGIN
    SELECT RAISE(ABORT, 'published CRLs are kept as evidence');
END;

CREATE TRIGGER blocked_keys_immutable_update BEFORE UPDATE ON blocked_keys
BEGIN
    SELECT RAISE(ABORT, 'a blocked key stays blocked');
END;

CREATE TRIGGER blocked_keys_immutable_delete BEFORE DELETE ON blocked_keys
BEGIN
    SELECT RAISE(ABORT, 'a blocked key stays blocked');
END;
