-- pki.db, migration 0006: older certificates of a CA key (PHASE1 step 15).
--
-- legacy/pki.sh renews a CA with the same key (renew-ca): the newest
-- certificate becomes the generation, the older ones of the same key are
-- kept here. They verify the same certificates and stay as evidence; they
-- are never changed or deleted.
CREATE TABLE ca_certificate_history (
    ca_id              TEXT NOT NULL,
    generation         INTEGER NOT NULL,
    serial_hex         TEXT NOT NULL,
    not_before         TEXT NOT NULL,
    not_after          TEXT NOT NULL,
    cert_der           BLOB NOT NULL,
    fingerprint_sha256 TEXT NOT NULL UNIQUE,
    source             TEXT NOT NULL CHECK (source IN ('legacy')),
    created_at         TEXT NOT NULL,
    FOREIGN KEY (ca_id, generation) REFERENCES ca_generations (ca_id, generation)
) STRICT;

CREATE INDEX ca_certificate_history_ca ON ca_certificate_history (ca_id, generation);

CREATE TRIGGER ca_certificate_history_no_update BEFORE UPDATE ON ca_certificate_history
BEGIN
    SELECT RAISE(ABORT, 'a CA certificate is never changed');
END;

CREATE TRIGGER ca_certificate_history_no_delete BEFORE DELETE ON ca_certificate_history
BEGIN
    SELECT RAISE(ABORT, 'CA certificates are kept as evidence');
END;
