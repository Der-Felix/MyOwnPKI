-- pki.db, migration 0010: ACME Renewal Information (RFC 9773, PHASE2 step 12).
--
-- An order may name the certificate it replaces ("replaces"); the issued
-- certificate then records it as renewal_of, and a certificate is replaced
-- by one live order at most (alreadyReplaced). renewalInfo looks a
-- certificate up by serial and checks the issuer's key ID.
ALTER TABLE acme_orders ADD COLUMN replaces TEXT REFERENCES certificates (id);

CREATE INDEX acme_orders_replaces ON acme_orders (replaces) WHERE replaces IS NOT NULL;
CREATE INDEX certificates_serial ON certificates (serial_hex);
