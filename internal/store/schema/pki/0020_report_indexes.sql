-- pki.db, migration 0020: indexes for the reports (docs/PHASE3.md section
-- 14.1, step 45, v0.3.8).
--
-- Indexes only: no column, no row and no constraint changes, so a failed run
-- leaves 0019 as it was and the data is exactly what it was.
--
-- certificates (created_at): the "issuances per week" report reads the
-- certificates of the last 12 weeks by creation time. (The expiry timeline
-- already has certificates_not_after.)
--
-- acme_orders (certificate_id): the report tells ACME certificates from UI
-- certificates by "an order points at the certificate"; without the index
-- every certificate would scan the order table. Partial: an order has a
-- certificate only once it is valid.

CREATE INDEX certificates_created_at ON certificates (created_at);

CREATE INDEX acme_orders_certificate ON acme_orders (certificate_id) WHERE certificate_id IS NOT NULL;
