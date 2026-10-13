-- pki.db, migration 0001: identify the file.
--
-- db_info lets the server refuse a file that is not a pki database (for
-- example a swapped file after a manual restore) before it migrates anything.
CREATE TABLE db_info (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

INSERT INTO db_info (key, value) VALUES ('db_type', 'pki');
