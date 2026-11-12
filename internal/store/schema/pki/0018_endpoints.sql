-- pki.db, migration 0018: TLS scan endpoints (docs/PHASE3.md section 10.2, v0.3.4).
--
-- An endpoint is a TLS service an admin entered. The server connects to it,
-- reads the certificate it serves and compares that with what this PKI
-- issued for the name. Everything the remote end sends is attacker input:
-- only clipped metadata of the served leaf is stored (never the DER, a
-- public key, a SAN list or the resolved address) and the page escapes it.
-- Additive: no existing table changes.

CREATE TABLE endpoints (
    id                TEXT PRIMARY KEY,                    -- ep_...
    host              TEXT NOT NULL,                       -- DNS name (lower case, no trailing dot) or IP literal
    port              INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    sni               TEXT,                                -- NULL: the host (none for an IP); else the name sent and expected
    source            TEXT NOT NULL CHECK (source IN ('manual', 'agent')),  -- 'agent' is a seam: nothing writes it yet
    created_at        TEXT NOT NULL,
    created_by        TEXT NOT NULL,
    next_scan_at      TEXT NOT NULL,                       -- due when this has passed; moved forward when a scan is claimed
    scan_requested_at TEXT,                                -- the last "scan now" (once per 60 seconds)
    last_scan_at      TEXT,
    last_ok_at        TEXT,
    fail_streak       INTEGER NOT NULL DEFAULT 0 CHECK (fail_streak >= 0),
    last_error_kind   TEXT,                                -- a fixed vocabulary, see internal/tlsscan
    last_error        TEXT,                                -- a fixed short message, never what the remote end said
    fingerprint       TEXT,                                -- SHA-256 of the served leaf, upper-case hex
    serial            TEXT,
    subject           TEXT,                                -- clipped, valid UTF-8, control characters replaced
    issuer            TEXT,
    not_before        TEXT,
    not_after         TEXT,
    chain_len         INTEGER CHECK (chain_len IS NULL OR chain_len >= 0),
    chain_state       TEXT CHECK (chain_state IS NULL OR chain_state IN ('trusted', 'incomplete', 'untrusted')),
    tls_version       TEXT,
    same_count        INTEGER NOT NULL DEFAULT 0 CHECK (same_count >= 0),  -- successful scans in a row that saw this fingerprint
    fingerprint_since TEXT
) STRICT;

CREATE UNIQUE INDEX endpoints_target ON endpoints (host, port, COALESCE(sni, ''));
CREATE INDEX endpoints_due ON endpoints (next_scan_at);
