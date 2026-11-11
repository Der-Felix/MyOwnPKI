-- system.db, migration 0014: monitoring (docs/PHASE3.md section 9). Alerts are what
-- the evaluation job found; notifications are the digests waiting for, or
-- done with, delivery. Both live in system.db so they work while sealed:
-- nothing here is encrypted, and no secret is ever stored (the channels and
-- their secrets come from the configuration).

-- One row per condition. The key (kind:subject id) is unique among open
-- alerts; a condition that comes back after it was resolved is a new row.
CREATE TABLE alerts (
    id                TEXT PRIMARY KEY,
    tenant            TEXT NOT NULL,
    alert_key         TEXT NOT NULL,
    kind              TEXT NOT NULL,
    subject           TEXT NOT NULL,           -- what it is about, for display
    severity          TEXT NOT NULL CHECK (severity IN ('warning', 'critical')),
    detail            TEXT NOT NULL,           -- one sentence: what and what to do
    href              TEXT NOT NULL,           -- path in the web UI, '' for none
    first_seen_at     TEXT NOT NULL,
    last_seen_at      TEXT NOT NULL,
    resolved_at       TEXT,
    -- What the last digest said: NULL = not reported yet. A rise from
    -- warning to critical is reported again; a reminder follows after
    -- monitor.repeat_every.
    notified_severity TEXT CHECK (notified_severity IN ('warning', 'critical')),
    notified_at       TEXT,
    resolve_notified  INTEGER NOT NULL DEFAULT 0 CHECK (resolve_notified IN (0, 1))
) STRICT;

CREATE UNIQUE INDEX alerts_open_key ON alerts (tenant, alert_key) WHERE resolved_at IS NULL;
CREATE INDEX alerts_resolved ON alerts (resolved_at);

-- One digest per channel and evaluation run. AUTOINCREMENT: ids are never
-- reused, so a log line about delivery n always means the same digest.
CREATE TABLE notifications (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    channel         TEXT NOT NULL CHECK (channel IN ('email', 'webhook')),
    created_at      TEXT NOT NULL,
    payload_json    TEXT NOT NULL,             -- the digest; never a secret
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    sent_at         TEXT,
    dropped_at      TEXT,                      -- gave up after the last retry
    last_error      TEXT
) STRICT;

CREATE INDEX notifications_due ON notifications (next_attempt_at) WHERE sent_at IS NULL AND dropped_at IS NULL;
