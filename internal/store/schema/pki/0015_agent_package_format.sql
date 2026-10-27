-- pki.db, migration 0015: how the admitted agent was installed (step 16).
-- Existing agents and older reporters remain legacy tarballs.
ALTER TABLE agents ADD COLUMN package_format TEXT NOT NULL DEFAULT 'tarball'
    CHECK (package_format IN ('deb', 'rpm', 'tarball'));
