-- xAuth keystore schema.
--
-- Setup:  sqlite3 db/auth < db/schema.sql
--
-- This file is the source of truth for the keystore layout. The database it
-- creates holds all per-device key material and is deliberately NOT tracked in
-- git; it needs its own backup plan (docs/development-plan.md, Phase 12).
--
-- Note on the original schema: it declared `ID TEXT PRIMARY_KEY`, which SQLite
-- parses as a column named ID of *type* "TEXT PRIMARY_KEY" -- not as a primary
-- key. The table had no key and no uniqueness constraint, so provisioning could
-- silently issue two devices the same ID. `PRIMARY KEY` below is the fix.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS secure_key_data (
    -- Public device ID, printed on the physical keychain. Crockford Base32,
    -- 4-8 chars; new devices get 4 (see tools/provision). Not a secret.
    ID     TEXT    NOT NULL PRIMARY KEY,

    -- Per-device HMAC-SHA256 secret, 128 lowercase hex chars.
    -- The bytes fed to HMAC are the ASCII hex characters themselves, NOT the
    -- 64 raw bytes they decode to. The firmware does the same thing, and the
    -- two must agree exactly -- do not "fix" one side in isolation.
    Key    TEXT    NOT NULL,

    -- Revocation flag. 1 = active, 0 = revoked. Revoking takes effect on the
    -- verifier's next lookup; no restart or redeploy.
    Status INTEGER NOT NULL DEFAULT 1 CHECK (Status IN (0, 1)),

    -- Admin-facing label ("Omar's primary", "lost 07/26"). Never shown on the
    -- login surface -- it must not become a way to correlate an ID to a person.
    Note   TEXT    NOT NULL DEFAULT 'OK',

    -- When the device was provisioned, UTC. Nullable only because keystores
    -- created before this column existed get it added by `provision` with
    -- ALTER TABLE, which cannot backfill a non-constant default.
    Created TEXT            DEFAULT (datetime('now'))
);

-- Revocation checks and any future "list active devices" admin view scan on
-- Status; the table is small enough that this is cheap insurance, not a
-- measured optimisation.
CREATE INDEX IF NOT EXISTS idx_secure_key_data_status
    ON secure_key_data (Status);
