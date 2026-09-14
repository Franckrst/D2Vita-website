-- D2Vita crash-report API, schema v1 (spec section 5.6).
-- Times are Unix seconds (UTC). Composite-key tables are WITHOUT ROWID so an
-- upsert touches a single b-tree (fewer billed D1 row writes).

-- Builds declared by the maintainer after each build (tools/crash builds register).
CREATE TABLE builds (
  build_id      TEXT PRIMARY KEY,
  version       TEXT NOT NULL,
  channel       TEXT NOT NULL CHECK (channel IN ('release', 'dev', 'test')),
  registered_at INTEGER NOT NULL
);

-- One row per crash signature ("S" + 15 base32 chars).
CREATE TABLE signatures (
  id                TEXT PRIMARY KEY,
  kind              TEXT NOT NULL CHECK (kind IN ('halt', 'guest_fault', 'host_fault', 'abnormal_exit', 'hang')),
  canon             TEXT NOT NULL,
  rules_version     INTEGER NOT NULL,
  count             INTEGER NOT NULL DEFAULT 0,
  installs          INTEGER NOT NULL DEFAULT 0,  -- distinct consoles
  first_seen        INTEGER NOT NULL,
  last_seen         INTEGER NOT NULL,
  first_build       TEXT,
  last_build        TEXT,
  status            TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'fixed', 'ignored', 'regressed')),
  status_changed_at INTEGER,
  fixed_in_version  TEXT,
  merged_into       TEXT,
  issue_url         TEXT,
  note              TEXT,
  sample_state      TEXT NOT NULL DEFAULT 'none' CHECK (sample_state IN ('none', 'leased', 'stored')),
  lease_report      TEXT,
  lease_expires     INTEGER,
  sample_report     TEXT,
  sample_purged_at  INTEGER
);

-- Per-build counters of a signature.
CREATE TABLE signature_builds (
  signature  TEXT NOT NULL,
  build_id   TEXT NOT NULL,
  count      INTEGER NOT NULL DEFAULT 0,
  first_seen INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  PRIMARY KEY (signature, build_id)
) WITHOUT ROWID;

-- Distinct consoles per signature (install_hash = HMAC(INSTALL_HASH_KEY, install_id)).
CREATE TABLE signature_installs (
  signature    TEXT NOT NULL,
  install_hash TEXT NOT NULL,
  first_seen   INTEGER NOT NULL,
  PRIMARY KEY (signature, install_hash)
) WITHOUT ROWID;

-- Every accepted claim is kept (rules can be re-applied to the history).
CREATE TABLE reports (
  report_id      TEXT PRIMARY KEY,
  ingest_nonce   TEXT NOT NULL,           -- identifies the request that inserted the row
  signature      TEXT NOT NULL,           -- signature the report was counted on (merge root)
  raw_signature  TEXT NOT NULL,           -- signature computed from the claim itself
  install_hash   TEXT NOT NULL,
  build_id       TEXT NOT NULL,
  channel        TEXT NOT NULL,
  kind           TEXT NOT NULL,
  received_at    INTEGER NOT NULL,
  claim          TEXT NOT NULL,           -- claim JSON as validated
  decision       TEXT NOT NULL,           -- decision JSON returned to the console (replayed as is)
  action         TEXT NOT NULL CHECK (action IN ('count_only', 'upload')),
  requested      TEXT,                    -- JSON [{name, max_bytes}] when action = upload
  upload_expires INTEGER,
  uploaded       INTEGER NOT NULL DEFAULT 0,  -- bit set of stored artifacts
  completed_at   INTEGER,
  sample_stored  INTEGER
);
CREATE INDEX reports_by_signature ON reports (signature, received_at);
CREATE INDEX reports_by_install ON reports (install_hash);
CREATE INDEX reports_by_received ON reports (received_at);

-- Bug reports sent from the public site.
CREATE TABLE bugs (
  id          TEXT PRIMARY KEY,
  title       TEXT NOT NULL,
  description TEXT NOT NULL,
  version     TEXT NOT NULL,
  contact     TEXT,
  lang        TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'fixed', 'ignored')),
  issue_url   TEXT,
  note        TEXT,
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
);
CREATE INDEX bugs_by_created ON bugs (created_at);

-- Exact daily counters (window = UTC day). IP subjects are keyed hashes only.
CREATE TABLE rate_counters (
  scope   TEXT NOT NULL,
  subject TEXT NOT NULL,
  day     TEXT NOT NULL,                  -- YYYY-MM-DD (UTC)
  n       INTEGER NOT NULL,
  PRIMARY KEY (scope, subject, day)
) WITHOUT ROWID;

-- Adjustable settings (kill switch, caps) and the daily IP salts.
CREATE TABLE settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
) WITHOUT ROWID;
