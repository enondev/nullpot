// Cloudflare D1 SQLite schema for nullpot edge API.
// Applied via `wrangler d1 execute` or the Cloudflare dashboard.

-- IP reputation records (populated by aggregator via KV sync)
CREATE TABLE IF NOT EXISTS ip_reputation (
  ip TEXT PRIMARY KEY,
  score REAL NOT NULL,
  ttl TEXT NOT NULL,
  asn TEXT,
  geo TEXT,
  updated_at TEXT NOT NULL
);

-- ASN reputation records
CREATE TABLE IF NOT EXISTS asn_reputation (
  asn TEXT PRIMARY KEY,
  score REAL NOT NULL,
  org TEXT,
  country TEXT,
  updated_at TEXT NOT NULL
);

-- Raw threat events (for historical analysis)
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_uid TEXT NOT NULL UNIQUE,
  src_ip TEXT NOT NULL,
  src_port INTEGER,
  dst_port INTEGER,
  module TEXT NOT NULL,
  risk_score REAL NOT NULL,
  risk_level TEXT NOT NULL,
  ttl_hours INTEGER NOT NULL,
  created_at TEXT NOT NULL
);

-- Index for fast IP lookups
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);

-- Blocklist entries for EDL feeds
CREATE TABLE IF NOT EXISTS blocklist (
  ip TEXT PRIMARY KEY,
  feed TEXT NOT NULL,
  score REAL NOT NULL,
  added_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_blocklist_feed ON blocklist(feed);
