PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA synchronous = NORMAL;

-- ─────────────────────────────────────────────────────────────
-- network_assets — every device God Eye's ARP radar has ever seen
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS network_assets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address      TEXT    NOT NULL UNIQUE,
    mac_address     TEXT    NOT NULL,
    hostname        TEXT,
    is_authorized   INTEGER NOT NULL DEFAULT 0 CHECK (is_authorized IN (0, 1)),
    first_seen      TEXT    NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'NOW')),
    last_seen       TEXT    NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'NOW'))
);

CREATE INDEX IF NOT EXISTS idx_assets_mac ON network_assets (mac_address);
CREATE INDEX IF NOT EXISTS idx_assets_authorized ON network_assets (is_authorized);

-- ─────────────────────────────────────────────────────────────
-- telemetry_events — raw sensor output, pre-AI-analysis
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS telemetry_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_module   TEXT    NOT NULL CHECK (
                        source_module IN ('RADAR', 'CANARY', 'HONEYPOT', 'AUTH_LOG', 'VISION')
                    ),
    suspicious_ip   TEXT,
    raw_payload     TEXT    NOT NULL,      -- JSON blob
    correlated      INTEGER NOT NULL DEFAULT 0 CHECK (correlated IN (0, 1)),
    timestamp       TEXT    NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'NOW'))
);

CREATE INDEX IF NOT EXISTS idx_telemetry_ip ON telemetry_events (suspicious_ip);
CREATE INDEX IF NOT EXISTS idx_telemetry_timestamp ON telemetry_events (timestamp);
CREATE INDEX IF NOT EXISTS idx_telemetry_uncorrelated ON telemetry_events (correlated)
    WHERE correlated = 0;

-- ─────────────────────────────────────────────────────────────
-- incidents — Ultron Core's reasoning output over correlated events
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS incidents (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_uid    TEXT    NOT NULL UNIQUE,   -- UUID4 string
    risk_score      INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    severity        TEXT    NOT NULL CHECK (
                        severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
                    ),
    mitre_tactic    TEXT,                       -- e.g. "Credential Access"
    mitre_id        TEXT,                       -- e.g. "T1110"
    summary         TEXT,                       -- plain-English agent explanation
    status          TEXT    NOT NULL DEFAULT 'ACTIVE' CHECK (
                        status IN ('ACTIVE', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE')
                    ),
    created_at      TEXT    NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'NOW'))
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents (severity);

-- ─────────────────────────────────────────────────────────────
-- shield_actions — every containment action Shields has executed
-- ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS shield_actions (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id         INTEGER NOT NULL REFERENCES incidents (id) ON DELETE RESTRICT,
    shield_type         TEXT    NOT NULL CHECK (
                            shield_type IN ('FIREWALL_DROP', 'PROCESS_KILL', 'QUARANTINE')
                        ),
    target_identifier   TEXT    NOT NULL,        -- IP address or PID
    latency_ms          INTEGER,                  -- NULL while PENDING approval
    status              TEXT    NOT NULL DEFAULT 'COMPLETED' CHECK (
                            status IN ('PENDING', 'COMPLETED', 'FAILED')
                        ),
    executed_at         TEXT    NOT NULL DEFAULT (STRFTIME('%Y-%m-%dT%H:%M:%fZ', 'NOW'))
);

CREATE INDEX IF NOT EXISTS idx_shield_incident ON shield_actions (incident_id);
