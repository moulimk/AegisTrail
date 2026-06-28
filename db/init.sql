-- AegisTrail detector schema (Postgres)
-- Data model reused/trimmed from the prior design:
--   events · identity_baseline · incidents · incident_events
-- identity_baseline is the "state store" the Round 2 hardening pass required.

-- Raw + normalized events
CREATE TABLE IF NOT EXISTS events (
    id          BIGSERIAL PRIMARY KEY,
    event_id    TEXT UNIQUE,                 -- CloudTrail eventID (dedup key)
    identity    TEXT        NOT NULL,         -- principal (username / "root" / arn)
    action      TEXT        NOT NULL,         -- eventName, e.g. AttachUserPolicy
    service     TEXT,                         -- e.g. iam, s3, sts
    resource    TEXT,
    source_ip   TEXT,
    region      TEXT,
    event_time  TIMESTAMPTZ NOT NULL,         -- CloudTrail eventTime
    raw_event   JSONB       NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_events_identity ON events (identity);
CREATE INDEX IF NOT EXISTS idx_events_time     ON events (event_time);
CREATE INDEX IF NOT EXISTS idx_events_service  ON events (service);

-- Per-identity behavioral baseline (rolling). Aggregates only, not full timeseries.
CREATE TABLE IF NOT EXISTS identity_baseline (
    identity           TEXT PRIMARY KEY,
    known_regions      JSONB  NOT NULL DEFAULT '[]'::jsonb,   -- AWS regions seen
    known_countries    JSONB  NOT NULL DEFAULT '[]'::jsonb,   -- source-IP geo countries seen
    known_services     JSONB  NOT NULL DEFAULT '[]'::jsonb,
    last_seen_ips      JSONB  NOT NULL DEFAULT '[]'::jsonb,   -- bounded set
    api_rate_mean      DOUBLE PRECISION NOT NULL DEFAULT 0,
    api_rate_std       DOUBLE PRECISION NOT NULL DEFAULT 0,
    per_service_counts JSONB  NOT NULL DEFAULT '{}'::jsonb,
    event_count        BIGINT NOT NULL DEFAULT 0,
    first_seen         TIMESTAMPTZ,
    last_updated       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Incidents raised by the detector
CREATE TABLE IF NOT EXISTS incidents (
    incident_id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity      TEXT    NOT NULL,
    incident_type TEXT    NOT NULL,           -- e.g. CREDENTIAL_COMPROMISE
    risk_score    INTEGER NOT NULL,           -- 0..100
    confidence    DOUBLE PRECISION NOT NULL DEFAULT 0,
    status        TEXT    NOT NULL DEFAULT 'OPEN'
        CHECK (status IN ('OPEN', 'CONTAINED', 'CLOSED', 'FALSE_POSITIVE')),
    summary       TEXT,
    signals       JSONB   NOT NULL DEFAULT '[]'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_incidents_identity ON incidents (identity);
CREATE INDEX IF NOT EXISTS idx_incidents_created  ON incidents (created_at);

-- Events that make up an incident (the timeline)
CREATE TABLE IF NOT EXISTS incident_events (
    id             BIGSERIAL PRIMARY KEY,
    incident_id    UUID NOT NULL REFERENCES incidents (incident_id) ON DELETE CASCADE,
    event_id       TEXT NOT NULL,
    sequence_order INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_incident_events_incident ON incident_events (incident_id);
