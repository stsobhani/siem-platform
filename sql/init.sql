-- ============================================================================
-- SIEM Platform - PostgreSQL Schema
-- ============================================================================

CREATE TABLE IF NOT EXISTS raw_logs (
    id              BIGSERIAL PRIMARY KEY,
    source_type     VARCHAR(50)  NOT NULL,          -- windows_auth | linux_ssh | firewall | web_server
    raw_message     TEXT         NOT NULL,
    ingested_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    processed       BOOLEAN      NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS normalized_events (
    id              BIGSERIAL PRIMARY KEY,
    raw_log_id      BIGINT REFERENCES raw_logs(id) ON DELETE SET NULL,
    event_time      TIMESTAMPTZ  NOT NULL,
    source_type     VARCHAR(50)  NOT NULL,
    host            VARCHAR(255),
    username        VARCHAR(255),
    src_ip          INET,
    dst_ip          INET,
    dst_port        INTEGER,
    event_type      VARCHAR(100) NOT NULL,          -- login_success | login_failure | privilege_escalation | conn_allowed | conn_denied | http_request ...
    severity        VARCHAR(20)  NOT NULL DEFAULT 'low',  -- low | medium | high | critical
    status_code     INTEGER,
    additional_data JSONB,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_events_time        ON normalized_events (event_time);
CREATE INDEX IF NOT EXISTS idx_events_src_ip       ON normalized_events (src_ip);
CREATE INDEX IF NOT EXISTS idx_events_username     ON normalized_events (username);
CREATE INDEX IF NOT EXISTS idx_events_event_type   ON normalized_events (event_type);
CREATE INDEX IF NOT EXISTS idx_events_source_type  ON normalized_events (source_type);

CREATE TABLE IF NOT EXISTS alerts (
    id              BIGSERIAL PRIMARY KEY,
    rule_name       VARCHAR(100) NOT NULL,
    severity        VARCHAR(20)  NOT NULL,
    src_ip          INET,
    username        VARCHAR(255),
    host            VARCHAR(255),
    title           VARCHAR(255) NOT NULL,
    description     TEXT,
    risk_score      NUMERIC(5,2) NOT NULL DEFAULT 0,
    event_ids       BIGINT[],
    detected_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    status          VARCHAR(20)  NOT NULL DEFAULT 'open'  -- open | acknowledged | closed
);

CREATE INDEX IF NOT EXISTS idx_alerts_detected_at ON alerts (detected_at);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip      ON alerts (src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_severity    ON alerts (severity);

CREATE TABLE IF NOT EXISTS threat_intel_ips (
    ip              INET PRIMARY KEY,
    category        VARCHAR(100),
    confidence      INTEGER,
    source          VARCHAR(100),
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ml_anomaly_scores (
    id              BIGSERIAL PRIMARY KEY,
    username        VARCHAR(255),
    event_time      TIMESTAMPTZ NOT NULL,
    anomaly_score   NUMERIC(6,4) NOT NULL,
    is_anomaly      BOOLEAN NOT NULL,
    features        JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
