-- 1.7.1: one row per proxied request, so the dashboard can open any request
-- (and every request from a country, IP or host) with full detail. The
-- filter columns are indexed; everything else rides in `event`.
-- Retention: AEGIS_REQUEST_LOG_DAYS for all rows, AEGIS_SECURITY_LOG_DAYS
-- for rows a security stage blocked or flagged.

CREATE TABLE request_log (
    seq          BIGSERIAL PRIMARY KEY,
    ts           TIMESTAMPTZ NOT NULL,
    request_id   TEXT NOT NULL DEFAULT '',
    host_id      TEXT NOT NULL DEFAULT '',
    domain       TEXT NOT NULL DEFAULT '',
    method       TEXT NOT NULL DEFAULT '',
    path         TEXT NOT NULL DEFAULT '',
    status       INTEGER NOT NULL DEFAULT 0,
    client_ip    TEXT NOT NULL DEFAULT '',
    country      TEXT NOT NULL DEFAULT '',
    block_stage  TEXT NOT NULL DEFAULT '',
    waf_action   TEXT NOT NULL DEFAULT '',
    waf_rule_id  TEXT NOT NULL DEFAULT '',
    event        JSONB NOT NULL
);

CREATE INDEX request_log_ts_idx ON request_log (ts DESC);
CREATE INDEX request_log_country_idx ON request_log (country, ts DESC);
CREATE INDEX request_log_client_idx ON request_log (client_ip, ts DESC);
CREATE INDEX request_log_host_idx ON request_log (host_id, ts DESC);
CREATE INDEX request_log_request_id_idx ON request_log (request_id) WHERE request_id <> '';
CREATE INDEX request_log_security_idx ON request_log (ts DESC)
    WHERE block_stage <> '' OR waf_action <> '';
