-- 1.0.2 data hygiene: shrink analytics rollup keys, add node revocation.
-- Path, country, and node_id stay on the live telemetry ring; they explode
-- the persisted PK. Existing rows are summed into the new grain.

ALTER TABLE nodes ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS nodes_revoked_serial_idx
    ON nodes (cert_serial)
    WHERE revoked_at IS NOT NULL;

CREATE TABLE analytics_hourly_v2 (
    bucket_start    TIMESTAMPTZ NOT NULL,
    host_id         TEXT NOT NULL DEFAULT '',
    domain          TEXT NOT NULL DEFAULT '',
    status_class    SMALLINT NOT NULL DEFAULT 0,
    count           BIGINT NOT NULL DEFAULT 0,
    latency_sum_ms  DOUBLE PRECISION NOT NULL DEFAULT 0,
    bytes_sum       BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_start, host_id, domain, status_class)
);

INSERT INTO analytics_hourly_v2 (bucket_start, host_id, domain, status_class, count, latency_sum_ms, bytes_sum)
SELECT bucket_start, host_id, domain, status_class,
       SUM(count), SUM(latency_sum_ms), SUM(bytes_sum)
FROM analytics_hourly
GROUP BY bucket_start, host_id, domain, status_class;

DROP TABLE analytics_hourly;
ALTER TABLE analytics_hourly_v2 RENAME TO analytics_hourly;
CREATE INDEX analytics_hourly_bucket_idx ON analytics_hourly (bucket_start DESC);

CREATE TABLE analytics_daily_v2 (
    bucket_start    TIMESTAMPTZ NOT NULL,
    host_id         TEXT NOT NULL DEFAULT '',
    domain          TEXT NOT NULL DEFAULT '',
    status_class    SMALLINT NOT NULL DEFAULT 0,
    count           BIGINT NOT NULL DEFAULT 0,
    latency_sum_ms  DOUBLE PRECISION NOT NULL DEFAULT 0,
    bytes_sum       BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_start, host_id, domain, status_class)
);

INSERT INTO analytics_daily_v2 (bucket_start, host_id, domain, status_class, count, latency_sum_ms, bytes_sum)
SELECT bucket_start, host_id, domain, status_class,
       SUM(count), SUM(latency_sum_ms), SUM(bytes_sum)
FROM analytics_daily
GROUP BY bucket_start, host_id, domain, status_class;

DROP TABLE analytics_daily;
ALTER TABLE analytics_daily_v2 RENAME TO analytics_daily;
CREATE INDEX analytics_daily_bucket_idx ON analytics_daily (bucket_start DESC);
