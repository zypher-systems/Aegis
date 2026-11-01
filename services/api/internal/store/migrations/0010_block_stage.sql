-- 1.3.0: persist which pipeline stage stopped a request. Cardinality is
-- tiny (none/waf/crowdsec/ratelimit/geo/acl). Live path/country stay off
-- the rollup grain.

CREATE TABLE analytics_hourly_v3 (
    bucket_start    TIMESTAMPTZ NOT NULL,
    host_id         TEXT NOT NULL DEFAULT '',
    domain          TEXT NOT NULL DEFAULT '',
    status_class    SMALLINT NOT NULL DEFAULT 0,
    block_stage     TEXT NOT NULL DEFAULT '',
    count           BIGINT NOT NULL DEFAULT 0,
    latency_sum_ms  DOUBLE PRECISION NOT NULL DEFAULT 0,
    bytes_sum       BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_start, host_id, domain, status_class, block_stage)
);

INSERT INTO analytics_hourly_v3 (bucket_start, host_id, domain, status_class, block_stage, count, latency_sum_ms, bytes_sum)
SELECT bucket_start, host_id, domain, status_class, '',
       SUM(count), SUM(latency_sum_ms), SUM(bytes_sum)
FROM analytics_hourly
GROUP BY bucket_start, host_id, domain, status_class;

DROP TABLE analytics_hourly;
ALTER TABLE analytics_hourly_v3 RENAME TO analytics_hourly;
CREATE INDEX analytics_hourly_bucket_idx ON analytics_hourly (bucket_start DESC);

CREATE TABLE analytics_daily_v3 (
    bucket_start    TIMESTAMPTZ NOT NULL,
    host_id         TEXT NOT NULL DEFAULT '',
    domain          TEXT NOT NULL DEFAULT '',
    status_class    SMALLINT NOT NULL DEFAULT 0,
    block_stage     TEXT NOT NULL DEFAULT '',
    count           BIGINT NOT NULL DEFAULT 0,
    latency_sum_ms  DOUBLE PRECISION NOT NULL DEFAULT 0,
    bytes_sum       BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_start, host_id, domain, status_class, block_stage)
);

INSERT INTO analytics_daily_v3 (bucket_start, host_id, domain, status_class, block_stage, count, latency_sum_ms, bytes_sum)
SELECT bucket_start, host_id, domain, status_class, '',
       SUM(count), SUM(latency_sum_ms), SUM(bytes_sum)
FROM analytics_daily
GROUP BY bucket_start, host_id, domain, status_class;

DROP TABLE analytics_daily;
ALTER TABLE analytics_daily_v3 RENAME TO analytics_daily;
CREATE INDEX analytics_daily_bucket_idx ON analytics_daily (bucket_start DESC);
