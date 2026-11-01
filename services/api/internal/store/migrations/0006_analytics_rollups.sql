CREATE TABLE analytics_hourly (
    bucket_start    TIMESTAMPTZ NOT NULL,
    host_id         TEXT NOT NULL DEFAULT '',
    node_id         TEXT NOT NULL DEFAULT '',
    domain          TEXT NOT NULL DEFAULT '',
    path            TEXT NOT NULL DEFAULT '',
    country         TEXT NOT NULL DEFAULT '',
    status_class    SMALLINT NOT NULL DEFAULT 0,
    count           BIGINT NOT NULL DEFAULT 0,
    latency_sum_ms  DOUBLE PRECISION NOT NULL DEFAULT 0,
    bytes_sum       BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_start, host_id, node_id, domain, path, country, status_class)
);

CREATE INDEX analytics_hourly_bucket_idx ON analytics_hourly (bucket_start DESC);

CREATE TABLE analytics_daily (
    bucket_start    TIMESTAMPTZ NOT NULL,
    host_id         TEXT NOT NULL DEFAULT '',
    node_id         TEXT NOT NULL DEFAULT '',
    domain          TEXT NOT NULL DEFAULT '',
    path            TEXT NOT NULL DEFAULT '',
    country         TEXT NOT NULL DEFAULT '',
    status_class    SMALLINT NOT NULL DEFAULT 0,
    count           BIGINT NOT NULL DEFAULT 0,
    latency_sum_ms  DOUBLE PRECISION NOT NULL DEFAULT 0,
    bytes_sum       BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_start, host_id, node_id, domain, path, country, status_class)
);

CREATE INDEX analytics_daily_bucket_idx ON analytics_daily (bucket_start DESC);
