-- Dedicated country rollup. The main hourly/daily grain stays host + domain +
-- status + stage. Country was removed from that PK in 0008 because path and
-- country exploded it. ~250 ISO codes is a safe separate table.

CREATE TABLE analytics_geo_hourly (
    bucket_start TIMESTAMPTZ NOT NULL,
    host_id      TEXT NOT NULL DEFAULT '',
    country      TEXT NOT NULL DEFAULT '',
    count        BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_start, host_id, country)
);
CREATE INDEX analytics_geo_hourly_bucket_idx ON analytics_geo_hourly (bucket_start DESC);

CREATE TABLE analytics_geo_daily (
    bucket_start TIMESTAMPTZ NOT NULL,
    host_id      TEXT NOT NULL DEFAULT '',
    country      TEXT NOT NULL DEFAULT '',
    count        BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_start, host_id, country)
);
CREATE INDEX analytics_geo_daily_bucket_idx ON analytics_geo_daily (bucket_start DESC);
