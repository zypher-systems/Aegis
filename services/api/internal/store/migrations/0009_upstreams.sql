-- Multiple origins per host. Legacy scheme/host/port stay as a copy of the
-- first target so older snapshots and the table view keep working.

ALTER TABLE hosts ADD COLUMN IF NOT EXISTS upstreams JSONB NOT NULL DEFAULT '[]'::jsonb;

UPDATE hosts
SET upstreams = jsonb_build_array(
    jsonb_build_object(
        'scheme', COALESCE(NULLIF(upstream_scheme, ''), 'http'),
        'host', COALESCE(upstream_host, ''),
        'port', COALESCE(upstream_port, 0)
    )
)
WHERE COALESCE(upstream_host, '') <> ''
  AND (upstreams = '[]'::jsonb OR upstreams IS NULL);
