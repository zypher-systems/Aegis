-- B9: a hostname belongs to one host. Overlapping TEXT[] values were
-- allowed and the proxy last-write-wins on apply. Newer hosts lose the
-- colliding name; a host left with no names is deleted.

UPDATE hosts AS h
SET domain_names = kept.names
FROM (
    SELECT
        h2.id,
        COALESCE(ARRAY(
            SELECT DISTINCT ON (lower(btrim(d))) lower(btrim(d))
            FROM unnest(h2.domain_names) WITH ORDINALITY AS t(d, ord)
            WHERE btrim(d) <> ''
              AND NOT EXISTS (
                  SELECT 1
                  FROM hosts older
                  CROSS JOIN unnest(older.domain_names) AS od
                  WHERE older.id <> h2.id
                    AND lower(btrim(od)) = lower(btrim(d))
                    AND (
                        older.created_at < h2.created_at
                        OR (older.created_at = h2.created_at AND older.id < h2.id)
                    )
              )
            ORDER BY lower(btrim(d)), ord
        ), '{}'::text[]) AS names
    FROM hosts h2
) AS kept
WHERE h.id = kept.id;

DELETE FROM hosts WHERE cardinality(domain_names) = 0;

CREATE TABLE host_domains (
    domain  TEXT PRIMARY KEY,
    host_id UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE INDEX host_domains_host_id_idx ON host_domains (host_id);

CREATE OR REPLACE FUNCTION sync_host_domains() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM host_domains WHERE host_id = NEW.id;
    INSERT INTO host_domains (domain, host_id)
    SELECT DISTINCT lower(btrim(d)), NEW.id
    FROM unnest(NEW.domain_names) AS d
    WHERE btrim(d) <> '';
    RETURN NEW;
END;
$$;

CREATE TRIGGER hosts_sync_domains
    AFTER INSERT OR UPDATE OF domain_names ON hosts
    FOR EACH ROW EXECUTE FUNCTION sync_host_domains();

INSERT INTO host_domains (domain, host_id)
SELECT DISTINCT lower(btrim(d)), h.id
FROM hosts h
CROSS JOIN unnest(h.domain_names) AS d
WHERE btrim(d) <> '';
