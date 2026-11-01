-- 1.7.1: which Host header a proxy host sends upstream.
--   ''          the client's Host (default; what nginx-proxy-manager does)
--   'upstream'  the upstream's own address (host:port), the 1.7.0 behaviour
--   anything else  that literal value
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS upstream_host_header TEXT NOT NULL DEFAULT '';
