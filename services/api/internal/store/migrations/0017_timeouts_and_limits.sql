-- 1.7.2: per-host timeouts and body limit, per-profile WAF inspection limit.
-- 0 = default (60 s idle, 60 s to first byte, no body limit). WAF profiles
-- default to inspecting the first 1 MiB of a body instead of rejecting
-- anything over 128 KiB.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS idle_timeout_seconds INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS upstream_response_timeout_seconds INTEGER NOT NULL DEFAULT 0;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS max_body_bytes BIGINT NOT NULL DEFAULT 0;
ALTER TABLE waf_profiles ADD COLUMN IF NOT EXISTS body_limit_bytes INTEGER NOT NULL DEFAULT 1048576;
