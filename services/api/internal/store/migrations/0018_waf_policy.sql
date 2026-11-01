-- 1.7.2: protocol policy per WAF profile. CRS's own defaults block PUT/PATCH/
-- DELETE, text/plain and octet-stream bodies, and the Expect and
-- Content-Encoding headers, which breaks REST APIs and SDKs before any attack
-- rule runs. Existing profiles get the Aegis defaults.
ALTER TABLE waf_profiles ADD COLUMN IF NOT EXISTS allowed_methods TEXT[] NOT NULL
    DEFAULT '{GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS}';
ALTER TABLE waf_profiles ADD COLUMN IF NOT EXISTS allowed_content_types TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE waf_profiles ADD COLUMN IF NOT EXISTS any_content_type BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE waf_profiles ADD COLUMN IF NOT EXISTS restricted_headers TEXT[] NOT NULL DEFAULT '{}';
