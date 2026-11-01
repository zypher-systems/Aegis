ALTER TABLE waf_profiles
    ADD COLUMN mode TEXT NOT NULL DEFAULT 'block',
    ADD COLUMN paranoia INT NOT NULL DEFAULT 1,
    ADD COLUMN inbound_threshold INT NOT NULL DEFAULT 5,
    ADD COLUMN disabled_tags TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN exclusions JSONB NOT NULL DEFAULT '[]';

ALTER TABLE waf_profiles DROP COLUMN rule_ids;
