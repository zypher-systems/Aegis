CREATE TABLE waf_profiles (
    id         UUID PRIMARY KEY,
    name       TEXT NOT NULL,
    rule_ids   TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE hosts
    ADD COLUMN waf_profile_id UUID REFERENCES waf_profiles(id) ON DELETE SET NULL;

ALTER TABLE hosts
    DROP COLUMN waf_exclusions,
    DROP COLUMN waf_enabled;
