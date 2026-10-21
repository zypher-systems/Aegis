CREATE TABLE access_lists (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL,
    satisfy     TEXT NOT NULL DEFAULT 'all',
    users       JSONB NOT NULL DEFAULT '[]',
    allow_cidrs TEXT[] NOT NULL DEFAULT '{}',
    deny_cidrs  TEXT[] NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE hosts
    ALTER COLUMN upstream_host DROP NOT NULL,
    ALTER COLUMN upstream_host SET DEFAULT '',
    ADD COLUMN kind            TEXT NOT NULL DEFAULT 'proxy',
    ADD COLUMN redirect_url    TEXT NOT NULL DEFAULT '',
    ADD COLUMN redirect_code   INT NOT NULL DEFAULT 301,
    ADD COLUMN request_headers JSONB NOT NULL DEFAULT '{}',
    ADD COLUMN response_headers JSONB NOT NULL DEFAULT '{}',
    ADD COLUMN access_list_id  UUID REFERENCES access_lists(id) ON DELETE SET NULL,
    ADD COLUMN listen_protocol TEXT NOT NULL DEFAULT '',
    ADD COLUMN listen_port     INT NOT NULL DEFAULT 0;

UPDATE hosts SET upstream_host = '' WHERE upstream_host IS NULL;
