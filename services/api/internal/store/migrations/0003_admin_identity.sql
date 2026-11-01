ALTER TABLE users
    ADD COLUMN session_epoch INT NOT NULL DEFAULT 0;

CREATE TABLE audit_events (
    id            UUID PRIMARY KEY,
    at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id      UUID,
    actor_email   TEXT NOT NULL DEFAULT '',
    action        TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id   TEXT NOT NULL DEFAULT '',
    summary       JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX audit_events_at_desc ON audit_events (at DESC);
