-- 1.7.2: logout revokes the session server-side instead of only clearing the
-- cookie. Rows are pruned once the session would have expired anyway.
CREATE TABLE IF NOT EXISTS revoked_sessions (
    jti        TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS revoked_sessions_expires_idx ON revoked_sessions (expires_at);
