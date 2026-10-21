-- 1.7.2: enrolment tokens are short-lived and single-use. The env token only
-- enrols the first node; after that only tokens from this table are accepted.
CREATE TABLE IF NOT EXISTS enroll_tokens (
    id          UUID PRIMARY KEY,
    token_hash  TEXT NOT NULL UNIQUE,
    label       TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    uses_left   INTEGER NOT NULL DEFAULT 1
);
