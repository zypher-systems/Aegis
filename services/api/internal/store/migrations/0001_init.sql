CREATE TABLE users (
    id            UUID PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'admin',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE hosts (
    id                UUID PRIMARY KEY,
    domain_names      TEXT[] NOT NULL,
    upstream_scheme   TEXT NOT NULL DEFAULT 'http',
    upstream_host     TEXT NOT NULL,
    upstream_port     INT NOT NULL DEFAULT 80,
    enabled           BOOLEAN NOT NULL DEFAULT TRUE,
    tls_mode          TEXT NOT NULL DEFAULT 'auto',
    cert_id           UUID,
    force_https       BOOLEAN NOT NULL DEFAULT TRUE,
    hsts              BOOLEAN NOT NULL DEFAULT FALSE,
    websocket_support BOOLEAN NOT NULL DEFAULT TRUE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Certificate material is envelope-encrypted (AES-256-GCM) before storage.
CREATE TABLE certificates (
    id           UUID PRIMARY KEY,
    domains      TEXT[] NOT NULL,
    issuer       TEXT NOT NULL,           -- 'letsencrypt' | 'selfsigned' | 'custom'
    cert_pem_enc TEXT NOT NULL,
    key_pem_enc  TEXT NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE nodes (
    id              UUID PRIMARY KEY,
    name            TEXT NOT NULL,
    agent_version   TEXT NOT NULL DEFAULT '',
    cert_serial     TEXT NOT NULL,
    cert_expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Small encrypted key/value store for CA key, ACME account key, etc.
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value_enc  TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE licenses (
    id         UUID PRIMARY KEY,
    key        TEXT NOT NULL,
    payload    JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
