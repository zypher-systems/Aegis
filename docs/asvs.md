# Admin app hardening (engineering self-check)

This is **not** an OWASP ASVS assessment. It names no ASVS level, cites no
requirement IDs, and covers the control plane plus dashboard only. The data
plane (public TLS termination) is out of scope here. Re-run 2026-09-09 as
part of 1.4.1 after CSRF Origin was required and localhost/`127.0.0.1`
were treated as equivalent.

| Control | Status |
|---|---|
| Session cookie HttpOnly, SameSite=Lax, Secure when TLS | Done |
| CSRF Origin allowlist + synchronizer token (`aegis_csrf` / `X-CSRF-Token`) | Done — mutating admin routes require Origin; `localhost` ≡ `127.0.0.1`; login/setup are token-exempt (cookie is issued on success) |
| Login rate-limit (Redis, 10 / 10 min) | Done — keyed on trusted-proxy-aware client IP |
| Client IP defaults to `RemoteAddr`; `X-Forwarded-For` only from trusted CIDRs | Done — Settings + `AEGIS_TRUSTED_PROXY_CIDRS`; empty list is the edge default |
| Passwords argon2id | Done |
| Secrets encrypted at rest (AES-256-GCM) | Done |
| License blob never returned or logged | Done — Settings paste is write-only; audit redacts `key`/`token`/`password` |
| Security headers on API JSON and Next responses | Done |
| mTLS for node config/telemetry | Done |
| Node revoke / cert denylist | Done — `DELETE /api/nodes/{id}`; handshake and Watch refuse the serial |
| Data plane never opens Postgres | Done |
| Last-known-good config snapshot on proxy boot | Done — encrypted AES-256-GCM `last_config.pb`; 0600; plaintext files refused |
| OIDC forward-auth not in the shipped pipeline | Done — cut permanently (D-OIDC); [origin-auth.md](origin-auth.md) |
| Non-root distroless images | Done |
| Trivy HIGH/CRITICAL fails the build job (`--ignore-unfixed`) | Done |

Parked: TOTP, dashboard SSO, RBAC, `__Host-` cookie prefix (2.1.0).

Still open: fail-closed licence (2.0.0).
