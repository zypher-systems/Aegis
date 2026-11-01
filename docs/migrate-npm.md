# Migrate from nginx-proxy-manager

NPM is a single-box UI over nginx + Let's Encrypt. Aegis is a control plane
plus a Go data plane. There is no import of NPM's SQLite database. Recreate
hosts in the dashboard (or the REST API).

## Concept map

| NPM | Aegis |
|---|---|
| Proxy host | Host kind `proxy` |
| Redirection host | Host kind `redirect` |
| 404 host | Host kind `dead` |
| Stream host | Host kind `stream` (publish extra ports on the proxy) |
| SSL — Let's Encrypt | Certificates → request, or host `tls_mode=auto` |
| SSL — custom | Certificates → upload PEM, host `tls_mode=custom` |
| Force SSL | `force_https` |
| HSTS | `hsts` |
| Websockets | `websocket_support` |
| `proxy_set_header Host $host` (NPM default) | Default: the client's Host is sent upstream. "Host header sent upstream" can send the upstream's address or a custom value. |
| `proxy_read_timeout` / `proxy_send_timeout` / `send_timeout` (advanced) | Host → Timeouts and limits: "Upstream response timeout" (time to first byte, default 60 s) and "Idle timeout" (no data either way, default 60 s). No fixed cap on a whole response, so long downloads and event streams run as long as bytes keep moving. |
| `client_max_body_size` (NPM default 2000m) | Host → "Max request body". Blank = no limit at the edge. |
| Access list | Access Lists, then attach on the host |
| Custom locations / advanced nginx | Not a 1:1. Request/response headers on the host. No raw nginx. |
| CrowdSec (separate compose) | In-stack L7 per host; optional nftables bouncer |
| Fail2ban | CrowdSec (Analytics ban + CAPI lists). nftables bouncer is optional. |

## Suggested order

1. Install Aegis on a second box or a different port pair (`PROXY_HTTP_PORT`)
   so NPM keeps serving until you cut DNS.
2. Recreate access lists, then certificates (or let ACME issue).
3. Recreate each proxy host: domains, upstream (failover if several), TLS, WAF
   profile, CrowdSec, rate limit. GeoIP country lists are optional.
4. Point one test name at Aegis. Confirm Overview and Analytics.
5. Move the rest of the names. Stop NPM last.

## What will not come over

- NPM "advanced" nginx snippets and custom locations
- NPM users / permissions (Aegis is all-admins until RBAC)
- NPM's Let's Encrypt account — Aegis has its own ACME account
- Audit history

WAF is Coraza + OWASP CRS (profiles), not NPM's optional ModSecurity add-on.
