# Configuration reference

Env bootstrap lives in `.env` (see `.env.example`). Settings in the dashboard
wins for tokens and lists that say so below.

## Required

| Variable | What |
|---|---|
| `AEGIS_SECRET_KEY` | Base64 32 bytes. Unwraps CA, cert keys, settings. Losing it is unrecoverable. |
| `AEGIS_ENROLL_TOKEN` | Bootstrap token that enrols the **first** proxy node only. Every later node (or a re-enrolment) uses a token generated in Settings → Edge → Enrolment tokens: shown once, one use and one hour by default. |
| `POSTGRES_PASSWORD` | Postgres user password. Required; no compose default. |
| `CROWDSEC_BOUNCER_KEY` | L7 bouncer key. Required; no compose default. |
| `CROWDSEC_FIREWALL_KEY` | nftables bouncer key. Required; must differ from L7. |

## TLS / ACME

| Variable | What |
|---|---|
| `AEGIS_SELFSIGNED` | `true` for local/e2e. Production: `false`. |
| `AEGIS_ACME_EMAIL` | Required when self-signed is false. |
| `AEGIS_ACME_DIRECTORY` | Let's Encrypt production by default. Use staging until HTTP-01 works. |
| `AEGIS_ACME_SKIP_TLS` | Pebble / test CAs only. |
| `AEGIS_CF_API_TOKEN` | Bootstrap for DNS-01 wildcards. Settings → Cloudflare wins once saved. DNS-01 precheck uses 1.1.1.1 / 8.8.8.8 so split-horizon internal NS cannot hide the TXT. |

## Dashboard / identity

| Variable | What |
|---|---|
| `AEGIS_PUBLIC_ORIGIN` | Extra origin the CSRF check accepts. Opening the dashboard directly (any IP or name that reaches it) always works; set this only when a proxy in front of the dashboard changes its Host. Mutating admin routes require an Origin header. |
| `API_PORT` / `WEB_PORT` | Host ports for API (`18080`) and dashboard (`3300`). |
| `AEGIS_REQUEST_LOG` | What the request log behind request details and Analytics → Requests keeps: `all` (default), `security` (only requests a layer blocked or the WAF flagged), or `off`. The live feed works either way. |
| `AEGIS_REQUEST_LOG_DAYS` | Days to keep served requests. Default `7`. Roughly 1 KB per request in Postgres. |
| `AEGIS_SECURITY_LOG_DAYS` | Days to keep blocked and WAF-flagged requests. Default `30`, never less than `AEGIS_REQUEST_LOG_DAYS`. |
| `AEGIS_METRICS_TOKEN` | Bearer token that reads `GET /api/metrics`. Unset = only a signed-in admin can. |
| `API_BIND` / `WEB_BIND` | Host interface. `.env.example` sets `WEB_BIND=0.0.0.0` (LAN) and `API_BIND=127.0.0.1`; compose falls back to `127.0.0.1` for both if unset. Never forward them on your router. The dashboard only needs `WEB_BIND`. |

## Certificates

Let's Encrypt certificates renew in place, hourly, once they are within the
renewal window (Settings → Edge → Certificate renewal; default 30 days,
7–60). Each certificate can have auto-renew turned off, be renewed now, or be
downloaded (chain only; private keys never leave the API). Uploaded and
self-signed certificates are never renewed: a notice and alert fire 14 days
before one that a host uses expires. Proxies staple OCSP responses to every
handshake when the certificate names a responder.

## WAF policy and tuning

CRS's stock protocol policy is written for a form-posting website: it allows
only `GET HEAD POST OPTIONS`, six request content types, and scores the
`Expect`, `Content-Encoding` and `Content-Range` headers as attacks. That
blocks REST APIs (`PUT`/`PATCH`/`DELETE`), `text/plain` beacons, binary
uploads and any client that sends `Expect: 100-continue`, at paranoia level 1
and before any attack rule runs. Aegis profiles start wider (REST methods, a
broad content-type list, those three headers allowed) and each profile can
tighten or loosen this under **Protocol policy** (a WebDAV preset adds the
Nextcloud/CalDAV methods).

To tune a profile, run it in Detect for a few days and open **WAF →
Findings**: every rule that matched, with hit counts, the input it matched,
sample values and paths. Each row offers **Allow this input** (the rule keeps
inspecting everything else), **Off under `<path>`**, **Off everywhere**, and
**Show requests**; the first three open the profile with the exclusion filled
in. The same three scopes are on a request's details. Rule ids in the
exclusion editor autocomplete against the CRS catalog and show the rule's
name.

## Metrics

Each proxy serves Prometheus text at `http://127.0.0.1:80/metrics` inside its
container (loopback only, like `/healthz`; not reachable through a host).
Counters per host: `aegis_proxy_requests_total`,
`aegis_proxy_responses_total{class}`, `aegis_proxy_blocked_total{stage}`,
`aegis_proxy_waf_matches_total{action}`, `aegis_proxy_upstream_errors_total{code}`;
gauges `aegis_proxy_config_version`, `aegis_proxy_hosts`,
`aegis_proxy_problems`, `aegis_proxy_disabled`. Scrape it with a sidecar or
`docker compose exec proxy /aegis-proxy healthcheck`-style local access;
publishing it needs a reverse-proxy rule of your own.

`aegis_proxy_upstream_healthy{host,upstream}` is 1 while an origin passes its
health checks.

`/readyz` (loopback) is 200 only when a config is loaded and the node is not
revoked; the compose health check uses it.

The control plane serves `GET /api/metrics` (port `18080` by default):
`aegis_api_nodes{state}`, `aegis_api_node_cert_expiry_seconds{node}`,
`aegis_api_hosts{kind,enabled}`, `aegis_api_certificate_expiry_seconds`,
`aegis_api_certificates_expiring_soon`, `aegis_api_notices{kind}`,
`aegis_api_dependency_up`,
`aegis_api_config_version` and `aegis_api_http_responses_total{class}`. Set
`AEGIS_METRICS_TOKEN` and scrape with `Authorization: Bearer <token>`; with
it unset the endpoint needs an admin session, so nothing leaks to an
anonymous caller. Keep the API bound to the LAN either way.

## Sign-in protection

Ten failed sign-ins from one address in 10 minutes block that address, and
ten wrong passwords for one account in 15 minutes lock that account for 15
minutes from every address (an alert is sent). A successful sign-in clears
the account's count. Basic-auth hosts have their own limiter (see Access
lists).

## Alerts

Settings → Alerts takes one webhook URL. Aegis calls it when an operator
notice is raised and again when it resolves: a certificate that will not
renew, a node offline for 2 minutes or within 14 days of losing its
certificate, a WAF profile that failed to
compile on a node, a node that cannot reach CrowdSec, a node with no GeoIP
database while hosts use country rules. Slack and Discord incoming webhooks
render the message as-is (`text` / `content`); other receivers get JSON with
`source`, `status` (`raised` | `resolved` | `test`), `kind`, `resource_id`,
`title`, `detail`, `at`. Delivery is retried twice; the URL is stored
encrypted and never shown back in full. "Send test" posts a test event.

## Proxy

| Variable | What |
|---|---|
| `PROXY_HTTP_PORT` / `PROXY_HTTPS_PORT` | Host ports for the edge. Defaults 80/443. |
| `AEGIS_GEOIP_MMDB` | Country MMDB inside api and proxy. Images default to baked DB-IP Country Lite at `/usr/share/aegis/geoip/country.mmdb`. Set `none` to disable. Country allow/deny only; CrowdSec lists cover most of the same job. |
| `AEGIS_TRUSTED_PROXY_CIDRS` | Hops whose `X-Forwarded-For` we honour. Empty = connecting address. Settings wins. |
| `AEGIS_ERROR_PAGE` | Optional path (inside the proxy container) to an `html/template` used for the proxy's own error responses (blocked requests, unknown host when `AEGIS_UNKNOWN_HOST=page`, 502/504, 413, 429). Fields: `.Status`, `.Title`, `.Message`, `.RequestID`, `.Host`, `.Time`. Browsers get the page; other clients get one line of text with the same request ID. A broken template is logged and the built-in page is kept. |
| `AEGIS_UNKNOWN_HOST` | What a request for a name no enabled host serves gets. `drop` (default): nothing. Over HTTPS the handshake is cut before the edge sends a byte (this includes requests with no SNI, such as `https://<ip>/`); over HTTP the connection is closed without a response, logged as status 444. A refused handshake is not an HTTP request and leaves no access-log line. `page`: the pre-1.7.2 behaviour, a self-signed placeholder certificate and the 404 error page. ACME challenge tokens are answered either way. |
| `AEGIS_ACCESS_LOG` | Proxy nginx-combined log for CrowdSec (`/var/log/aegis/access.log`). Rotates itself at 100 MB, keeping three older copies (`.1`–`.3`), so it never exceeds ~400 MB. Container stdout/stderr is capped by compose at 5 × 20 MB per service. |

HTTP listeners use `ReadHeaderTimeout` 10s and `IdleTimeout` 120s (keep-alive
between requests). There is no whole-request read or write timeout: each host
applies an **idle timeout** (default 60 s with no bytes moving in either
direction) and an **upstream response timeout** (default 60 s to the first
byte, then 504), both editable per host under Timeouts and limits, plus an
optional **max request body** (413 past it). A WAF profile inspects the first
1 MiB of a body by default (editable 16 KiB–64 MiB) and forwards the rest
uninspected rather than rejecting the request. TCP stream sessions idle out after 60s, same as UDP.

WAF and rate limit inspect the WebSocket upgrade request. Frames after the
handshake are not inspected.

### Upstreams

A proxy host lists one or more origins. **Failover** (default) sends every
request to the first healthy origin in order; **round robin** rotates over
the healthy ones in proportion to their weights (1–100, smooth weighting so a
5:1 split is A A A B A A rather than five in a row). Each node probes every
origin every 5 s: a TCP connect by default, or a `GET` of the host's **health
check path** when one is set (sent with the host's own name as `Host`, or the
upstream's when the host header mode says so). Any answer below 500 counts as
healthy, so a 404 at the path does not take an origin out; a 5xx, a refused
connection or no answer within 4 s does. Two failed probes remove an origin
from rotation, one good probe restores it, and a connection failure while
proxying removes it at once. A removed origin raises a notice (and alert)
naming the host, the origin and the error, cleared when it recovers. A
request that fails to *connect* is retried on the next origin when its body
is under 1 MiB; a request the origin accepted is never replayed.

A CrowdSec config apply keeps the live decision cache until the LAPI stream
has a first payload. A WAF compile failure keeps the last-good engine for
that host, or fails open (no 503) if there is none.

## CrowdSec

| Variable | What |
|---|---|
| `CROWDSEC_BOUNCER_KEY` | L7 stream (`origins=crowdsec`). Required; seeds `crowdsec.lapi`. |
| `CROWDSEC_FIREWALL_KEY` | nftables stream (`CAPI`, `cscli`, `lists`). Required; must differ from the L7 key. |
| `CROWDSEC_MACHINE_PASSWORD` | Watcher password so Analytics can add/delete `cscli` bans. |
| `CROWDSEC_MACHINE_ID` | Default `aegis-api`. |
| `CROWDSEC_ENROLL_KEY` | Optional CrowdSec console. Community lists work without it. |
| `CROWDSEC_LAPI_PORT` | Host bind for LAPI (`18081`) if you need to debug `cscli`. |

Settings → Host firewall writes `firewall.enabled` on the `crowdsec-control`
volume. The bouncer watches that file; the API has no Docker socket.

## Data at rest

Named volumes: `pgdata`, `redisdata`, `proxystate`, `crowdsec-data`,
`crowdsec-config`, `crowdsec-control`, `aegis-logs`. `proxystate` holds an
AES-256-GCM envelope of last-known-good, keyed from the node identity.
See [backup.md](backup.md). Origin auth is not in Aegis; see
[origin-auth.md](origin-auth.md).
