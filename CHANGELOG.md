# Changelog

All notable changes to Aegis are documented in this file.

## [Unreleased] — 1.8.0

The Graphite theme with a light alternate, and an Overview that says more.

### Changed

- **Published images.** `ghcr.io/zypher-systems/aegis-api`, `aegis-proxy`, and
  `aegis-web` for linux/amd64 and linux/arm64. `:latest` and the `VERSION`
  tags track `main`; `sha-<commit>` is that build. The firewall bouncer is
  still built on the box.
- **The Graphite palette, and a light theme.** The dashboard takes the
  palette Argus uses: neutral greys with no tint, one blue accent
  (`#6c9dff` dark, `#1f5bd8` light) for actions, links and the served-traffic
  line, and green, amber and red only on status marks. The mint accent is
  gone. Dark stays the default; a light theme is new, switched from the
  account menu and remembered per browser. Layouts are unchanged.
  - A passing posture score, the live indicator and "layers on" are green
    (status), no longer the accent colour.
  - Block stages in the donut and bars have their own five colours instead of
    borrowing the warning and danger colours.
  - Form fields have a border that clears 3:1, and the "Remove license"
    button's label is readable in the dark theme.
  - The proxy's built-in error page and the favicon use the new colours.
- **A more informative Overview.** The page keeps its place and theme and
  says more:
  - Five figures across the top (requests served, requests blocked, average
    response time, upstream 5xx rate, data sent), each with its trend and a
    comparison with the period before.
  - A 24h / 7d / 30d range, as on Analytics. The traffic chart draws the
    period before as a dotted line when there is one.
  - **Needs attention** replaces the posture ring: each check that does not
    pass names the hosts, nodes or certificates it is about and links to
    where it is fixed; the passing ones are listed below, with the score.
  - **Busiest hosts**: served, blocked, 5xx rate and average latency per
    host, and the protection layers each has on. A proxy host without HTTPS
    or a WAF is marked.
  - **Edge nodes**: requests per second, median and 99th-percentile latency
    per node.
  - The stage donut and attack origins are on Analytics, where they already
    were; Overview no longer repeats them.
  - Its figures are summed by the API rather than in the browser:
    `GET /api/analytics/rollups` takes `group=bucket` (hosts summed away) or
    `group=host` (buckets summed away, busiest host first), so the number of
    hosts no longer decides how much of a range fits in one response. Every
    rollups response now carries `truncated`, true when more rows matched
    than the 2000 it returns; Overview then makes no comparison with the
    period before rather than one against missing buckets.
  - The period before is counted up to the same point in its last bucket as
    the current one, so steady traffic does not read as a drop.

### Security

- **Go 1.27.3.** The api and proxy build on Go 1.27 (was 1.25, which has no
  fix for CVE-2026-111943, -78667, -78669 or -97031), with
  `golang.org/x/net` 0.60.0.
- **Coraza 3.8.1** fixes CVE-2026-107826 and CVE-2026-41510 in the WAF.
- **Next.js 15.5.28** fixes an unauthenticated remote code execution in the
  image optimizer (GHSA-2464-fhr4-w9xw) and CVE-2026-94482, and the CVEs
  that were ignored for 15.5.25. `sharp` 0.35.5 and `source-map-js` 1.2.2.
- **No npm in the web image.** The dashboard runs `node server.js`; the
  base image's npm is removed.

## [Unreleased] — 1.7.2

Production-readiness fixes from the pre-cutover audit.

### Added

- **Alerts.** Settings → Alerts takes a webhook URL (Slack and Discord
  incoming webhooks work as-is; anything else gets JSON). It is called when a
  notice is raised and when it resolves: a certificate that will not renew, a
  node offline or about to lose its certificate, the license in grace or
  lapsed, a WAF profile that failed to compile on a node, a node that cannot
  reach CrowdSec, a node without a GeoIP database while hosts use country
  rules. Until now the only signal for any of these was a banner on the
  Overview.
- **WAF profiles ship an API-friendly protocol policy and can edit it.** CRS's
  stock policy blocked `PUT`/`PATCH`/`DELETE` (rule 911100), `text/plain` and
  `application/octet-stream` bodies (920420) and the `Expect`,
  `Content-Encoding` and `Content-Range` headers (920450) at paranoia level
  1, before any attack rule ran: every REST API, SDK upload and beacon failed
  on a Block host. Profiles now default to REST methods, a broad content-type
  list and those three headers allowed, with a Protocol policy section to
  tighten or loosen each (and a WebDAV preset for Nextcloud/CalDAV). Existing
  profiles pick up the new defaults.
- **WAF → Findings**: every rule that matched in the request log, grouped,
  with hit counts, the input and value it matched, sample paths and hosts,
  and one-click exclusions at the right scope (this input / under this path /
  everywhere) that open the profile prefilled. A request's details offer the
  same three scopes.
- The exclusion editor names rules (autocomplete over the bundled CRS catalog,
  `GET /api/waf/catalog`) and validates rule ids and paths, so a typo cannot
  become a stray SecLang directive.
- Nodes report their own problems to the control plane (WAF compile
  failures, CrowdSec stream state, missing GeoIP), so the dashboard no longer
  shows a WAF as on while a node is silently running without it.

- **Certificate renewal is visible and controllable.** The Certificates page
  shows what will happen to each certificate (auto-renews in N days, renews
  at the next check, renewal failing with the next attempt time, auto-renew
  off, uploaded / self-signed: not renewed) and offers **Renew now**,
  **auto-renew on/off** and **Download certificate (PEM)** per certificate.
  Settings → Edge → Certificate renewal sets how many days before expiry
  Let's Encrypt certificates renew (7–60, default 30). A notice and alert
  fire 14 days before an uploaded (or auto-renew-off) certificate that a host
  uses expires; until now only ACME failures raised one.
- **OCSP stapling.** Each proxy fetches OCSP responses for the certificates it
  serves and staples them to the handshake, refreshing at the half-life.
  Certificates without a responder are served as before.
- **HSTS options per host**: max-age (6 months, 1 or 2 years), includeSubDomains
  and preload, with the preload rules enforced. The header is sent only on
  HTTPS responses (including behind a trusted proxy that terminated TLS).
- **Error pages.** Responses the proxy writes itself (a blocked request, an
  unknown host, 502/504, 413, 429, a revoked node) are a small page with the
  status, a neutral sentence and the request ID, so a visitor can quote
  something an operator can find in Analytics. Browsers get HTML; API clients
  and curl get one line of text with the same ID. `AEGIS_ERROR_PAGE` points
  the proxy at your own template. The page never says which layer blocked a
  request or why.
- **Sessions end on logout and after 12 hours idle.** Logout now revokes the
  session server-side (a copied cookie stops working), sessions expire after
  12 hours without use (activity renews them, 7 days at most), and Settings →
  Account has **Sign out everywhere**. Every enrolment is written to the audit
  log and announced through the alert webhook.
- The proxy serves Prometheus metrics at `/metrics` (loopback only, like
  `/healthz`): requests, responses by class, blocks by layer, WAF matches and
  upstream errors per host, plus config version and reported problems.
- `/readyz` on the proxy reports whether a config is loaded and the node is
  not revoked; the compose health check uses it, so a node with nothing to
  serve shows unhealthy instead of green.
- **Enrolment tokens are generated, short-lived and single-use.** Settings →
  Edge → Enrolment tokens mints a token (one use and one hour by default, up
  to ten uses and a day), shows it once, lists the live ones and revokes them;
  each is audited. The `AEGIS_ENROLL_TOKEN` in `.env` now enrols only the
  **first** node; after that it is ignored, so a leaked env file can no
  longer add a rogue edge that would receive every certificate key. The
  "Rotate token" button is gone. See the upgrade notes.
- **Per-account sign-in lockout.** Ten wrong passwords for one account within
  15 minutes lock that account for 15 minutes from every address (the
  per-address limit stays), and the lockout is announced through the alert
  webhook.
- **Upstream health checks and weighted round robin.** A proxy host can name
  a health path that each node GETs on every upstream every 5 s (any answer
  below 500 is healthy, two failures take an origin out, one success brings
  it back); without a path the probe stays a TCP connect. Selection is
  failover (first healthy in order, as before) or weighted round robin. An
  origin that fails its checks raises a notice and alert naming the host, the
  origin and the error, cleared on recovery, and
  `aegis_proxy_upstream_healthy{host,upstream}` exposes each origin's state.
- **Control-plane metrics** at `GET /api/metrics`: nodes by state, node and
  server certificate expiry, hosts by kind, open notices by kind, license
  features, dependency health, config version and API responses by class.
  A scraper presents `AEGIS_METRICS_TOKEN` as a bearer token; without one an
  admin session is required.
- **Hosts: bulk actions, export and import.** Select hosts (list or cards) to
  enable, disable, delete, or set the access list or WAF profile on all of
  them at once. **Export** downloads every host as JSON with access lists,
  WAF profiles and custom certificates referenced by name; **Import** adds
  them on another install (skipping or replacing hosts whose domain exists)
  and reports anything it could not place rather than importing a host
  without its protection.
- Nodes can be renamed from the Nodes page.

### Changed

- **Requests for a name no host serves get no reply.** The edge used to
  answer them with a generic "No such site here" page (and, over HTTPS, a
  placeholder certificate), which told a scanner this address ran a web edge.
  It now drops them: over HTTPS the handshake is cut before the edge sends a
  byte, including requests with no SNI such as `https://<ip>/`; over HTTP the
  connection closes with no response (HTTP/2 resets the stream). A dropped
  HTTP request is logged as 444; a refused handshake never becomes a request,
  so it leaves no access-log line, metric or telemetry event, and CrowdSec
  does not see it. ACME challenge tokens are still answered.
  `AEGIS_UNKNOWN_HOST=page` on the proxy restores the page.

### Fixed

- **Host input was not validated.** A proxy host could point at the control
  plane, Postgres, Redis or a cloud-metadata address; domains with spaces,
  `javascript:` redirects, header values with newlines and two stream hosts on
  one port were all accepted. Each is now refused with a plain message; a
  mistyped access-list CIDR is rejected instead of silently never matching,
  and a trusted-proxy range covering every address is refused.
- Emails are matched case-insensitively (`Admin@Corp.com` and `admin@corp.com`
  are one account), and first-run setup and last-admin deletion cannot race
  into two first admins or zero admins.
- **A revoked node kept serving with its cached certificates forever.** It now
  stops serving (503), drops its stored config and identity, and needs the
  enrolment token to come back.
- Stream (TCP) listeners no longer die permanently on a transient accept or
  bind error; they back off and re-listen.
- Rate limiting keys IPv6 clients by /64, so one subscriber cannot spawn
  unlimited buckets (and exhaust the local cap) from one prefix.
- Untrusted clients could plant a fake first address in `X-Forwarded-For`
  (the proxy appended to whatever they sent); from an untrusted hop the header
  is now rewritten to that hop alone and the other client-IP headers
  (`Forwarded`, `CF-Connecting-IP`, …) are dropped. A trusted proxy's chain is
  kept.
- The config stream's 4 MB gRPC ceiling (a few hundred certificates) is raised
  to 64 MB on both ends, and the proxy's two config writers no longer race.
- Dashboard: an expired session on a page without polling said "csrf: token
  mismatch"; it now signs you out with a clear message and returns you to the
  same page after sign-in. Half-filled upstream rows are refused instead of
  silently dropped (which could promote a backup to primary). Switching the
  Analytics range quickly no longer shows stale data under the wrong label.
  Disabling a host asks first. Daily chart buckets are labelled by their UTC
  day. Dialogs ignore Escape and backdrop clicks while saving and ask before
  discarding edits.
- **The API sent its master key to every proxy node.** Each config snapshot
  carried `AEGIS_SECRET_KEY` in an unused field, so a node's state volume held
  the key that decrypts every certificate, the CA and the settings, and the
  same key signed admin sessions. The field is gone and sessions sign with a
  derived key (everyone is signed out once).
- **Node certificates expired after 90 days with nothing to renew them**, after
  which a proxy kept serving its last config but received no updates and sent
  no telemetry. Nodes now renew over the mTLS stream from 30 days out
  (`ConfigService.Renew`), re-enrol on restart if already expired and a token
  is set, and the Overview warns 14 days before a node's certificate lapses.
- **A renewed certificate could lose to the one it replaced.** Renewal added a
  second row and the proxy took whichever the snapshot listed last, so from
  the first renewal a site could serve the old certificate at random and, after
  day 90, an expired one. Renewals now replace the certificate in place, and
  the proxy serves the newest valid certificate for a name whatever order it
  receives them in (an expired one only when nothing valid covers the name).
- Switching `AEGIS_ACME_DIRECTORY` from Let's Encrypt staging to production
  re-issues the staging certificates instead of keeping them for 60 days. The
  issuing directory is stored per certificate and backfilled on first boot.
- Renewal only runs for certificates an enabled host uses, backs off from one
  hour to a day after failures instead of retrying hourly forever, and an
  issuance is no longer thrown away when the browser that triggered it closes.
- Wildcard certificates and wildcard hosts match one label, as browsers do:
  `*.example.com` no longer claims to cover `a.b.example.com`.
- A host whose certificate is not issued yet gets a self-signed placeholder
  certificate instead of a random customer certificate naming other hosts.
- **Long downloads, uploads and event streams were cut at 60 s** by a fixed
  whole-request timeout, and anything slower than 30 s to first byte was a
  502. Each host now has an idle timeout (default 60 s with no bytes moving,
  not a cap on the transfer), an upstream response timeout (default 60 s to
  first byte, then 504) and an optional max request body (413), under
  Timeouts and limits.
- **WAF Block mode rejected every request body over 128 KiB with 413**, so
  uploads failed on protected hosts. A profile now inspects the first 1 MiB
  (editable) and forwards the rest uninspected instead of rejecting.
- **Failover could replay a request the primary had already processed** and
  marked a healthy upstream down whenever a visitor closed the tab. A request
  is now retried on the next upstream only when the connection itself failed
  (refused, unreachable, DNS) and its body is empty or under 1 MiB; anything
  the upstream accepted is never sent twice, and client aborts (now 499, not
  logged as upstream errors) do not change upstream health. Upstream timeouts
  answer 504 instead of 502.
- **Restarts were hard kills.** The API waited forever on node streams that
  never end, so Docker killed it at 10 s with REST requests in flight; the
  proxy dropped every WebSocket and stream session at the same 10 s mark.
  Both now shut down in order within a 30 s `stop_grace_period`: the API ends
  node streams (proxies keep serving their last config and reconnect), drains
  REST and gRPC, and flushes the last telemetry; the proxy stops accepting,
  finishes in-flight requests, gives WebSockets and streams the rest of the
  budget, then closes them and sends its final telemetry batch.
- **Force HTTPS looped behind a trusted proxy and challenged for passwords
  over plain HTTP.** The redirect only looked at the connection, so a host
  set to TLS Auto + Force HTTPS behind NPM (which forwards plain HTTP)
  redirected forever; and access lists ran before the redirect, so a browser
  sent Basic credentials in the clear first. The redirect now honours a
  trusted proxy's `X-Forwarded-Proto`, drops a non-standard port from the
  target, and runs before any credential challenge (deny lists still apply
  first).
- **Basic-auth access lists were a CPU/memory hole.** Every request with an
  Authorization header cost a 64 MiB argon2id hash, including a logged-in
  browser's every asset, and failed guesses were unthrottled. Verified
  credentials are now remembered for 5 minutes, at most 4 hashes run at once
  (503 with Retry-After past that), and an IP that fails 5 times in 10
  minutes is refused for 10 minutes without hashing.
- Dashboard login throttling let every attempt through whenever Redis
  errored; it now falls back to an in-process counter. Unknown emails take
  as long to answer as wrong passwords.
- **Logs could fill the disk.** Container logs had no cap and the proxy's
  access log was never rotated, so a scanner campaign could fill the Docker
  data root and take Postgres down. Compose now caps every service's log at
  5 × 20 MB and the access log rotates itself at 100 MB keeping three copies.
- **Backups no longer stop the edge.** `scripts/backup.sh` takes a
  `pg_dump` plus the CrowdSec state while everything runs (the old runbook
  stopped the proxy and tarred a live data directory); `scripts/restore.sh`
  restores a dump with only the API and dashboard paused. `docs/backup.md`
  now includes a cron line and a rebuild-from-nothing checklist.

## 1.7.1

Edge hardening before Aegis replaces an internet-facing proxy.

### Fixed

- Telemetry from a proxy is no longer lost when the API restarts: the proxy
  reconnects as soon as the stream drops and re-sends what failed, instead of
  writing into the dead stream until the next send errored.
- **WAF Detect mode no longer flags every request.** A Detect-mode host marked
  each request as a WAF detection, named after whichever CRS bookkeeping rule
  ran last (typically 980014, a paranoia-level skip that matches everything),
  and real detections carried that id too instead of the rule that matched.
  Only CRS detection rules (911000–948999) flag a request now, and the
  request is labelled with the most severe one. Migration 0015 clears the
  false flags already in the request log.
- The live window (Overview live threats and attack origins, the live feed,
  top paths and clients) is reloaded from the request log when the API
  starts, instead of coming back empty after every restart or upgrade.
- The world map no longer draws streaks across the top for countries that
  cross the 180° meridian (Russia, Fiji).
- **Proxy hosts send the client's Host header upstream** (as nginx-proxy-manager
  does) instead of the upstream's address, so vhost routing, absolute URLs and
  WebSocket origin checks work behind Aegis. A per-host "Host header sent
  upstream" option can send the upstream's address or a custom value instead,
  and the choice holds on failover to a backup upstream.
- **Client IP behind a trusted proxy is read from the right of
  `X-Forwarded-For`**, skipping trusted hops. Taking the leftmost entry let a
  visitor behind NPM or a CDN spoof their address (and slip past rate limits,
  CrowdSec, GeoIP and IP access lists) by sending their own header.
- Behind a trusted proxy the upstream now gets that proxy's
  `X-Forwarded-Proto` (so apps behind NPM see `https`) and the real client IP
  in `X-Real-Ip`, not the proxy's address.
- **First login on a fresh install no longer crashes the dashboard.** Empty
  lists (hosts, nodes, certificates, …) were returned as `null` and the
  Overview called `.filter` on them. The API now returns `[]`, and the
  dashboard treats a `null` list as empty.
- A fresh install's Overview shows "Getting started / Add your first host"
  instead of scoring an empty install 100 and "Protected".
- `.env.example`: each required secret has its own generator line
  (`AEGIS_SECRET_KEY` is `openssl rand -base64 32`), `WEB_BIND=0.0.0.0` so the
  dashboard is reachable from the LAN out of the box (API stays on loopback),
  and `AEGIS_PUBLIC_ORIGIN` is documented as optional.
- WAF exclusions can target one input (`REQUEST_COOKIES:name`, `ARGS:q`,
  or a `/regex/` over names), optionally under a path, so a false positive
  such as PostHog's analytics cookie tripping 942290 can be excluded while the
  rule keeps inspecting everything else.
- WAF blocks and detections name the CRS rules that scored (in the proxy log,
  with their messages) and Analytics shows the top one, instead of only the
  generic anomaly rule 949110.
- Rate limiting is a real token bucket that honours both rate and burst. With
  Redis it is one atomic script shared by every node, and every key gets an
  expiry in the same step, so a client can no longer stay blocked for good.
- Per-node rate buckets are swept when idle and capped per host, so a flood
  from many addresses cannot grow memory without bound. They also survive
  config pushes instead of resetting.
- 429 responses carry `Retry-After`.
- The dashboard no longer pulls every CrowdSec decision on each refresh: the
  API pages, searches and filters them, with a 10-second cache in front of LAPI.
- The login page no longer makes a logout call that fails on CSRF.
- WAF profile routes use the same "needs an Aegis Pro license" message as
  every other gate.
- `./ae` runs under its own compose project (`aegis-tools`) so it cannot
  recreate the running stack's network.

### Added

- **Request details.** Any request in the dashboard (Overview live threats,
  the live feed, the new Requests explorer) opens a window with its source
  (client IP, country, the trusted proxy it came through, user agent,
  referer), destination (host, the upstream that answered, edge node,
  scheme / protocol / TLS version), the call (method, path, query and decoded
  parameters, body size, request ID) and the response, plus what each
  security layer decided and why ("country RU is denied", "over 10 req/s per
  client IP"). WAF blocks and detections list every CRS rule that matched,
  with its severity, the input it matched and the value, a link to other
  requests matching that rule, and "Exclude …" to open the host's WAF profile
  with the exclusion filled in. The client IP can be banned in CrowdSec from
  the same window.
- **Analytics → Requests**: the request log, filtered on the server by time,
  host, country, client IP, outcome (blocked / flagged / served), blocking
  layer, WAF rule, status, method, path or free text, and paged newest first.
  Filters live in the URL, so a view can be bookmarked or shared.
- Clicking through: countries (map and list), top paths and clients, WAF rule
  hits, top blocked clients, the "where attacks stop" donut and bars, CrowdSec
  L7 blocks, Overview's top attack origins and a chart's hour or day all open
  the matching requests.
- Chart hover: the traffic charts show the bucket's time range, served and
  blocked counts, blocked by layer, total and average latency (arrow keys
  when focused); the world map shows each country's count and share; the
  donut shows the hovered layer.
- CrowdSec decisions and audit log entries open a details window.
- The proxy sends `X-Request-Id` upstream (unless the client set one), so an
  app's own logs can be matched to the request in Aegis.
- `AEGIS_REQUEST_LOG`, `AEGIS_REQUEST_LOG_DAYS` and `AEGIS_SECURITY_LOG_DAYS`
  control what the request log keeps and for how long.
- `docs/cutover-from-npm.md`: a host-by-host runbook for moving an internet
  edge from nginx-proxy-manager, with rollback at every step.

## 1.7.0

Licensing on the Zypher `zsl2` contract, and the Shield dashboard.

### Added

- Settings → License: activate a key, request a 14-day trial, upload an offline
  license file, remove (releases the seat). `AEGIS_LICENSE_KEY` activates on boot.
- Signed `zsl2` leases and license files, verified against the compiled-in key
  and bound to this install. 14-day grace for paid licenses, with an app-wide
  banner showing when Pro features switch off.
- Edge nodes verify the license themselves and re-check every minute, so a
  lapse applies even while the control plane is down.
- `docs/licensing.md`: what is sent to the licensing server and when.
- Shield dashboard: posture-first Overview, host cards or list, tabbed
  Analytics and Settings, WAF/node/certificate cards, branded sign-in.

### Changed

- A Community install never contacts the licensing server; no hostname is sent.
- `AEGIS_LICENSE_DEV` works only in a `-tags licensedev` build (local/CI).
  Compose defaults it to `false`.
- CrowdSec bans, unbans and turning on the host firewall need the `crowdsec`
  entitlement on the server; the firewall bouncer follows the license.
- A plan's node limit is shown, never enforced on enrollment.

### Removed

- Anonymous `/v1/register` check-in and the unsigned TLS grant it applied.
- `aegis1` air-gap blobs (use a `zsl2` license file).

### Fixed

- Disabling a host from the Hosts list no longer strips its WAF profile,
  CrowdSec, GeoIP and rate limits.
- Nodes report their current version after an upgrade, not the enrolment one.

### Also in 1.7.0

- Compose publishes dashboard/API on `WEB_BIND` / `API_BIND` (default loopback).
  Set `WEB_BIND=0.0.0.0` for LAN access; keep `AEGIS_PUBLIC_ORIGIN` matching
  the URL in the browser.
- Certificates warns when `AEGIS_SELFSIGNED` is on. The dashboard rewrite waits
  up to 5 minutes so Cloudflare DNS-01 can finish.
- DNS-01 precheck uses 1.1.1.1 / 8.8.8.8 so split-horizon internal nameservers
  cannot make Let's Encrypt wait on a TXT they will never serve.
- GeoIP allow/deny skips RFC1918 and loopback, matching CrowdSec L7. Compose
  e2e clients were 403 on `k6.local` after the baked MMDB + fail-closed.
- Images and check-in report `AEGIS_VERSION` from `VERSION` (1.7.0). Publish
  on `main` tags `:1.7.0` instead of the leftover `:1.4.0` / `dev` stamp.
- Check-in no longer fails the grant when `offline_blob` does not match
  `pubkey.bin`.

## [1.6.0] — 2026-09-10

Dashboard polish: real charts on Overview and Analytics, a country
choropleth, 10s refresh.

### Added

- SVG time-series for requests vs blocked (24h / 7d / 30d).
- Country choropleth on Analytics from a dedicated geo rollup.
- `GET /api/analytics/geo`.
- DB-IP IP to Country Lite MMDB baked into api and proxy images (CC BY 4.0).

### Changed

- Overview and Analytics poll every 10s.

## [1.5.0] — 2026-09-09

Trust spine: tests for the CA, envelope, enrollment, identity, and password hashing.
Compose fails closed without secrets; services restart and report health.
Dashboard login and ACME issuance fail the pipeline. CrowdSec cache, WAF
compile, edge timeouts, WebSocket handshake inspection, and ACME renewal
banners.

### Added

- Table-driven tests for `ca`, `crypto`, `enroll`, `identity`, and `passwd`.
- Compose healthchecks for `api` (`/api/readyz`), `proxy` (loopback `/healthz`),
  and `web`. Restart policies and resource limits on the long-running services.
- Playwright against compose: setup or login, then create a host on Hosts.
- CI runs ACME issuance against in-stack Pebble after the happy-path.
- GitLab check: `-race` and a 60% coverage floor on the trust-spine packages.
- HTTP listener timeouts (header 10s, read/write 60s, idle 120s) and a 60s
  idle timeout on TCP stream sessions.
- `GET /api/notices` and an Overview banner when ACME renewal fails
  (`renew_failed` audit row, retry in one hour).

### Changed

- `POSTGRES_PASSWORD`, `CROWDSEC_BOUNCER_KEY`, and `CROWDSEC_FIREWALL_KEY` have
  no in-file defaults. An empty `.env` does not boot.
- CrowdSec decision cache stays live across config apply until the LAPI stream
  has a first payload.
- A WAF compile failure keeps last-good for that host, or fails open. The
  vhost is never 503 “WAF unavailable”.
- WAF and rate limit inspect the WebSocket handshake. Frames after upgrade
  stay uninspected.

## [1.4.1] — 2026-09-09

Truth and lockout: copy matches the code; CSRF no longer locks operators out
or skips Origin for curl; hostnames are unique; expired sessions return to
login; GeoIP and enrollment fail closed; last-known-good is encrypted;
operators can change their own password; tables scroll at 375px.

### Fixed

- README and `.env.example` no longer claim production images are fail-closed.
  `pubkey.bin` is still empty.
- CSRF treats `localhost` and `127.0.0.1` as the same host. Mutating admin
  routes require an Origin header. Login names CSRF instead of “Is the API up?”.
- README quick start includes CrowdSec secrets so Analytics bans work.
- Hostnames are unique (case-insensitive). A colliding create or update
  returns 409. The proxy keeps the first host on a duplicate name instead of
  last-write-wins. Existing collisions are stripped from newer hosts on migrate.
- An expired dashboard session redirects to Sign in instead of “Failed to load”.
- GeoIP allow/deny with no MMDB (or unknown country) is 403, not a skip.
  Settings and Analytics say GeoIP is not active until a file is mounted.
- Enrollment compares tokens in constant time and rate-limits :9444 per IP
  and per token in Redis before the CA signs.
- Last-known-good `last_config.pb` is AES-256-GCM, keyed from the node
  identity. Plaintext leftovers are refused.
- `FeatForwardAuth` is gone. Authelia/Authentik: `docs/origin-auth.md`.
- Settings has a self-service password change (current, new, confirm).
- Nodes, certificates, access lists, WAF, Settings, and Analytics tables
  scroll horizontally. The shell stacks; tables scroll.

### Changed

- `docs/asvs.md` is an engineering self-check, not an ASVS pass.
- Copy: multiple origins are failover; GeoIP and TCP/UDP streams are demoted;
  nftables firewall is optional. OIDC forward-auth stays cut
  (`docs/origin-auth.md`).

## [1.4.0] — 2026-09-08

Commercial polish: overview home, history on analytics, usable on a laptop, docs.

### Added

- Overview at `/` (nodes, 24h traffic, blocks, CrowdSec, expiring certs).
- Analytics time presets (24h / 7d / 30d) and per-host filter on rollups.
- Favicon and a mobile nav for the dashboard shell.
- Install, configuration, NPM migration, and backup/restore docs.

### Fixed

- CI Trivy scan writes `.trivyignore` into the scanner instead of bind-mounting
  a path the host Docker socket cannot see.
- Web image `apk upgrade`s Alpine so openssl is not stuck on the node tag, and
  Next 15.5.25 standalone transitives are listed in `.trivyignore` until a
  patched next ships.
- CI e2e does not publish host ports, and CrowdSec config is copied into a
  volume instead of bind-mounted, so main and dev jobs can share a runner.

## [1.3.1] — 2026-09-08

CrowdSec operator control: independent layers, firewall switch, manual bans.

### Added

- Settings toggle for the host firewall (control file; the bouncer idles and
  drops its nftables tables when off). Default remains on.
- Split decision origins: community lists and manual bans at L3/L4; local log
  scenarios at L7 per host. Separate bouncer keys for each stream.
- Analytics: ban an IP or CIDR onto the firewall (duration presets, optional
  reason) and unban manual decisions. RFC1918 / loopback are refused.

## [1.3.0] — 2026-09-08

CrowdSec in-stack + in-app reporting.

### Added

- CrowdSec LAPI in the default compose stack with CAPI (community lists) on,
  nginx log acquisition, and an auto-registered bouncer key.
- Proxy L7 bouncer uses the CrowdSec decision stream and an in-memory cache
  instead of a per-request LAPI GET.
- Box-level `crowdsec-firewall` (nftables, host network) with RFC1918 /
  loopback allowlisted in LAPI. CI replaces this service so runners are not
  mutated.
- Telemetry `block_stage` (`waf`, `crowdsec`, `ratelimit`, `geo`, `acl`) and
  CrowdSec decision origin on the live feed and hourly rollups.
- Analytics: requests vs blocked, blocks by stage, CrowdSec decisions panel.
- Settings CrowdSec section is status for the in-stack LAPI, not a URL/key form.
- LICENSE (Apache-2.0), SECURITY.md, and a third-party licence note.

### Changed

- Proxy gRPC keepalive no longer trips `too_many_pings` (telemetry actually arrives).
- Trivy HIGH/CRITICAL now fails the build job (`--ignore-unfixed` plus
  `.trivyignore`).

### Parked

- Prometheus scrape, CrowdSec AppSec, arm64 images, testcontainers.
