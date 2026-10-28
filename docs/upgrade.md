# Upgrade

Migrations run on API boot inside a transaction. Pull the new api image and
recreate it so it applies pending SQL, then roll the proxy and web.

## Unreleased

- **Commercial licensing is gone.** WAF, CrowdSec, and GeoIP are included.
  See [licensing.md](licensing.md).
- Migration `0024` deletes stored license keys, leases, and instance ids.
  Host configuration is unchanged.
- Roll every proxy with the API. A 1.8.0 proxy still strips those layers
  when the snapshot has no license token.
- `AEGIS_LICENSE_KEY`, `AEGIS_LICENSE_SERVER`, `AEGIS_LICENSE_DEV`, and
  `AEGIS_GO_TAGS` are unused. Remove them from `.env`.
- **Images are published** to `ghcr.io/zypher-systems/aegis-api`,
  `aegis-proxy`, and `aegis-web` (`linux/amd64` and `linux/arm64`). See
  [Install a published image](#install-a-published-image).

## 1.8.0

- **No migrations and nothing to configure.** Rebuild and recreate the API,
  proxy and web containers as usual; the order does not matter.
- **The dashboard changes colour.** It uses the Graphite palette. Dark is
  still the default; a light theme is in the account menu and is remembered
  per browser.
- **Overview is rebuilt.** The posture ring gives way to a "Needs attention"
  list with the same checks and score; the stage donut and attack origins
  are on Analytics.
- **`GET /api/analytics/rollups` gains `group` and `truncated`.** Both are
  additive: a client that sends no `group` gets the same rows as before, now
  with a `truncated` field that is true when more than 2000 rows matched.

## 1.7.2

- **Node certificates now renew themselves.** Each proxy's mTLS client
  certificate lasts 90 days; before 1.7.2 nothing renewed it, so on day 91 a
  node silently stopped receiving config and telemetry stopped. Nodes on
  1.7.2 renew over the existing stream from 30 days out, and the Overview
  shows a notice for any node that has not renewed with 14 days left.
  **Update every proxy to 1.7.2 before its certificate is 14 days from
  expiry** (Nodes shows the date). A node whose certificate has already
  expired re-enrols on restart when `AEGIS_ENROLL_TOKEN` holds a valid token,
  keeping its stored config.
- **The `.env` enrolment token only enrols the first node.** Once any node is
  enrolled, `AEGIS_ENROLL_TOKEN` from `.env` is refused; new nodes and
  re-enrolments use a token from Settings → Edge → Enrolment tokens (shown
  once; one use and one hour by default). To add or re-enrol a proxy, generate
  one and pass it as `AEGIS_ENROLL_TOKEN` to that proxy (in the compose stack,
  put it in `.env` and `docker compose up -d proxy`; nodes that already hold
  an identity ignore the variable). A token rotated in Settings before 1.7.2
  keeps working for the first node only. Migration 0022 adds `enroll_tokens`.
- Migration 0023 adds `hosts.lb_policy` and `hosts.health_path`. Existing
  hosts keep failover with TCP probes; nothing changes until you set a health
  path or round robin on a host. Update proxies to 1.7.2 to use either.
- Migration 0016 adds `certificates.acme_directory`; the API fills it in for
  existing Let's Encrypt certificates on first boot. If production is
  configured and any certificate came from staging, it is re-issued within
  the hour.
- Requests for a name no host serves are now dropped without a reply: over
  HTTPS the handshake fails (also with no SNI, as with `https://<ip>/`), over
  HTTP the connection closes empty. Anything that reached a host by bare IP,
  or with `curl -H 'Host: …' https://localhost/` (some health checkers and
  scripts), must send the hostname as SNI instead (`curl --resolve` or
  `--connect-to`). `AEGIS_UNKNOWN_HOST=page` on the proxy brings back the
  placeholder certificate and 404 page.
- The API no longer sends its master key to proxy nodes (it was carried in an
  unused snapshot field). Admin sessions sign with a derived key, so everyone
  is signed out once after the upgrade.

## 1.7.1

- Migration 0013 adds `hosts.upstream_host_header`; 0014 adds `request_log`;
  0015 clears false WAF "detect" flags (rule 980014 and other CRS bookkeeping)
  from it.
  Rebuild and recreate `api`, `proxy` and `web`.
- **Every proxied request is now kept in Postgres** for request details and
  Analytics → Requests: 7 days for served requests, 30 for blocked or flagged
  ones, about 1 KB each. A busy edge may want `AEGIS_REQUEST_LOG=security`
  (only blocked and flagged) or shorter `AEGIS_REQUEST_LOG_DAYS`; see
  [configuration.md](configuration.md). Proxies older than 1.7.1 still report,
  without the new detail fields.
- **Proxy hosts now send the client's Host header upstream** (1.7.0 sent the
  upstream's `host:port`). This is what nginx-proxy-manager does and what most
  apps expect. For an origin that only answers to its own name (an external
  service, an S3-style vhost), edit the host and set "Host header sent
  upstream" to **Upstream address** or **Custom**.
- Rate limits now refill at the host's configured rate instead of resetting
  every second, so a host with `rps` well below `burst` becomes stricter than
  before. Review rate-limited hosts after upgrading.
- Contributors: `./ae` now uses the `aegis-tools` compose project, so its Go and
  pnpm caches start empty once.

## 1.7.0

- **Licensing is key-based and signed.** Paid features come only from a
  `zsl2` lease or license file that verifies against the compiled-in key.
  Install one in Settings → License (key, trial, or offline file) or set
  `AEGIS_LICENSE_KEY`. See [licensing.md](licensing.md).
- A Community install no longer contacts the licensing server. The 1.7.0
  preview's anonymous `/v1/register` check-in is gone, and its stored
  unsigned grant (`license.grant`) and `aegis1` blob are cleared on boot.
- `AEGIS_LICENSE_DEV` works only in a `licensedev` build. Local compose: add
  `AEGIS_GO_TAGS=licensedev` and `AEGIS_LICENSE_DEV=true` to `.env` and
  rebuild, or the stack comes up as Community. Compose now defaults
  `AEGIS_LICENSE_DEV` to `false`.
- Edge nodes verify the license themselves and re-check every minute. Roll
  the proxy with the API so nodes understand the new snapshot fields.
- A plan's node limit no longer blocks enrollment; Settings shows it instead.
- `AEGIS_VERSION` is 1.7.0 (file `VERSION`). Recreate api/proxy so
  check-in and the dashboard stop reporting `dev`.
- Compose `WEB_BIND` / `API_BIND` (default `127.0.0.1`). Set `WEB_BIND=0.0.0.0`
  and `AEGIS_PUBLIC_ORIGIN` to the URL you type to open the dashboard from
  another machine.
- Dashboard rewrite timeout is 5 minutes so Cloudflare DNS-01 can finish.
  Certificates warns when `AEGIS_SELFSIGNED=true`.
- DNS-01 waits on public resolvers (1.1.1.1 / 8.8.8.8), not the box resolver,
  so split-horizon NS like `svc-ns-*` cannot fail the TXT precheck.

## 1.6.0

- Overview and Analytics poll every 10s and draw SVG charts.
- Analytics has a country choropleth. Country codes come from the DB-IP
  Country Lite MMDB baked into the api and proxy images. Override with
  `AEGIS_GEOIP_MMDB`, or set `none` to disable.
- New tables `analytics_geo_hourly` / `analytics_geo_daily` (applied on API boot).

## 1.5.0

- Compose no longer defaults `POSTGRES_PASSWORD` to `aegis` or CrowdSec
  keys to `dev-bouncer-not-for-prod`. Set them in `.env` or `docker compose
  up` refuses to start. `AEGIS_LICENSE_DEV` still defaults true until 2.0.0.
- `api`, `proxy`, `web`, `postgres`, and `redis` use `restart: unless-stopped`,
  healthchecks, and memory/CPU limits.
- GitLab e2e runs Playwright (login + Hosts) and ACME against in-stack Pebble.
  Check runs `-race` and a 60% coverage floor on the trust-spine packages.

## 1.4.0

- Dashboard `/` is Overview (not a redirect to Hosts).
- Analytics: Live / 24h / 7d / 30d and a per-host filter.
- New `.env` keys if you skipped 1.3.1: `CROWDSEC_FIREWALL_KEY`,
  `CROWDSEC_MACHINE_PASSWORD` (and keep `CROWDSEC_BOUNCER_KEY` different).
- Docs: [install](install.md), [configuration](configuration.md),
  [backup](backup.md), [NPM migration](migrate-npm.md).

## Install a published image

```sh
docker compose pull api proxy web
docker compose up -d api        # applies pending migrations
docker compose up -d proxy web
```

Compose tracks `:latest`. Keep the same `AEGIS_SECRET_KEY`. Changing it makes
encrypted settings and certs unreadable.

A box that was building images from the licensed checkout keeps its database
when this file replaces the old one in the same Docker project. The project
name is `aegis`, so Postgres stays on the volume `aegis_pgdata`, and the
proxy keeps `aegis_proxystate`. Leave `AEGIS_SECRET_KEY` and
`POSTGRES_PASSWORD` as they are. Remove `AEGIS_LICENSE_KEY`,
`AEGIS_LICENSE_SERVER`, `AEGIS_LICENSE_DEV`, and `AEGIS_GO_TAGS`. Then:

```sh
docker compose pull api proxy web
docker compose up -d
```

That recreates the containers and leaves the named volumes in place. Do not
pass `--volumes` to `down`.

To compile this checkout instead:

```sh
git pull
docker compose -f compose.yaml -f compose.build.yaml build api proxy web
docker compose -f compose.yaml -f compose.build.yaml up -d api
docker compose -f compose.yaml -f compose.build.yaml up -d proxy web
```

## What 1.0 added

- Analytics live feed + hourly/daily rollups (`analytics_hourly`, `analytics_daily`)
- Node health heartbeat and per-node RPS / p50 / p99
- License entitlement matrix and `node_limit` on enroll
- Dashboard CSRF token (`aegis_csrf`) plus security headers
- k6 added-latency gate in CI

TOTP, admin OIDC, and RBAC are still parked.

## After upgrade

1. `docker compose up -d`
2. Open the dashboard, complete onboarding if this is a new install
3. Confirm Overview, Nodes online, and Analytics fill after a few proxied requests
