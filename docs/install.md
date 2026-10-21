# Install Aegis

Published images, `linux/amd64` and `linux/arm64`:

- `ghcr.io/zypher-systems/aegis-api`
- `ghcr.io/zypher-systems/aegis-proxy`
- `ghcr.io/zypher-systems/aegis-web`

`:latest` and the version in `VERSION` (`1.8.0`, and `1.8`) track `main`.
`sha-<commit>` is that exact build. The firewall bouncer is not published;
compose builds it on the box.

`.env.example` sets `WEB_BIND=0.0.0.0`, so the dashboard is reachable from
your LAN at `http://<this-box>:3300`; the API stays on loopback (the dashboard
forwards `/api` itself). Never forward `:3300` or `:18080` on your router: the
admin UI belongs on the LAN or a VPN. The proxy owns public `80`/`443`.

## Prerequisites

Docker and Docker Compose. Nothing else on the host.

## From the published images

```sh
cp .env.example .env
# AEGIS_SECRET_KEY    openssl rand -base64 32
# AEGIS_ENROLL_TOKEN  openssl rand -hex 24
# POSTGRES_PASSWORD   openssl rand -hex 16
# CROWDSEC_BOUNCER_KEY, CROWDSEC_FIREWALL_KEY, CROWDSEC_MACHINE_PASSWORD
#   openssl rand -hex 32 each. L7 and firewall keys must differ.
#   Compose fails closed if Postgres or CrowdSec keys are unset.

docker compose pull api proxy web
docker compose up -d
```

Pin a version with `AEGIS_VERSION=1.8.0` in `.env`. To compile this checkout
instead, `AEGIS_PULL_POLICY=build docker compose up -d --build`.

Country lookup is already in the api and proxy images (DB-IP Country Lite).
Do not download a MaxMind database.

Open `http://<this-box>:3300`, create the first admin, finish onboarding.
Overview is `/`. Add a host (for local: `demo.local` → `demo:80`, TLS none)
and `curl -H 'Host: demo.local' http://127.0.0.1:${PROXY_HTTP_PORT:-80}`.

If host `80`/`443` are taken, set `PROXY_HTTP_PORT` / `PROXY_HTTPS_PORT` in
`.env`.

## Upgrading

`docker compose pull api proxy web`, then recreate; see [upgrade](upgrade.md).
Keep `AEGIS_SECRET_KEY` identical to the box that created the Postgres volume.

## CrowdSec

LAPI is in the default stack. Per-host CrowdSec is L7 local log scenarios.
Analytics can ban an IP onto the LAPI (`cscli` origin) when
`CROWDSEC_MACHINE_PASSWORD` is set — without it, the ban UI is a silent no-op.

The nftables box-level bouncer is **optional**. It needs `NET_ADMIN` and host
networking, and CI disables it so runners are not mutated. CrowdSec CAPI
lists plus the in-app ban are the usual path.

RFC1918 and loopback are allowlisted so you cannot ban yourself off SSH.

## Production checklist

See the README "Production notes". Short version: back up `AEGIS_SECRET_KEY`,
`AEGIS_SELFSIGNED=false`, staging ACME first, do not publish dashboard ports
on a public NIC.

## Next

- [Configuration](configuration.md)
- [Origin auth (Authelia / Authentik)](origin-auth.md)
- [Backup / restore](backup.md)
- [Migrate from nginx-proxy-manager](migrate-npm.md)
