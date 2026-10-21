# Aegis

Security-first reverse proxy: a Go data plane, a control plane, and a dark
command-center dashboard. **1.8.0** puts the dashboard on the Graphite palette
(dark by default, with a light alternate) and rebuilds Overview around what is
happening and what needs attention. **1.7.2** was the production-readiness cut:
node certificate renewal, in-place certificate renewal, per-host timeouts,
ordered shutdown, webhook alerts and a backup that does not stop the edge.
and [docs/upgrade.md](docs/upgrade.md).

The admin UI is for your LAN or VPN (`.env.example` sets `WEB_BIND=0.0.0.0`; the API stays on loopback). Never forward its ports on your router.
The proxy owns public `80`/`443`.

## Prerequisites

- Docker and Docker Compose
- Nothing else on the host. Builds and tests run in `./ae` (toolchain container).

## Quick start (local)

```sh
cp .env.example .env
# Fill in:
#   AEGIS_SECRET_KEY    openssl rand -base64 32
#   AEGIS_ENROLL_TOKEN  openssl rand -hex 24
#   POSTGRES_PASSWORD   openssl rand -hex 16
#   CROWDSEC_BOUNCER_KEY, CROWDSEC_FIREWALL_KEY, CROWDSEC_MACHINE_PASSWORD
#     openssl rand -hex 32 each. L7 and firewall keys must differ.
#     Compose refuses to start if Postgres or CrowdSec keys are empty.
#     Without CROWDSEC_MACHINE_PASSWORD, Analytics bans are a no-op.
# Leave AEGIS_SELFSIGNED=true for local/e2e (no public DNS required).

docker compose up -d --build
```

| Service | Host address | Notes |
|---|---|---|
| Dashboard | `http://<this-box>:3300` | LAN (`WEB_BIND=0.0.0.0` in `.env.example`). Not for the internet. |
| API | `http://127.0.0.1:18080` | Default loopback. Browser uses the dashboard rewrite. |
| Proxy HTTP | `0.0.0.0:80` | Public. Override with `PROXY_HTTP_PORT` if 80 is taken. |
| Proxy HTTPS | `0.0.0.0:443` | Public. Override with `PROXY_HTTPS_PORT` if 443 is taken. |

Open `http://<this-box>:3300`, complete first-run setup. The home screen is
Overview. Add a host (`demo.local` → `demo:80`, TLS none) and curl with
`Host: demo.local`.

### Toolchain

```sh
./ae go build ./...
./ae go vet ./...
./ae go test ./...
./ae buf lint
./ae buf generate   # after proto changes; commit gen/
```

### Hot reload

```sh
docker compose -f compose.yaml -f compose.dev.yaml up --build
```

## Certificates (0.2)

Two first-class paths:

1. **Let's Encrypt (ACME)** — request on the **Certificates** page before
   creating hosts, or let `tls_mode=auto` issue on host save (reuses a covering
   cert if one exists). HTTP-01 for exact names; DNS-01 for wildcards.
   `AEGIS_SELFSIGNED=false` and `AEGIS_ACME_EMAIL` required. Use the **staging**
   directory first: `https://acme-staging-v02.api.letsencrypt.org/directory`.
2. **Custom upload** — PEM certificate + private key + optional chain
   (DigiCert, Sectigo, internal PKI). `tls_mode=custom` + pick a cert.
   No auto-renew; re-upload before expiry.

HTTP-01 cannot issue `*.example.com`. Use **DNS-01 via Cloudflare**: set a
token in Settings (or `AEGIS_CF_API_TOKEN`), then **Request cert** for
`example.com, *.example.com`. Attach that cert on the host (`Existing cert` or
Auto). Custom uploaded wildcards still work without Cloudflare.

Stream (TCP/UDP) hosts bind extra listen ports on the proxy — NPM parity, not
a reason to switch. Compose publishes `19000-19002` for local/e2e. Production
stream ports must be published on the proxy container (or run the proxy on the
host network).

## e2e

```sh
docker compose up -d --build
./tests/e2e/happy-path.sh
```

Needs `curl` and `openssl` on the host. ACME-against-Pebble is the `e2e`
compose profile:

```sh
docker compose --profile e2e up -d --build
AEGIS_SELFSIGNED=false AEGIS_ACME_DIRECTORY=https://pebble:14000/dir \
  AEGIS_ACME_SKIP_TLS=true ./tests/e2e/happy-path.sh
```

### Security layers

WAF (Coraza, OWASP CRS), CrowdSec, and GeoIP are included. Attach a WAF
profile and turn CrowdSec or country lists on per host. No license key.

```sh
# CrowdSec LAPI is in the default stack (CAPI community lists + L7 per host).
# Analytics bans need CROWDSEC_MACHINE_PASSWORD in .env.
# The nftables box-level bouncer is optional (host network + NET_ADMIN).
# Optional console enrollment: CROWDSEC_ENROLL_KEY in .env

# Country allow/deny and the Analytics map use a DB-IP Country Lite MMDB
# baked into the api and proxy images (CC BY 4.0, attributed on Analytics).
# Override AEGIS_GEOIP_MMDB, or set it to none to disable.
```

The per-host pipeline is CrowdSec → GeoIP → rate limit → WAF →
upstream. Disabled stages compile out. Multiple origins are **failover**, not
load balancing. Client IP defaults to the connecting address unless the hop
is in Settings → Trusted proxies (or `AEGIS_TRUSTED_PROXY_CIDRS`).

k6 smoke (numbers) and the added-latency gate (proxy minus direct demo).
Both hit `k6.local`, which has the security pipeline on (after happy-path):

```sh
k6 run tests/load/smoke.js
DIRECT=http://127.0.0.1:8081 PROXY=http://127.0.0.1:80 HOST=k6.local k6 run tests/load/gate.js
```

## CI

No CI runs right now. Before merging, run `./ae go vet ./...`, `./ae go test ./...`,
`./ae buf lint`, `./ae sh tests/coverage-floor.sh`, the [e2e](#e2e) suite, and the k6
smoke above.

## Production notes (before you point 80/443 at a box)

- **Do not lose `AEGIS_SECRET_KEY`.** It unwraps the CA and every certificate
  private key. Back it up offline. Changing it makes stored material unreadable.
- Set `AEGIS_SELFSIGNED=false` and `AEGIS_ACME_EMAIL`.
- Start on Let's Encrypt **staging**, then switch the directory to production.
- The dashboard listens on the LAN (`WEB_BIND=0.0.0.0`); the API on loopback.
  Never forward `:3300` / `:18080` on your router. `AEGIS_PUBLIC_ORIGIN` is
  only needed when another proxy in front of the dashboard changes its Host.
- Proxy `80`/`443` must be reachable from the internet for HTTP-01.
- Wildcards need DNS-01 (Cloudflare token) or a custom uploaded cert.
- Enroll token: env is bootstrap. Rotate it in Settings after first login.

## Layout

```
proto/aegis/v1/     protobuf contracts
services/api/       control plane
services/proxy/     data plane
web/                Next.js dashboard
tests/e2e/          happy-path.sh
tests/load/         k6 smoke + gate
docs/               install, configuration, backup, origin auth, NPM migration, ASVS
```

See [plan.md](plan.md) and [roadmap.md](roadmap.md).
