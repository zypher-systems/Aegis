# Cut over the internet edge from NPM

A runbook for moving a production edge from nginx-proxy-manager to Aegis one
host at a time, with NPM as the rollback until the last step. For how NPM
concepts map to Aegis, see [migrate-npm.md](migrate-npm.md).

The rule throughout: **NPM keeps serving until a host is proven on Aegis, and
every step can be undone by pointing traffic back at NPM.**

## 0. Before you start

- [ ] **Back up `AEGIS_SECRET_KEY` offline.** It unwraps every certificate key
      and the internal CA. Losing it is unrecoverable. See
      [backup.md](backup.md), and take a first Postgres backup now.
- [ ] **Version.** Dashboard footer (user menu) and Nodes both show the same
      version on the API and every proxy.

## 1. Rehearse failure on the internal deployment

Do each of these once, on purpose, and watch the dashboard:

| Break | Expected |
|---|---|
| `docker compose stop api` | Proxies keep serving their last-known-good config; traffic is unaffected. The dashboard is down until the API starts again, then Nodes shows them online. |
| `docker compose restart proxy` | Proxy reloads its encrypted last-known-good config, then reconnects. |
| `docker compose stop crowdsec` | The L7 bouncer **fails open** (log: `crowdsec stream fail-open`); traffic flows unfiltered by CrowdSec. WAF still runs. |
| `docker compose stop redis` | Rate limiting falls back to a per-node bucket. Limits still apply. |

## 2. Real client IPs

If anything sits in front of the edge (Cloudflare, a load balancer, a router
that proxies instead of port-forwarding), add its ranges in **Settings → Edge
→ Trusted proxies**. Without them, rate limiting, GeoIP, CrowdSec and the
access log all see the front device's address instead of the visitor's.

- While NPM sits in front of Aegis (step 5): add **NPM's LAN address**.
- Plain port-forward from the router straight to Aegis: leave the list
  **empty** (the default).
- Cloudflare proxied DNS: add Cloudflare's published IPv4 and IPv6 ranges.

Aegis reads `X-Forwarded-For` from the right and stops at the first address
that is not a trusted proxy, so a visitor cannot spoof their IP by sending the
header themselves.

Check: Analytics → Live feed shows real visitor IPs, not your router or CDN.

## 3. Certificates first, while NPM still owns 80/443

HTTP-01 cannot work until Aegis owns port 80, so issue certificates ahead of
time with DNS-01:

1. Settings → Edge → Cloudflare DNS-01: save an API token (Zone:DNS:Edit).
2. `AEGIS_SELFSIGNED=false` and `AEGIS_ACME_EMAIL` set; recreate the API.
3. Certificates → **Request certificate** for each name (or `example.com,
   *.example.com` for a wildcard). Use the Let's Encrypt **staging** directory
   first if you are unsure, then production.
4. Attach them on each host (TLS: Existing cert, or Auto, which reuses a
   covering certificate).

Uploaded certificates from NPM also work (TLS: Existing cert), but do not
auto-renew.

## 4. Recreate hosts with protection in Detect mode

1. WAF → create a profile in **Detect** mode (paranoia 1). Detect logs what it
   would block without blocking.
2. Recreate each host from NPM (access lists first). Attach the Detect profile,
   turn CrowdSec on, add rate limits where NPM had them. Leave "Host header
   sent upstream" on **Client's Host** (NPM's behaviour) unless NPM had a custom
   `proxy_set_header Host` in its advanced config.
3. Leave GeoIP off until the rest is stable.

## 5. Move one low-risk host (NPM in front, one public IP)

With a single public IP whose 80/443 are forwarded to NPM, move a host by
**chaining**: NPM keeps TLS and forwards that one host to Aegis over the LAN.
Nothing about DNS or the router changes, and rollback is one field in NPM.

```
visitor ──https──▶ router ──▶ NPM (TLS, cert) ──http──▶ Aegis proxy ──▶ app
```

**In Aegis**

1. **Settings → Edge → Trusted proxies:** add NPM's LAN address (for example
   `192.168.1.10`). This is required. Without it Aegis sees every visitor as
   NPM's address: rate limits would throttle everyone together, and CrowdSec
   and GeoIP skip private addresses, so they would stop nothing.
2. **Hosts → Add host:** the same domain as in NPM, upstream = the app (the
   address NPM points at today).
   - TLS: **HTTP only** (NPM terminates TLS). Leave Force HTTPS and HSTS to
     NPM. (TLS Auto + Force HTTPS also works once NPM is a trusted proxy,
     because Aegis honours NPM's `X-Forwarded-Proto`, but there is no reason
     to issue a second certificate yet.)
   - Host header sent upstream: **Client's Host**.
   - WAF: the **Detect** profile. CrowdSec: on. Rate limit: as NPM had it.
   - WebSockets: on if the app uses them.

**In NPM**, edit that proxy host:

3. Forward Hostname / IP: the Aegis proxy's LAN address. Forward Port: Aegis's
   HTTP port (`PROXY_HTTP_PORT`, 80 by default). Scheme: `http`.
4. Leave its SSL certificate and Force SSL as they are. Turn on Websockets
   Support if the app uses them. Remove NPM access lists you recreated in Aegis.

**Check**

5. Open the site. Aegis Analytics → Live feed should show your **real public
   IP**, not NPM's, and the request as 2xx/3xx.
6. From outside, send `curl -H 'X-Forwarded-For: 1.2.3.4' https://that.host/`.
   The live feed must still show your real IP, not `1.2.3.4` (Aegis reads
   `X-Forwarded-For` from the right and ignores what visitors add).
7. Watch for a day. Analytics → Security shows what the WAF would have blocked;
   Analytics → Requests with **Flagged** lists each request, and clicking one
   shows the rules that matched and the input they matched.

**Rollback:** in NPM, point the host's Forward Hostname / Port back at the app.

## 6. Switch the WAF to Block

Every request the WAF flags (in Detect) or stops (in Block) is logged with the
CRS rules that scored:

```sh
docker compose logs proxy | grep "proxy: waf"
# proxy: waf detect host=app.example.com path=/wp-admin/admin-ajax.php score=5 rules: 942100 "SQL Injection Attack Detected via libinjection"
```

`949110` in a block only means "the anomaly score passed the threshold"; the
rules listed after it are the cause, and Analytics shows the top one. The text
after `at` is the input that matched. For each legitimate request that shows
up, add an exclusion on the WAF profile rather than lowering the paranoia level
or raising the threshold, as narrow as the log allows. In the dashboard, open
the request (Analytics → Requests → Flagged) and use **Exclude … from …** on
the rule; it opens the host's profile with the exclusion filled in:

| Log says | Exclusion |
|---|---|
| `942290 … at REQUEST_COOKIES:ph_phc_…_posthog=…` (PostHog analytics) | Rule `942290`, input `REQUEST_COOKIES:/^ph_.+_posthog$/` |
| `920450 "HTTP header is restricted by policy (/expect/)"` (curl, SDKs and some browsers send `Expect: 100-continue` on uploads over 1 MB) | Rule `920450`, input `REQUEST_HEADERS_NAMES:expect` |
| a rule at `ARGS:q` on `/search` only | Rule id, path `/search`, input `ARGS:q` |
| a rule that has no use for this app | Rule id, no path, no input (rule off) |

With an input, the rule keeps inspecting everything else.

**WAF → Findings** does the same job without the log: every rule that
matched in the last 24h/7d/30d, how often, on which hosts, with the input and
value it matched, and one-click exclusions at the right scope.

When Detect shows no false positives for your real traffic (typically a few
days), edit the profile and set Mode to **Block**.

## 7. Move the rest, then take over 80/443

1. Move the remaining hosts a few at a time, as in step 5.
2. Issue each host's certificate in Aegis with DNS-01 (step 3) while NPM still
   holds 80/443.
3. Cut over: for each host set TLS back to **Auto** or **Existing cert**, turn
   on Force HTTPS (and HSTS if NPM had it), then move the router's 80/443
   forward from NPM to the Aegis proxy. Remove NPM from Trusted proxies.
4. **Rollback:** move the port-forward back to NPM (its hosts still point at
   Aegis over HTTP, so set TLS to HTTP only again, or point them at the apps).
5. Keep NPM's data for a week before deleting it.

## 8. After cutover

- Overview's posture checks should all pass (nodes, WAF coverage, CrowdSec,
  certificates, HTTPS). "Fix issues" links to what is left.
- Consider a second proxy node on another box for failover
  (Nodes → Enrol a node).
- Back up Postgres on a schedule ([backup.md](backup.md)).
