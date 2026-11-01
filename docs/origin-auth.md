# Origin auth (Authelia / Authentik)

Aegis does not terminate OIDC or forward-auth. That engine was removed in
1.0.1 and is cut. Put Authelia or Authentik **in front of the origin**, not
inside Aegis.

```
clients → Aegis (TLS, WAF, CrowdSec) → Authelia/Authentik → app
```

Or sit the IdP on its own host and have the app trust it:

```
clients → Aegis → app
                 ↘ Authelia (session / forward-auth headers the app already understands)
```

## Authelia

1. Run Authelia as an upstream Aegis can reach (compose service or another
   box). Do not publish Authelia on the public NIC if Aegis already terminates
   TLS.
2. Add an Aegis host for the app. Upstream is Authelia or the app, matching
   however you already wire NPM / Traefik / Caddy today.
3. Keep session cookies on the app domain. Aegis does not mint visitor
   cookies.

## Authentik

Same shape: Authentik is an origin (or an out-of-band IdP). Aegis proxies TLS
and the security pipeline. Outpost / embedded outpost stays Authentik’s job.

## What Aegis will not do

- Dashboard SSO (parked for 2.1.0).
- `X-Forwarded-*` identity headers invented here.
- Forward-auth as a built-in stage.

If a host payload still sends `oidc.enabled`, the API returns 400.
