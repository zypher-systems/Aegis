# Third-party licences

Aegis itself is MIT (see [LICENSE](../LICENSE)). Dependencies keep their own licences.

This is the 1.3.0 dependency licence note, not a generated SPDX dump.

| Tree | Where | Notes |
|---|---|---|
| Go | `go.mod` at repo root | Standard library plus modules. Notable: Coraza (Apache-2.0), chi, pgx, lego, grpc, protobuf, coraza-coreruleset (Apache-2.0). |
| Dashboard | `web/package.json` | Next.js, React, Tailwind, TypeScript. Next.js is MIT. Icons: lucide-react (ISC). |
| Dashboard fonts | `@fontsource-variable/*` in `web/package.json` | Space Grotesk, Manrope, JetBrains Mono. SIL Open Font License 1.1. Bundled at build; no font CDN at runtime. |
| World map | `web/lib/world-110m.json` | Natural Earth 110m, public domain. |
| Country MMDB | baked into api/proxy images | [DB-IP IP to Country Lite](https://db-ip.com/db/lite.php), CC BY 4.0. Downloaded at image build (`deploy/fetch-dbip-country.sh`). Analytics links to [db-ip.com](https://db-ip.com). Not MaxMind GeoLite2 (no redistribution). |
| Compose images | `compose.yaml` | Postgres, Redis, CrowdSec, firewall-bouncer, whoami — their upstream licences apply. CrowdSec is MIT. |
| CRS | compiled into the proxy | OWASP Core Rule Set, Apache-2.0. |

To re-audit after adding modules:

```sh
./ae go list -m all
./ae sh -lc 'cd web && pnpm licenses list'
```

Do not copy GPL code into this tree. New Go modules should be Apache-2.0,
MIT, or BSD.
