# Licensing

Aegis has no commercial license. WAF, CrowdSec, and GeoIP are part of the
product. Turn them on per host (and CrowdSec in Settings) and they run.

Releases through 1.8.0 gated those layers behind a Zypher Systems license.
That gate is gone.

- Rebuild and recreate the API and every proxy together. A proxy from 1.8.0
  or earlier still strips WAF, CrowdSec, and GeoIP when a snapshot carries no
  license token.
- On boot the API deletes stored license keys, leases, and instance ids
  (`0024_drop_license.sql`). Host settings are unchanged, and those layers
  stay on.
- `AEGIS_LICENSE_KEY`, `AEGIS_LICENSE_SERVER`, `AEGIS_LICENSE_DEV`, and
  `AEGIS_GO_TAGS` do nothing. Remove them from `.env`.
