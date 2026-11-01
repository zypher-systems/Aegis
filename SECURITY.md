# Security

Aegis is a reverse proxy. Treat the control plane as a privileged admin
surface: bind it to localhost or a VPN, keep `AEGIS_SECRET_KEY` offline, and
do not publish `:3300` / `:18080` on a public NIC.

## Reporting a vulnerability

Please report it privately through a GitHub security advisory on
[zypher-systems/aegis](https://github.com/zypher-systems/aegis/security/advisories/new).
Do not file a public issue or pull request that includes an exploit, proof of
concept, or reproduction steps.

Include the version (`AEGIS_VERSION` / image tag), which service is affected
(api, proxy, web), and enough context to reproduce on a current `main` image.

We will acknowledge reports and ship a patch release (sub-point or
sub-sub-point, depending on severity).

## Operational notes

- Enrollment uses `InsecureSkipVerify` only for the single token-authenticated
  enroll call. The returned CA is pinned for all subsequent mTLS.
- Certificate private keys are decrypted in memory to build config snapshots
  and are never logged.
- CrowdSec L7 is fail-open if LAPI is down (last cached decisions are kept).
  The nftables host-network bouncer is optional and whole-box; RFC1918 and
  loopback are allowlisted so operators are not locked out of SSH or the
  dashboard. CrowdSec CAPI lists plus the in-app ban are the usual path.
