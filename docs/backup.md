# Backup, restore, rollback

## What you must keep

| Item | Why |
|---|---|
| `AEGIS_SECRET_KEY` | Unwraps the internal CA and every certificate private key. Offline copy. |
| Nothing for enrolment | Tokens are generated in Settings when a node needs one. Existing nodes keep mTLS. |
| Postgres volume `pgdata` | Hosts, certs, settings, rollups, audit, users. |
| CrowdSec volumes | LAPI decisions, allowlists, machine/bouncer keys in `crowdsec-config` / `crowdsec-data`. |
| `.env` | Ports, CrowdSec keys, ACME email. Do not commit it. |

`proxystate` is last-known-good proxy config, encrypted with a key derived
from `node_key.pem`. Losing the volume only means the proxy re-enrols (with
`AEGIS_ENROLL_TOKEN` set to a token generated in Settings → Edge) and
pulls a fresh snapshot. A leftover plaintext `last_config.pb` from before
1.4.1 is refused.

`redisdata` is rate-limit / live analytics. Safe to drop.

`aegis-logs` is nginx-combined for CrowdSec. Losing it loses local learning,
not CAPI lists.

## Backup (compose)

`scripts/backup.sh` takes a consistent `pg_dump` and a copy of the CrowdSec
state **while everything keeps running**; the proxy is never stopped.

```sh
scripts/backup.sh                 # → ./backups/aegis-<stamp>.dump, crowdsec-<stamp>.tgz
BACKUP_KEEP_DAYS=30 scripts/backup.sh /mnt/backups/aegis
```

Nightly, from cron on the host (adjust the path):

```cron
15 3 * * * cd /opt/aegis && scripts/backup.sh /mnt/backups/aegis >> /var/log/aegis-backup.log 2>&1
```

Copy `.env` separately, by hand, to somewhere as safe as the key itself:
without its `AEGIS_SECRET_KEY` every dump is unreadable. Sync the backup
directory off the box.

## Restore

1. Install the same image tag you backed up (or a newer one; migrations run
   on API boot, forward only).
2. Put `.env` back with the **same** `AEGIS_SECRET_KEY`.
3. `docker compose up -d`, then `scripts/restore.sh backups/aegis-<stamp>.dump`.
   It stops the API and dashboard, replaces the database, and starts them
   again; proxies keep serving their last config throughout.
4. CrowdSec state, if wanted: `docker compose stop crowdsec crowdsec-firewall`,
   untar `crowdsec-<stamp>.tgz` into the `crowdsec-data` and `crowdsec-config`
   volumes, start them again.

A different secret key makes stored certs and settings unreadable.

### Rebuilding from nothing

If the box is gone: new host, clone, restore `.env`, `docker compose up -d`,
`scripts/restore.sh` the newest dump. Existing proxy nodes keep working the
whole time on their last-known-good config and reconnect once the API is
back, because the internal CA lives in the database (restored) and is sealed
by the key (in `.env`). If you start from an **empty** database instead, the
API mints a new CA and every existing node must be re-enrolled: wipe its
`proxystate` volume and start it with `AEGIS_ENROLL_TOKEN` set to a token
generated in Settings → Edge (the `.env` value works only while the new
database has no node).

## Rollback

Check out the previous version and rebuild. Schema migrations are forward-only;
do not roll an API image back past a migration that already applied unless you
restore Postgres from a backup taken before that boot.

```sh
# example: leave 1.4.0, return to 1.3.1
git checkout <1.3.1 commit>
docker compose up -d --build
```

Restore `pgdata` from the matching backup if the newer API already migrated.

## What is not a backup

`docker compose down -v` deletes volumes. Snapshots of the host disk that
include Docker volumes are a backup; compose project reset is not.
