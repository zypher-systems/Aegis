#!/bin/sh
# Restore an Aegis pg_dump into the running Postgres, replacing the current
# database. The API is stopped during the restore (the proxy keeps serving
# its last config) and started again afterwards.
#
#   scripts/restore.sh backups/aegis-20260924T120000Z.dump
#
# .env must hold the SAME AEGIS_SECRET_KEY the dump was taken under.
set -eu
DUMP="${1:?usage: scripts/restore.sh <aegis-*.dump>}"
[ -f "$DUMP" ] || { echo "no such file: $DUMP" >&2; exit 1; }

docker compose stop api web
docker compose exec -T postgres psql -U aegis -d postgres -v ON_ERROR_STOP=1 -c \
  "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='aegis' AND pid <> pg_backend_pid();" \
  -c "DROP DATABASE IF EXISTS aegis;" -c "CREATE DATABASE aegis OWNER aegis;"
docker compose exec -T postgres pg_restore -U aegis -d aegis --no-owner --no-privileges < "$DUMP"
docker compose start api web
echo "restored $DUMP; proxies pick up the restored config on their next stream connect"
