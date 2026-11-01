#!/bin/sh
# Aegis backup: a consistent pg_dump plus the CrowdSec state, taken while the
# edge keeps serving. Run from the repo directory (where compose.yaml is).
#
#   scripts/backup.sh [DEST_DIR]        default ./backups
#   BACKUP_KEEP_DAYS=14 scripts/backup.sh
#
# What it does NOT copy: .env. Keep your own copy of .env (it holds
# AEGIS_SECRET_KEY, without which every dump here is unreadable) somewhere
# at least as safe as these files.
set -eu
DEST="${1:-./backups}"
KEEP_DAYS="${BACKUP_KEEP_DAYS:-14}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$DEST"
umask 077

# Postgres: custom-format dump (compressed, restorable table by table).
docker compose exec -T postgres pg_dump -U aegis -d aegis -Fc > "$DEST/aegis-$STAMP.dump"

# CrowdSec: LAPI database and config (bouncer keys, allowlists, machines).
# The tar is taken live; CrowdSec's SQLite copes with that for a restore.
docker run --rm \
  -v "$(docker compose config --format json | sed -n 's/.*"name": *"\([^"]*\)".*/\1/p' | head -1)_crowdsec-data:/data:ro" \
  -v "$(docker compose config --format json | sed -n 's/.*"name": *"\([^"]*\)".*/\1/p' | head -1)_crowdsec-config:/config:ro" \
  -v "$(cd "$DEST" && pwd):/out" \
  alpine:3.20 sh -c "tar -czf /out/crowdsec-$STAMP.tgz -C / data config && chown $(id -u):$(id -g) /out/crowdsec-$STAMP.tgz && chmod 600 /out/crowdsec-$STAMP.tgz"

# Prune old backups.
find "$DEST" -maxdepth 1 -type f \( -name 'aegis-*.dump' -o -name 'crowdsec-*.tgz' \) -mtime "+$KEEP_DAYS" -delete

ls -lh "$DEST/aegis-$STAMP.dump" "$DEST/crowdsec-$STAMP.tgz"
echo "ok: keep .env (AEGIS_SECRET_KEY) with these files"
