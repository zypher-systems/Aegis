#!/bin/sh
# Runs once against the in-stack LAPI: RFC1918 + loopback are never banned
# (SSH and the dashboard stay reachable). Registers the API machine user so
# the dashboard can add/delete cscli decisions. Failures are non-fatal.
set -eu
for i in $(seq 1 60); do
  if cscli lapi status >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
cscli allowlists create lan --description "RFC1918 and loopback" >/dev/null 2>&1 || true
for cidr in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 127.0.0.1/32 ::1/128; do
  cscli allowlists add lan "$cidr" >/dev/null 2>&1 || true
done
id="${CROWDSEC_MACHINE_ID:-aegis-api}"
if [ -n "${CROWDSEC_MACHINE_PASSWORD:-}" ]; then
  if cscli machines add "$id" --password "$CROWDSEC_MACHINE_PASSWORD" --force >/dev/null 2>&1; then
    echo "crowdsec-init: machine $id registered"
  else
    echo "crowdsec-init: machine add failed (non-fatal)" >&2
  fi
fi
echo "crowdsec-init: LAN allowlist applied"
