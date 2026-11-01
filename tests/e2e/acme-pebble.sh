#!/usr/bin/env bash
# ACME HTTP-01 against Pebble. Start the stack with:
#   AEGIS_SELFSIGNED=false
#   AEGIS_ACME_EMAIL=test@aegis.local
#   AEGIS_ACME_DIRECTORY=https://pebble:14000/dir
#   AEGIS_ACME_SKIP_TLS=true
#   docker compose --profile e2e up -d --build
set -euo pipefail

API="${API:-http://127.0.0.1:18080}"
ORIGIN="${AEGIS_E2E_ORIGIN:-$API}"
HDRS="$(mktemp)"; trap 'rm -f "$HDRS"' EXIT
SESSION=""
CSRF=""

capture_session() {
  SESSION=$(tr -d '\r' < "$HDRS" | grep -i '^set-cookie:' | sed -n 's/.*aegis_session=\([^;]*\).*/\1/p' | head -1)
  CSRF=$(tr -d '\r' < "$HDRS" | grep -i '^set-cookie:' | sed -n 's/.*aegis_csrf=\([^;]*\).*/\1/p' | head -1)
}
auth() { printf '%s' "aegis_session=${SESSION}; aegis_csrf=${CSRF}"; }

echo "== pebble ACME obtain =="
curl -sf -D "$HDRS" -o /dev/null -X POST "$API/api/auth/login" -H "Origin: ${ORIGIN}" -H 'Content-Type: application/json' \
  -d '{"email":"admin@aegis.local","password":"supersecretpassword"}' || {
  curl -sf -D "$HDRS" -o /dev/null -X POST "$API/api/setup" -H "Origin: ${ORIGIN}" -H 'Content-Type: application/json' \
    -d '{"email":"admin@aegis.local","name":"Admin","password":"supersecretpassword"}'
}
capture_session
[ -n "$SESSION" ] && [ -n "$CSRF" ] || { echo "FAIL: no session"; exit 1; }

echo "requesting ACME cert for pebble.local via tls_mode=auto"
body=$(curl -sf --max-time 120 -X POST "$API/api/hosts" -b "$(auth)" \
  -H "Origin: ${ORIGIN}" -H "X-CSRF-Token: ${CSRF}" -H 'Content-Type: application/json' \
  -d '{"domain_names":["pebble.local"],"upstream_scheme":"http","upstream_host":"demo","upstream_port":80,"enabled":true,"tls_mode":"auto","force_https":true}')
echo "$body" | grep -q '"cert_id"' && echo "  ok: pebble.local issued" || {
  echo "  FAIL: ACME issue"
  echo "$body"
  exit 1
}
echo "RESULT: pebble ACME obtain passed"
