#!/usr/bin/env bash
# e2e happy-path for the Aegis skeleton.
# Requires: docker compose stack running, configured .env, curl + openssl.
set -euo pipefail

API="${API:-http://localhost:18080}"
EDGE_HTTP="${EDGE_HTTP:-http://localhost:80}"
EDGE_HTTPS="${EDGE_HTTPS:-https://localhost:443}"
HTTPS_HOSTPORT="${EDGE_HTTPS#https://}"
HTTPS_HOSTPORT="${HTTPS_HOSTPORT#http://}"
# Origin must match the API Host header (ports ignored). CI uses http://api:8080.
ORIGIN="${AEGIS_E2E_ORIGIN:-$API}"
HDRS="$(mktemp)"; trap 'rm -f "$HDRS"' EXIT
SESSION=""
CSRF=""

PASS=0; FAIL=0
ok()    { PASS=$((PASS+1)); echo "  ok: $1"; }
bad()   { FAIL=$((FAIL+1)); echo "  FAIL: $1"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want=$3 got=$2)"; fi; }

# curl's cookie jar refuses cookies for single-label hosts (compose DNS
# name "api"). Send the session as name=value instead.
capture_session() {
  SESSION=$(tr -d '\r' < "$HDRS" | grep -i '^set-cookie:' | sed -n 's/.*aegis_session=\([^;]*\).*/\1/p' | head -1)
  CSRF=$(tr -d '\r' < "$HDRS" | grep -i '^set-cookie:' | sed -n 's/.*aegis_csrf=\([^;]*\).*/\1/p' | head -1)
  export AEGIS_E2E_ORIGIN="$ORIGIN" AEGIS_CSRF="$CSRF"
}
auth() { printf '%s' "aegis_session=${SESSION}; aegis_csrf=${CSRF}"; }
curl_mut() {
  curl -H "Origin: ${ORIGIN}" -H "X-CSRF-Token: ${CSRF}" -b "$(auth)" "$@"
}
# edge_https HOST [curl args]: GET https://HOST/ on the edge with HOST as the
# SNI. The edge drops a handshake for a name no host serves, "localhost" too.
edge_https() {
  local host="$1"; shift
  curl -sk --connect-to "$host:443:$HTTPS_HOSTPORT" "$@" "https://$host/"
}

echo "== setup / login =="
curl -sf "$API/api/healthz" | grep -q '"status":"ok"' && ok "healthz" || bad "healthz"
curl -sf "$API/api/readyz" | grep -q '"postgres":true' && ok "readyz postgres" || bad "readyz"
needs=$(curl -s "$API/api/setup/status" | grep -o '"needs_setup":true' || true)
if [ -n "$needs" ]; then
  curl -sf -D "$HDRS" -o /dev/null -X POST "$API/api/setup" -H "Origin: ${ORIGIN}" -H 'Content-Type: application/json' \
    -d '{"email":"admin@aegis.local","name":"Admin","password":"supersecretpassword"}' \
    && ok "admin created"
else
  curl -sf -D "$HDRS" -o /dev/null -X POST "$API/api/auth/login" -H "Origin: ${ORIGIN}" -H 'Content-Type: application/json' \
    -d '{"email":"admin@aegis.local","password":"supersecretpassword"}' \
    && ok "logged in"
fi
capture_session
[ -n "$SESSION" ] && ok "session cookie" || bad "session cookie"
[ -n "$CSRF" ] && ok "csrf cookie" || bad "csrf cookie"

me=$(curl -s "$API/api/me" -b "$(auth)")
echo "$me" | grep -q 'admin@aegis.local' && ok "me returns admin" || bad "me"

echo "== create hosts =="
curl_mut -sf -X POST "$API/api/hosts" -b "$(auth)" -H 'Content-Type: application/json' \
  -d '{"domain_names":["demo.local"],"upstream_scheme":"http","upstream_host":"demo","upstream_port":80,"enabled":true,"tls_mode":"none","force_https":false}' >/dev/null \
  && ok "demo.local created" || echo "  (demo.local may already exist)"
curl_mut -sf -X POST "$API/api/hosts" -b "$(auth)" -H 'Content-Type: application/json' \
  -d '{"domain_names":["secure.local"],"upstream_scheme":"http","upstream_host":"demo","upstream_port":80,"enabled":true,"tls_mode":"auto","force_https":true}' >/dev/null \
  && ok "secure.local created" || echo "  (secure.local may already exist)"
dup_code=$(curl_mut -s -o /tmp/aegis-dup.json -w '%{http_code}' -X POST "$API/api/hosts" \
  -H 'Content-Type: application/json' \
  -d '{"domain_names":["demo.local"],"upstream_scheme":"http","upstream_host":"demo","upstream_port":80,"enabled":true,"tls_mode":"none","force_https":false}')
check "duplicate demo.local is 409" "$dup_code" "409"
grep -q 'already in use' /tmp/aegis-dup.json && ok "duplicate domain message" || bad "duplicate domain message"

sleep 2

echo "== http proxy =="
body=$(curl -s -H 'Host: demo.local' "$EDGE_HTTP/")
echo "$body" | grep -q 'Hostname:' && ok "demo.local proxied" || bad "demo.local proxy"

echo "== https proxy (self-signed) =="
body=$(edge_https secure.local || true)
echo "$body" | grep -q 'Hostname:' && ok "secure.local proxied over TLS" || bad "secure.local proxy"
echo "$body" | grep -q 'X-Forwarded-Host: secure.local' && ok "X-Forwarded-Host correct" || bad "XFH"
echo "$body" | grep -q 'X-Forwarded-Proto: https' && ok "X-Forwarded-Proto correct" || bad "XFP"

echo "== http->https redirect =="
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: secure.local' "$EDGE_HTTP/")
check "redirect" "$code" "301"

echo "== unknown host dropped =="
# No reply at all: curl reports 000 (empty reply over HTTP, failed handshake
# over HTTPS) rather than any status.
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: nope.local' "$EDGE_HTTP/" || true)
check "unknown host over HTTP" "$code" "000"
code=$(edge_https nope.local -o /dev/null -w '%{http_code}' || true)
check "unknown SNI over HTTPS" "$code" "000"

echo "== tls cert SNI =="
subj=$(echo | openssl s_client -connect "$HTTPS_HOSTPORT" -servername secure.local 2>/dev/null | openssl x509 -noout -subject 2>/dev/null || true)
echo "$subj" | grep -q 'secure.local' && ok "cert CN=secure.local" || bad "cert subject ($subj)"

echo "== nodes / certificates API =="
curl -sf "$API/api/nodes" -b "$(auth)" | grep -q '"name"' && ok "nodes list" || bad "nodes list"
code=$(curl_mut -s -o /dev/null -w '%{http_code}' -X DELETE "$API/api/nodes/00000000-0000-0000-0000-000000000001")
check "revoke unknown node" "$code" "404"
curl -sf "$API/api/certificates" -b "$(auth)" | grep -q '"issuer"' && ok "certificates list" || bad "certificates list"
iss=$(curl_mut -sf -X POST "$API/api/certificates/issue" -b "$(auth)" -H 'Content-Type: application/json' \
  -d '{"domains":["issued.local"]}' || true)
echo "$iss" | grep -q '"issuer"' && ok "standalone cert issue" || bad "standalone cert issue"

echo "== custom cert upload =="
WORKDIR="$(mktemp -d)"
openssl req -x509 -newkey rsa:2048 -keyout "$WORKDIR/k.pem" -out "$WORKDIR/c.pem" -days 2 -nodes \
  -subj "/CN=custom.local" -addext "subjectAltName=DNS:custom.local" >/dev/null 2>&1
if command -v python3 >/dev/null; then
  BODY=$(python3 -c "import json; print(json.dumps({'cert_pem':open('$WORKDIR/c.pem').read(),'key_pem':open('$WORKDIR/k.pem').read()}))")
else
  bad "python3 required for custom-upload e2e"
  BODY=""
fi
if [ -n "$BODY" ]; then
  cid=$(curl_mut -sf -X POST "$API/api/certificates" -b "$(auth)" -H 'Content-Type: application/json' -d "$BODY" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
  [ -n "$cid" ] && ok "custom cert uploaded" || bad "custom cert upload"
  if [ -n "$cid" ]; then
    curl_mut -sf -X POST "$API/api/hosts" -b "$(auth)" -H 'Content-Type: application/json' \
      -d "{\"domain_names\":[\"custom.local\"],\"upstream_scheme\":\"http\",\"upstream_host\":\"demo\",\"upstream_port\":80,\"enabled\":true,\"tls_mode\":\"custom\",\"cert_id\":\"$cid\",\"force_https\":true,\"hsts\":true,\"websocket_support\":false}" >/dev/null \
      && ok "custom.local host" || echo "  (custom.local may already exist)"
    sleep 1
    body=$(edge_https custom.local || true)
    echo "$body" | grep -q 'Hostname:' && ok "custom.local proxied" || bad "custom.local proxy"
    hsts=$(edge_https custom.local -D - -o /dev/null | tr -d '\r' | grep -i '^strict-transport-security:' || true)
    echo "$hsts" | grep -qi 'max-age' && ok "HSTS set" || bad "HSTS"
    ws=$(edge_https custom.local --http1.1 -o /dev/null -w '%{http_code}' -H 'Upgrade: websocket' -H 'Connection: Upgrade')
    check "websocket rejected" "$ws" "403"
  fi
fi
rm -rf "$WORKDIR"

echo "== 0.3 host kinds =="
curl_mut -sf -X POST "$API/api/hosts" -b "$(auth)" -H 'Content-Type: application/json' \
  -d '{"kind":"redirect","domain_names":["go.local"],"enabled":true,"tls_mode":"none","redirect_url":"https://example.com/x","redirect_code":301}' >/dev/null \
  && ok "redirect host created" || echo "  (go.local may already exist)"
curl_mut -sf -X POST "$API/api/hosts" -b "$(auth)" -H 'Content-Type: application/json' \
  -d '{"kind":"dead","domain_names":["gone.local"],"enabled":true,"tls_mode":"none"}' >/dev/null \
  && ok "dead host created" || echo "  (gone.local may already exist)"
curl_mut -sf -X POST "$API/api/hosts" -b "$(auth)" -H 'Content-Type: application/json' \
  -d '{"kind":"proxy","domain_names":["hdr.local"],"upstream_scheme":"http","upstream_host":"demo","upstream_port":80,"enabled":true,"tls_mode":"none","force_https":false,"request_headers":{"X-Aegis-Test":"ok"}}' >/dev/null \
  && ok "header host created" || echo "  (hdr.local may already exist)"
curl_mut -sf -X POST "$API/api/hosts" -b "$(auth)" -H 'Content-Type: application/json' \
  -d '{"kind":"proxy","domain_names":["*.wild.local"],"upstream_scheme":"http","upstream_host":"demo","upstream_port":80,"enabled":true,"tls_mode":"auto","force_https":false}' >/dev/null \
  && ok "wildcard host created" || echo "  (*.wild.local may already exist)"

AL=$(curl_mut -sf -X POST "$API/api/access-lists" -b "$(auth)" -H 'Content-Type: application/json' \
  -d '{"name":"e2e-auth","satisfy":"all","users":[{"username":"alice","password":"supersecret"}],"allow_cidrs":[],"deny_cidrs":[]}')
ALID=$(echo "$AL" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
[ -n "$ALID" ] && ok "access list created" || bad "access list create"
if [ -n "$ALID" ]; then
  curl_mut -sf -X POST "$API/api/hosts" -b "$(auth)" -H 'Content-Type: application/json' \
    -d "{\"kind\":\"proxy\",\"domain_names\":[\"auth.local\"],\"upstream_scheme\":\"http\",\"upstream_host\":\"demo\",\"upstream_port\":80,\"enabled\":true,\"tls_mode\":\"none\",\"force_https\":false,\"access_list_id\":\"$ALID\"}" >/dev/null \
    && ok "auth host created" || echo "  (auth.local may already exist)"
fi

DENY=$(curl_mut -sf -X POST "$API/api/access-lists" -b "$(auth)" -H 'Content-Type: application/json' \
  -d '{"name":"e2e-deny","satisfy":"all","users":[],"allow_cidrs":[],"deny_cidrs":["0.0.0.0/0"]}')
DID=$(echo "$DENY" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
if [ -n "$DID" ]; then
  curl_mut -sf -X POST "$API/api/hosts" -b "$(auth)" -H 'Content-Type: application/json' \
    -d "{\"kind\":\"proxy\",\"domain_names\":[\"deny.local\"],\"upstream_scheme\":\"http\",\"upstream_host\":\"demo\",\"upstream_port\":80,\"enabled\":true,\"tls_mode\":\"none\",\"force_https\":false,\"access_list_id\":\"$DID\"}" >/dev/null \
    && ok "deny host created" || echo "  (deny.local may already exist)"
fi

curl_mut -sf -X POST "$API/api/hosts" -b "$(auth)" -H 'Content-Type: application/json' \
  -d '{"kind":"stream","domain_names":["echo-stream"],"enabled":true,"listen_protocol":"tcp","listen_port":19000,"upstream_host":"demo","upstream_port":80}' >/dev/null \
  && ok "stream host created" || echo "  (echo-stream may already exist)"

sleep 2

code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: go.local' "$EDGE_HTTP/")
check "redirect host 301" "$code" "301"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: gone.local' "$EDGE_HTTP/")
check "dead host 404" "$code" "404"
body=$(curl -s -H 'Host: hdr.local' "$EDGE_HTTP/")
echo "$body" | grep -q 'X-Aegis-Test: ok' && ok "custom request header" || bad "custom request header"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: app.wild.local' "$EDGE_HTTP/")
check "wildcard *.wild.local" "$code" "200"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: auth.local' "$EDGE_HTTP/")
check "basic auth 401" "$code" "401"
code=$(curl -s -o /dev/null -w '%{http_code}' -u alice:supersecret -H 'Host: auth.local' "$EDGE_HTTP/")
check "basic auth 200" "$code" "200"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: deny.local' "$EDGE_HTTP/")
check "ip deny 403" "$code" "403"

STREAM_HOST="${EDGE_HTTP#http://}"
STREAM_HOST="${STREAM_HOST#https://}"
STREAM_HOST="${STREAM_HOST%%/*}"
STREAM_HOST="${STREAM_HOST%%:*}"
[ -z "$STREAM_HOST" ] && STREAM_HOST="127.0.0.1"
body=$(curl -s --max-time 3 "http://${STREAM_HOST}:19000/" || true)
echo "$body" | grep -q 'Hostname:' && ok "tcp stream echo" || bad "tcp stream echo"

echo "== multi-admin + audit =="
FIRST_SESSION="$SESSION"
FIRST_CSRF="$CSRF"
curl_mut -sf -X POST "$API/api/users" -b "$(auth)" -H 'Content-Type: application/json' \
  -d '{"email":"second@aegis.local","name":"Second","password":"supersecretpassword2"}' >/dev/null \
  && ok "second admin created" || echo "  (second admin may already exist)"
curl -sf -D "$HDRS" -o /dev/null -X POST "$API/api/auth/login" -H "Origin: ${ORIGIN}" -H 'Content-Type: application/json' \
  -d '{"email":"second@aegis.local","password":"supersecretpassword2"}' \
  && ok "second admin login" || bad "second admin login"
capture_session
[ -n "$SESSION" ] && ok "second session cookie" || bad "second session cookie"
curl_mut -sf -X POST "$API/api/hosts" -b "$(auth)" -H 'Content-Type: application/json' \
  -d '{"kind":"dead","domain_names":["audit.local"],"enabled":true,"tls_mode":"none","force_https":false}' >/dev/null \
  && ok "audit.local created" || echo "  (audit.local may already exist)"
sleep 1
events=$(curl -s "$API/api/audit?limit=30" -b "$(auth)")
echo "$events" | grep -q 'second@aegis.local' && ok "audit records second admin" || bad "audit records second admin"
echo "$events" | grep -q '"resource_type":"host"' && ok "audit records host change" || bad "audit records host change"

SESSION="$FIRST_SESSION"
CSRF="$FIRST_CSRF"
export AEGIS_CSRF="$CSRF"
users_json=$(curl -s "$API/api/users" -b "$(auth)")
echo "$users_json" | grep -q 'second@aegis.local' && ok "list users includes second" || bad "list users includes second"
user_id_by_email() {
  python3 -c 'import json,sys
email=sys.argv[1]
users=json.load(sys.stdin)
for u in users:
    if u.get("email")==email:
        print(u["id"], end="")
        break
' "$1" <<<"$2"
}
first_user_id() {
  python3 -c 'import json,sys
users=json.load(sys.stdin)
print(users[0]["id"] if users else "", end="")
'
}
sid=$(user_id_by_email "second@aegis.local" "$users_json")
if [ -n "$sid" ]; then
  curl_mut -sf -X DELETE "$API/api/users/$sid" \
    && ok "second admin deleted" || bad "second admin deleted"
else
  bad "second admin id"
fi
remain=$(curl -s "$API/api/users" -b "$(auth)")
lid=$(printf '%s' "$remain" | first_user_id)
code=$(curl_mut -s -o /dev/null -w '%{http_code}' -X DELETE "$API/api/users/$lid")
check "last admin 400" "$code" "400"

echo "== 0.5 security suite =="
upsert_host() {
  python3 -c '
import json,sys,os,urllib.request
api,cookie,domain,body=sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4]
origin=os.environ.get("AEGIS_E2E_ORIGIN","")
csrf=os.environ.get("AEGIS_CSRF","")
hdr={"Cookie":cookie}
if origin:
    hdr["Origin"]=origin
if csrf:
    hdr["X-CSRF-Token"]=csrf
req=urllib.request.Request(api+"/api/hosts", headers=hdr)
hosts=json.load(urllib.request.urlopen(req))
hid=""
for h in hosts:
    if domain in (h.get("domain_names") or []):
        hid=h["id"]; break
payload=json.loads(body)
mut=dict(hdr)
mut["Content-Type"]="application/json"
if hid:
    r=urllib.request.Request(api+"/api/hosts/"+hid, data=json.dumps(payload).encode(), method="PUT",
        headers=mut)
else:
    r=urllib.request.Request(api+"/api/hosts", data=json.dumps(payload).encode(), method="POST",
        headers=mut)
urllib.request.urlopen(r)
' "$API" "$(auth)" "$1" "$2"
}
WAF=$(curl_mut -sf -X POST "$API/api/waf-profiles" -b "$(auth)" -H 'Content-Type: application/json' \
  -d '{"name":"e2e-waf","mode":"block","paranoia":1,"inbound_threshold":5}')
WAFID=$(echo "$WAF" | python3 -c 'import json,sys
d=json.load(sys.stdin)
print(d.get("id",""), end="")' 2>/dev/null || true)
[ -n "$WAFID" ] && ok "waf profile created" || bad "waf profile create"
if [ -n "$WAFID" ]; then
  upsert_host "waf.local" "{\"kind\":\"proxy\",\"domain_names\":[\"waf.local\"],\"upstream_scheme\":\"http\",\"upstream_host\":\"demo\",\"upstream_port\":80,\"enabled\":true,\"tls_mode\":\"none\",\"force_https\":false,\"waf_profile_id\":\"$WAFID\"}" \
    && ok "waf.local upserted" || bad "waf.local upsert"
  # k6.local runs the full compile-in pipeline: WAF PL1, a high rate-limit
  # (Redis consult, no 429), CrowdSec wrap, geo wrap (deny CN). RFC1918 and
  # loopback skip CrowdSec and GeoIP so compose e2e/k6 still get 200.
  upsert_host "k6.local" "{\"kind\":\"proxy\",\"domain_names\":[\"k6.local\"],\"upstream_scheme\":\"http\",\"upstream_host\":\"demo\",\"upstream_port\":80,\"enabled\":true,\"tls_mode\":\"none\",\"force_https\":false,\"waf_profile_id\":\"$WAFID\",\"rate_limit_rps\":100000,\"rate_limit_burst\":100000,\"crowdsec_enabled\":true,\"geo_deny\":[\"CN\"]}" \
    && ok "k6.local upserted" || bad "k6.local upsert"
else
  bad "waf.local upsert"
fi
upsert_host "rl.local" '{"kind":"proxy","domain_names":["rl.local"],"upstream_scheme":"http","upstream_host":"demo","upstream_port":80,"enabled":true,"tls_mode":"none","force_https":false,"rate_limit_rps":1,"rate_limit_burst":1}' \
  && ok "rl.local upserted" || bad "rl.local upsert"
sleep 2
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: waf.local' "$EDGE_HTTP/waf-probe")
check "waf probe 403" "$code" "403"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: waf.local' "$EDGE_HTTP/?q=union+select+1")
check "waf sqli 403" "$code" "403"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: waf.local' "$EDGE_HTTP/")
check "waf pass 200" "$code" "200"
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: k6.local' "$EDGE_HTTP/")
check "k6.local pipeline 200" "$code" "200"
curl -s -o /dev/null -H 'Host: rl.local' "$EDGE_HTTP/" || true
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: rl.local' "$EDGE_HTTP/")
check "rate limit 429" "$code" "429"
sleep 2
tel=$(curl -s "$API/api/telemetry" -b "$(auth)")
echo "$tel" | python3 -c 'import json,sys
d=json.load(sys.stdin)
raise SystemExit(0 if int(d.get("received",0))>0 else 1)' \
  && ok "telemetry received > 0" || bad "telemetry received ($tel)"
sum=$(curl -s "$API/api/analytics/summary" -b "$(auth)")
echo "$sum" | python3 -c 'import json,sys
d=json.load(sys.stdin)
raise SystemExit(0 if int(d.get("received",0))>0 else 1)' \
  && ok "analytics summary received > 0" || bad "analytics summary ($sum)"

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
