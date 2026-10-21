#!/bin/sh
# Watches CONTROL_DIR/firewall.enabled (1/0). Missing file means on, matching
# the 1.3.0 default. Off: stop the bouncer and drop nftables tables so bans
# do not linger. The API writes the file; this container has no Docker socket.
set -eu
API_KEY="${API_KEY:-${CROWDSEC_FIREWALL_KEY:-}}"
CONTROL_DIR="${CONTROL_DIR:-/control}"
FLAG="${CONTROL_DIR}/firewall.enabled"
if [ -z "$API_KEY" ]; then
  echo "crowdsec-firewall: API_KEY is empty" >&2
  exit 1
fi
sed "s|\${API_KEY}|${API_KEY}|g" /tpl/firewall-bouncer.yaml > /tmp/firewall-bouncer.yaml

firewall_on() {
  if [ ! -f "$FLAG" ]; then
    return 0
  fi
  val=$(tr -d ' \n\t\r' < "$FLAG" || true)
  case "$val" in
    1|true|on|yes) return 0 ;;
    *) return 1 ;;
  esac
}

drop_tables() {
  nft delete table ip crowdsec >/dev/null 2>&1 || true
  nft delete table ip6 crowdsec6 >/dev/null 2>&1 || true
}

PID=""
stop_bouncer() {
  if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
    echo "crowdsec-firewall: stopping bouncer"
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  PID=""
  drop_tables
}

trap 'stop_bouncer; exit 0' INT TERM

while true; do
  if firewall_on; then
    if [ -z "$PID" ] || ! kill -0 "$PID" 2>/dev/null; then
      echo "crowdsec-firewall: starting bouncer"
      crowdsec-firewall-bouncer -c /tmp/firewall-bouncer.yaml &
      PID=$!
    fi
    sleep 2
    if [ -n "$PID" ] && ! kill -0 "$PID" 2>/dev/null; then
      echo "crowdsec-firewall: bouncer exited, will restart"
      PID=""
      wait || true
      sleep 2
    fi
  else
    if [ -n "$PID" ]; then
      stop_bouncer
    else
      drop_tables
    fi
    echo "crowdsec-firewall: idle (host firewall off)"
    while ! firewall_on; do
      sleep 2
    done
  fi
done
