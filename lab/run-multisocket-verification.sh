#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/lab/docker-compose.multisocket.yml"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/lab/artifacts/multisocket}"
REAUTH_WAIT="${REAUTH_WAIT:-45}"
RUN_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

mkdir -p "$ARTIFACT_DIR"

cleanup() {
  docker rm -f ovpn-ms-udp ovpn-ms-tcp >/dev/null 2>&1 || true
}
trap cleanup EXIT

require_running_stack() {
  docker compose -f "$COMPOSE_FILE" ps --status running >/dev/null
}

start_client() {
  local name="$1"
  local config="$2"

  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d \
    --name "$name" \
    --network host \
    --cap-add NET_ADMIN \
    --device /dev/net/tun \
    -v "$ROOT_DIR/lab/$config:/client.ovpn:ro" \
    lab-openvpn openvpn --config /client.ovpn >/dev/null
}

wait_for_webauth_url() {
  local name="$1"
  local deadline=$((SECONDS + 60))
  local url=""

  while [ "$SECONDS" -lt "$deadline" ]; do
    url="$(docker logs "$name" 2>&1 | sed -n "s/.*WEB_AUTH::\\(http[^']*\\).*/\\1/p" | tail -n 1)"
    if [ -n "$url" ]; then
      printf '%s\n' "$url"
      return 0
    fi
    sleep 1
  done

  echo "ERROR: WEB_AUTH URL not found in $name logs" >&2
  docker logs "$name" >&2 || true
  return 1
}

callback_via_alb_mock() {
  local url="$1"
  local path="$url"

  path="${path#http://localhost:8080}"
  path="${path#http://127.0.0.1:8080}"
  docker compose -f "$COMPOSE_FILE" exec -T alb-mock wget -qO- "http://localhost:8080$path" >/dev/null
}

wait_for_init() {
  local name="$1"
  local deadline=$((SECONDS + 60))

  while [ "$SECONDS" -lt "$deadline" ]; do
    if docker logs "$name" 2>&1 | grep -q "Initialization Sequence Completed"; then
      return 0
    fi
    sleep 1
  done

  echo "ERROR: client $name did not establish tunnel" >&2
  docker logs "$name" >&2 || true
  return 1
}

verify_client() {
  local name="$1"
  local config="$2"
  local url

  echo "==> Starting $name using $config"
  start_client "$name" "$config"
  url="$(wait_for_webauth_url "$name")"
  echo "==> Completing callback for $name"
  callback_via_alb_mock "$url"
  wait_for_init "$name"
  echo "==> $name established"
}

summarize() {
  local daemon_log="$ARTIFACT_DIR/daemon.log"

  docker compose -f "$COMPOSE_FILE" logs --since "$RUN_STARTED_AT" --no-color daemon > "$daemon_log"

  echo ""
  echo "==> Raw management summary"
  rg "CLIENT:CONNECT|CLIENT:ESTABLISHED|CLIENT:REAUTH|CLIENT:DISCONNECT|SUCCESS: client-auth|connect cid=|reauth cid=|disconnect cid=|established cid=|CLIENT_LIST|ROUTING_TABLE" "$daemon_log" || true
  echo ""
  echo "==> Listener metadata candidates"
  rg "common_name=|trusted_port=|local_port_[0-9]+=|local_[0-9]+=|proto_[0-9]+=|remote_port_[0-9]+=" "$daemon_log" || true
  echo ""
  echo "==> Full daemon log saved to $daemon_log"
}

require_running_stack
cleanup

verify_client ovpn-ms-udp client-udp.ovpn
verify_client ovpn-ms-tcp client-tcp.ovpn

echo "==> Waiting ${REAUTH_WAIT}s for renegotiation events"
sleep "$REAUTH_WAIT"

echo "==> Restarting daemon to capture status 3 with active multi-socket sessions"
docker compose -f "$COMPOSE_FILE" restart daemon >/dev/null
sleep 8

docker stop -t 10 ovpn-ms-udp >/dev/null 2>&1 || true
docker stop -t 10 ovpn-ms-tcp >/dev/null 2>&1 || true

summarize
