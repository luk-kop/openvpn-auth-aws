#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/lab/docker-compose.multisocket.yml"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/lab/artifacts/local-new-wins-2.7.5/$RUN_ID}"
RUN_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

mkdir -p "$ARTIFACT_DIR"

VPN_AUTH_MANAGEMENT_RAW_LOG=true docker compose -f "$COMPOSE_FILE" up -d --force-recreate daemon >/dev/null

cleanup() {
  docker rm -f ovpn-nw-old ovpn-nw-new >/dev/null 2>&1 || true
}
trap cleanup EXIT

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

wait_for_log() {
  local name="$1"
  local pattern="$2"
  local deadline=$((SECONDS + 60))
  until docker logs "$name" 2>&1 | grep -q "$pattern"; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "ERROR: $name did not emit $pattern" >&2
      docker logs "$name" >&2 || true
      return 1
    fi
    sleep 0.5
  done
}

latest_connect_cid() {
  local since="$1"
  local cn="$2"
  docker compose -f "$COMPOSE_FILE" logs --since "$since" --no-color daemon \
    | grep -F "msg=connect " \
    | grep -F "cn=$cn " \
    | awk '{for (i = 1; i <= NF; i++) if ($i ~ /^cid=/) {sub(/^cid=/, "", $i); print $i}}' \
    | tail -n 1
}

wait_for_server_disconnect() {
  local since="$1"
  local cid="$2"
  local deadline=$((SECONDS + 20))
  until docker compose -f "$COMPOSE_FILE" logs --since "$since" --no-color daemon | grep -q "msg=disconnect cid=$cid"; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "ERROR: server did not emit disconnect for old CID=$cid" >&2
      return 1
    fi
    sleep 0.5
  done
}

wait_for_bootstrap() {
  local since="$1"
  local deadline=$((SECONDS + 30))
  until docker compose -f "$COMPOSE_FILE" logs --since "$since" --no-color daemon | grep -q 'management bootstrap complete'; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "ERROR: daemon bootstrap did not complete" >&2
      return 1
    fi
    sleep 0.5
  done
}

webauth_url() {
  local name="$1"
  local deadline=$((SECONDS + 60))
  local url
  while [ "$SECONDS" -lt "$deadline" ]; do
    url="$(docker logs "$name" 2>&1 | sed -n "s/.*WEB_AUTH::\(http[^']*\).*/\1/p" | tail -n 1)"
    if [ -n "$url" ]; then
      printf '%s\n' "$url"
      return 0
    fi
    sleep 0.5
  done
  return 1
}

complete_callback() {
  local url="$1"
  local path="${url#http://localhost:8080}"
  path="${path#http://127.0.0.1:8080}"
  docker compose -f "$COMPOSE_FILE" exec -T alb-mock wget -qO- "http://localhost:8080$path" >/dev/null
}

assert_old_alive_while_pending() {
  if ! docker ps --format '{{.Names}}' | grep -qx ovpn-nw-old; then
    echo "ERROR: old client container exited during replacement pending-auth" >&2
    return 1
  fi
  if docker logs ovpn-nw-old 2>&1 | grep -q "SIGTERM\|AUTH_FAILED\|process restarting"; then
    echo "ERROR: old client was interrupted during replacement pending-auth" >&2
    return 1
  fi
}

reset_openvpn_state() {
  docker compose -f "$COMPOSE_FILE" restart openvpn daemon >/dev/null
  local deadline=$((SECONDS + 30))
  until docker compose -f "$COMPOSE_FILE" ps --status running openvpn | grep -q 'healthy'; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "ERROR: OpenVPN did not become healthy after reset" >&2
      return 1
    fi
    sleep 0.5
  done
  sleep 1
}

run_scenario() {
  local scenario="$1"
  local new_config="$2"
  local scenario_dir="$ARTIFACT_DIR/$scenario"
  mkdir -p "$scenario_dir"
  cleanup
  reset_openvpn_state
  local scenario_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  echo "==> [$scenario] establishing old client"
  start_client ovpn-nw-old client-udp.ovpn
  local old_url
  old_url="$(webauth_url ovpn-nw-old)"
  complete_callback "$old_url"
  wait_for_log ovpn-nw-old "Initialization Sequence Completed"
  local old_cid
  old_cid="$(latest_connect_cid "$scenario_started_at" udp-user@example.com)"
  if [ -z "$old_cid" ]; then
    echo "ERROR: could not determine old client CID" >&2
    return 1
  fi

  echo "==> [$scenario] starting replacement and preserving old during pending"
  start_client ovpn-nw-new "$new_config"
  local new_url
  new_url="$(webauth_url ovpn-nw-new)"
  sleep 1
  assert_old_alive_while_pending
  echo "old_alive_during_pending=true" > "$scenario_dir/assertions.txt"

  echo "==> [$scenario] abandoning replacement and preserving old session"
  docker rm -f ovpn-nw-new >/dev/null
  sleep 1
  assert_old_alive_while_pending
  echo "old_alive_after_abandoned_replacement=true" >> "$scenario_dir/assertions.txt"

  echo "==> [$scenario] starting successful replacement"
  start_client ovpn-nw-new "$new_config"
  new_url="$(webauth_url ovpn-nw-new)"
  sleep 1
  assert_old_alive_while_pending

  echo "==> [$scenario] authenticating replacement"
  complete_callback "$new_url"
  wait_for_log ovpn-nw-new "Initialization Sequence Completed"
  wait_for_server_disconnect "$scenario_started_at" "$old_cid"

  local bootstrap_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  docker compose -f "$COMPOSE_FILE" restart daemon >/dev/null
  wait_for_bootstrap "$bootstrap_started_at"
  if ! docker ps --format '{{.Names}}' | grep -qx ovpn-nw-new; then
    echo "ERROR: replacement client did not survive daemon bootstrap" >&2
    return 1
  fi

  docker logs ovpn-nw-old > "$scenario_dir/old-client.log" 2>&1 || true
  docker logs ovpn-nw-new > "$scenario_dir/new-client.log" 2>&1 || true
  docker compose -f "$COMPOSE_FILE" logs --since "$scenario_started_at" --no-color daemon > "$scenario_dir/daemon.log"
  echo "replacement_established=true" >> "$scenario_dir/assertions.txt"
  echo "old_server_cid=$old_cid" >> "$scenario_dir/assertions.txt"
  echo "old_server_disconnect_after_replacement=true" >> "$scenario_dir/assertions.txt"
  echo "final_bootstrap_established_sessions=1" >> "$scenario_dir/assertions.txt"

  if ! rg -q 'management bootstrap complete.*established_sessions=1' "$scenario_dir/daemon.log"; then
    echo "ERROR: final authoritative snapshot did not contain exactly one established session" >&2
    return 1
  fi

  if [[ "$scenario" == exact-cn-* ]] && rg -q 'active eviction requested' "$scenario_dir/daemon.log"; then
    echo "ERROR: daemon sent client-kill for exact-CN native replacement" >&2
    return 1
  fi
  if [[ "$scenario" == case-only-cn-* ]] && ! rg -q 'active eviction requested.*identity=udp-user@example.com' "$scenario_dir/daemon.log"; then
    echo "ERROR: daemon did not request case-only eviction" >&2
    return 1
  fi
  if [[ "$scenario" == case-only-cn-* ]] && ! rg -q 'SUCCESS: client-kill command succeeded' "$scenario_dir/daemon.log"; then
    echo "ERROR: case-only eviction did not capture the client-kill acknowledgement" >&2
    return 1
  fi
}

run_scenario exact-cn-udp client-udp.ovpn
run_scenario exact-cn-tcp client-tcp-same.ovpn
run_scenario case-only-cn-udp client-udp-case.ovpn
run_scenario case-only-cn-tcp client-tcp-case.ovpn

docker compose -f "$COMPOSE_FILE" logs --since "$RUN_STARTED_AT" --no-color daemon > "$ARTIFACT_DIR/daemon.log"
docker compose -f "$COMPOSE_FILE" logs --since "$RUN_STARTED_AT" --no-color openvpn > "$ARTIFACT_DIR/openvpn.log"
docker compose -f "$COMPOSE_FILE" exec -T openvpn openvpn --version > "$ARTIFACT_DIR/openvpn-version.txt"

if ! rg -q 'active eviction requested.*identity=udp-user@example.com' "$ARTIFACT_DIR/daemon.log"; then
  echo "ERROR: case-only scenario did not request daemon-driven eviction" >&2
  exit 1
fi

echo "==> Local new-wins verification passed"
echo "==> Artifacts: $ARTIFACT_DIR"
