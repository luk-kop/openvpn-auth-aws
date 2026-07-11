#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/lab/docker-compose.multisocket.yml"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/lab/artifacts/pending-status-2.7.5/$RUN_ID}"
PROBE_BIN="$(mktemp /tmp/openvpn-pending-status-probe.XXXXXX)"
PROBE_CONTAINER="ovpn-pending-status-probe-$RUN_ID"
CLIENT_CONTAINER="ovpn-pending-status-client-$RUN_ID"
PROBE_LOG="$ARTIFACT_DIR/management.log"

mkdir -p "$ARTIFACT_DIR"

cleanup() {
  docker rm -f "$CLIENT_CONTAINER" "$PROBE_CONTAINER" >/dev/null 2>&1 || true
  docker compose -f "$COMPOSE_FILE" start daemon >/dev/null 2>&1 || true
  rm -f "$PROBE_BIN"
}
trap cleanup EXIT

echo "==> Building pending-status probe"
CGO_ENABLED=0 go build -o "$PROBE_BIN" ./lab/cmd/pending-status-probe

echo "==> Restarting OpenVPN with the current lab PKI"
docker compose -f "$COMPOSE_FILE" restart openvpn >/dev/null
deadline=$((SECONDS + 30))
until docker compose -f "$COMPOSE_FILE" ps --status running openvpn | grep -q 'healthy'; do
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "ERROR: OpenVPN did not become healthy after restart" >&2
    exit 1
  fi
  sleep 0.5
done

echo "==> Recording OpenVPN version"
docker compose -f "$COMPOSE_FILE" exec -T openvpn openvpn --version > "$ARTIFACT_DIR/openvpn-version.txt"

echo "==> Stopping daemon so the probe owns the management socket"
docker compose -f "$COMPOSE_FILE" stop daemon >/dev/null

echo "==> Starting management probe"
docker compose -f "$COMPOSE_FILE" run --rm --no-deps -T \
  --name "$PROBE_CONTAINER" \
  --entrypoint /probe \
  -v "$PROBE_BIN:/probe:ro" \
  daemon \
  --socket=/run/openvpn/management.sock \
  --password-file=/etc/openvpn/management-pw \
  > "$PROBE_LOG" 2>&1 &
probe_pid=$!

deadline=$((SECONDS + 30))
until grep -q "PROBE_READY" "$PROBE_LOG" 2>/dev/null; do
  if ! kill -0 "$probe_pid" 2>/dev/null; then
    wait "$probe_pid" || true
    echo "ERROR: probe exited before becoming ready" >&2
    cat "$PROBE_LOG" >&2
    exit 1
  fi
  if [ "$SECONDS" -ge "$deadline" ]; then
    echo "ERROR: probe did not become ready" >&2
    cat "$PROBE_LOG" >&2
    exit 1
  fi
  sleep 0.2
done

echo "==> Starting a client and letting the probe authenticate and terminate it"
docker run -d \
  --name "$CLIENT_CONTAINER" \
  --network host \
  --cap-add NET_ADMIN \
  --device /dev/net/tun \
  -v "$ROOT_DIR/lab/client-udp.ovpn:/client.ovpn:ro" \
  lab-openvpn openvpn --config /client.ovpn >/dev/null

if ! wait "$probe_pid"; then
  docker logs "$CLIENT_CONTAINER" > "$ARTIFACT_DIR/client.log" 2>&1 || true
  docker compose -f "$COMPOSE_FILE" logs --no-color openvpn > "$ARTIFACT_DIR/openvpn.log" 2>&1 || true
  echo "ERROR: pending-status probe failed; artifacts: $ARTIFACT_DIR" >&2
  cat "$PROBE_LOG" >&2
  exit 1
fi

docker logs "$CLIENT_CONTAINER" > "$ARTIFACT_DIR/client.log" 2>&1 || true
docker compose -f "$COMPOSE_FILE" logs --no-color openvpn > "$ARTIFACT_DIR/openvpn.log" 2>&1 || true

grep "PROBE_ASSERT\|PROBE_COMPLETE" "$PROBE_LOG" > "$ARTIFACT_DIR/assertions.txt"

echo "==> Probe passed"
cat "$ARTIFACT_DIR/assertions.txt"
echo "==> Artifacts: $ARTIFACT_DIR"
