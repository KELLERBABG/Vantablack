#!/usr/bin/env bash
# Deploy-Not-Design Reference Mesh Smoke Test (§48)
#
# Validates reference 3-node container mesh:
# 1. Container running state checks (mesh-hub, mesh-relay, mesh-client)
# 2. Bound UDP :8000 mesh sockets inside hub & relay containers
# 3. Relay netem link shaping and routing verification
# 4. Live HTTP telemetry/status endpoint verification on mesh-client (:18080)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$ROOT/deploy/docker-compose.yml"
TELEMETRY_BASE="${TELEMETRY_BASE:-http://127.0.0.1:18080}"

dc() {
  docker compose -f "$COMPOSE_FILE" "$@"
}

echo "==> [1/4] Checking Reference Mesh Container Status..."
RUNNING_SERVICES="$(dc ps --status running --services)"
for svc in mesh-hub mesh-relay mesh-client; do
  if ! printf '%s\n' "$RUNNING_SERVICES" | grep -qx "$svc"; then
    echo "FAIL: service '$svc' is not running"
    dc ps
    exit 1
  fi
done
echo "    All 3 services running: mesh-hub, mesh-relay, mesh-client"

echo "==> [2/4] Verifying Hub & Relay UDP :8000 Mesh Sockets..."
# Port 8000 in hex is 1F40 in /proc/net/udp
for svc in mesh-hub mesh-relay; do
  if ! dc exec -T "$svc" sh -c "grep -qi ':1F40 ' /proc/net/udp"; then
    echo "FAIL: $svc is not listening on UDP :8000"
    exit 1
  fi
done
echo "    Hub and relay UDP :8000 sockets verified bound."

echo "==> [3/4] Verifying Relay Network Shaping & Connectivity..."
if ! dc exec -T mesh-relay sh -c "tc qdisc show dev eth0 | grep -q netem"; then
  echo "FAIL: mesh-relay missing netem qdisc on eth0"
  exit 1
fi
if ! dc exec -T mesh-client sh -c "ip route show | grep -q '172.29.'"; then
  echo "FAIL: mesh-client missing 172.29.0.0/16 mesh network route"
  exit 1
fi
echo "    Relay netem qdisc and mesh subnet routing verified."

echo "==> [4/4] Verifying Live Client Telemetry / Status Endpoint..."
RESP=""
ENDPOINT=""
for _ in $(seq 1 30); do
  for path in /api/telemetry /api/status; do
    BODY="$(curl -fsS --max-time 3 "${TELEMETRY_BASE}${path}" 2>/dev/null || true)"
    if [ -n "$BODY" ] && printf '%s' "$BODY" | grep -q '"status"'; then
      RESP="$BODY"
      ENDPOINT="$path"
      break 2
    fi
  done
  sleep 1
done

if [ -z "$RESP" ]; then
  echo "FAIL: ${TELEMETRY_BASE}/api/telemetry (and /api/status) did not return valid JSON within 30s"
  exit 1
fi

echo "    Verified HTTP 200 JSON from ${TELEMETRY_BASE}${ENDPOINT} (${#RESP} bytes)"
if printf '%s' "$RESP" | grep -q '"cycle"'; then
  CYCLE="$(printf '%s' "$RESP" | sed -n 's/.*"cycle"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -1)"
  echo "    Telemetry cycle=${CYCLE:-0}"
fi
echo "    Deploy-Not-Design Smoke Test Passed."
