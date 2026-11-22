#!/usr/bin/env bash
# Multi-NAT E2E Verification Script (Track F1)
#
# Verifies the 4-node Multi-NAT Docker Compose topology:
#   - ggn-public-relay (:18180)
#   - ggn-cone-a       (:18181)
#   - ggn-cone-b       (:18182)
#   - ggn-sym-c        (:18183)
#
# Checks:
#   1. All 4 services are running
#   2. UDP :8000 mesh sockets are bound inside each container
#   3. Netem qdisc shaping is active on eth0
#   4. /api/status and /api/topology return HTTP 200 JSON on all 4 nodes

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$ROOT/deploy/docker-compose.nat-e2e.yml"

dc() {
  docker compose -f "$COMPOSE_FILE" "$@"
}

SERVICES=(ggn-public-relay ggn-cone-a ggn-cone-b ggn-sym-c)
PORTS=(18180 18181 18182 18183)

echo "==> [1/4] Checking Multi-NAT Container Status..."
RUNNING_SERVICES="$(dc ps --status running --services)"
for svc in "${SERVICES[@]}"; do
  if ! printf '%s\n' "$RUNNING_SERVICES" | grep -qx "$svc"; then
    echo "FAIL: service '$svc' is not running"
    dc ps
    exit 1
  fi
done
echo "    All 4 services running: ${SERVICES[*]}"

echo "==> [2/4] Verifying UDP :8000 Mesh Sockets..."
# Port 8000 in hex is 1F40 in /proc/net/udp
for svc in "${SERVICES[@]}"; do
  if ! dc exec -T "$svc" sh -c "grep -qi ':1F40 ' /proc/net/udp"; then
    echo "FAIL: $svc is not listening on UDP :8000"
    exit 1
  fi
done
echo "    All 4 nodes bound on UDP :8000."

echo "==> [3/4] Verifying Netem Link Shaping..."
for svc in "${SERVICES[@]}"; do
  if ! dc exec -T "$svc" sh -c "tc qdisc show dev eth0 | grep -q netem"; then
    echo "FAIL: $svc missing netem qdisc on eth0"
    exit 1
  fi
done
echo "    Netem qdisc verified on all 4 nodes."

echo "==> [4/4] Verifying /api/status and /api/topology Across All Nodes..."
for idx in "${!SERVICES[@]}"; do
  svc="${SERVICES[$idx]}"
  port="${PORTS[$idx]}"
  base="http://127.0.0.1:${port}"

  status_ok=0
  for _ in $(seq 1 30); do
    BODY="$(curl -fsS --max-time 3 "${base}/api/status" 2>/dev/null || true)"
    if [ -n "$BODY" ] && printf '%s' "$BODY" | grep -q '"status"'; then
      status_ok=1
      break
    fi
    sleep 1
  done
  if [ "$status_ok" -ne 1 ]; then
    echo "FAIL: ${svc} (${base}/api/status) did not return valid JSON within 30s"
    exit 1
  fi

  topo_body="$(curl -fsS --max-time 3 "${base}/api/topology" 2>/dev/null || true)"
  if [ -z "$topo_body" ] || ! printf '%s' "$topo_body" | grep -q '"self"'; then
    echo "FAIL: ${svc} (${base}/api/topology) did not return valid topology JSON"
    exit 1
  fi

  echo "    OK: ${svc} (${base}) /api/status + /api/topology verified"
done

echo "==> Multi-NAT E2E Verification Passed."
