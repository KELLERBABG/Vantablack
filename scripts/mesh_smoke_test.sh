#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Vantablack — live 2-node mesh smoke test
#
# REAL everything: real UDP sockets, real X25519+ML-KEM-512 hybrid handshake,
# real ChaCha20-Poly1305 + Reed-Solomon sharding, real TCP through the mesh.
# No mocks, no virtual transport, no fake data.
#
# A Linux-with-root section additionally runs the kernel-level symmetric-NAT gate
# (scripts/nat_gate_iptables.sh, throwaway network namespaces); elsewhere it is
# skipped and `tests/p1_nat.rs` / `tests/p1_relay.rs` cover the same logic.
#
# Topology (all on localhost):
#   HTTP server (py -m http.server)     :19000
#   node B  — exit node                 :15252  (opens the real TCP connection)
#   node A  — SOCKS5 initiator          :15253  (proxy on 127.0.0.1:1080)
#
#   curl ──SOCKS5──▶ node A ──mesh(UDP)──▶ node B ──TCP──▶ HTTP server
#
# Run:  bash scripts/mesh_smoke_test.sh
# ─────────────────────────────────────────────────────────────────────────────
set -u
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
TMP="$ROOT/target/smoke_test_$$"
BIN=""
for d in "$ROOT/target/debug"; do
  if [ -f "$d/vantablack.exe" ]; then BIN="$d/vantablack.exe"; break; fi
done
[ -n "$BIN" ] || BIN="$(cargo metadata --format-version 1 2>/dev/null | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p')/debug/vantablack.exe"

# Unique ports per run so stale processes from previous runs can't interfere
BASE=$(( ($$ % 20000) + 10000 ))
# 32-byte hex pre-shared key shared by both nodes (defense-in-depth)
PSK="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
HTTP_PORT=$BASE
NODE_B_PORT=$((BASE + 1))
NODE_A_PORT=$((BASE + 2))
SOCKS_PORT=$((BASE + 3))
PASS=0; FAIL=0

# Kill anything still listening on our ports (leaked from a previous run)
for port in "$HTTP_PORT" "$NODE_B_PORT" "$NODE_A_PORT" "$SOCKS_PORT"; do
  for pid in $(netstat -ano 2>/dev/null | grep "LISTENING" | grep ":$port " | awk '{print $NF}' | sort -u); do
    taskkill //F //PID "$pid" >/dev/null 2>&1
  done
done

say()  { printf '==> %s\n' "$*"; }
ok()   { printf '    [PASS] %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '    [FAIL] %s\n' "$*"; FAIL=$((FAIL+1)); }

say "building (debug)..."
cargo build >/dev/null 2>&1 || { bad "cargo build"; exit 1; }
[ -f "$BIN" ] || { bad "binary missing: $BIN"; exit 1; }

rm -rf "$TMP"; mkdir -p "$TMP/http" "$TMP/nodeA" "$TMP/nodeB"
printf 'Vantablack mesh smoke test — %s\n0123456789\n' "$(date)" > "$TMP/http/mesh_test.txt"

say "starting HTTP server on 127.0.0.1:$HTTP_PORT"
( cd "$TMP/http" && py -m http.server "$HTTP_PORT" --bind 127.0.0.1 >/dev/null 2>&1 ) &
HTTP_PID=$!

say "starting node B (exit) on 127.0.0.1:$NODE_B_PORT"
touch "$TMP/nodeB/commands.txt"   # node B also reads CLI commands (EXITAUTH etc.)
# Note: commands are fed via `tail -f` (a pipe), not `< commands.txt` — on
# Windows a redirected stdin FILE stops seeing appends once it hits EOF, so
# commands written late in the test (CHAT/EXPORTTOPOLOGY) would be dropped.
( cd "$TMP/nodeB" && GHOST_BIND="127.0.0.1:$NODE_B_PORT" GHOST_PSK="$PSK" "$BIN" \
    < <(tail -f "$TMP/nodeB/commands.txt") > node_b.log 2>&1 ) &
B_PID=$!

touch "$TMP/nodeA/commands.txt"   # CLI commands get appended; the binary keeps reading
say "starting node A (SOCKS5) on 127.0.0.1:$NODE_A_PORT"
( cd "$TMP/nodeA" && GHOST_SOCKS5=1 GHOST_SOCKS5_PORT="$SOCKS_PORT" GHOST_BIND="127.0.0.1:$NODE_A_PORT" GHOST_PSK="$PSK" "$BIN" \
    < <(tail -f "$TMP/nodeA/commands.txt") > node_a.log 2>&1 ) &
A_PID=$!

cleanup() {
  kill "$A_PID" "$B_PID" "$HTTP_PID" 2>/dev/null
  wait "$A_PID" "$B_PID" "$HTTP_PID" 2>/dev/null
  # kill any tail -f feeders left over (they exit on EPIPE, but be safe)
  for pid in $(ps -ef 2>/dev/null | grep "tail -f.*commands.txt" | grep -v grep | awk '{print $1}'); do
    kill "$pid" 2>/dev/null
  done
}
trap cleanup EXIT

sleep 2

say "disabling beacons (avoid LAN interference)"
printf 'BEACON off\n' >> "$TMP/nodeA/commands.txt"

say "peering node A → node B"
printf 'PEER 127.0.0.1:%s\n' "$NODE_B_PORT" >> "$TMP/nodeA/commands.txt"

# Wait for the post-quantum handshake to complete (session established)
SESSIONS=0
for i in $(seq 1 30); do
  sleep 1
  printf 'STATUS\n' >> "$TMP/nodeA/commands.txt"
  if grep -q "Sessions: [1-9]" "$TMP/nodeA/node_a.log" 2>/dev/null; then SESSIONS=1; break; fi
done
[ "$SESSIONS" = 1 ] && ok "mesh session established (X25519 + ML-KEM-512 handshake)" \
                   || bad "no session after 30s (see $TMP/node_a.log)"

if [ "$SESSIONS" = 1 ]; then
  # Pin node B as the exit node so beacon-discovered LAN peers are ignored
  BFP=$(sed 's/\x1b\[[0-9;]*m//g' "$TMP/nodeB/node_b.log" | tr -d '\000' | grep -o 'fingerprint=[0-9a-f]\{16\}' | head -1 | cut -d= -f2)
  if [ -n "$BFP" ]; then
    printf 'EXIT %s\n' "$BFP" >> "$TMP/nodeA/commands.txt"
    ok "exit node pinned: $BFP"
  fi
  # Exit authorization: node B only serves as an exit for node A's fingerprint
  # (proves the allowlist flow; exit service is closed by default).
  AFP=$(sed 's/\x1b\[[0-9;]*m//g' "$TMP/nodeB/node_b.log" | tr -d '\000' | grep -o 'Verified peer fingerprint=[0-9a-f]\{16\}' | head -1 | cut -d= -f2)
  if [ -n "$AFP" ]; then
    printf 'EXITAUTH %s\n' "$AFP" >> "$TMP/nodeB/commands.txt"
    ok "exit allowlisted for: $AFP"
  fi
  sleep 1
  say "routing real HTTP through the mesh (curl via SOCKS5 :$SOCKS_PORT)"
  BODY=""
  for i in $(seq 1 20); do
    BODY=$(curl -s --max-time 5 --socks5-hostname 127.0.0.1:$SOCKS_PORT \
                  "http://127.0.0.1:$HTTP_PORT/mesh_test.txt" 2>/dev/null)
    [ -n "$BODY" ] && break
    sleep 1
  done
  if echo "$BODY" | grep -q "0123456789"; then
    ok "HTTP response tunneled through the mesh (${#BODY} bytes)"
  else
    bad "no tunneled HTTP response (body='${BODY}' truncated)"
  fi

  # ── Direct chat (CHAT command) ──
  say "testing direct chat A → B (CHAT command)"
  printf 'CHAT %s hello-mesh-chat\n' "$BFP" >> "$TMP/nodeA/commands.txt"
  CHAT_OK=""
  for i in $(seq 1 10); do
    sleep 1
    if grep -q "\[Chat from .*\] hello-mesh-chat" "$TMP/nodeB/node_b.log" 2>/dev/null; then CHAT_OK=1; break; fi
  done
  [ -n "$CHAT_OK" ] && ok "chat message delivered A → B (encrypted, direct session)" \
                    || bad "chat message not received (see $TMP/nodeB/node_b.log)"

  say "testing direct chat B → A"
  printf 'CHAT %s reply-from-b\n' "$AFP" >> "$TMP/nodeB/commands.txt"
  CHAT_OK2=""
  for i in $(seq 1 10); do
    sleep 1
    if grep -q "\[Chat from .*\] reply-from-b" "$TMP/nodeA/node_a.log" 2>/dev/null; then CHAT_OK2=1; break; fi
  done
  [ -n "$CHAT_OK2" ] && ok "chat message delivered B → A" \
                    || bad "reverse chat not received (see $TMP/nodeA/node_a.log)"

  # ── QEL integration (optional): export the live mesh and route quantum
  # ── entanglement. Runs only when `quantumnet` is installed (QEL lives in
  # ── its own repo); the Rust core is fully tested without it.
  if py -c "import quantumnet" >/dev/null 2>&1; then
  if py -m quantumnet --help 2>/dev/null | grep -q "ghost-net"; then
  say "exporting live mesh topology and routing quantum entanglement (QEL)"
  # the Rust daemon needs a Windows-style path, not a Git-Bash /c/... path
  EXPORT_PATH=$(cygpath -w "$TMP/ghost-topology.json" 2>/dev/null || echo "$TMP/ghost-topology.json")
  printf 'EXPORTTOPOLOGY %s\n' "$EXPORT_PATH" >> "$TMP/nodeA/commands.txt"
  sleep 1
  if [ -f "$TMP/ghost-topology.json" ]; then
    AFP=$(sed 's/\x1b\[[0-9;]*m//g' "$TMP/nodeA/node_a.log" | tr -d '\000' | grep -o 'fingerprint=[0-9a-f]\{16\}' | head -1 | cut -d= -f2)
    # positions: place the two nodes far apart so the optical link is physical
    QOUT=$(py -m quantumnet ghost-net \
        --topology "$TMP/ghost-topology.json" \
        --from "$AFP" --to "$BFP" \
        --positions "${AFP}=0,0 ${BFP}=500,300" 2>&1)
    if echo "$QOUT" | grep -q "END-TO-END FIDELITY"; then
      ok "quantum entanglement routed over the live mesh"
      echo "$QOUT" | grep -E "QuantumTopology|Route:|END-TO-END|swap at" | sed 's/^/    /'
    else
      bad "ghost-net route failed"
      echo "$QOUT" | tail -5 | sed 's/^/    /'
    fi
  else
    bad "EXPORTTOPOLOGY produced no file"
  fi
  else
    say "skipping QEL integration (installed quantumnet has no ghost-net command — QEL workstream is separate)"
  fi
  else
    say "skipping QEL integration (quantumnet not installed — optional)"
  fi
fi

# ── iptables symmetric-NAT topology (SOTA P1-1) ─────────────────────────────
# The Rust gates (`tests/p1_nat.rs`, `tests/p1_relay.rs`) model an RFC 4787 NAT
# and run on every platform. This checks the model against the real kernel, in
# throwaway network namespaces, when the host can do it at all (Linux + root).
# It is a separate script because it needs namespaces, `ip` and `iptables`; when
# those are missing it exits 0 having said so, and this section reports the skip
# rather than a vacuous pass.
say "NAT topology: kernel-level symmetric-NAT gate"
NAT_OUT=$(bash "$ROOT/scripts/nat_gate_iptables.sh" 2>&1); NAT_RC=$?
echo "$NAT_OUT" | sed 's/^/    /'
case "$NAT_OUT" in
  *skipping*)
    say "    (skipped — needs Linux + root; the Rust gates cover the same logic here)"
    ;;
  *)
    if [ "$NAT_RC" -eq 0 ]; then
      ok "kernel-level symmetric-NAT gate: symmetric mapping, relay pinhole, filtering"
    else
      bad "kernel-level symmetric-NAT gate failed (see output above)"
    fi
    ;;
esac

say "node A log (tail):"
tail -5 "$TMP/nodeA/node_a.log" 2>/dev/null | sed 's/^/    /'
say "node B log (tail):"
tail -5 "$TMP/nodeB/node_b.log" 2>/dev/null | sed 's/^/    /'

printf '\n==== %s passed, %s failed ====\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
