#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Vantablack — VPN loopback self-test (zero elevation)
#
# The gate PROTOTYPE.md calls "nothing is wire-proven yet", made runnable
# without hardware: two REAL processes (hub + client) over REAL UDP sockets,
# the REAL hybrid PQ handshake, the REAL tunnel seal/open path — with the
# client on the in-memory TUN (`GHOST_VPN_FAKE_TUN`), so no wintun.dll, no
# Administrator, no OS interface and no traffic leaving the machine.
#
#   hub   GHOST_VPN=hub    127.0.0.1:22711   (allowlists the client fingerprint)
#   client GHOST_VPN=client 127.0.0.1:22712   (fake TUN, probes the hub overlay)
#
# The client pushes a synthetic ICMP echo request (the same packet its watchdog
# sends as a keepalive) toward 10.66.0.1 every second. The hub's netstack answers
# it. A returned echo reply proves the whole path:
#   TUN → seal(tunnel AEAD, per-epoch counter) → session AEAD → GTF bulk frame
#   → UDP → hub ingress → lease/re-anchor → ICMP answer → seal → UDP → open → TUN
#
# Run:  bash scripts/vpn_loopback_test.sh
# Requires: cargo build --features vpn   (this script builds it if missing)
# ─────────────────────────────────────────────────────────────────────────────
set -u
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
BIN="$TARGET_DIR/debug/vantablack.exe"
[ -f run_node ] || BIN="$TARGET_DIR/debug/vantablack"

T="$ROOT/target/vpn_selftest"
rm -rf "$T"; mkdir -p "$T"

# Unique ports per run so a leaked process from a previous run cannot interfere.
BASE=$(( ($$ % 12000) + 23000 ))
HUB_PORT=$BASE
CLIENT_PORT=$((BASE + 1))
PASS=0; FAIL=0

say(){ printf '\n=== %s ===\n' "$*"; }
ok(){  printf '  [PASS] %s\n' "$*"; PASS=$((PASS+1)); }
bad(){ printf '  [FAIL] %s\n' "$*"; FAIL=$((FAIL+1)); }

# tracing_subscriber emits ANSI even when redirected to a file — strip it before
# grepping (this is the trap that made the first run of this test report
# "no fingerprint" while the fingerprint was plainly in the log).
clean(){ sed 's/\x1b\[[0-9;]*m//g' "$1" 2>/dev/null | tr -d '\000'; }
fp_of(){ clean "$1" | grep -o 'fingerprint=[0-9a-f]\{16\}' | head -1 | cut -d= -f2; }

cleanup(){
  [ -n "${PC:-}" ] && kill "$PC" 2>/dev/null
  [ -n "${PH:-}" ] && kill "$PH" 2>/dev/null
  [ -n "${P1:-}" ] && kill "$P1" 2>/dev/null
  # tail -f feeders exit on EPIPE, but be safe
  for pid in $(ps -ef 2>/dev/null | grep "tail -f.*cmds.txt" | grep -v grep | awk '{print $1}'); do
    kill "$pid" 2>/dev/null
  done
}
trap cleanup EXIT

say "ensuring binary is built (debug, --features vpn)"
if ! command -v cargo >/dev/null 2>&1; then
  bad "cargo is not on PATH (add ~/.cargo/bin to Git Bash PATH)"
  exit 1
fi
cargo build --features vpn || { bad "cargo build --features vpn"; exit 1; }
[ -f "$BIN" ] || { bad "binary missing: $BIN"; exit 1; }

# Git Bash can try to load a Windows GNU executable through the MSYS runtime,
# which makes Windows API-set DLLs appear missing. Launch Windows binaries via
# cmd.exe when available; retain direct execution for Linux/WSL.
run_node() {
  if command -v cmd.exe >/dev/null 2>&1; then
    cmd.exe /c "$BIN"
  else
    "$BIN"
  fi
}

# ── phase 1: learn the hub fingerprint ──────────────────────────────────────
# The hub's identity persists in GHOST_IDENTITY_FILE, so its fingerprint is
# stable across the restart in phase 3. (GHOST_IDENTITY_FILE is what makes this
# test possible at all — before it, both nodes had to run from separate CWDs.)
say "phase 1: hub fingerprint"
GHOST_VPN=hub GHOST_BIND="127.0.0.1:$HUB_PORT" GHOST_IDENTITY_FILE="$T/hub.key" \
  GHOST_METRICS_ENABLED=0 RUST_LOG=info run_node </dev/null >"$T/p1.log" 2>&1 &
P1=$!
sleep 7
kill "$P1" 2>/dev/null; sleep 3; P1=""
FP_HUB=$(fp_of "$T/p1.log")
if [ -n "${FP_HUB:-}" ]; then ok "hub fingerprint $FP_HUB"; else bad "no hub fingerprint"; clean "$T/p1.log" | head -20; fi

# ── phase 2: fake-TUN client ────────────────────────────────────────────────
say "phase 2: fake-TUN client (no admin, no OS interface)"
touch "$T/cmds.txt"
GHOST_VPN=client GHOST_VPN_FAKE_TUN=1 GHOST_VPN_HUB_FP="$FP_HUB" GHOST_VPN_LOCAL_IP=10.66.0.10 \
  GHOST_BIND="127.0.0.1:$CLIENT_PORT" GHOST_IDENTITY_FILE="$T/client.key" \
  GHOST_METRICS_ENABLED=0 RUST_LOG=info run_node < <(tail -f "$T/cmds.txt") >"$T/client.log" 2>&1 &
PC=$!
sleep 7
FP_CLIENT=$(fp_of "$T/client.log")
[ -n "${FP_CLIENT:-}" ] && ok "client fingerprint $FP_CLIENT" || bad "no client fingerprint"
if clean "$T/client.log" | grep -q "GHOST_VPN_FAKE_TUN is set"; then
  ok "fake-TUN mode active"
else
  bad "fake-TUN mode NOT active"
fi

# ── phase 3: hub with the client allowlisted ────────────────────────────────
say "phase 3: hub restarted with the client allowlisted"
GHOST_VPN=hub GHOST_VPN_CLIENTS="$FP_CLIENT" GHOST_BIND="127.0.0.1:$HUB_PORT" \
  GHOST_IDENTITY_FILE="$T/hub.key" GHOST_METRICS_ENABLED=0 RUST_LOG=info run_node </dev/null >"$T/hub.log" 2>&1 &
PH=$!
sleep 7
if clean "$T/hub.log" | grep -q "address=127.0.0.1:$HUB_PORT"; then
  ok "hub bound $HUB_PORT"
else
  bad "hub did not bind (a previous process may still hold the port)"
fi
# Two nodes on one host both want 0.0.0.0:2270 for beacons; only one wins.
# Expect an ERROR from the loser — it is harmless here (no beacons are needed)
# but it is a real operational wart worth knowing about.
if clean "$T/hub.log" | grep -q "Beacon listener"; then
  printf '  [note] beacon listener collision (both nodes wanted 0.0.0.0:2270) — expected on one host\n'
fi

# ── phase 4: PEER, then wait for a tunneled echo reply ──────────────────────
say "phase 4: PEER + tunneled ICMP round trip"
printf 'PEER 127.0.0.1:%s\n' "$HUB_PORT" >> "$T/cmds.txt"
for _ in $(seq 1 20); do
  sleep 2
  clean "$T/client.log" | grep -q "FAKE-TUN self-test: PASS" && break
done

if clean "$T/client.log" | grep -q "Session established (initiator)"; then
  ok "mesh session established (hybrid X25519 + ML-KEM-512 handshake)"
else
  bad "no mesh session between client and hub"
fi

if clean "$T/client.log" | grep -q "FAKE-TUN self-test: PASS"; then
  R=$(clean "$T/client.log" | grep -o 'replies_total=[0-9]*' | tail -1 | cut -d= -f2)
  ok "tunnel round trip: ${R:-?} ICMP echo repl(y|ies) returned through the mesh"
  clean "$T/client.log" | grep "FAKE-TUN self-test: PASS" | tail -2
else
  bad "no tunneled echo reply within the window"
  clean "$T/client.log" | grep "FAKE-TUN self-test" | tail -3
fi

printf '\n==== %s passed, %s failed ====\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
