#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Global Ghost Net — kernel-level NAT gate (SOTA P1-1)
#
# `tests/p1_nat.rs` and `tests/p1_relay.rs` model an RFC 4787 NAT in Rust and run
# everywhere. This script checks the *model itself* against the real kernel: it
# builds two hosts behind `MASQUERADE --random` NATs (address-and-port dependent
# mapping — the behaviour that makes a CGNAT unsolvable without a relay) plus a
# public host that stands in for the relay, and then asserts the four facts the
# Phase 1 fallback rests on:
#
#   1. A mapping toward the STUN server is useless toward the relay: the NAT gives
#      the same host a different external port per destination (symmetric NAT).
#   2. A datagram the relay sends to a peer's *observed* address arrives, because
#      that peer has already sent something to the relay (the pinhole).
#   3. A datagram the relay sends to the peer's *advertised* (STUN-reported)
#      address is dropped by the peer's own NAT — there is no mapping for it.
#   4. One peer cannot reach another's advertised address directly, which is what
#      makes an ICE failure in this topology real rather than a bug.
#
# Fact 2 is why `NatHolePuncher::send_relay_keepalives` exists; fact 3 is why the
# relay is told the address it *observed*, not the one the peer advertises.
#
# Requirements: Linux, root, `ip`, `iptables`, `python3`. Everything is created in
# throwaway network namespaces and removed on exit.
#
# Run:  sudo bash scripts/nat_gate_iptables.sh
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

PASS=0; FAIL=0
say() { printf '==> %s\n' "$*"; }
ok()  { printf '    [PASS] %s\n' "$*"; PASS=$((PASS+1)); }
bad() { printf '    [FAIL] %s\n' "$*"; FAIL=$((FAIL+1)); }

# ── Preflight ───────────────────────────────────────────────────────────────
for tool in ip iptables; do
  command -v "$tool" >/dev/null 2>&1 || { say "skipping: '$tool' not available"; exit 0; }
done
PY=$(command -v python3 || command -v py || true)
[ -n "$PY" ] || { say "skipping: no python3"; exit 0; }
if [ "$(id -u)" != 0 ]; then
  say "skipping: network namespaces and iptables need root (run with sudo)"
  exit 0
fi

NS_A=ggn-dev-a      # node A's side
NS_NA=ggn-nat-a     # A's NAT (router with MASQUERADE)
NS_B=ggn-dev-b
NS_NB=ggn-nat-b
NS_NET=ggn-net      # the public internet: STUN stand-in + relay
ALL_NS="$NS_A $NS_NA $NS_B $NS_NB $NS_NET"

TMP="$(mktemp -d)"
cleanup() {
  for ns in $ALL_NS; do ip netns del "$ns" 2>/dev/null; done
  rm -rf "$TMP"
}
trap cleanup EXIT

say "creating ${ALL_NS} network namespaces"
cleanup_ns() { for ns in $ALL_NS; do ip netns del "$ns" 2>/dev/null; done; }
cleanup_ns
for ns in $ALL_NS; do ip netns add "$ns" || { bad "ip netns add $ns"; exit 1; }; done

# Bring up loopback everywhere, then the links. Each home is two hops: a device on
# a private LAN, and a NAT router that masquerades toward the internet.
for ns in $ALL_NS; do ip -n "$ns" link set lo up; done

wire() { # wire <ns1> <if1> <ip1> <ns2> <if2> <ip2>
  local ns1=$1 if1=$2 ip1=$3 ns2=$4 if2=$5 ip2=$6
  ip -n "$ns1" link add "$if1" type veth peer name "$if2" netns "$ns2"
  ip -n "$ns1" addr add "$ip1" dev "$if1"
  ip -n "$ns1" link set "$if1" up
  ip -n "$ns2" addr add "$ip2" dev "$if2"
  ip -n "$ns2" link set "$if2" up
}

wire "$NS_A"  dev0  192.168.10.2/24 "$NS_NA" lan0 192.168.10.1/24
wire "$NS_B"  dev0  192.168.20.2/24 "$NS_NB" lan0 192.168.20.1/24
wire "$NS_NA" wan0  10.0.0.2/24     "$NS_NET" wan_a 10.0.0.1/24
wire "$NS_NB" wan0  10.0.0.3/24     "$NS_NET" wan_b 10.0.0.1/24

# Default routes out of each home, and the internet host as the gateway.
ip -n "$NS_A"  route add default via 192.168.10.1
ip -n "$NS_B"  route add default via 192.168.20.1
ip -n "$NS_NA" route add default via 10.0.0.1
ip -n "$NS_NB" route add default via 10.0.0.1
# ip_forward is per-namespace; a router without it drops everything.
for ns in $NS_NA $NS_NB $NS_NET; do ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1; done

# The NATs themselves: MASQUERADE with `--random` is address-and-port dependent
# mapping — a fresh external port per destination, which is a CGNAT's behaviour.
# Inbound to an existing mapping is further restricted to the hosts that mapping
# has sent to (the kernel's default is port-restricted cone filtering).
for pair in "$NS_NA:wan0" "$NS_NB:wan0"; do
  ns=${pair%%:*}; iface=${pair##*:}
  ip netns exec "$ns" iptables -t nat -A POSTROUTING -o "$iface" -j MASQUERADE --random
done

say "starting the public-side harness (STUN stand-in :19000, relay :19001)"
cat > "$TMP/harness.py" <<'PY'
import socket, sys, select
stun = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); stun.bind(("0.0.0.0", 19000))
relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); relay.bind(("0.0.0.0", 19001))
seen = {"stun": {}, "relay": {}}
socks = [stun, relay, sys.stdin]
print("READY", flush=True)
while True:
    r, _, _ = select.select(socks, [], [])
    for s in r:
        if s is sys.stdin:
            line = sys.stdin.readline()
            if not line:
                sys.exit(0)
            parts = line.split()
            if parts[0] == "send":      # send <ip> <port> <text>  (from the relay)
                relay.sendto(parts[3].encode(), (parts[1], int(parts[2])))
                print("SENT", flush=True)
            elif parts[0] == "seen":    # seen <tag>
                print(f"{parts[1]}={seen['stun'].get(parts[1], '-')},{seen['relay'].get(parts[1], '-')}", flush=True)
            continue
        data, src = s.recvfrom(2048)
        which = "stun" if s is stun else "relay"
        tag = data.decode(errors="replace")
        seen[which][tag] = f"{src[0]}:{src[1]}"
        if which == "stun":
            s.sendto(b"PONG", src)   # a STUN server always answers
        print(f"OBS {which} {tag} {src[0]}:{src[1]}", flush=True)
PY

cat > "$TMP/client.py" <<'PY'
import socket, sys, select
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", 0))
print("READY", flush=True)
while True:
    r, _, _ = select.select([s, sys.stdin], [], [])
    for ready in r:
        if ready is sys.stdin:
            line = sys.stdin.readline()
            if not line:
                sys.exit(0)
            p = line.split()
            if p[0] == "send":
                s.sendto(p[3].encode(), (p[1], int(p[2])))
                print("SENT", flush=True)
        else:
            data, src = s.recvfrom(2048)
            print(f"RECV {src[0]}:{src[1]} {data.decode(errors='replace')}", flush=True)
PY

# Coprocesses: one client in each device namespace, plus the harness.
coproc HARNESS { ip netns exec "$NS_NET" "$PY" -u "$TMP/harness.py"; }
coproc DEVA    { ip netns exec "$NS_A"   "$PY" -u "$TMP/client.py"; }
coproc DEVB    { ip netns exec "$NS_B"   "$PY" -u "$TMP/client.py"; }

# Wait for each READY line.
for fd in HARNESS DEVA DEVB; do
  eval "read -t 10 _ready <&\"\${${fd}[0]}\"" || { bad "$fd did not start"; exit 1; }
done
say "harness and both devices are up"

# senddev <A|B> <ip> <port> <text>
senddev() {
  local which=$1; shift
  if [ "$which" = A ]; then printf 'send %s\n' "$*" >&"${DEVA[1]}"
  else                      printf 'send %s\n' "$*" >&"${DEVB[1]}"; fi
}
# relay_send <ip> <port> <text>
relay_send() { printf 'send %s\n' "$*" >&"${HARNESS[1]}"; }
# seen_ports <tag> — prints "stun_port|relay_port"
seen_ports() { printf 'seen %s\n' "$1" >&"${HARNESS[1]}"; read -t 5 line <&"${HARNESS[0]}"; echo "$line"; }

# ── 1. Symmetric mapping: one external port per destination ────────────────
senddev A 10.0.0.1 19000 stun-a
senddev A 10.0.0.1 19001 ka-a
sleep 1
STUN_A=$(seen_ports stun-a | cut -d= -f2 | cut -d, -f1)
KA_A=$(seen_ports ka-a | cut -d= -f2 | cut -d, -f2)
if [ -z "$STUN_A" ] || [ "$STUN_A" = "-" ]; then bad "the STUN stand-in saw nothing from A"; else
  if [ "$STUN_A" = "$KA_A" ]; then
    bad "A's external port is the same toward two destinations ($STUN_A) — this NAT is not symmetric, so the gate is not testing what it claims"
  else
    ok "symmetric mapping: A appears as $STUN_A to the STUN server and $KA_A to the relay"
  fi
fi

# ── 2. The pinhole: the relay reaches the peer it has a mapping toward ─────
relay_send "${KA_A%:*}" "${KA_A##*:}" forward-pinhole
sleep 1
if read -t 3 deva_line <&"${DEVA[0]}" && [[ "$deva_line" == *forward-pinhole* ]]; then
  ok "the relay's forward reached A at its observed address (pinhole open)"
else
  bad "the relay's forward did not reach A at $KA_A (got '${deva_line:-}')"
fi

# ── 3. …and nowhere else: the advertised address has no mapping ────────────
relay_send "${STUN_A%:*}" "${STUN_A##*:}" forward-advertised
sleep 1
if read -t 2 deva_line <&"${DEVA[0]}"; then
  bad "the relay reached A at its advertised address ${STUN_A} without a mapping (got '$deva_line')"
else
  ok "the relay's forward to A's advertised address ${STUN_A} was dropped by the NAT"
fi

# ── 4. Two peers behind symmetric NATs cannot reach each other ────────────
senddev B 10.0.0.1 19000 stun-b
sleep 1
STUN_B=$(seen_ports stun-b | cut -d= -f2 | cut -d, -f1)
if [ -z "$STUN_B" ] || [ "$STUN_B" = "-" ]; then bad "the STUN stand-in saw nothing from B"; else
  senddev A "${STUN_B%:*}" "${STUN_B##*:}" direct-to-advertised
  sleep 1
  if read -t 2 devb_line <&"${DEVB[0]}"; then
    bad "A reached B at its advertised address ${STUN_B} (got '$devb_line')"
  else
    ok "A's direct attempt to B's advertised address ${STUN_B} was dropped — ICE must fail here, and it does"
  fi
fi

printf '\n==== %s passed, %s failed ====\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
