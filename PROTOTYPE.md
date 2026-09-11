# PROTOTYPE — LAN over WAN ("Home LAN on my phone")

Working folder for the road-warrior VPN prototype built on the GHOST mesh.
**Baseline:** commit `4bc75b7` (upstream v0.4.0 source snapshot). In this repository, the import is tagged `audit-baseline`.

## Rollback

```bash
git tag                            # shows audit-baseline
git reset --hard audit-baseline    # reset to audit baseline
```

The original source tree (`../Global-Ghost-Net-main`) stays untouched as a
second-level fallback. This repo is local-only; there is no remote.

## Mission

Phone on LTE/cellular behaves as a logical member of the home LAN
(`192.168.1.0/24`): SMB, SSH, Home Assistant, LAN DNS — tunneled through the
post-quantum GHOST mesh instead of a commercial VPN. Full VPN app scope,
Android first, iOS later.

## Architecture (locked after 3 audit rounds)

```
Phone TUN 10.66.0.x  ──GHOST mesh (UDP, PQ-encrypted)──  Hub in home LAN
route 192.168.1.0/24, DNS=router                          smoltcp netstack,
                                                          per-flow OS sockets
```

- Overlay `10.66.0.0/24`, leases keyed by **Ed25519 fingerprint** (allowlist
  env `GHOST_VPN_CLIENTS`). Identity-keyed, never address-keyed.
- Hub (`GHOST_VPN=hub`) runs an embedded **smoltcp** netstack on a custom
  `Device` fed by decrypted mesh datagrams. **No hub TUN, no admin, no IP
  forwarding.** Terminated flows proxy out via ordinary `TcpStream` /
  per-flow `UdpSocket`.
- Client TUN MTU **1280** → every IP packet fits one 1472 B GTF bulk frame
  (1446 B payload). MSS equivalent 1240 (TCP legs are per-side; no PMTUD
  crossing the mesh in netstack mode).

## Non-negotiable implementation rules (audit conclusions)

1. **Tunnel frames are unreliable datagrams.** No AckEngine registration, no
   retransmit, no reorder wait, no head-of-line blocking. Inner TCP owns
   retransmission. Mesh provides auth + replay guard only. New flags bit
   (bit 0 = bulk is taken → bit 1 = tunnel/unordered) and a **separate counter
   space** so tunnel traffic can never collide with control-channel replay
   windows.
2. **`RxState`/`AckEngine` remain control-channel-only** (handshake, CHAT,
   CONNECT, keepalives).
3. **No `unbounded_channel` anywhere in the VPN data path.** Existing code
   uses them (SOCKS5 included); that pattern must not leak.
4. **Backpressure:** single-owner smoltcp driver task (no locks). LAN reader
   pauses at TX headroom < 25 %, resumes > 75 %, signalled via a `watch`
   channel carrying headroom **state** (not edge-based `Notify` — a late
   reader must always see current truth). Driver sleep is capped at
   `iface.poll_delay()`; teardown (FIN/RST/close) also wakes paused readers.
   Phone→LAN direction: smoltcp's own TCP window does it, provided the loop
   never blocks on a LAN write (bounded channels).
5. **Re-anchor precedence ladder:** (a) valid signed handshake with fresh
   ephemeral key → rotate epoch, `V_MAX = 0`, clear window, re-anchor,
   **evict all per-fingerprint state** (flows, netstack sockets, tunnels);
   (b) data packet advancing the replay window (`N > V_MAX`) → re-anchor
   permitted (monotonic rule); (c) ≥ 15 s silence + valid in-window packet
   from another address → re-anchor (route-flap fallback). A late packet from
   a dead address is accepted as data but never moves the endpoint.
6. **UDP flow table:** key `(fingerprint, proto, overlay_port, dst_ip,
   dst_port)` → bound OS socket. TTL 10 s (dst 53) / 45 s (general), lazy
   expiry + 1 Hz sweeper. Caps **64 per fingerprint / 1024 global**, LRU
   eviction, drop beyond cap. Bind to the hub's **LAN IP** (not 0.0.0.0) +
   `SO_REUSEADDR`. UDP has no TIME_WAIT — fd churn is the hazard, caps are
   the fix.
7. **DNS v1:** VPN DNS = router IP **plus search domain** (`fritz.box`/`lan`;
   Android `addSearchDomain`). Unicast DNS never resolves `.local`; mDNS
   relay is explicitly v2.
8. **Android (M3):** `VpnService.protect(fd)` on the outer UDP socket before
   first bind (via socket2 fd through JNI) or the mesh routes into its own
   TUN and dies. `ConnectivityManager.NetworkCallback` drives re-bind →
   re-protect → re-STUN on Wi-Fi↔LTE without tearing down the TUN. Adaptive
   keepalive (Wi-Fi 30 s / LTE 90 s). Session state survives because it is
   identity-keyed.

## Milestones & verification gates

| Phase | Objective | Gate |
|---|---|---|
| M1 | wintun client TUN + unordered datagram tunnel frames | `LossyVirtualLink` in `tests/virtual_net.rs`: reorder (1,3,2,5,4), drop 15 % of tunnel frames → inner TCP advances, tunnel path structurally free of RxState/AckEngine |
| M2 | Hub netstack + leases + allowlist + console `VPN`/`LEASES` | SMB copy over LTE-like link; backpressure test (10 MB producer vs 1 pkt/10 ms → bounded buffers, `paused_ticks > 0`); migration race test (N+1@IP_B then N@IP_A → egress locked to IP_B); 2 000-query UDP flood → caps hold, no EMFILE |
| M3 | Android NDK app (cargo-ndk → .so, JNI surface, Kotlin VpnService) | Hard Wi-Fi→LTE handover mid-SSH, no session loss |
| M4 | iOS NetworkExtension + v2 mDNS relay | separate distribution effort |

## Environment notes (this machine)

- Toolchain: `cargo 1.97.0-nightly`, targets `x86_64-pc-windows-msvc` +
  `x86_64-pc-windows-gnu` installed. Project builds with `cargo build
  --release` (profile: opt-level "z", fat LTO, panic=abort).
- `wintun.dll`: Tailscale ships one at
  `C:\Program Files\Tailscale\wintun.dll` — usable for local dev, but
  **download the official 0.14.x zip from wintun.net for anything shipped**
  (redistribution license). Adapter creation needs Administrator.
- Codebuff `code_search` (ripgrep) is broken in this environment — use
  `grep -n` / `find` fallbacks.
- New deps (all pure Rust): `smoltcp` (hub netstack), `wintun` (client TUN),
  `socket2` (fd access), `cargo-ndk` (build tool only). Gate new modules
  behind a `vpn` cargo feature so the v0.4.0 surface stays intact.

## Ground rules

- Baseline semantics frozen: existing SOCKS5/CHAT/beacon/relay paths keep
  passing `cargo test --lib` and `tests/simulation.rs` before every commit.
- One milestone per branch off `main`; merge only with its verification gate
  green. Never commit `identity*.key`, `wintun.dll`, or `target/`.
- `docs/LAN_OVER_WAN.md` is the in-repo design doc (to be written from this
  file's rules); GGN.canvas gets a LAN-over-WAN cluster in template style
  after M1 is real.

## Known flaws & missing spots (honest ledger)

Updated 2026-09-11 (reconciled with tree and THINKTANK-BIN pass).
Everything below reflects current tree status; fixed items are struck and detailed.

### The big one: driver & hardware layer pending

Every rule above is proven in simulation and through the real crypto/framing
path (see ledger below), including zero-elevation two-process loopback ICMP.
However, **no real wintun client has talked to a physical LAN host**.
Remaining hardware/elevation unknowns: wintun adapter creation under Windows
admin, NAT44 against a real LAN host, actual Wi-Fi→LTE handover mid-SSH.
Every unit- and protocol-level excuse for failure has been removed; the OS
driver/hardware layer is the top remaining gate.

### Status of audit flaws

1. ~~**Counter exhaustion has no trigger.**~~ **CLOSED.** `COUNTER_REKEY_AT`
   triggers `Action::Rehandshake` before wrap in `TunnelWatchdog::poll_with_counter`
   (`client.rs`); hub proximity warning active in `hub.rs`. Tested by
   `counter_exhaustion_triggers_rehandshake_before_wrap`.
2. ~~**UDP reply truncation at 2048 B.**~~ **CLOSED.** Flow-reader buffer is
   4096 B (EDNS0 ceiling) with explicit truncation note (`hub.rs:284`).
3. **No ICMP proxying to LAN targets.** **OPEN (v2 by design).** Client pings
   to real LAN IPs are dropped (counted) — userspace echo responder only
   answers the hub's own overlay IP.
4. ~~**Egress seals at produce, not at drain.**~~ **CLOSED.** `poll_egress`
   now seals at drain time reading current session material and counter;
   mid-queue re-anchors no longer orphan queued packets.
5. ~~**Mesh handshakes are not allowlisted.**~~ **CLOSED.** Hub handshake path
   rejects non-allowlisted fingerprints in `main.rs:397`.
6. ~~**`identity.key` is CWD-relative.**~~ **CLOSED.** `GHOST_IDENTITY_FILE`
   override implemented in `l0_identity.rs:24`.

### Missing surfaces status

- ~~**`vpn_*` metrics**~~: **CLOSED.** 7 `ghost_vpn_*` series on `/metrics`
  (including `counter_headroom_min`); `"vpn"` + `vpn_stats` on `/healthz`.
- ~~**Zero-elevation demo**~~: **CLOSED.** `PlatformTun::Fake` wired in via
  `GHOST_VPN_FAKE_TUN=1`; validated via `scripts/vpn_loopback_test.sh` and
  `run-vpn-test.bat`.
- ~~**`VPN STATUS`**~~: **CLOSED.** Implemented in `main.rs:2129+` (per-lease
  table with FP, IP, endpoint, epoch, flows, headroom).
- **LAN→client initiated connections** are unsupported by design (NAT44
  outbound only). mDNS relay stays v2 as originally scoped.
- **main.rs god-file**: ~2k lines owning VPN wire protocol, egress pumps
  and console; `ClientState`/`VpnHub` mirror epoch/counter state.

### Verification ledger

| Layer | Proof |
|---|---|
| Simulator (virtual net, lossy links, flood caps) | 174 tests green, `--features vpn` |
| Real crypto + framing path (GTF, ChaCha, tunnel magic) | `vpn_transport`, `vpn_dns`, `vpn_resilience`, `vpn_churn` gates |
| Zero-elevation loopback (real handshake + ICMP roundtrip) | `scripts/vpn_loopback_test.sh` (6/6 passed) |
| Real process (binary boot, console, handshake) | hub binary exercised; `PEER` via shared `initiate_handshake` |
| Real hardware (wintun, LAN, LTE handover) | ❌ pending — the smoke test |

### Bug classes the gates already caught (why the gates exist)

Unsealed UDP relays (every DNS reply unopenable); shard-pool swallow of
tunnel frames; missing length prefix in `send_tunnel_frame`; no-drop
violations on both proxy paths; re-key desync (client epoch not rotated,
hub counters not reset); reader/flow lifecycle desync (post-idle DNS
blackhole). Each was found by a gate, not by review.

### Build corrections vs. this document's earlier text

- The role env is `GHOST_VPN=hub|client` (this doc once said `GHOST_ROLE`).
- The allowlist env is `GHOST_VPN_CLIENTS` (once `GHOST_LAN_CLIENTS`).
- M2's "SMB copy over LTE-like link" shipped as the 10 MB backpressure gate
  + netstack e2e echo; a literal SMB copy is part of the pending smoke test.
