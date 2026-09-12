# Global Ghost Net — LAN over WAN (VPN Layer)

This document defines the **LAN-over-WAN** subsystem: a road-warrior VPN built on top of the GHOST mesh. It gives a mobile device (phone, laptop) a virtual network interface that makes the hub's home LAN (`192.168.1.0/24` by default) routable from anywhere — SMB, SSH, Home Assistant, LAN DNS — as if the device were plugged into the home switch, tunneled through the post-quantum mesh instead of a commercial VPN.

The subsystem is compiled behind the `vpn` cargo feature. Without it, the binary is byte-for-byte the v0.4.0 surface.

---

## 1. Architecture

```
Phone (LTE/Wi-Fi)                      Home Hub (always-on PC/NAS in LAN)
┌─────────────────┐                   ┌──────────────────────────────┐
│ Apps            │                   │  Home LAN devices            │
│  ↓              │                   │   192.168.1.0/24             │
│ TUN: 10.66.0.x  │                   │        ↑                     │
│ route 192.168.1/24,                 │  smoltcp netstack + UDP/ICMP │
│   DNS=192.168.1.1                   │  proxying (userspace, no     │
│  ↓              │    GHOST mesh     │  admin, no OS forwarding)    │
│ GHOST core ─────┼───UDP/shards──────┼── GHOST core (GHOST_VPN=hub) │
└─────────────────┘   post-quantum    └──────────────────────────────┘
```

- **Overlay network:** `10.66.0.0/24`. Each client leases one overlay IP bound to its **Ed25519 fingerprint**. Membership is an explicit authorization decision: the hub admits only fingerprints listed in `GHOST_VPN_CLIENTS`.
- **Hub (server):** unprivileged, single binary. TCP is terminated by an embedded [smoltcp](https://github.com/smoltcp-rs/smoltcp) userspace stack; terminated flows proxy out through ordinary OS sockets to the LAN. UDP and ICMP are proxied per-flow. No TUN device, no IP forwarding, no OS NAT commands.
- **Client (phone/laptop):** a real TUN device (wintun on Windows, `/dev/net/tun` on Unix) with the overlay IP; the GHOST core seals every packet the OS routes into it and ships it to the hub over the mesh.
- **MTU:** the client TUN runs at **1280 bytes** (the IPv6 minimum). Every tunneled packet fits in a single bulk GTF frame (1446-byte payload capacity) — the mesh never fragments tunnel traffic.

---

## 2. Address Plan

| Range | Purpose |
|---|---|
| `10.66.0.0/24` | Client overlay leases (`.1` reserved conceptually for the hub) |
| `10.200.0.1/30` | Netstack-side address (`NETSTACK_ADDR`) — smoltcp's own IP |
| `10.200.0.2/30` | NAT alias address (`NAT_ADDR`) — source address the NAT rewrites client packets to |
| `20000..40000` | Per-flow local TCP port pool inside the netstack NAT |

The client chooses its own overlay IP (`GHOST_VPN_LOCAL_IP`, default `10.66.0.10`); the hub validates it against the allowlist and binds the lease (`lease_for_hint`). A full smoltcp NAT rewrites both directions of the 5-tuple, so LAN servers see traffic sourced from the hub machine's LAN IP via the proxy sockets — no static routes on LAN devices are needed.

---

## 3. Wire Format: Tunnel Frames

Tunnel traffic rides the existing GTF **bulk frame** with flag bit 1 set (`0x02`, on top of the bulk bit `0x01`) — a *tunnel/datagram* frame. Its payload is:

```text
[len u16 BE] [GVPN1 magic] [tunnel datagram]
```

The inner **tunnel datagram** is independently encrypted (ChaCha20-Poly1305, directional nonce, per-direction counter space shared with nothing else):

```text
[epoch u32 BE] [tunnel counter u32 BE] [ciphertext..] [tag 16]
```

Decryption and replay-guarding use the dedicated `VpnIngress`/`ClientState` pipeline — **never** the session `RxState`/`AckEngine`.

### Transport Rule (Non-Negotiable)

Tunnel frames are **unreliable datagrams**: they bypass the shard pool, are never ACKed, never retransmitted, never reordered. Inner TCP owns retransmission and pacing — an outer reliable channel would recreate TCP-over-TCP meltdown on lossy LTE links. Loss manifests as ordinary IP loss; the inner stacks recover. The control channel (handshake, CHAT, SOCKS5, beacons) keeps using the reliable path unchanged.

---

## 4. Multi-Hop Mesh WAN Integration

When operating across wide-area networks or multi-carrier topologies, the VPN tunnel operates over the **Level 2 Multi-Hop Carrier Mesh**:

```
[Mobile Device] 
      │ 
      ▼
[Carrier 1 (45ms)] ──► [Carrier 4 (25ms)] ──► [Hub Gateway (Exit)] ──► Local Home LAN
      ▲
      │ (Multi-Hop Shard Dispersal / Fallback)
[Carrier 5 (Hot Standby Reserve - 55ms)]
```

1. **Multi-Hop Traversal:** Tunnel datagrams traverse intermediate carriers using Level 2 hop decrement headers `[hops_remaining][next_addr]`, isolating the physical location of the mobile client from the home hub.
2. **Traffic Shaping & Obfuscation:** Outbound VPN frames apply Layer 5 randomized jitter padding ($16..64\text{ bytes}$), preventing cellular carriers or ISP deep packet inspection from identifying WireGuard, OpenVPN, or IPsec flow signatures.
3. **Byzantine & Loss Resilience:** In multi-path mode, tunnel traffic is erasure-sharded via Reed-Solomon RS(2,1). Corrupted or dropped carrier hops are healed dynamically in real-time.

---

## 5. Hub Pipeline

1. **Ingress (Dispatcher):** A decrypted bulk frame whose framed payload carries `GVPN1` is handed to the VPN path *before* any control-channel handling. Tunnel traffic can never be confused with SOCKS5/CHAT/relay payloads.
2. **Open:** `VpnIngress::open` authenticates with the session key, checks the tunnel replay window (per direction, per epoch), and returns the raw IP packet.
3. **Lease Observe:** `LeaseTable::observe_tunnel_packet` runs the re-anchor ladder (§6).
4. **Route:** IPv4 TCP $\rightarrow$ netstack (NAT + smoltcp); UDP $\rightarrow$ flow table; ICMP echo $\rightarrow$ answered in userspace.
5. **Egress:** Netstack egress packets are NAT-reverse-rewritten to the true `(client, target)` 5-tuple, sealed as tunnel datagrams, and sent to the lease's current endpoint.

### Netstack (TCP)

One **synchronous driver thread** owns the `Interface` + `SocketSet` (no locks). Wakeup sources: mesh-ingest packets, per-flow LAN-reader notifications, and a sleep capped at `iface.poll_delay()` — a pending ACK or zero retransmit delay always wakes it immediately.

Per flow: a listener socket pre-created on the allocated local port $L$, two bounded channels (`FLOW_QUEUE`), and a **headroom watch**. The LAN `TcpStream` reader pauses when smoltcp TX free space drops below **25 %** and resumes above **75 %** (hysteresis prevents thrash). Pausing the reader lets the LAN server's own TCP window collapse — backpressure propagates end-to-end. The headroom is broadcast as *state* (Condvar), never as an edge event, so late wakeups always observe the truth; a paused reader is additionally woken by flow teardown (bounded-wait on a done flag), so it can never leak or deadlock. Bounded queues everywhere: a full queue drops (IP is lossy by design) or gates the producer, never grows.

New SYNs are refused when the socket set is full (256) — the client's TCP retries, which is connection-level backpressure.

### UDP Flow Table

| Parameter | Value |
|---|---|
| Key | `(fingerprint, proto, src_port, dst_ip, dst_port)` |
| TTL | DNS (dst port 53): **10 s** · general: **45 s** |
| Caps | **64** flows per fingerprint · **1024** global |
| Bind | Hub's LAN IP (never `0.0.0.0`) |
| Eviction | LRU; reply demux on the bound socket's local port |

UDP has no `TIME_WAIT`; closed sockets release their fd immediately. The caps exist because a bursty mobile client (fragmented DNS prefetchers, QUIC probes) must not be able to exhaust hub file descriptors (`EMFILE`).

---

## 6. Endpoint Migration: The Re-Anchor Ladder

The hub maps fingerprint $\rightarrow$ current `SocketAddr`. On mobile networks the address changes constantly (Wi-Fi $\leftrightarrow$ LTE), and late/reordered packets from the *old* address must never flap the endpoint back. Precedence, strictly ordered:

1. **Valid Handshake (Signed, Fresh Ephemeral Key) $\rightarrow$ Epoch Rotation.** Processed on the handshake path before any data-session replay window exists. Sets a new epoch, $V_{\text{max}} = 0$, clears the window, re-anchors unconditionally, and **evicts all per-epoch state** (UDP flows, netstack sockets, live tunnel channels) so a stale epoch's buffers can never answer. This is the reboot path: a phone that crashed mid-session returns with counter 0, which the *old* epoch's window would reject — correctly — and re-handshakes instead.
2. **Window-Advance Re-Anchor.** A data packet from a new address may move the endpoint **only if its counter advances the replay window** ($N > V_{\text{max}}$, the replay algorithm's "newer than anything seen" branch). A late packet from the dead Wi-Fi address (in-window, not advancing) is accepted *as data* but can *never* move the endpoint.
3. **Silence Fallback.** If the current endpoint has been silent $\ge 15\text{ s}$, an authenticated *in-window* packet from a different address re-anchors — this rescues route-flapping clients whose counter legitimately fell behind $V_{\text{max}}$. It can never fire for a rebooted client (step 1 owns that case).

Verified by the migration-race gate: $N+1$ from $\text{IP}_B$, then $N$ from $\text{IP}_A \rightarrow$ return traffic stays locked to $\text{IP}_B$.

---

## 7. DNS

The client TUN's DNS server is the home router (`GHOST_VPN_DNS`, default `192.168.1.1`); UDP:53 flows through the flow table like any UDP traffic. v1 additionally pushes the hub's **search domain** (`GHOST_VPN_SEARCH`, e.g. `fritz.box`) so `nas` resolves unicast — plain unicast DNS never resolves `.local` (that is multicast, RFC 6762). An mDNS relay/responder across the tunnel is deferred to v2.

---

## 8. Mobile Clients (Android, M3)

The Rust core is unmodified; the platform shell provides:

- **`VpnService.protect(fd)`** on the outer UDP socket *before* any handshake — otherwise the core's own mesh traffic loops back into the TUN and dies instantly.
- **`ConnectivityManager.NetworkCallback`** (`onAvailable`/`onLost`): re-bind + re-`protect()` the socket on network change, signal the core to re-STUN and migrate immediately — without tearing down the TUN, the lease, or the session. The re-anchor ladder (§6) makes the address change invisible to the tunnel.
- Adaptive keepalive: Wi-Fi 30 s, LTE 90 s (carrier NAT re-binding).
- DNS search domain via `VpnService.Builder.addSearchDomain`.

Build: `cargo ndk -t arm64-v8a -o app/src/main/jniLibs build --release --features vpn` — one `.so`, Kotlin calls a thin JNI surface (`init`, `setSessionKey`, `start`, `stats`, `pump`, `drain`, `destroy`). The native JNI core handles the post-quantum Kyber-512 + X25519 hybrid handshake automatically upon tunnel start and wraps all packets in GTF bulk wire frames.

Verified live on physical hardware (Xiaomi 2506BPN68G, Android 14): TUN allocated (`tun0`), pump/drain threads active.

---

## 9. Live WAN Simulation & Chaos Hardening

The LAN over WAN architecture is tested within the Docker 7-node carrier simulation environment (`docker-compose.wan.yml`), subjecting the VPN transport to real-world carrier conditions:

- **Linux `tc netem` Link Conditions:** Link delays from 25ms to 160ms, jitter up to 25ms, and packet loss rates up to 8%.
- **Live Failover Convergence:** When primary carrier routes degrade or are severed by Chaos Monkey, the `AdaptiveShardRouter` re-routes tunnel traffic to hot standby carriers within 55 ms, preserving TCP connections without session drop or re-keying.
- **Byzantine Protection:** Intermediary carrier tampering is detected via combinatorial Poly1305 MAC tag checks, ensuring tunnel frames cannot be forged or manipulated in transit.

---

## 10. Configuration

| Variable | Role | Default |
|---|---|---|
| `GHOST_VPN` | `hub` / `client` / unset (off) | — |
| `GHOST_VPN_LAN_SUBNET` | Hub home LAN, `a.b.c.d/p` | `192.168.1.0/24` |
| `GHOST_VPN_DNS` | DNS server handed to clients | `192.168.1.1` |
| `GHOST_VPN_SEARCH` | Unicast search domain | — |
| `GHOST_VPN_CLIENTS` | Comma-separated allowlisted fingerprints | deny all |
| `GHOST_VPN_BIND` | Hub LAN bind address for flow sockets | any |
| `GHOST_VPN_HUB_FP` | Client: hub fingerprint | required |
| `GHOST_VPN_LOCAL_IP` | Client overlay IP | `10.66.0.10` |
| `GHOST_VPN_KEY` | Client: initial tunnel key (hex; replaced by the real session key at handshake) | — |

Console: `LEASES` (hub lease table + counters), `VPNSTATS` (hub or client statistics).

Windows clients need **wintun.dll** beside the executable and one-time Administrator elevation (adapter creation).

---

## 11. Verification Gates

| Gate | Invariant | Test |
|---|---|---|
| Tunnel datagram crypto | roundtrip, replay-reject, tamper-reject, epoch eviction | `vpn::tests` |
| Re-anchor ladder | lease stability, window-advance migration, silence fallback, stale-epoch rejection | `vpn::tests`, `vpn_gates` |
| UDP flow table | caps hold (64/fp, 1024 global), TTL expiry, demux | `vpn::tests`, flood gate |
| DNS round-trip | phone query → NAT'd flow → real LAN server → reply sealed by the flow reader → TUN; flow/reader reuse | `vpn_dns` |
| UDP churn | reader exits drop their dedup key: post-idle query re-served (fresh socket after sweep; same socket/port in the racy window) | `vpn_churn` |
| Client resilience | idle → keepalive echo (answered by hub) → dead at 30 s silence → re-handshake with capped backoff; re-handshake rotates the client epoch, hub re-anchors + resets counters | `client::resilience::tests`, `vpn_resilience` |
| Netstack NAT | ingress/egress 5-tuple rewrite, allocation contract, unregistered non-SYN drop | `netstack::tests` |
| MSS clamp | SYN/SYN-ACK options ≤ OVERLAY_MSS (1240) in both directions; PMTUD blackhole guard | `netstack::tests::clamp_mss_*`, `vpn_mss` |
| Netstack end-to-end | SYN → SYN-ACK → ACK → data → real LAN proxy → echo back | `netstack_syn_establish_echo` |
| M1 LossyVirtualLink | reorder + 15 % drop → inner pipeline survives, ≥ 7/10 delivered | `vpn_gates` |
| M2 end-to-end | phone→hub→phone through the real pipeline order; endpoint stability | `m2_end_to_end_phone_to_hub_and_back` |
| Backpressure | paused reader wakes on headroom/teardown; bounded buffers | `headroom_and_done_signalling`, `proxy_pump_end_to_end_localhost` |
| Multi-Hop Carrier WAN | 7-node carrier simulation, 4 active test scenarios, live telemetry | `docker-compose.wan.yml`, `wan_mesh` |

Run everything: `cargo test --features vpn`. The pristine surface: `cargo test` (68 lib tests, no vpn code compiled).
