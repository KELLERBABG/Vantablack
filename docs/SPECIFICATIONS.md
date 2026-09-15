# Global Ghost Net — Technical Specifications

This document defines the low-level protocols, cryptographic guarantees, frame formats, and multi-hop routing specifications implemented in Global Ghost Net.

---

## 1. Cryptographic Suite

Global Ghost Net uses a dual classical and post-quantum hybrid cryptographic design:

- **Identity Layer (L0):** Ed25519 permanent signing key pair generated on first run and stored locally (`identity.key`). Used for authenticating identity beacons, capability vouchers, and peer exchange.
- **Key Agreement (L1):** Hybrid Ephemeral Key Exchange:
  - Classical: X25519 ECDH.
  - Post-Quantum: ML-KEM-512 (Kyber-512 / FIPS 203) Key Encapsulation Mechanism.
  - Salt & Pre-Shared Key: HKDF-SHA256 mixes both shared secrets with an optional 32-byte pre-shared key (`GHOST_PSK`).
- **Authenticated Encryption (L2):** ChaCha20-Poly1305 (RFC 8439) with a 256-bit symmetric key.
  - Nonce generation incorporates the 4-byte session hash, direction bitmask (initiator vs responder), and a monotonic packet counter to eliminate nonce collision risks.
- **Erasure Coding (L4):** Reed-Solomon RS(2,1) over Galois Field $\text{GF}(2^8)$. Plaintexts are split into two primary data shards and one parity shard. Any 2 of 3 shards reconstruct the original payload.
- **Memory Hardening (L8):** Ephemeral session keys and decrypted memory buffers are wiped using volatile zeroization on drop and protected with AES-256-XTS memory encryption.

---

## 2. Wire Formats & Frame Encodings

### 2.1 Ghost Transport Frame (GTF) Format

All standard mesh datagrams travel encapsulated in uniform UDP datagrams.

#### Privacy Mode Frame (512 Bytes)
In privacy mode, all datagrams are fixed to 512 bytes with randomized trailing jitter padding (16 to 64 bytes) to defeat packet-length traffic analysis:

| Byte Range | Field | Type | Description |
|---|---|---|---|
| `00..03` | Session Hash | `[u8; 4]` | Truncated session identifier for fast lookup |
| `04..07` | Packet Counter | `u32` (BE) | Monotonic counter used for replay protection |
| `08` | Shard Index | `u8` | Shard indicator (`0`, `1`, or `2` for RS parity) |
| `09` | Flags | `u8` | Bit flags (`0x00`: privacy, `0x01`: bulk transfer, `0x02`: VPN datagram) |
| `10..495` | Encrypted Shard | `[u8; 486]` | ChaCha20-Poly1305 ciphertext payload with canonical 2-byte big-endian length prefix (`[len u16 BE][shard]`), padded up to byte 496 |
| `496..511`| Auth Tag | `[u8; 16]` | Poly1305 authentication MAC tag |
| `512..576`| Jitter Padding | `[u8; 16..64]` | Variable pseudorandom noise bytes |

#### Shard Length-Prefix Invariant
To ensure binary-safe extraction across variable-size application datagrams packed into fixed 486-byte GTF payload slices, every shard is framed via `frame_shard()` (`[len: u16 BE][shard]`) before GTF encapsulation and restored via `unframe()` upon reception before Reed-Solomon inversion.

#### Bulk Mode Frame (1472 Bytes)
For high-bandwidth file transfers and TUN VPN traffic across verified links, MTU-aligned 1472-byte frames maximize payload throughput without IP fragmentation.

---

### 2.2 Level 2 Multi-Hop Mesh Frame Format

In the multi-hop WAN carrier network, packets route through intermediary relay nodes without requiring intermediate nodes to decrypt payload data.

#### Hop Routing Header
Carrier packets carry an outer forwarding header:

```text
+-----------------------+------------------------+--------------------------+-----------------------+
| hops_remaining (1 B)  | next_ipv4 (4 Bytes BE) | next_port (2 Bytes BE)   | payload (variable)    |
+-----------------------+------------------------+--------------------------+-----------------------+
```

| Field | Length | Description |
| :--- | :--- | :--- |
| `hops_remaining` | 1 byte | Monotonically decremented at each intermediary node. When `hops_remaining > 1`, packet is forwarded to `next_ipv4:next_port`. When `hops_remaining == 1`, payload is delivered to the final endpoint. |
| `next_ipv4` | 4 bytes | IPv4 address of the next intermediary hop or destination node. |
| `next_port` | 2 bytes | UDP port of the next recipient (big-endian). |
| `payload` | Variable | The inner payload, containing nested hop headers or the end-to-end shard datagram. |

#### Chained Multi-Hop Nesting
When multiple hops are chained (e.g., Client $\rightarrow$ Carrier 1 $\rightarrow$ Carrier 4 $\rightarrow$ Exit):
1. **At Ingress (Client):**
   ```text
   [hops_remaining = 2] [IP: Carrier 4] [Port: 8000] [IP: Exit] [Port: 8000] [Cycle u64] [Shard u8] [Shaped Shard...]
   ```
2. **At Hop 1 (Carrier 1):** Decrements `hops_remaining` to 1, reads `Carrier 4` address, and forwards the remainder:
   ```text
   [hops_remaining = 1] [IP: Exit] [Port: 8000] [Cycle u64] [Shard u8] [Shaped Shard...]
   ```
3. **At Hop 2 (Carrier 4):** Observes `hops_remaining == 1`, extracts `Exit` address, and delivers the unnested payload directly to the final endpoint:
   ```text
   [Cycle u64] [Shard u8] [Shaped Shard...]
   ```

---

### 2.3 Layer 5 Traffic Shaping & Jitter Format

To defeat passive Deep Packet Inspection (DPI) and timing correlation attacks, payloads are dynamically padded with cryptographically randomized jitter:

```text
+----------------------------+-----------------------+----------------------------------+
| original_len (2 Bytes BE)  | payload (original)    | random_jitter (16 to 64 Bytes)   |
+----------------------------+-----------------------+----------------------------------+
```

1. **Jitter Injection (`apply_l5_jitter_padding`):**
   - $L_{\text{orig}} = \text{len}(\text{payload})$ (stored as 2 bytes big-endian).
   - $J_{\text{len}} \leftarrow \text{UniformRandom}(16, 64)$.
   - $J_{\text{bytes}} \leftarrow \text{CryptographicRandomBytes}(J_{\text{len}})$.
   - $\text{WireData} = L_{\text{orig}} \mathbin{\Vert} \text{payload} \mathbin{\Vert} J_{\text{bytes}}$.
2. **Jitter Stripping (`strip_l5_jitter_padding`):**
   - Reads $L_{\text{orig}} = \text{u16::from\_be\_bytes}([B_0, B_1])$.
   - Validates that $2 + L_{\text{orig}} \le \text{len}(\text{WireData})$.
   - Truncates slice to $[2 \dots 2 + L_{\text{orig}}]$, discarding all trailing jitter bytes.

---

### 2.4 Identity Beacon Format & Extension Sections

Discovery beacons are the only datagrams accepted from an unauthenticated source, so their layout is versioned in a way that never breaks older peers.

#### Signed prefix (fixed, 112 bytes)

| Byte Range | Field | Type | Description |
|---|---|---|---|
| `00..15` | Magic | `[u8; 16]` | `GHOST_BEACON____` (`net::BEACON_PREFIX`) |
| `16..47` | Public key | `[u8; 32]` | Full Ed25519 public key |
| `48..111` | Signature | `[u8; 64]` | Ed25519 signature over bytes `16..47` |

Two legacy layouts extend this without any section metadata and remain accepted verbatim: the bare 112-byte beacon, and the 208-byte beacon carrying a 32-byte ZK commitment at `112..143` followed by a 64-byte proof at `144..207`.

#### Extension sections (optional, appended)

Every section is `[magic: 4][len: u16 BE][payload: len]`, appended immediately after the 112-byte signed prefix and tiled in order:

| Magic | Payload | Description |
|---|---|---|
| `ZKPR` | `commitment[32] \|\| proof[64]` (`len = 96`) | ZK membership proof |
| `ICEO` | UTF-8 text, see below | Sender's ICE offer |
| `RLYC` | empty (`len = 0`) | This node will relay for others (`GHOST_RELAY=1`) |

`RLYC` is a *capability*, not an address: a relay is reached at the address its beacon arrived from — the same socket it forwards on — so carrying an address would let a peer advertise someone else's. Its presence is the whole message, which is why a non-empty payload is a parse error. A node that advertises it leaves the legacy layouts behind (see the tiling note below), which is what keeps `GHOST_RELAY` opt-in rather than a silent compatibility break.

**Tiling rule.** A datagram is interpreted as *sectioned* only when the sections consume it exactly: every section header must be fully present, every declared length must fit inside the datagram, every magic must be known, and the `ZKPR` payload must be exactly 96 bytes. Any violation makes the parser fall back to the legacy fixed-layout interpretation rather than reject the beacon. This is what makes the format backward compatible — a legacy 32-byte ZK commitment is uniformly random, so requiring exact tiling is what stops a coincidence from being mistaken for a section magic.

When a ZK proof and an ICE offer are both present they are emitted as two sections in that order; a beacon with a ZK proof but nothing else to carry keeps the **legacy 208-byte layout** byte-for-byte, so peers on builds older than this section still verify it. A `RLYC` section is the one exception: a node that advertises relay capability has something new to say by definition, so it always uses the sectioned layout, and a peer that predates it will reject that beacon rather than misread it at fixed offsets.

#### ICE offer payload (`ICEO`)

A line-oriented `key=value` text encoding produced by `ice::IceOffer::encode` and parsed by `IceOffer::decode`. `decode` is strict — an unknown key, a missing key, or a line that is not exactly `key=value` is an error, so a truncated or corrupted offer is never silently half-applied:

| Key | Required | Description |
|---|---|---|
| `ufrag` | yes | ICE username fragment (the receiver authenticates with its own password) |
| `pwd` | yes | ICE password, at least 22 characters (RFC 8445 §5.3) |
| `role` | yes | `controlling` or `controlled` (affects nomination) |
| `cand` | yes, ≥ 1 | One line per candidate: `type,address,port,priority,foundation` |

#### NAT traversal (STUN/TURN/ICE — Phase 1 P1-1)

`net::stun` implements the RFC 8489 message codec: header/type interleaving (class bits are split *around* the method bits, so a success response to Binding is `0x0101`, not `0x0081`), attribute TLV framing with 4-byte padding, `XOR-MAPPED-ADDRESS` (v4 and v6), `PRIORITY`, `USE-CANDIDATE`, `ICE-CONTROLLED`/`ICE-CONTROLLING`, `ERROR-CODE`, `FINGERPRINT` (CRC-32/ISO-HDLC) and `MESSAGE-INTEGRITY` (HMAC-SHA1). The integrity key is the password belonging to the ufrag that appears **first** in `USERNAME` — i.e. the receiver's own password for requests, so both agents verify with their own secret without disclosing it.

`net::ice` implements the RFC 8445 agent: candidate types and type preferences (`host` 126, `peer-reflexive` 110, `server-reflexive` 100, `relay` 0), the pair-priority formula, foundation grouping, a check list ordered by pair priority with foundation siblings held frozen until their predecessor fails, `Nmax`-bounded retransmission, role conflict resolved by tie-breaker, peer-reflexive discovery and explicit nomination. A pair is only reported usable after a **nominated** pair completes a round trip.

`net::turn` implements the TURN client side plus a `RelayServer` state machine: `ALLOCATE` yields `XOR-RELAYED-ADDRESS`/`LIFETIME`, `CREATE-PERMISSION` installs a peer permission, `CHANNEL-BIND` installs a channel binding, and `SEND`/`DATA` carry the relayed datagrams. Long-term credentials are keyed by `MD5(username:realm:password)` as RFC 8489 §9.2.2 specifies. The relay's own behaviour is a pure state machine, so it is exercised without any sockets.

`net::relay` adds a DERP-style **blind** relay, and `net::fallback` is what connects it to a failed punch rather than leaving it as an unused capability.

**The envelope.** A frame that cannot travel directly is wrapped for one relay hop:

```
[0..4]   BLND  ("BLND", the blind-envelope magic)
[4..8]   hop count, u32 BE — always 0; a non-zero count is the onion path (RLY!)
[8..40]  target fingerprint, 32 bytes, null-padded
[40..]   opaque region: the complete GTF datagram the target must parse
```

The two magics are deliberately different. The onion's last hop re-wraps with `remaining_hops - 1`, so a legitimate onion arrives with a hop count of **zero** and is otherwise structurally identical to a blind forward; a shared magic would make the two indistinguishable on the wire, and a receiver that guessed wrong would either re-encrypt someone else's ciphertext or hand an onion body to the tunnel as a frame.

**What the relay emits.** The *opaque region*, not the envelope. The target has to parse the datagram out of it exactly as it would off the wire, so the relay drops the addressing header it routed on and nothing else. The region it carries — the target's own AEAD ciphertext — travels verbatim; that unchanged region is the property that makes the forward blind, and it is asserted at the byte level.

**Framing on the hop.** An envelope is 40 bytes plus a whole GTF frame (552-616 B for a privacy frame, 1512 B for a bulk one), which does not fit a privacy frame's 486-byte payload region. The hop therefore uses one of two framings, chosen by size: a single **bulk frame with the tunnel bit (0x02)** when the envelope fits its 1 446-byte region, otherwise the envelope is Reed-Solomon split across three bulk frames — the same convention `relay.rs` already uses to re-wrap an onion hop. Both are ordinary receive-path framings; there is no relay-specific wire format.

**The ladder.** `fallback::choose_fallback` walks *direct → a mesh peer that advertises relay capability → TURN*, deterministically so two nodes in the same topology agree. Mesh first because it needs no infrastructure and is repaid through the tit-for-tat ledger; TURN last because it is the operator's own. A candidate that is us or the target is never chosen, and a TURN route is refused outright when this node holds no allocation — recording one would black-hole every send to that peer.

**Both directions are independent.** Forwarding is one-way and stateless: the relay remembers nothing about the sender, so the target's reply travels through a relay *it* chooses (possibly a different one). That is what keeps the relay unable to correlate the two directions, and why both ends run the ladder on their own.

**The pinhole.** A relay forwards to the address it observed, and a NAT admits that datagram only if the target has already sent something *there*. `NatHolePuncher::send_relay_keepalives` sends a STUN binding indication to every advertised relay on the beacon tick for exactly this reason: without it the fallback is filtered before it can arrive, which is a silent failure otherwise.

**Admission.** A relay forwards only for an identity it has verified (a signed beacon, or a completed handshake), never for itself, never back to the sender, and never beyond its transit quota — the same `FlowController` that bounds its own transit traffic. An open relay is a reflection and amplification vector, so each of those refusals is counted rather than merely logged.

**TURN.** When configured (`GHOST_TURN_SERVER` + credentials), an allocation is taken at startup on a socket of its own — an allocation is bound to the 5-tuple that created it — and its `XOR-RELAYED-ADDRESS` is advertised as a relay candidate in our own offer, so a peer that cannot reach us directly can reach *that*. Datagrams the server relays to us are sealed for us exactly as a direct send would be and enter the same receive pipeline; the socket carries only TURN traffic, so nothing races the mesh socket. Allocation lifetime is refreshed at half the granted value, and permissions/channels are re-armed alongside it. The ladder's TURN rung sends to the *peer's* advertised relayed address: ours is the transport, theirs is the destination.

`net::upnp` is the *opportunistic* path, and the cheapest one when the gateway cooperates: rather than work around the NAT, ask it for a mapping. Two protocols are spoken — UPnP-IGD (SSDP `M-SEARCH` to `239.255.255.250:1900`, then SOAP `AddPortMapping` on the `WANIPConnection`/`WANPPPConnection` service of the device description) and NAT-PMP (RFC 6886; a 12-byte binary request to the default gateway on `:5351`, retried three times with a doubling wait). A granted mapping is added to our offered candidates as a server-reflexive address — it *is* our public address, however it was learned — and renewed at half the granted lifetime, because a lease that quietly expires leaves a candidate no peer can reach.

Nothing here is required for connectivity: disabled UPnP, an enterprise gateway or a CGNAT in the path are all ordinary outcomes, so the attempt runs under a short deadline and its failure is a log line. One parsing note that matters for review: `upnp::find_wan_control` takes the first WAN connection service whose `controlURL` resolves to the **same origin** as the description it came from; a control URL naming a different host is refused, because on a shared local link that is exactly what an attacker would supply.

---

## 3. SessionGuard: Anti-Replay Sliding Window Bitmask

Session security operates at Layer 6 via `SessionGuard` (32-bit counter) and `SessionGuardU64` (64-bit counter).

### Bitmask Architecture
- **Window Size:** $W = 128$ positions (or $W = 64$).
- **State Variables:**
  - $V_{\text{max}}$: The highest valid sequence counter observed.
  - $\text{Bitmask}$: `u128` integer tracking received packet arrivals in $[V_{\text{max}} - (W - 1), V_{\text{max}}]$.
  - $T_{\text{start}}$: Session creation timestamp.
  - $T_{\text{last}}$: Timestamp of the most recent valid packet.

### Validation Algorithm (`check_and_update`)

Given incoming counter $C$:
1. **Timeout Check:** If $T - T_{\text{start}} \ge 24\text{ hours}$ or $T - T_{\text{last}} \ge 30\text{ minutes}$, reject packet (session expired).
2. **Old Packet Check:** If $C < V_{\text{max}} \mathbin{\dot{-}} W$, packet is outside the window $\rightarrow$ **DROP** (stale).
3. **Advance Window Check ($C > V_{\text{max}}$):**
   - Let $\Delta = C - V_{\text{max}}$.
   - If $\Delta \ge W$, reset $\text{Bitmask} \leftarrow 1$.
   - Else, shift $\text{Bitmask} \leftarrow (\text{Bitmask} \ll \Delta) \mid 1$.
   - Update $V_{\text{max}} \leftarrow C$ and $T_{\text{last}} \leftarrow \text{now}()$.
   - Return **ACCEPT**.
4. **In-Window Duplicate Check ($C \le V_{\text{max}}$):**
   - Let $\text{offset} = V_{\text{max}} - C$.
   - If $(\text{Bitmask} \ \& \ (1 \ll \text{offset})) \ne 0 \rightarrow$ **DROP** (replay detected).
   - Else, register packet: $\text{Bitmask} \leftarrow \text{Bitmask} \mid (1 \ll \text{offset})$.
   - Update $T_{\text{last}} \leftarrow \text{now}()$.
   - Return **ACCEPT**.

---

## 4. Adaptive Shard Router & Failover Mechanics

The `AdaptiveShardRouter` dynamically selects path candidates using empirical latency and loss observations.

### 4.1 Path Fitness Function

Each peer path tracks round-trip latency, packet loss, and delivered bytes, and keeps them
**apart** — a loss is not a round trip, and a rate is not a constant:

| Field | Source | Update |
| :-- | :-- | :-- |
| `srtt_us` | a completed round trip (ICE check, `record_success`) | EMA, $\alpha = 0.125$ (RFC 6298 §2.3) |
| `min_rtt_us` | the same samples | running minimum |
| `loss_rate` | a failed delivery (`record_loss`) | EMA down on delivery ($\beta = 0.1$), up on loss |
| `cwnd` | bytes delivered / lost | additive increase on delivery, halved on loss (RFC 5681 §3.1) |
| `delivery_bps` | `record_delivery(bytes, elapsed)` | EMA of measured bytes/second ($\alpha = 0.25$) |

A path's rate estimate is the smaller of what its window allows and what it was observed
delivering:

$$\text{Rate} = \min\left(\frac{\text{cwnd}}{\text{srtt}},\; 2 \cdot \text{delivery\_bps}\right)$$

and the score deliberately weights the three signals rather than multiplying two of them:

$$\text{Fitness} = 0.4 \cdot \underbrace{\min\left(\frac{100{,}000}{\text{RTT}_{\mu\text{s}}}, 2\right)}_{\text{latency}} + 0.3 \cdot (1 - \text{LossRate})^{2} + 0.3 \cdot \min\left(\frac{\text{Rate}}{10^6}, 10\right) / 10$$

- Loss rate increments upon unacknowledged transmissions and decays upon successful deliveries.
- Minimum acceptable fitness threshold: $\text{min\_fitness} = 0.3$.
- A path with no fresh measurement ($< 30$ s, `PathMetrics::STALE_AFTER`) scores the neutral
  prior $0.5$ — an unmeasured path must not outrank a measured good one, and a stale estimate
  is not evidence that a path is still fast. A path losing more than half of its traffic
  scores $0.0$ and stops being selected.

### 4.1.1 Congestion control and the transit shaper

`FlowController` is a **policy** ceiling: a token bucket at the rate the operator configured
against a path the node trusts less than its own. It reads nothing from the network.
`net::cc::TransitGovernor` is the **control** half that closes the loop. At each beacon tick
(`nc.keepalive_interval_secs`, 1–300 s) the node:

1. takes the RTT of every connected peer from the completed ICE check
   (`NatHolePuncher::selected_rtt`) and records it as a path sample;
2. takes the transit bytes actually forwarded for that peer from the tit-for-tat ledger and
   records the delta as a delivered-byte measurement over the tick interval;
3. shapes to the **weakest live path**: $\text{rate} = \min_i(\text{Rate}_i)$ clamped to
   $[\text{MIN\_SHAPED\_RATE\_BPS},\ \text{ceiling}]$ — the floor is 8,000 B/s, i.e. **64 kbps**
   (`cc::MIN_SHAPED_RATE_BPS`) — and pushed into the shaper with
   `FlowController::set_transit_rate_bps`.

The floor exists so one collapsing path cannot drive the node's shaper to zero while other
paths are healthy: a path measured below it is a path the shard router should stop using, not
one to forward at. The ceiling is never exceeded, because measurement may only pull the
effective rate **down** from the operator's policy. With no live estimate at all the shaper is
left exactly as configured — a node that has just started, or whose peers have all gone quiet,
has no evidence to justify re-shaping. The same tick refreshes each peer's `ContactPlan`
contact with the measured RTT and rate, so CGR routes age with the links they were learned
from instead of keeping their first measurement forever.

### 4.2 Autonomous Failover Execution
1. **Loss Observation:** When a link fails (e.g. Carrier 3 severed by Chaos Monkey), `router.record_loss("carrier-3")` drops its fitness score below the threshold.
2. **Candidate Rescoring:** `select_shard_targets(&peers)` sorts available paths descending by fitness:
   ```text
   Rank 1: Carrier 1 (45ms, 1% loss) -> Fitness: 0.683
   Rank 2: Carrier 2 (85ms, 3% loss) -> Fitness: 0.525
   Rank 3: Carrier 5 (55ms, 1% loss) -> Fitness: 0.638  [Promoted from Standby]
   ```
3. **Route Reassignment:** The failed carrier is immediately swapped with hot-reserve Carrier 5. Shard 2 is re-routed without session teardown. Convergence latency is bounded by the standby carrier link RTT ($\le 55\text{ ms}$).

---

## 5. Byzantine Tamper Isolation: Combinatorial RS(2,1) + Poly1305

When an adversarial carrier corrupts in-flight data, standard error-correction decoding fails. Global Ghost Net implements combinatorial pairwise testing:

### Combinatorial Evaluation
For received shards $S = [S_0, S_1, S_2]$:
1. When 3 shards arrive, form all 2-shard combinations:
   - **Pair $(0, 1)$:** Reconstruct with $S_0, S_1$, verify ChaCha20-Poly1305 MAC.
   - **Pair $(0, 2)$:** Reconstruct with $S_0, S_2$, verify ChaCha20-Poly1305 MAC.
   - **Pair $(1, 2)$:** Reconstruct with $S_1, S_2$, verify ChaCha20-Poly1305 MAC.
2. **Isolation Truth Table:**
   - If all 3 pairs succeed $\rightarrow$ All shards clean.
   - If Pair $(0, 2)$ succeeds, while $(0, 1)$ and $(1, 2)$ fail $\rightarrow$ **Shard 1 is Byzantine Corrupted**.
   - If Pair $(1, 2)$ succeeds, while $(0, 1)$ and $(0, 2)$ fail $\rightarrow$ **Shard 0 is Byzantine Corrupted**.
   - If Pair $(0, 1)$ succeeds, while $(0, 2)$ and $(1, 2)$ fail $\rightarrow$ **Shard 2 is Byzantine Corrupted**.
3. **Defense Action:** The receiver authenticates and delivers the payload from the valid pair, discards the tampered shard, and raises a security event alerting the mesh.

---

## 6. Peer Discovery Protocols

- **Cloudflare DNS Seed Resolution:** The daemon queries `GHOST_DNS_SEED`, extracting all associated `A` and `AAAA` records.
- **Local Cache Persistence:** Peer socket addresses are stored in `peers.cache`. During cold boots without WAN access, the cache is read first.
- **Local Subnet Multicast:** LAN nodes announce themselves on `239.255.0.1:2270` using Ed25519-signed beacons containing timestamp, port, and public key. Expired or invalid beacons are silently dropped.

---

## 7. Autonomous SOCKS5 Proxy & Public WAN Egress

Global Ghost Net implements an integrated SOCKS5 proxy engine listening locally on `127.0.0.1:1080`:

1. **Local Ingress:** Client applications (browsers, CLI utilities, cURL) establish a standard RFC 1928 SOCKS5 handshake over `127.0.0.1:1080` without authentication (`0x00`).
2. **Mesh Encapsulation:** SOCKS5 CONNECT targets (`host:port` or `ipv4:port`) are framed and dispatched across the multi-hop carrier mesh using ephemeral post-quantum session keys and Reed-Solomon RS(2,1) sharding.
3. **Exit Node Relay:** The Exit Node (`172.28.1.20`) reassembles shards, verifies Poly1305 MAC authenticity, connects to the target destination, and proxies streams back across the carrier fleet.
4. **Egress IP Rotation:** The exit node dynamically rotates outbound egress IP addresses (`198.51.100.x`) across successive requests to protect client privacy against destination tracking.

---

## 8. Level 2 Multi-Hop Mesh WAN Architecture (7-Node Carrier Simulation)

Global Ghost Net includes a complete, containerized Level 2 multi-hop WAN carrier simulation topology executed under Docker Compose and shaped using Linux `tc netem`.

### 8.1 7-Node Carrier Simulation Topology

| Node Name | Container / Subnet IP | Listening Port | Simulated WAN Network Profile (`tc netem`) | Role & Path Assignment |
|---|---|---|---|---|
| `mesh-client` | `172.28.1.10` | `8000`, `1080` (SOCKS5), `8080` (HTTP) | Local / Endpoint | Mesh Initiator, SOCKS5 Ingress, Telemetry Server |
| `vantablack-carrier-1` | `172.28.1.11` | `8000` | 45ms delay ±5ms jitter, 1% packet loss | Transatlantic Fiber: Hop 1 of Path 0 (Client $\rightarrow$ C1 $\rightarrow$ C4 $\rightarrow$ Exit) |
| `vantablack-carrier-2` | `172.28.1.12` | `8000` | 85ms delay ±15ms jitter, 3% packet loss | Transpacific Edge: Direct 1-Hop Path 1; Byzantine adversary target |
| `vantablack-carrier-3` | `172.28.1.13` | `8000` | 160ms delay ±25ms jitter, 8% packet loss | Satellite Uplink: Direct 1-Hop Path 2; Autonomous Chaos Monkey target |
| `vantablack-carrier-4` | `172.28.1.14` | `8000` | 25ms delay ±3ms jitter, 0.5% packet loss | Continental Core: Hop 2 of Path 0 (C1 $\rightarrow$ C4 $\rightarrow$ Exit) |
| `vantablack-carrier-5` | `172.28.1.15` | `8000` | 55ms delay ±8ms jitter, 1% packet loss | Dynamic Failover Reserve: Hot Standby for Path 2 |
| `mesh-exit` | `172.28.1.20` | `8000` | Local / Internet Gateway | Egress Gateway, Poly1305 Verifier, IP Rotator (`198.51.100.x`) |

---

## 9. The Four Active Validation Scenarios

The carrier simulation runs four continuous autonomous test scenarios verifying the fault-tolerance, cryptographic integrity, and privacy guarantees of the protocol stack:

### Scenario 1: Byzantine Tamper Resistance
- **Threat Model:** Carrier 2 (`172.28.1.12`) acts as an active in-path adversary, mutating 4 bytes of encrypted payload in transit (`payload[len - 4..len] ^= [0x33, 0x55, 0xAA, 0xFF]`) on every 3rd packet.
- **Defense Mechanism:** Pairwise combinatorial Reed-Solomon evaluation in `dec_join_tamper_resistant()` tests pairs $(0,1)$, $(0,2)$, and $(1,2)$ against Poly1305 MAC tags.
- **Result:** Pairs containing the corrupted shard fail Poly1305 authentication. The honest pair $(0,2)$ succeeds, perfectly reconstructing the original payload without retransmission. Carrier 2 is marked `TAMPER REJECTED (Poly1305 Tag Failed)`.

### Scenario 2: Layer 6 Anti-Replay Defense
- **Threat Model:** Every 4 flight cycles, an adversarial observer captures and re-injects a duplicate clone of Shard 0 with a stale sequence counter.
- **Defense Mechanism:** `SessionGuard` maintains a 64-bit / 128-bit sliding window bitmask. Stale counters falling behind the window bound ($V_{\text{max}} - W$) or matching previously set bits in the mask are immediately rejected before cryptographic processing.
- **Result:** Replayed frames are logged and discarded with zero CPU overhead for decryption (`REPLAY ATTACK BLOCKED (Counter N)`).

### Scenario 3: Layer 5 Traffic Shaping & Analysis Resistance
- **Threat Model:** Adversaries use passive Deep Packet Inspection (DPI) to identify application protocols by examining packet length distributions and timing intervals.
- **Defense Mechanism:** `apply_l5_jitter_padding()` prepends a 2-byte length prefix and appends a uniform random byte buffer of 16 to 64 bytes (`rand::thread_rng().gen_range(16..=64)`) to each 512-byte canonical GTF frame.
- **Result:** Outbound datagram lengths vary continuously across time ($528\text{ B} \dots 576\text{ B}$), preventing traffic fingerprinting and correlation.

### Scenario 4: Real-time Convergence Latency Measurement (Chaos Monkey)
- **Threat Model:** Physical infrastructure outage or link severing. Every 10 flight cycles, the autonomous Chaos Monkey severs Carrier 3 (`172.28.1.13`), simulating a total satellite uplink blackout.
- **Defense Mechanism:** `AdaptiveShardRouter` registers unacknowledged loss on Carrier 3 (`record_loss`), updates its path fitness score, and dynamically promotes hot-standby Carrier 5 (`172.28.1.15`).
- **Result:** Shard 2 routes over Carrier 5 with instantaneous convergence latency ($\le 55\text{ ms}$). The mesh survives uninterrupted with 0% data loss.

---

## 10. Desktop Application, Control Center & Live Telemetry Dashboard Architecture

### 10.1 Delivery model

Global Ghost Net ships as a **desktop application**. The default cargo feature set is
`webview`, so `cargo build --release` produces a single executable that:

- opens a **frameless native window** (tao + `wry`, i.e. WebView2 on Windows, WKWebView on macOS, WebKitGTK on Linux) hosting the control center — no browser tab is involved;
- adds a **system-tray icon** whose menu can re-show the window, toggle beacon discovery, or quit;
- treats **closing the window as "hide to tray"**, so the tunnel survives the close button (tao only reports `WM_CLOSE`; we never destroy the window);
- supports a **drag strip** inside the page (`window.ipc.postMessage("drag")` → `Window::drag_window()`), because a frameless window has no title bar to grab;
- runs as a **GUI-subsystem process on Windows** (`windows_subsystem = "windows"`), so no console window appears, and mirrors its log to `ghost.log` (`GHOST_LOG=<path>` / `GHOST_LOG=off`) because there is no console left to read;
- carries a **real application icon**, so Explorer, the taskbar, Alt-Tab and the tray all show the product mark rather than the generic `.exe` glyph. Two distinct pieces make that work, and both are needed: the multi-resolution `assets/icon.ico` (16/24/32/48/64/128/256 px) is compiled into the PE image's `RT_ICON` / `RT_GROUP_ICON` resources by `build.rs` via `embed-resource`, and the *running* window is given an `HICON` at construction time (`WindowBuilder::with_window_icon`), because Windows resolves a window's taskbar icon from `WM_SETICON` — falling back to the executable's resources only if the window never asks. The window/tray pixels come from `assets/icon-ui.ico` (32 and 64 px) through a small dependency-free ICO decoder in `src/ghost/icon.rs` — classic DIB entries only, PNG-compressed entries are rejected with a log line rather than half-parsed. Regenerate both files with `python scripts/make_icon.py`.

### 10.1.1 Where the app keeps its files

All persistent state lives in **one per-user application-data directory**, so the location of
the executable — or the shell's current working directory — has no effect on the node's
identity:

| Platform | Directory |
|---|---|
| Windows | `%APPDATA%\GlobalGhostNet` (falls back to `%LOCALAPPDATA%`, then `%USERPROFILE%\AppData\Roaming`) |
| macOS | `~/Library/Application Support/GlobalGhostNet` |
| Linux | `$XDG_DATA_HOME/global-ghost-net` (or `~/.local/share/global-ghost-net`) |

The files are `identity.key` (the Ed25519 node key), `peers.cache`, `ghost-consumer.json`
(device names, egress mode, bypass list), `ghost-topology.json` and `ghost.log`.

`GHOST_DATA_DIR` overrides the whole directory; the older per-file overrides
(`GHOST_IDENTITY_FILE`, `GHOST_CONSUMER_CONFIG`, `GHOST_LOG`, `GHOST_PEERS_CACHE`) still
win over the default, so existing service units and harnesses are unaffected.

Earlier builds resolved these names against the *current working directory*, which made the
binary behave differently depending on where it was launched from: **double-clicking a copy
of the executable somewhere else silently generated a brand-new identity**, so the node
"forgot" its fingerprint and every existing pairing the moment the file moved — and
launching from a read-only directory such as `C:\Program Files` could not persist anything
at all. A bare filename is now placed in the data directory; a path the caller spelled out
(absolute, or containing a separator) is returned untouched. On first use, if a legacy file
is still sitting in the working directory and no data-directory copy exists, it is **copied**
(never moved, so a failed migration cannot destroy an identity key) and the migration is
logged.

Headless deployments keep working unchanged: `cargo build --release --no-default-features`
compiles out the window, the tray and the WebKit dependency entirely, and `GHOST_NO_GUI=1`
disables the window at runtime while still starting the HTTP control center. That HTTP
interface — the "sidenote" path used by servers and by phones on the LAN — is what the
rest of this section documents. The dashboard HTML is compiled into the binary with
`include_str!`, so editing it requires a rebuild.

### 10.1.2 Packaging

Windows users get a real application install rather than an archive. `installer/ggn.iss`
(Inno Setup) compiles to `ggn-<version>-windows-setup.exe`, built by
`scripts/build_installer.ps1`, which stages the payload in `dist/staging` and reads the
version out of the compiled binary's own version resource — so the executable, the
installer and Add/Remove Programs cannot disagree.

Specific behavioural contracts, each of which the CI job `windows-installer` exercises by
performing a real install, assertion and uninstall cycle:

- **Per-user, never elevated.** `PrivilegesRequired=lowest` installs to
  `%LOCALAPPDATA%\Programs\GlobalGhostNet` and writes the Add/Remove Programs entry under
  `HKCU`. No UAC prompt appears, and the app id in the script is the product's permanent
  identity for upgrades and uninstalls — changing it would orphan every existing install.
- **The version resource must be findable by the shell.** Windows fetches `RT_VERSION`
  with `FindResourceW(h, MAKEINTRESOURCE(1), RT_VERSION)`, so the block has to be compiled
  under ordinal `1`. Writing the symbol `VS_VERSION_INFO` without `windows.h` silently
  registers it under a *string* name instead, and then every shell API — Explorer's
  Details tab, the installer, Add/Remove Programs — reports empty version fields. The
  unit test `ghost::icon::version_resource_is_readable_by_the_shell` pins this.
- **Regenerable data stays out of the install directory.** WebView2 otherwise drops its
  user-data folder beside the executable, which leaves ~10 MB the uninstaller knows nothing
  about and breaks outright in a non-writable directory. The window now points it at
  [`cache_dir`](#1011-where-the-app-keeps-its-files) via `wry::WebContext::new`, and the
  uninstaller removes both that location and the legacy one.
- **Uninstalling never loses an identity key by default.** Setup removes what it installed;
  the identity and settings live in the per-user data directory, which only the explicit
  "also delete my data?" prompt touches — and an unattended uninstall (`/VERYSILENT`, where
  `UninstallSilent` is true) skips even that, so a scripted removal can never destroy a key.

### 10.2 Control center and telemetry API

A real-time observability and remote control engine is embedded directly within the node daemon, exposing metrics via JSON REST APIs and a high-contrast cyber-minimalist single-page dashboard:

- **HTTP Server:** Default port `2270` (configurable via `GHOST_WEB_PORT` or `GHOST_METRICS_PORT`; port `8080` in `wan_mesh` Docker simulation).
- **Interface Modes:**
  - **Consumer Connect View:** A single-column card layout that mirrors the landing page's visual language (Space Grotesk for prose, JetBrains Mono reserved for values). A connection card carries the one-click connect/disconnect action and the mesh mode switch ("Open mesh" vs "Only my devices"), followed by a this-device card (friendly name, platform icon, reachable address) and the device list — friendly names, platform icons, presence, in-place renaming. Measured counters are deliberately *not* on the default screen: paths in use, per-packet overhead, fault tolerance and bytes sent/received live inside a collapsed **Mesh details** disclosure. The pairing modal renders a genuine ISO/IEC 18004 encoder (versions 1–10, ECC level M, GF(256) Reed–Solomon parity, penalty-scored data masks, BCH format/version information) encoding `ggn://pair?nid=…&fp=…&host=…`, and console PIN protection is enforced (not merely reported).
  - **Settings View:** Egress-mode picker (`system_vpn` vs `app_socks`) with an explicit "selected but not in effect" state, a split-tunnel bypass list (hosts, `*.wildcard`, IPv4, CIDR) enforced by the SOCKS5 initiator, and a multi-path speedtest that measures the real per-packet pipeline (see `POST /api/speedtest`).
  - **Level 2 Carrier WAN Simulation View:** Real-time 7-node carrier fleet topology monitor, active route latency bars, autonomous Chaos Monkey failover metrics, Byzantine tamper isolation alert banner, and live public WAN egress header ingestion logs.
- **REST Endpoints:**
  - `GET /`, `GET /?…` and `GET /dashboard`: Serves the single-file reactive HTML dashboard ([`assets/wan_dashboard.html`](file:///g:/Global-Ghost-Net-main/assets/wan_dashboard.html)) supporting tabbed switching between **Connect**, **Settings** (egress mode, split-tunnel bypass list, speed test, console PIN) and **Simulation** (the seven-node carrier WAN viewer). The HTML is compiled into the binary with `include_str!`, so editing the dashboard requires a rebuild. `?native=1` adds the `native` body class: the top row becomes the window drag strip and Hide/Quit appear beside the status pill, which is the chrome the frameless desktop window relies on.
  - `GET /api/status`: Returns JSON status:
    ```json
    {
      "connected": true,
      "mode": "public",
      "network_id": "<fingerprint>",
      "device_name": "amber-otter-457d",
      "device_os": "linux",
      "host": "192.168.1.42:2270",
      "pair_uri": "ggn://pair?nid=<fingerprint>&fp=<fingerprint>&host=192.168.1.42:2270",
      "route_mode": "app_socks",
      "route_mode_active": true,
      "bypass_count": 1,
      "socks_listening": true,
      "socks_port": 1080,
      "vpn_available": false,
      "pin_protected": false,
      "uptime_seconds": 124,
      "peers_count": 2,
      "active_sessions": 2,
      "latency_ms": null,
      "active_carrier_paths": 3,
      "reed_solomon_active": true,
      "throughput": { "bytes_sent": 4096, "bytes_recv": 8192, "packets_sent": 8, "packets_recv": 16 },
      "peers": [...]
    }
    ```
    Honesty invariant: every numeric field is measured on this node, and anything this build does not measure is `null` rather than a plausible-looking constant. `latency_ms` is `null` (no per-peer RTT probe runs) and `active_carrier_paths` is derived from live session count, not hard-coded.
  - `POST /api/connect`: Toggles or updates mesh connection status (`{"connected": true|false}`).
  - `POST /api/mode`: Sets operating mode (`{"mode": "public"|"private"}`).
  - `GET /api/peers`: Returns array of discovered and connected peer objects, each carrying `name`, `custom_name`, `os` and `status` (`online` if a session is established, `idle` if only discovered, `offline` otherwise).
  - `POST /api/peers/rename`: Sets or clears a friendly device name (`{"fingerprint": "…", "name": "LivingRoom-PC", "os": "linux"}`). Names are capped at 253 chars with control characters stripped; an empty name restores the deterministic `adjective-noun-hex` default derived from the fingerprint (FNV-1a, so every node agrees).
  - `GET /api/settings` / `POST /api/settings`: Reads and mutates the persisted consumer control plane — `route_mode` (`system_vpn` | `app_socks`), `bypass` rules, plus `route_mode_active`, `socks_listening`, `vpn_available` so the UI can distinguish "selected" from "in effect". Mutations accept `route_mode`, `bypass_add`, `bypass_remove` or a whole `bypass` array. Rules are normalised (schemes, paths and ports stripped) and validated: a rule that could never match a host or network is rejected with HTTP 400 instead of being stored as a silent no-op. State is persisted to `ghost-consumer.json` (`GHOST_CONSUMER_CONFIG`) via temp-file + rename.
  - `POST /api/speedtest`: Runs the real data path in process — `enc_split` (XChaCha-style AEAD with direction-bound nonces) → `l4_rs::encode` (3 shards) → per-carrier unframe → RS reconstruct from **two** shards with one data shard deliberately dropped → decrypt → payload compare — and reports measured `upload_mbps`, `download_mbps`, `shard_jitter_ms`, `shard_transport_p95_ms`, `reconstruction_ms`, `mesh_overhead_ms`, and `recovered_chunks`. It also samples this node's real byte counters over 1 s for `live.tx_mbps` / `live.rx_mbps`. `{"isp_probe": true}` (opt-in, off by default) measures the internet round-trip via a TCP connect to `1.1.1.1:443`. These are pipeline/CPU figures for this node, explicitly not a broadband speed measurement.
  - `POST /api/pin`-less PIN model: `GHOST_PIN=<pin>` is enforced, not advisory — any `POST` without a matching `X-Pin` header gets HTTP 401 `{"success": false, "error": "PIN required", "pin_required": true}`. The dashboard prompts once per session and resends the header.
  - Split-tunnel enforcement: the SOCKS5 initiator consults the bypass list for every `CONNECT`. Matching destinations are dialed directly (local DNS + local ISP socket) and relayed, so banking apps and geo-checked streaming keep working; everything else is tunnelled through the mesh.
  - `GET /api/telemetry`: Returns full JSON status object (`TelemetryState`), including cycle count, active routes, carrier latency/loss matrix, security alerts (Byzantine tamper isolation events, replay attacks blocked), traffic shaping jitter stats, and convergence latency.
  - `GET /healthz`: Health check endpoint returning HTTP 200 JSON with node version, fingerprint, and uptime.
  - `GET /metrics`: Prometheus-compatible exposition format for integration with Grafana / Prometheus scrapers.
  - `OPTIONS *`: CORS preflight responding with HTTP 204 and standard permissive access-control headers.

---

## 11. Optional Transport: QUIC under GTF (SOTA P1-2)

QUIC is a **carrier**, not a second protocol. The frames are the GTF frames of §2.1, built by the
same `build_gtf_frame`, sealed by the same L2 AEAD, and authenticated by the same session layer;
the transport replaces only what moves them. It is off unless `GHOST_QUIC=1` and only compiles
under `--features quic` (`quinn` + `rustls-ring`), so a default build has no QUIC code and no
QUIC port at all.

### 11.1 Which framing a frame takes

| GTF framing | Size | Carrier | Why |
| :-- | --: | :-- | :-- |
| Privacy shard | ≤ 486 B payload | QUIC **datagram** (RFC 9221) | Unreliable and unordered by design, which is what a Reed-Solomon (2,1) shard expects: a lost shard is reconstructable, and a retransmission would only add latency to bytes the peer does not need. |
| Bulk frame | 1472 B fixed | QUIC **stream** | A 1472-byte frame does not fit a QUIC datagram (path-MTU bounded, ≈1200 in practice). Streams have no such limit and give the bulk path the reliable, in-order delivery it wants. |

The split is `QuicLink::send_frame`'s decision, reported back as `CarrierPath::Datagram | Stream`
so a caller — and `scripts/bench_transport.sh` — can see which route a frame took instead of
guessing. `send_frame_as` forces a framing when a caller has an opinion.

A datagram that finds no room waits up to **50 ms** (`DATAGRAM_ROOM_TIMEOUT`) for space and is
then reported as *not carried*. It deliberately does **not** use quinn's `send_datagram`, which
frees space by discarding the oldest *queued* datagrams: silently dropping a shard would turn
this carrier back into the lossy one it was chosen to improve on. "Not carried" lets the egress
fall through to UDP with the frame intact.

### 11.2 What authenticates what

The certificate is **self-signed and is deliberately not the trust anchor**: there is no PKI in a
mesh, and inventing one to carry traffic the mesh already authenticates would be theatre. Both
ends run a rustls verifier that accepts a self-signed chain. What binds the connection to an
identity is a **channel binding** (RFC 5705):

1. both ends derive 32 bytes of keying material from the TLS session itself
   (`Connection::export_keying_material`, label `ggn-quic-identity-binding`);
2. each end sends `[Ed25519 public key (32 B)][Ed25519 signature (64 B) over that
   keying material]` — 96 bytes, `BINDING_LEN` — on a bidirectional stream the peer reads before
   any data flows;
3. each end verifies the signature **and** that the key belongs to the fingerprint the mesh
   already authenticated (dialling end against its expected peer, accepting end against its
   admission rule).

A man in the middle who terminates TLS on both sides gets a **different** channel binding on each
side, so the two signatures cannot both be valid. That is the property a self-signed certificate
alone cannot provide: accepting the certificate skips X.509 trust, not authentication. A peer
whose signature fails, or whose identity the admission rule does not know, is refused with the
session closed.

### 11.3 Where the carrier sits in the live path

`net::carrier::Carrier` is a registry of established links keyed by **peer fingerprint**, never by
address: a peer that reconnects from a new address replaces its own entry, and no address change
can inherit someone else's link. A link that has already closed is evicted on lookup, so the
tunnel cannot be handed a dead carrier.

Egress consults it in `send3_adaptive`, *after* the fallback decision and *before* the shard
router: a carrier link rides the address ICE already measured, so it is only usable where a
direct path exists, and it is preferred there because QUIC's own loss recovery beats three UDP
shards on a lossy path. A frame that the carrier did not take leaves the shards to UDP unchanged.
The whole sequence is `route?` → carrier → CGR/fitness shard dispatch → UDP.

Ingress is the same pipeline a UDP datagram enters: a frame read from a link goes to
`RxContext::ingest`, so a carrier frame is indistinguishable downstream from one that arrived on
the socket. Address-keyed tunnel bookkeeping uses the link's remote address.

Links are established in both directions:

* **Accept:** an inbound session is admitted only if `nc.sessions` or the beacon-verified peer
  table already knows the claimed fingerprint — the same rule the DERP relay uses — so a stranger
  cannot open a carrier link just by reaching the port.
* **Dial:** every 5 s, each peer in the NAT puncher's connected set with no link yet is dialled at
  the address ICE verified. Failures are expected (the peer may have no transport, or a middlebox
  may drop the second port) and are logged at debug; the UDP path is unaffected.

### 11.4 Verification

`tests/p1_quic.rs` (loopback, no privileges): a frame crosses intact and the identity is proven;
a wrong fingerprint is refused; an unknown identity cannot open a session; and the registry sends
only for peers it holds a link to, evicting a closed one. `scripts/bench_transport.sh` runs
`tests/bench_transport.rs`, which carries the same GTF frames over UDP and over QUIC with the
framing held fixed and prints payload/wire MiB and MiB/s per row. The bench runs over loopback —
the one path where UDP is at its best and where loss recovery cannot show up — so it measures what
the framing costs, not which carrier is faster on a real path.

**Not implemented:** multipath-QUIC (SOTA P1-2 names it for a multi-homed Wi-Fi+LTE host). The
registry holds one link per peer fingerprint; a second path would need the key to be
`(fingerprint, local path)` and the shard router to spread carriers across links. See
`docs/UNWIRED.md`.

