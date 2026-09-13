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
Each peer path tracks round-trip latency ($\text{RTT}$) and packet loss ($\text{LossRate}$):

$$\text{Fitness} = \frac{1.0}{1.0 + (\text{RTT}_{\mu\text{s}} / 100{,}000.0)} \times (1.0 - \text{LossRate})$$

- $\text{RTT}$ is smoothed using an Exponential Moving Average (EMA).
- Loss rate increments upon unacknowledged transmissions and decays upon successful deliveries.
- Minimum acceptable fitness threshold: $\text{min\_fitness} = 0.3$.

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

## 10. Live Telemetry Dashboard Architecture

A real-time observability engine is embedded directly within the client node, exposing metrics via JSON API and a single-page reactive HTML dashboard:

- **HTTP Server:** Bound to `0.0.0.0:8080` (or configured via `GHOST_METRICS_PORT`, defaults to `9090` in daemon mode, `8080` in `wan_mesh`).
- **Endpoints:**
  - `GET /api/telemetry`: Returns full JSON status object (`TelemetryState`), including cycle count, active routes, carrier latency/loss matrix, security alerts (Byzantine tamper isolation events, replay attacks blocked), traffic shaping jitter stats, and convergence latency.
  - `GET /` and `GET /dashboard`: Serves the high-performance, single-file HTML dashboard ([`assets/wan_dashboard.html`](file:///g:/Global-Ghost-Net-main/assets/wan_dashboard.html)) with 1-second auto-polling, dynamic SVG carrier topology map, real-time alert banners, and active route latency bars.
  - `GET /healthz`: Health check endpoint returning HTTP 200 JSON with node version, fingerprint, and uptime.
  - `GET /metrics`: Prometheus-compatible exposition format for integration with Grafana / Prometheus scrapers.

