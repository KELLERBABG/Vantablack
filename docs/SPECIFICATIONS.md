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

