<div align="center">

# &#128420; Vantablack

**Autonomous Post-Quantum WAN Mesh Routing & Serverless Traffic Sharding**

<br>

[![License](https://img.shields.io/badge/License-MIT-059669?style=flat-square)](LICENSE)
[![Language](https://img.shields.io/badge/Language-Rust%20(Pure)-orange?style=flat-square)](https://www.rust-lang.org/)
[![Runtime](https://img.shields.io/badge/Runtime-Tokio%20Async-blue?style=flat-square)](https://tokio.rs/)
[![Crypto](https://img.shields.io/badge/Crypto-ML--KEM--512%20%7C%20X25519-blueviolet?style=flat-square)](docs/SPECIFICATIONS.md)

<br>

[**Technical Specifications**](docs/SPECIFICATIONS.md) &bull; [**Protocol Whitepaper**](docs/WHITEPAPER.md) &bull; [**Onion Routing Architecture**](docs/ONION_ARCHITECTURE.md) &bull; [**LAN over WAN**](docs/LAN_OVER_WAN.md) &bull; [**Configuration Reference**](config.env.example)

</div>

---

## What is Vantablack?

**Vantablack** is an autonomous peer-to-peer mesh routing daemon written in pure Rust. It enables personal computers, servers, and edge devices to communicate securely across the public internet without central servers, commercial VPN providers, or trusted Certificate Authorities.

Instead of funneling traffic through a central VPN provider where it can be monitored, logged, or intercepted, Vantablack encrypts traffic with **post-quantum cryptography**, breaks it into **Reed-Solomon mathematical shards**, and routes them across multiple independent intermediary carrier nodes simultaneously over divergent WAN paths.

---

## Why Use It?

* **Quantum-Resilient Privacy:** Uses hybrid ML-KEM-512 (Kyber / FIPS 203) and ephemeral X25519 ECDH. Data captured by state surveillance today cannot be decrypted when cryptographically relevant quantum computers arrive.
* **Asymmetric Shard Routing:** Every message is split into 3 mathematical shards (Reed-Solomon RS(2,1)) dispatched across divergent internet paths for packet-loss resilience. Payload confidentiality is strictly enforced by AEAD encryption, while erasure coding guarantees reconstruction from any 2 shards without retransmission.
* **Byzantine Tamper Resistance:** Pairwise combinatorial Poly1305 MAC tag verification isolates and drops corrupted shards in real-time, reconstructing intact payloads via pristine alternate paths.
* **Zero Infrastructure Costs:** No need to pay for a central VPS. Connect your devices seamlessly using free Cloudflare DNS seeds and automatic local peer caching.
* **Anti-Traffic Fingerprinting:** Layer 5 traffic shaping injects randomized jitter noise (16–64 bytes) to defeat deep packet inspection (DPI), packet-length analysis, and timing correlation.
* **Instant SOCKS5 Proxy:** Runs a built-in proxy on `127.0.0.1:1080` out of the box, allowing any browser, terminal tool, or application to immediately route through the mesh.
* **Self-Healing & Chaos Resilience:** Autonomous multi-path failover seamlessly switches around severed carrier links with zero packet loss or connection drops.

---

## Level 2 Multi-Hop Mesh WAN Architecture

Vantablack includes a complete **Level 2 Multi-Hop WAN Mesh Simulation Environment** built on Docker Compose, replicating realistic transcontinental carrier links using Linux `tc netem` (traffic control network emulator).

```
                      +-------------------+
                      |   Client Node     |
                      | (172.28.1.10:8000)|
                      +---------+---------+
                                |
       +------------------------+------------------------+
       | Shard 0 (2 Hops)       | Shard 1 (1 Hop)        | Shard 2 (1 Hop / Failover)
       v                        v                        v
+--------------+         +--------------+         +--------------+
|  Carrier 1   |         |  Carrier 2   |         |  Carrier 3   |
| 172.28.1.11  |         | 172.28.1.12  |         | 172.28.1.13  |
| 45ms / 1% loss|        | 85ms / 3% loss|        | 160ms / 8%   |
+------+-------+         | (Byzantine)  |         +------+-------+
       |                 +------+-------+                | (Chaos Sever)
       v                        |                        v
+--------------+                |                 +--------------+
|  Carrier 4   |                |                 |  Carrier 5   |
| 172.28.1.14  |                |                 | 172.28.1.15  |
| 25ms / 0.5%  |                |                 | 55ms Hot Res.|
+------+-------+                |                 +------+-------+
       |                        |                        |
       +------------------------+------------------------+
                                |
                                v
                      +-------------------+
                      |     Exit Node     |
                      | (172.28.1.20:8000)|
                      +---------+---------+
                                | Egress IP Rotation (198.51.100.x)
                                v
                       Public Internet (WAN)
                         e.g. Google HTTP
```

### 7-Node Carrier Topology

| Node Name | Container Name | Subnet IP | Linux `tc netem` Condition | Simulated Role |
| :--- | :--- | :--- | :--- | :--- |
| **mesh-client** | `vantablack-client` | `172.28.1.10` | Unconstrained | Protected Client Node (Dashboard & SOCKS5) |
| **mesh-carrier-1**| `vantablack-carrier-1`| `172.28.1.11`| `delay 45ms 5ms loss 1%` | Transatlantic Fiber (Hop 1 of 2) |
| **mesh-carrier-2**| `vantablack-carrier-2`| `172.28.1.12`| `delay 85ms 15ms loss 3%` | Transpacific Edge (`BYZANTINE_TAMPER=1`) |
| **mesh-carrier-3**| `vantablack-carrier-3`| `172.28.1.13`| `delay 160ms 25ms loss 8%`| High-Latency Satellite Uplink (Chaos Target) |
| **mesh-carrier-4**| `vantablack-carrier-4`| `172.28.1.14`| `delay 25ms 3ms loss 0.5%`| Continental Core Backbone (Hop 2 of 2) |
| **mesh-carrier-5**| `vantablack-carrier-5`| `172.28.1.15`| `delay 55ms 8ms loss 1%` | Dynamic Hot Standby Failover Reserve |
| **mesh-exit** | `vantablack-exit` | `172.28.1.20` | Unconstrained | Egress Gateway & IP Rotator |

---

## 4 Active Test Scenarios

The Level 2 WAN simulation autonomously evaluates 4 critical cryptographic and networking resilience invariants:

### Scenario 1: Byzantine Tamper Isolation (RS(2,1) + Combinatorial Poly1305)
* **Mechanics:** `mesh-carrier-2` acts as an active Byzantine adversary (`BYZANTINE_TAMPER=1`), deliberately corrupting 4 bytes of in-flight encrypted shard payloads every 3 cycles.
* **Defense:** When all 3 shards arrive, the receiver executes pairwise combinatorial reconstruction:
  - Pair $(0, 1)$ testing (excludes Shard 2)
  - Pair $(0, 2)$ testing (excludes Shard 1)
  - Pair $(1, 2)$ testing (excludes Shard 0)
* **Outcome:** The ChaCha20-Poly1305 AEAD tag authentication fails on corrupted pairs and succeeds on pristine pairs. The router isolates the adversarial carrier, marks it as `TAMPER REJECTED`, and reconstructs pristine plaintext with zero data loss.

### Scenario 2: Layer 6 Anti-Replay Sliding Window Defense (SessionGuard)
* **Mechanics:** The test harness periodically launches duplicate clone transmissions of Shard 0 with stale sequence counters ($T_x$) to simulate network replay attacks.
* **Defense:** Both Client and Exit nodes maintain a `SessionGuard` tracking packet counters across a 64-bit/128-bit sliding window bitmap.
* **Outcome:** Counters trailing the window or already recorded in the bitmask are unconditionally dropped before reaching decryption buffers (`REPLAY_ATTACK_BLOCKED`), preventing replay side-channels.

### Scenario 3: Layer 5 Traffic Shaping & Analysis Resistance (Randomized Jitter)
* **Mechanics:** DPI and timing-correlation attacks analyze packet size patterns and interval histograms to infer traffic types.
* **Defense:** Every outbound frame is wrapped with a 2-byte big-endian original length prefix, followed by the ciphertext and $16..64$ cryptographically randomized padding bytes (`apply_l5_jitter_padding`).
* **Outcome:** Packet lengths vary continuously on the wire, masking MTU signatures and frustating deep packet inspection.

### Scenario 4: Real-time Convergence Latency Measurement (Autonomous Chaos Monkey)
* **Mechanics:** An integrated Chaos Monkey routine severs the link to `mesh-carrier-3` on alternating cycles (5 out of every 10 cycles).
* **Defense:** The `AdaptiveShardRouter` registers link loss, updates Poisson path fitness metrics, and dynamically redirects the shard through the hot standby `mesh-carrier-5`.
* **Outcome:** Real-time failover convergence occurs in $\le 55\text{ ms}$ (the RTT of the standby carrier) without dropping TCP streams or invalidating session crypto.

---

## Running the Level 2 WAN Mesh Simulation

### Prerequisites
- Docker & Docker Compose
- Linux kernel with `sch_netem` support (available by default on Linux; WSL2 on Windows supports `cap_add: NET_ADMIN`)

### Step 1: Start the 7-Node Carrier Mesh
```bash
# Build and start all 7 nodes in detached mode
docker compose -f docker-compose.wan.yml up --build -d

# View live container logs
docker compose -f docker-compose.wan.yml logs -f mesh-client
```

### Step 2: Access the Live Telemetry Dashboard
Open your browser to:
```
http://localhost:8080
```
The real-time dashboard monitors:
- Live network topology diagram with dynamic link color-coding.
- Shard delivery rates (RS(2,1) quorum progress: 2/3 and 3/3).
- Active security alerts (Byzantine tamper detection, Replay attacks blocked).
- Live RTT per carrier under Linux `tc netem` rules.
- Autonomous Chaos Monkey link severance and failover convergence latency.
- Egress IP rotation (`198.51.100.x`).
- Live HTTP headers ingested from upstream targets.

The JSON telemetry feed is available programmatically at `http://localhost:8080/api/telemetry`.

### Step 3: Route Client Traffic via Mesh SOCKS5
While the simulation runs, you can route terminal commands and browser traffic through the multi-hop mesh on port `1080`:
```bash
curl --socks5 127.0.0.1:1080 http://httpbin.org/ip
```

### Step 4: Stop the Simulation
```bash
docker compose -f docker-compose.wan.yml down
```

---

## Install on Windows

The recommended way to install on Windows is the setup file attached to every
[release](https://github.com/KELLERBABG/Vantablack/releases):

```
ggn-<version>-windows-setup.exe
```

It installs **for the current user only**, so it never asks for administrator
rights:

| What | Where |
|---|---|
| Program | `%LOCALAPPDATA%\Programs\GlobalGhostNet` |
| Start Menu | `Vantablack` |
| Uninstall | *Settings → Apps → Installed apps* (or *Programs and Features*) |
| Your data | `%APPDATA%\GlobalGhostNet` — untouched by upgrades and uninstalls |

Uninstalling removes the program, the Start Menu entry, the registry entry and
the WebView2 cache, and then **asks** whether to delete your identity key and
settings. Answer *No* and a later reinstall comes back as the same device, with
the same name and pairings. An unattended uninstall (`/VERYSILENT`) always keeps
the data.

<details>
<summary>Unattended install / uninstall, and building the installer yourself</summary>

```powershell
# Silent install
.\ggn-0.4.1-windows-setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART

# Silent uninstall (keeps your data)
"$env:LOCALAPPDATA\Programs\GlobalGhostNet\unins000.exe" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART

# Build it from a checkout (needs Inno Setup 6: winget install JRSoftware.InnoSetup)
.\scripts\build_installer.ps1
```

On Linux and macOS, and for servers or containers, use the archive from the same
release instead — it needs no installer.
</details>

---

## Quick Start (Standalone Binary)

### Option 1: Running the Desktop App

Vantablack is a desktop application. A plain `cargo build --release` produces it:

1. **Launch the app:**
   ```bash
   cargo run --release
   # Or run the built binary directly: target/release/ggn (same program as target/release/vantablack)
   ```
   - Binds its mesh data socket per `GHOST_BIND` (default: ephemeral port). Port `2270/UDP` is used for discovery beacons.
   - Starts local SOCKS5 proxy on `127.0.0.1:1080`.
   - Opens its **own window** (frameless, with a tray icon) hosting the full control center. Closing the window hides it to the tray; use the tray menu to quit.
   - Starts the HTTP control center on `http://localhost:2270` (`GHOST_WEB_PORT` / `GHOST_METRICS_PORT`) at the same time, so the same UI is reachable from a browser or a phone on your network.
   - Mirrors logs to `ghost.log` (`GHOST_LOG=off` disables, `GHOST_LOG=<path>` moves it), because the Windows build is a GUI process with no console.
   - Automatically queries DNS seeds and connects to active mesh peers.

   The executable is relocatable — copy it anywhere, to a USB stick or `C:\Program Files`; its identity and settings do not move with it. Everything persistent is kept in one per-user directory:

   | Platform | Location |
   |---|---|
   | Windows | `%APPDATA%\GlobalGhostNet` |
   | macOS | `~/Library/Application Support/GlobalGhostNet` |
   | Linux | `~/.local/share/global-ghost-net` (`$XDG_DATA_HOME`) |

   That directory holds `identity.key`, `peers.cache`, `ghost-consumer.json` (device names, egress mode, bypass list), `ghost-topology.json` and `ghost.log`. `GHOST_DATA_DIR` moves the whole directory; the older `GHOST_IDENTITY_FILE` / `GHOST_CONSUMER_CONFIG` / `GHOST_LOG` overrides still work. If an older build left a state file in the working directory, it is copied into the new location on first use — the original is never deleted.

   On Linux the desktop build needs GTK/WebKit development headers:
   ```bash
   # Debian / Ubuntu
   sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev
   # Fedora
   sudo dnf install webkit2gtk4.1-devel gtk3-devel libappindicator-gtk3-devel librsvg2-devel
   ```
   Servers and containers should skip all of that with the headless build, which is HTTP-only:
   ```bash
   cargo build --release --no-default-features
   GHOST_NO_GUI=1 ./target/release/ggn      # no window; browser control center only
   ```

2. **The control center (also available in a browser at `http://localhost:2270`):**
   - **Dashboard UI (`GET /` or `GET /dashboard`):** A single-column, dark-mode interface in the same visual language as the landing page — Space Grotesk for text, JetBrains Mono only for values. One card connects or disconnects and picks who may join ("Open mesh" vs "Only my devices"), the next shows this device and how to pair it, then the device list with friendly names, platform icons, presence and rename-in-place. Measured figures (paths in use, per-packet overhead, bytes sent/received) stay behind a collapsed **Mesh details** disclosure instead of four shouting tiles, so the default screen is just the connection state. Tabs: **Connect**, **Settings** (egress mode, split-tunnel bypass list, speed test, console PIN) and **Simulation** (the seven-node WAN viewer). The pairing modal shows a real ISO/IEC 18004 QR symbol (versions 1–10, error correction level M) encoding a `ggn://pair` link. Appending `?native=1` turns the top row into the drag strip and adds Hide/Quit, which is what the desktop window loads; it is a normal page, so the browser remains a complete way in.
   - **`GET /api/status`:** Returns live node status JSON. Every field is either measured or explicitly `null` — nothing is a placeholder constant:
     ```json
     {
       "connected": true,
       "mode": "public",
       "network_id": "a9c7482f1b0e457d",
       "device_name": "amber-otter-457d",
       "device_os": "linux",
       "host": "192.168.1.42:2270",
       "pair_uri": "ggn://pair?nid=a9c7482f1b0e457d&fp=a9c7482f1b0e457d&host=192.168.1.42:2270",
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
     `latency_ms` is `null` because this build runs no per-peer RTT probe; `active_carrier_paths` counts the primary route plus up to two additional live sessions.
   - **`POST /api/connect`:** Toggles or sets connection state (`{"connected": bool}`).
   - **`POST /api/mode`:** Updates operating mesh mode (`{"mode": "public" | "private"}`).
   - **`GET /api/peers`:** Returns JSON list of all discovered and active peers, each with `name`, `custom_name`, `os`, `status` (`online` / `idle` / `offline`) and fingerprint.
   - **`POST /api/peers/rename`:** Sets or clears a device's friendly name (`{"fingerprint": "...", "name": "LivingRoom-PC", "os": "linux"}`). An empty name restores the deterministic default.
   - **`GET /api/settings`:** Returns the consumer control-plane state: `route_mode` (`system_vpn` / `app_socks`), `route_mode_active` (whether that choice is genuinely in force), `bypass` rules, SOCKS5 listener state and TUN availability.
   - **`POST /api/settings`:** Applies `route_mode`, `bypass_add`, `bypass_remove` (or a replacement `bypass` array). Rules accept hosts (`banking.example.de`), wildcards (`*.netflix.com`), IPv4 addresses and CIDR blocks (`192.168.1.0/24`); anything that could never match is rejected with HTTP 400. Persisted to `ghost-consumer.json` (override path with `GHOST_CONSUMER_CONFIG`).
   - **`POST /api/speedtest`:** Pushes a real payload through encrypt → 3-carrier shard → rebuild-from-two-shards → decrypt (one carrier is cut every packet) and returns measured per-stage timings, plus live TX/RX from this node's real byte counters over a 1 s window. `{"isp_probe": true}` additionally measures the internet round-trip by TCP-connecting to `1.1.1.1:443`.
   - **`GET /api/telemetry`:** Returns full Level 2 WAN carrier simulation metrics.
   - **`GET /healthz` & `GET /metrics`:** Health check and Prometheus metrics exposition.

   Setting `GHOST_PIN=<pin>` now *enforces* the console PIN: every `POST` endpoint rejects requests that do not carry a matching `X-Pin` header with HTTP 401. The control center binds `0.0.0.0`, so set a PIN if the machine is on a shared network.

   Split tunneling is enforced in the SOCKS5 initiator: destinations matching a bypass rule are dialed directly over the local ISP instead of being tunnelled through the mesh. Set the egress mode with `GHOST_EGRESS_MODE=system_vpn|app_socks` for the first run, then the saved choice wins.

   The tray-only build (a tray icon that opens the browser, no native window) is still available:
   ```bash
   cargo build --release --no-default-features --features tray
   ```

3. **Exit Node (Transit Provider):**
   ```bash
   GHOST_EXIT_ALLOWLIST=any cargo run --release
   ```
   - Acts as an egress gateway that routes external internet traffic for mesh computers.

4. **Browse Securely:**
   Configure your browser proxy or terminal to use `127.0.0.1:1080`:
   ```bash
   curl --socks5 127.0.0.1:1080 https://httpbin.org/ip
   ```

---

### Option 2: Zero-Cost Peer Discovery via Cloudflare

You do not need to rent a virtual private server. You can bootstrap your mesh with any domain managed on Cloudflare:

1. In your **Cloudflare Dashboard**, navigate to **DNS** &rarr; **Records**.
2. Add an **A** record (e.g. `seeds.yourdomain.com`) pointing to the public IP of one of your stable nodes.
3. Set proxy status to **DNS only (Grey Cloud)**.
4. Copy `config.env.example` to `config.env` and set:
   ```env
   GHOST_DNS_SEED=seeds.yourdomain.com:2270
   ```
Connecting nodes automatically query this record, establish the post-quantum mesh, and persist verified nodes to `peers.cache` for offline-first reconnection.

---

### Option 3: Terminal & Interactive Console

When running in a terminal, Vantablack provides an interactive command console for live mesh management:

```bash
# Connect to a remote peer directly
PEER 198.51.100.24:2270

# Display connected peers and link latency
PEERS

# View node health, active sessions, and tunnel state
STATUS

# View live throughput and error correction stats
STATS

# Send an end-to-end encrypted direct message across the mesh
CHAT 9a4f7e2c hello-mesh   # one token only - the console splits on spaces
```

---

## Operational Capabilities & Boundaries

| Threat / Scenario | Defense Mechanism | Protection Level |
| :--- | :--- | :---: |
| **Quantum Computing Decryption** | Hybrid ML-KEM-512 (Kyber) + Ephemeral X25519 ECDH | **Immune** |
| **Single-Node Eavesdropping** | RS(2,1) Reed-Solomon asymmetric multi-path sharding | **Immune** |
| **Byzantine Node Tampering** | Pairwise combinatorial Poly1305 AEAD validation | **Immune** |
| **Deep Packet Inspection (DPI)** | L5 Random Jitter Padding (16–64 bytes) + Uniform Frames | **Immune** |
| **Packet Replay Attacks** | Sliding window bitmask guard (`SessionGuard` / `SessionGuardU64`) | **Immune** |
| **Carrier Failover / Severance** | Dynamic `AdaptiveShardRouter` with Poisson fitness tracking | **Resilient (<55ms)** |
| **In-Memory Scraping** | Volatile zeroization on drop + AES-256-XTS RAM protection | **Hardened** |
| **Central Server Seizure** | Pure decentralized P2P architecture with local `peers.cache` | **Immune** |

---

## Technical Architecture (L0-L9)

Vantablack implements the 10-layer GHOST protocol stack:

```
+-------------------------------------------------------------+
|                     GHOST PROTOCOL                          |
+------+----------------------+-------------------------------+
|Layer | Component            | Specification                 |
+------+----------------------+-------------------------------+
| L0   | Permanent Identity   | Ed25519 cryptographic keys    |
| L1   | Hybrid KEM           | X25519 + ML-KEM-512 (Kyber)   |
| L2   | Authenticated AEAD   | ChaCha20-Poly1305 + HKDF      |
| L3   | Secret Sharing       | Shamir SSS (GF256, 2-of-3)    |
| L4   | Erasure Coding       | Reed-Solomon RS(2,1) shards   |
| L5   | Traffic Shaping      | 16-64B jitter cover padding   |
| L6   | Session Guard        | Sliding window replay bitmask |
| L7   | Forward Error Corr.  | LDPC parity-check matrix      |
| L8   | Memory Defense       | AES-256-XTS RAM encryption    |
| L9   | Infrastructure Trust | TPM/HSM enclave & NTS sync    |
+------+----------------------+-------------------------------+
```

---

## Technical Documentation & Deep Dives

Interactive documentation portal is live at [**vantablack.kellersystems.dev/docs**](https://vantablack.kellersystems.dev/docs).

For engineers, cryptographers, and contributors wishing to inspect the mathematics, security models, and implementation details:

* [**Technical Specifications**](docs/SPECIFICATIONS.md) — Low-level frame layouts, Level 2 multi-hop headers, L5 jitter wire structures, and SessionGuard bitmasks.
* [**Protocol Whitepaper**](docs/WHITEPAPER.md) — Architectural overview of the GHOST network layers (L0 through L9).
* [**Clean-Room Onion Routing**](docs/ONION_ARCHITECTURE.md) — In-depth breakdown of the multi-hop onion peeling protocol, `RLY!` headers, and zero-legacy design.
* [**LAN over WAN (VPN Layer)**](docs/LAN_OVER_WAN.md) — Road-warrior userspace VPN architecture, TUN drivers, and mobile network roaming.
* [**Cryptographic Deep Dive**](docs/CRYPTOGRAPHY_DEEP_DIVE.md) — Formal analysis of ML-KEM-512, X25519 hybrid key exchange, directional nonces, and memory security.
* [**Zero-Cost Peer Discovery Guide**](docs/PEER_DISCOVERY_GUIDE.md) — Step-by-step walkthrough for configuring free Cloudflare DNS seeds and local caching.
* [**Configuration Reference**](config.env.example) — Parameter reference for network ports, transit rate limits, and egress allowlists.

---

## Building from Source

Vantablack is written in pure Rust. `cargo build --release` produces the desktop
application (native window + tray); the headless server build needs no C toolchain,
no GTK/WebKit and no display:

```bash
# Desktop application (default features)
cargo build --release

# Headless server / container build
cargo build --release --no-default-features

# Run comprehensive unit & integration test suite
cargo test --lib
cargo test --test simulation

# Build and run the Level 2 Multi-Hop WAN binary (headless)
cargo run --bin wan_mesh --no-default-features
```

---

## License

Vantablack is open-source software distributed under the [MIT License](LICENSE).
