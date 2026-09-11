<div align="center">

# &#128420; Global Ghost Net

**Autonomous Post-Quantum WAN Mesh Routing & Serverless Traffic Sharding**

<br>

[![License](https://img.shields.io/badge/License-MIT-059669?style=flat-square)](LICENSE)
[![Language](https://img.shields.io/badge/Language-Rust%20(Pure)-orange?style=flat-square)](https://www.rust-lang.org/)
[![Runtime](https://img.shields.io/badge/Runtime-Tokio%20Async-blue?style=flat-square)](https://tokio.rs/)
[![Crypto](https://img.shields.io/badge/Crypto-ML--KEM--512%20%7C%20X25519-blueviolet?style=flat-square)](docs/SPECIFICATIONS.md)

<br>

[**Technical Specifications**](docs/SPECIFICATIONS.md) &bull; [**Protocol Whitepaper**](docs/WHITEPAPER.md) &bull; [**Configuration Reference**](config.env.example)

</div>

---

## What is Global Ghost Net?

**Global Ghost Net** is an autonomous peer-to-peer mesh routing daemon written in Rust. It enables personal computers, servers, and devices to communicate securely across the public internet without central servers, commercial VPN providers, or trusted Certificate Authorities.

Instead of sending your data through a central VPN provider where it can be monitored, logged, or intercepted, Global Ghost Net encrypts your traffic with **post-quantum cryptography**, breaks it into **Reed-Solomon mathematical shards**, and routes them across multiple independent computers simultaneously.

---

## Why Use It?

* **Quantum-Resilient Privacy:** Uses hybrid ML-KEM-512 (Kyber / FIPS 203) and ephemeral X25519 ECDH. Data captured by state surveillance today cannot be decrypted when quantum computers arrive.
* **Asymmetric Shard Routing:** Every message is split into 3 mathematical shards (Reed-Solomon RS(2,1)). Shards travel through different computers across divergent internet paths; intercepting any single path yields zero readable information.
* **Zero Infrastructure Costs:** No need to pay for a central VPS. Connect your devices seamlessly using free Cloudflare DNS seeds and automatic local peer caching.
* **Anti-Traffic Fingerprinting:** All mesh packets are normalized to a uniform size with randomized jitter noise, defeating deep packet inspection (DPI), packet-length analysis, and timing correlation.
* **Instant SOCKS5 Proxy:** Runs a built-in proxy on `127.0.0.1:1080` out of the box, allowing any browser, terminal tool, or application to immediately route through the mesh.
* **100% Peer-to-Peer & Self-Healing:** The mesh automatically reconnects, routes around failed nodes, and discovers peers through local subnet multicast beacons and peer exchange.

---

## Quick Start (Windows & Linux)

### Option 1: Running the Node

Run the pre-compiled binary or build with cargo:

1. **Client Node (Protected User):**
   ```bash
   cargo run --release
   # Or run target/release/vantablack
   ```
   - Binds local mesh listener to port `2270`.
   - Starts local SOCKS5 proxy on `127.0.0.1:1080`.
   - Automatically queries DNS seeds and connects to active mesh peers.

2. **Exit Node (Transit Provider):**
   ```bash
   GHOST_EXIT_ALLOWLIST=any cargo run --release
   ```
   - Acts as an egress gateway that routes external internet traffic for mesh computers.

3. **Browse Securely:**
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
   ```
Connecting nodes automatically query this record, establish the post-quantum mesh, and persist verified nodes to `peers.cache` for offline-first reconnection.

---

### Option 3: Terminal & Interactive Console

When running in a terminal, Global Ghost Net provides an interactive command console for live mesh management:

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
CHAT 9a4f7e2c "Direct post-quantum encrypted ping"
```

---

## Operational Capabilities & Boundaries

| Threat / Scenario | Defense Mechanism | Protection Level |
| :--- | :--- | :---: |
| **Quantum Computing Decryption** | Hybrid ML-KEM-512 (Kyber) + Ephemeral X25519 ECDH | **Immune** |
| **Single-Node Eavesdropping** | RS(2,1) Reed-Solomon asymmetric multi-path sharding | **Immune** |
| **Deep Packet Inspection (DPI)** | 512-byte fixed frame size + 0â€“64 byte random jitter padding | **Immune** |
| **Packet Replay Attacks** | Atomic 64-bit sliding window bitmap (`SessionGuardU64`) | **Immune** |
| **In-Memory Scraping** | Volatile zeroization on drop + AES-256-XTS RAM protection | **Hardened** |
| **Central Server Seizure** | Pure decentralized P2P architecture with local `peers.cache` | **Immune** |

---

## Technical Architecture (L0â€“L9)

Global Ghost Net implements the 10-layer GHOST protocol stack:

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
| L5   | Traffic Padding      | Jitter-padded uniform frames  |
| L6   | Session Guard        | 64-bit replay sliding window  |
| L7   | Forward Error Corr.  | LDPC parity-check matrix      |
| L8   | Memory Defense       | AES-256-XTS RAM encryption    |
| L9   | Infrastructure Trust | TPM/HSM enclave & NTS sync    |
+------+----------------------+-------------------------------+
```

---

## Technical Documentation & Deep Dives

For engineers, cryptographers, and contributors wishing to inspect the mathematics, security models, and implementation details:

* [**Technical Specifications**](docs/SPECIFICATIONS.md) â€” Low-level frame layouts, GTF byte structures, and replay window bitmasks.
* [**Protocol Whitepaper**](docs/WHITEPAPER.md) â€” Architectural overview of the GHOST network layers (L0 through L9).
* [**Clean-Room Onion Routing**](docs/ONION_ARCHITECTURE.md) â€” In-depth breakdown of the multi-hop onion peeling protocol, `RLY!` headers, and zero-legacy design.
* [**Cryptographic Deep Dive**](docs/CRYPTOGRAPHY_DEEP_DIVE.md) â€” Formal analysis of ML-KEM-512, X25519 hybrid key exchange, directional nonces, and memory security.
* [**Zero-Cost Peer Discovery Guide**](docs/PEER_DISCOVERY_GUIDE.md) â€” Step-by-step walkthrough for configuring free Cloudflare DNS seeds and local caching.
* [**Configuration Reference**](config.env) â€” Parameter reference for network ports, transit rate limits, and egress allowlists.

---

## Building from Source

Global Ghost Net is written in pure Rust with zero C toolchain dependencies:

```bash
# Build optimized release binary (~1.1 MB)
cargo build --release

# Run comprehensive test suite
cargo test --lib
cargo test --test simulation
```

---

## License

Global Ghost Net is open-source software distributed under the [MIT License](LICENSE).
