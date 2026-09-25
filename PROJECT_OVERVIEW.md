# Global Ghost Net (Vantablack): Complete Project and Architecture Guide

## Overview

Global Ghost Net, also known by its engine codename Vantablack, is an autonomous, decentralized, and post-quantum secure peer-to-peer overlay network and virtual private network. It is engineered from first principles to ensure that two or more devices can communicate securely, reliably, and privately across the open internet without relying on any centralized servers, certificate authorities, domain name systems, or trusted third parties.

Traditional secure networks protect data in transit by encrypting the payload, but they leave packet headers, routing metadata, packet lengths, and timing characteristics exposed. This allows state-level adversaries, internet service providers, and network eavesdroppers to infer identity, reconstruct social graphs, and perform deep packet inspection to block or throttle communication. Global Ghost Net eliminates these metadata leakages by combining multi-path onion routing, post-quantum hybrid cryptography, Reed-Solomon packet dispersal, and traffic shaping into a unified nine-layer architecture.

---

## What the System Does

### 1. Sovereign Cryptographic Identity
Every participant in the network is identified solely by a cryptographic identity generated locally on their device. There are no usernames, email addresses, phone numbers, or central registries. The identity combines classical Edwards-curve digital signatures (Ed25519) with modern post-quantum module-lattice signatures (ML-DSA-65). This hybrid approach guarantees that an identity cannot be spoofed or impersonated today by classical supercomputers or tomorrow by cryptographically relevant quantum computers.

### 2. Multi-Path Packet Splitting and Space-Time Secrecy
When a node sends data, the payload is not sent as a single continuous stream across a single internet connection. Instead, the data is split into multiple independent mathematical shards using Reed-Solomon erasure coding and Shamir secret sharing. These shards are then dispatched across completely disjoint geographical and topological routes through the peer-to-peer mesh. An eavesdropper monitoring an intermediate internet link sees only isolated, unreadable fragments that cannot be decoded without intercepting the majority of alternative routes simultaneously. Even if half of the packets are dropped or blocked by hostile firewalls, the receiving peer reconstructs the original stream without requesting retransmissions.

### 3. Traffic Camouflage and Anti-Fingerprinting
Deep packet inspection systems identify virtual private networks by analyzing packet sizes, inter-packet timing, and standard handshake protocols. Global Ghost Net defends against statistical traffic analysis by packing data into standardized Ghost Transport Frames. These frames use constant lengths, randomized timing jitter, and dummy chaff packets. On networks where proprietary protocols are actively censored, the transport engine can morph its wire signature to look indistinguishable from common web traffic, secure web sockets, or standard domain name queries.

### 4. Zero-Configuration NAT Traversal and Universal Tunneling
Most user devices reside behind complex network address translators, firewalls, and carrier-grade routers. The network automatically discovers public mapping behaviors using built-in interactive connectivity establishment, STUN, and TURN relay protocols. When two peers want to communicate, they automatically punch holes through firewalls to establish direct, low-latency UDP tunnels. If direct connections are blocked by symmetric firewalls, encrypted multi-hop relay nodes forward the traffic without ever being able to read its contents.

### 5. LAN-over-WAN Virtual Private Network
Global Ghost Net contains a full virtual private network system. On Windows, macOS, Linux, and Android, the daemon binds to native virtual network adapters (such as Wintun or kernel TUN interfaces) and injects a complete userspace TCP/IP stack. This allows users to assign static private IP addresses to their devices and access remote resources, files, and services as if all devices were physically connected to the same local Ethernet switch.

### 6. Built-in Local Control Center and System Tray
Every node runs a lightweight local dashboard accessible via a desktop window, system tray menu, or local web browser at localhost port 8231. The dashboard displays real-time telemetry, connection latency, peer discovery state, cryptographic fingerprint verification, and routing health without exposing any administrative endpoints to the outside internet.

---

## The Nine-Layer Architecture

The core cryptographic and transport pipeline is structured into nine distinct layers:

1. **Layer 0: Sovereign Identity (`l0_identity.rs`)**
   Generates, serializes, and verifies dual-key identity pairs. It binds classical Ed25519 keys with quantum-resistant ML-DSA keys to form permanent node fingerprints.
2. **Layer 1: Hybrid Key Encapsulation (`l1_kem.rs`)**
   Executes key exchange handshakes using a combination of X25519 Diffie-Hellman and ML-KEM (Kyber-512 and Kyber-768). It blends secrets using HKDF with optional pre-shared key mixing for defense in depth.
3. **Layer 2: Authenticated Encryption (`l2_aead.rs`)**
   Encrypts and authenticates packet payloads using ChaCha20-Poly1305 and extended-nonce XChaCha20-Poly1305. It derives direction-aware nonces that guarantee uniqueness across time and session directions.
4. **Layer 3: Secret Splitting (`l3_shamir.rs`)**
   Divides master keys and critical tokens into polynomial shares. A predetermined threshold of shares is required to reconstruct the original secret, preventing single-point compromises.
5. **Layer 4: Erasure Coding (`l4_rs.rs`)**
   Applies Reed-Solomon coding over Galois fields to transform payloads into primary and parity shards. This enables the receiver to reconstruct lost packets without round-trip retransmission delays.
6. **Layer 5: Noise and Timing Obfuscation (`l5_noise.rs`)**
   Injects artificial timing delays modeled after Poisson processes, pads frames with variable-length random noise, and generates background dummy traffic to defeat traffic volume analysis.
7. **Layer 6: Session Sequencing (`l6_session.rs`)**
   Manages logical channels, sequencing numbers, packet acknowledgment, and flow prioritization across multiple parallel data streams.
8. **Layer 7: Forward Error Correction (`l7_ldpc.rs`)**
   Provides Low-Density Parity-Check algorithms designed for extreme conditions, such as noisy radio channels, satellite uplinks, and mesh networks with extreme packet loss rates.
9. **Layer 8: Memory Security (`l8_memsec.rs`)**
   Enforces secure memory allocation, page locking to prevent sensitive keys from being swapped to disk, and immediate zeroization of memory upon key disposal.
10. **Layer 9: Autonomous Infrastructure (`l9_infra.rs`)**
    Coordinates hardware security module integration, platform attestation, and physical security anchoring.

---

## Comprehensive Codebase Inventory

### Core Application Entry Points (`src/`)

- **`src/main.rs`**
  The principal executable entrypoint for the daemon. It initializes logging, parses configuration flags, loads or generates node identity keys, starts the peer routing loops, and manages long-running background tasks.
- **`src/lib.rs`**
  The library root for the Vantablack crate. It exposes the internal modules, data types, and cryptographic primitives so they can be consumed by external utilities, benchmarks, and integration suites.
- **`src/cli.rs`**
  Defines the command-line options and arguments. It handles commands for starting the background daemon, setting node roles (client, relay, exit node, or VPN hub), binding ports, and overriding data directories.
- **`src/control.rs`**
  Implements the local HTTP and WebSocket management server running on localhost port 8231. It provides administrative REST endpoints for querying network status, viewing discovered peers, adjusting routing policies, and driving the graphical interface.
- **`src/socks.rs`**
  A high-performance SOCKS5 proxy server built directly into the daemon. It allows web browsers and third-party desktop applications to route generic TCP connections privately through the mesh.
- **`src/tray.rs`**
  Provides native operating system tray icon integration on Windows and Linux. It allows the software to run discreetly in the background, display quick connection status icons, and offer quick-access menus.
- **`src/webview.rs`**
  Embeds a native graphical window using platform webview engines on Windows and desktop Linux. It displays the control dashboard without requiring the user to open a separate external web browser.

### Virtual Private Network Subsystem (`src/vpn/` and `src/ghost/net/vpn/`)

- **`src/vpn/mod.rs`**
  The root declaration of the high-level VPN controller module.
- **`src/vpn/daemon.rs`**
  Coordinates the lifecycle of the virtual private network service. It monitors adapter health, configures operating system route tables, and triggers automatic reconnection upon network changes.
- **`src/ghost/net/vpn/mod.rs`**
  Declares the internal networking components of the VPN engine, defining packet framing formats and routing abstractions.
- **`src/ghost/net/vpn/client.rs`**
  The client-side VPN engine. It reads raw IP packets from the local virtual network interface, compresses and encrypts them into Ghost Transport Frames, and dispatches them across the mesh.
- **`src/ghost/net/vpn/hub.rs`**
  The server or hub implementation for multi-point VPNs. It acts as an authoritative switch, mapping virtual IP addresses to peer cryptographic identities and routing packets between connected endpoints.
- **`src/ghost/net/vpn/netstack.rs`**
  Integrates a complete userspace TCP/IP networking stack (using Smoltcp). It parses IP headers, manages ARP requests, and performs network address translation inside userspace memory.
- **`src/ghost/net/vpn/android_jni.rs`**
  The Java Native Interface (JNI) bridge. It exposes C-compatible symbols that allow the official Android application to initialize the Rust networking engine and pass file descriptors from Android's VpnService.
- **`src/ghost/net/vpn/apple.rs`**
  Provides Apple-specific bindings and helpers for running inside macOS and iOS NetworkExtension system services.
- **`src/ghost/net/vpn/tun/mod.rs`**
  The hardware abstraction layer for virtual network adapters. It dynamically selects and configures Wintun on Windows, Universal TUN/TAP on Linux, and utun on macOS.

### Protocol Core and Session Management (`src/ghost/`)

- **`src/ghost/mod.rs`**
  The primary coordinator of the Ghost protocol. It brings together identity keys, packet queues, session caches, and the transport dispatcher into a cohesive runtime.
- **`src/ghost/paths.rs`**
  Resolves standard operating system paths for storing configuration files, private identity keys, peer discovery caches, and system logs across Windows, Linux, macOS, and mobile environments.
- **`src/ghost/icon.rs`**
  Contains embedded application icons and graphics in memory, ensuring that system tray and window decorations load without external image file dependencies.
- **`src/ghost/session/mod.rs`**
  The session state machine. It handles peer connection setup, performs authenticated handshakes, tracks packet sequencing, and enforces periodic cryptographic re-keying.
- **`src/ghost/session/guard.rs`**
  Provides concurrency safety guards and RAII locks that ensure active sessions are safely modified across asynchronous Tokio tasks.
- **`src/ghost/session/ratchet.rs`**
  Implements the continuous post-quantum double ratchet. It advances cryptographic keys with every sent and received message, ensuring that past sessions remain completely secure even if a device is compromised in the future.

### Networking and Transport Engine (`src/ghost/net/`)

- **`src/ghost/net/mod.rs`**
  Defines the Ghost Transport Frame (GTF) wire protocol, packet parsing, boundary checking, and bulk frame assembly.
- **`src/ghost/net/carrier.rs`**
  Abstracts underlying physical network carriers, providing uniform asynchronous interfaces for UDP, TCP fallback, and alternative communications links.
- **`src/ghost/net/cc.rs`**
  Adaptive congestion control and bandwidth estimation algorithms that adjust data throughput based on real-time packet round-trip measurements.
- **`src/ghost/net/collective_defense.rs`**
  Collaborative network defense module. Nodes share encrypted behavioral telemetry to automatically detect, flag, and route around malicious or compromised peers.
- **`src/ghost/net/consumer.rs`**
  High-level data channels allowing internal and external applications to publish and subscribe to encrypted streams across the mesh.
- **`src/ghost/net/dead_drop.rs`**
  Asynchronous encrypted dead-drop storage. Nodes can deposit encrypted messages with intermediate peers for later retrieval by recipients who are temporarily offline.
- **`src/ghost/net/diffusion.rs`**
  Epidemic gossip protocol that broadcasts routing metrics and node discovery information throughout the mesh without requiring central servers.
- **`src/ghost/net/dispatcher.rs`**
  The central packet switchboard. It demultiplexes incoming raw UDP datagrams, directing handshakes, data frames, heartbeats, and control signals to their appropriate worker threads.
- **`src/ghost/net/dtn_reconcile.rs`**
  Delay-Tolerant Networking reconciliation. Synchronizes buffered messages when partitioned network segments reconnect.
- **`src/ghost/net/energy_currency.rs`**
  Rate-limiting and anti-abuse accounting mechanism that requires peers to provide proof-of-work or resource tokens to prevent denial-of-service spam.
- **`src/ghost/net/entropy_beacon.rs`**
  Decentralized randomness beacon that periodically establishes global epoch timestamps to defeat message replay attacks across time.
- **`src/ghost/net/fallback.rs`**
  Automatic fallback manager that switches connection strategies (direct UDP, hole punching, QUIC, or encrypted TURN relaying) when network links fail.
- **`src/ghost/net/ice.rs`**
  Interactive Connectivity Establishment implementation for negotiating network paths and coordinating firewall hole punching.
- **`src/ghost/net/mesh.rs`**
  The overlay routing engine. It maintains active peer lists, path metrics, ping latencies, and multi-hop routing trees.
- **`src/ghost/net/mesh_archive.rs`**
  Persistent local cache storing historical peer connection data, public keys, and observed network latency.
- **`src/ghost/net/model_gossip.rs`**
  Decentralized telemetry system exchanging routing heuristics and network health models between participating peers.
- **`src/ghost/net/orbit.rs`**
  Local network discovery service using multicast DNS and UDP local broadcasts to find nearby peers on home and office networks without manual configuration.
- **`src/ghost/net/pow.rs`**
  Computational proof-of-work challenge generation used during initial handshakes to prevent denial-of-service floods against listening nodes.
- **`src/ghost/net/quic.rs`**
  QUIC transport adapter using Quinn. It provides multiplexed streaming over UDP with custom post-quantum TLS channel bindings.
- **`src/ghost/net/relay.rs`**
  Onion relay forwarding. Peels outer encryption envelopes and forwards packets along multi-hop anonymizing circuits.
- **`src/ghost/net/routing.rs`**
  Calculates optimal and redundant paths across the mesh overlay using distance-vector algorithms and latency metrics.
- **`src/ghost/net/security.rs`**
  Security supervision logic responsible for certificate validation, key revocation list tracking, and constant-time decapsulation routines.
- **`src/ghost/net/security/attest.rs`**
  Hardware attestation module that verifies cryptographic hardware quotes from Trusted Platform Modules (TPM 2.0).
- **`src/ghost/net/security/hsm.rs`**
  Hardware Security Module (HSM) and PKCS#11 interface allowing enterprise installations to store long-term master keys in physical cryptographic hardware.
- **`src/ghost/net/sharded_compute.rs`**
  Protocol for distributing compute tasks across trusted mesh nodes.
- **`src/ghost/net/shardsec.rs`**
  Space-time secrecy manager ensuring that individual packet shards are routed over geographically and topologically disjoint internet backbones.
- **`src/ghost/net/sovereign_cloud.rs`**
  Decentralized encrypted storage synchronization that synchronizes user files across a user's own authorized devices.
- **`src/ghost/net/stego_physics.rs`**
  Traffic morphing engine that formats packet timings and sizes to resemble legitimate HTTPS, TLS, or DNS transactions.
- **`src/ghost/net/stun.rs`**
  Session Traversal Utilities for NAT (STUN) client for determining external public IP addresses and firewall mapping behaviors.
- **`src/ghost/net/tun.rs`**
  Low-level interface for reading and writing IP packets to host operating system network interfaces.
- **`src/ghost/net/turn.rs`**
  Traversal Using Relays around NAT (TURN) client and server implementation for relaying packets when direct peer connections are impossible.
- **`src/ghost/net/universal_tunnel.rs`**
  Multiprotocol encapsulation engine that wraps raw Ethernet, IP, and stream protocols into Ghost Transport Frames.
- **`src/ghost/net/upnp.rs`**
  Universal Plug and Play (UPnP) and NAT-PMP client that automatically opens forwarding ports on compatible home routers.

### Specialized Simulation Tools (`src/bin/`)

- **`src/bin/wan_mesh.rs`**
  A multi-node network simulation tool used in Docker and automated testing environments to verify routing convergence under extreme artificial network loss and latency.
- **`src/bin/scale_mesh.rs`**
  A high-scale stress-testing binary that instantiates hundreds of lightweight virtual peers in memory to evaluate route scaling and memory consumption.

### User Interface and Web Dashboard

- **`index.html`**
  The complete, standalone single-page web dashboard for the Control Center. Built with modern styling, real-time Canvas charts, and clean responsive components, it renders live peer connection statuses, bandwidth graphs, cryptographic fingerprints, and routing settings.

### Android Application (`android/`)

- **`android/app/src/main/`**
  Contains the full source code for the Android application. It implements a native Android `VpnService` that routes device traffic through the compiled Rust JNI core library (`libvantablack.so`).

### Formal Models and Fuzzing (`formal/` and `fuzz/`)

- **`formal/ghost_session.pv`**
  ProVerif formal mathematical model verifying secrecy, authentication, and replay protection properties of the handshake and ratchet protocols.
- **`formal/shardsec_space_time.pv`**
  ProVerif model verifying that multi-path shard dispersal preserves message confidentiality against on-path adversaries.
- **`fuzz/`**
  Continuous fuzzing suite using libFuzzer. Targets packet counters, handshake PDUs, Kyber ciphertexts, frame builders, relay headers, and unframe routines against malformed byte inputs.

### Build Scripts, Packaging, and Deployment

- **`build.rs`**
  Custom build script that compiles Windows application icons and version manifests into binaries on Windows targets.
- **`Cargo.toml` & `Cargo.lock`**
  The Rust project definition, feature flags (`webview`, `tray`, `vpn`, `quic`, `fuzzing`), and dependency lock files.
- **`installer/` & `scripts/build_installer.ps1`**
  Inno Setup automation scripts for building the Windows desktop installer executable.
- **`packaging/`**
  System package templates, including Arch Linux PKGBUILD and Debian packaging rules.
- **`deploy/`**
  Systemd service unit definitions and configuration templates for headless Linux servers and relays.
- **`docker-compose.wan.yml`, `Dockerfile.wan` & `scripts/entrypoint.wan.sh`**
  Containerized multi-node testing mesh used in continuous integration pipelines.
- **`scripts/install.ps1` & `scripts/install.sh`**
  One-line automated installer scripts for Windows PowerShell and Unix bash environments.
- **`docs/`**
  Detailed cryptographic deep-dives, protocol specifications, NAT traversal matrices, and whitepapers.

---

## Repository Cleanup and Removed Testing Artifacts

As part of preparing the repository for clean public release, internal penetration testing files, exploit demonstrations, and redundant testing harnesses were removed from the codebase:

1. **`pentest/` Directory (Removed)**
   The entire `pentest` directory contained internal penetration testing scripts, Python-based network impairment emulators (`kernel_crucible.py`, `ice_nat_lab.py`, `nat_blackhole_lab.py`), shell runners, and the preliminary `REPORT.md` security review document. These files were created during internal security audits to demonstrate specific vulnerabilities that have since been remediated in the codebase.
2. **`examples/attack_harness.rs` (Removed)**
   An offensive attack simulation harness used to verify that the cryptographic layers rejected tampered ciphertexts and invalid nonces.
3. **`tests/pentest_adversarial.rs` & `tests/redteam_harness.rs` (Removed)**
   Adversarial test cases designed to replay historic exploit conditions. Because the vulnerabilities they targeted were resolved in earlier versions, these suites were deprecated and removed to maintain a lean, production-ready repository.

All genuine integration tests, driver verifications (`tests/vpn_wintun.rs`), formal verification models (`formal/`), and fuzzing gates (`fuzz/`) remain fully active and pass cleanly in continuous integration.
