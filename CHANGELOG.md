# Changelog

All notable changes to the Vantablack project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.5.0] - 2026-11-22 - Android Parity, Divergent Sharding, Self-Healing Watchdog, Anti-Abuse, Vouchers & Multi-NAT E2E

- **Android & Mobile Parity (`src/ghost/net/vpn/android_jni.rs`, `android/`):** Upgraded JNI tunnel framing to GTF v2 (`build_gtf_v2_frame`, `V2FrameMeta`, `FLAG_V2`), `parse_packet_counter_u64`, STUN/ICE demux, and `BLND!` DERP relay fallback; added `vb-net://` / `vb://` QR invite scan/import, `GHOST_RENDEZVOUS_URL` support, and live connection path / RTT / handover telemetry in `MainActivity.kt`.
- **Divergent Sharding, Watchdog & Anti-Abuse (`src/main.rs`, `src/ghost/net/{fallback,mesh,relay}.rs`, `tests/wan_resilience_e2e.rs`):** Added `GHOST_DIVERGENT_SHARDS=1` `BLND!` multi-carrier RS sharding in `send3_adaptive`, self-healing network-change & dead-peer/TUN watchdog, and `WanRateLimiter` per-IP token bucket + stateless handshake cookies under load.
- **Guest Exit Vouchers (`src/control.rs`, `assets/wan_dashboard.html`, `tests/control_center_api.rs`):** Added PIN-protected `POST /api/exit/voucher` (`ExitCapability::issue`) and Guest Exit Voucher generator UI.
- **Multi-NAT E2E Harness (`deploy/docker-compose.nat-e2e.yml`, `scripts/wan_nat_e2e.sh`, `tests/multi_nat_e2e.rs`):** Added reproducible Cone/Symmetric/Relay Docker Compose topology and 3-test multi-NAT & multi-hop onion E2E suite.

---

## [1.4.0] - 2026-11-21 - End-to-End WAN Discovery, Live Telemetry & Invite Wiring

- **Blind WAN Discovery & Tier-1 Cache Wiring (`src/main.rs`):** Wired `LocalPeerCache::{load_v2, save_v2}` (`peers.bin` with legacy `peers.cache` fallback), `BlindMailboxClient` (`GHOST_RENDEZVOUS_URL`, preserving `http_bootstrap` fallback only when unset), and signed `GHOST_PEX2____` (`PeerDescriptorV2`) gossip alongside backward-compatible `GHOST_PEX_____` v1 frames, installing peer `IceOffer`s into `NatHolePuncher` and `CAP_RELAY` peers into `Fallback`.
- **Live WAN Telemetry & `vb://2.` / `vb-net://` Invites (`src/ghost/net/mesh.rs`, `src/control.rs`, `assets/wan_dashboard.html`):** Connected `wan_telemetry_snapshot()` and per-peer `PeerTopologyTelemetry` (`public_addr`, `nat_type`, `stun_ok`, `upnp_ok`, `relay_count`, `relayed_peer_count`, `rtt_ms`, `transport`, `via_relay_fp`) into `GET /api/topology` and `GET /api/status`; added PIN-protected `GET /api/invite`, `vb://2.` / `vb-net://` support in `POST /api/peers/add`, and a "Copy Signed `vb://` Invite" button in the Pairing Studio.
- **Full Cross-Subsystem E2E Tests (`tests/wan_full_e2e.rs`):** Added end-to-end integration tests covering blind-mailbox publish/fetch with zero plaintext leakage on the wire, `LocalPeerCache` v2 roundtrip & Tier-1 boot, live `/api/topology` telemetry, and `GET /api/invite` + `POST /api/peers/add` pairing.

---

## [1.5.0] - 2026-11-22 - Android Parity, Divergent Sharding, Self-Healing Watchdog, Anti-Abuse, Vouchers & Multi-NAT E2E

- **Android & Mobile Parity (`src/ghost/net/vpn/android_jni.rs`, `android/`):** Upgraded JNI tunnel framing to GTF v2 (`build_gtf_v2_frame`, `V2FrameMeta`, `FLAG_V2`), `parse_packet_counter_u64`, STUN/ICE demux, and `BLND!` DERP relay fallback; added `vb-net://` / `vb://` QR invite scan/import, `GHOST_RENDEZVOUS_URL` support, and live connection path / RTT / handover telemetry in `MainActivity.kt`.
- **Divergent Sharding, Watchdog & Anti-Abuse (`src/main.rs`, `src/ghost/net/{fallback,mesh,relay}.rs`, `tests/wan_resilience_e2e.rs`):** Added `GHOST_DIVERGENT_SHARDS=1` `BLND!` multi-carrier RS sharding in `send3_adaptive`, self-healing network-change & dead-peer/TUN watchdog, and `WanRateLimiter` per-IP token bucket + stateless handshake cookies under load.
- **Guest Exit Vouchers (`src/control.rs`, `assets/wan_dashboard.html`, `tests/control_center_api.rs`):** Added PIN-protected `POST /api/exit/voucher` (`ExitCapability::issue`) and Guest Exit Voucher generator UI.
- **Multi-NAT E2E Harness (`deploy/docker-compose.nat-e2e.yml`, `scripts/wan_nat_e2e.sh`, `tests/multi_nat_e2e.rs`):** Added reproducible Cone/Symmetric/Relay Docker Compose topology and 3-test multi-NAT & multi-hop onion E2E suite.

---

## [1.3.0] - 2026-11-21 - Single-Socket WAN Transport, Relay Discovery & Safe Exits

- **Single-Socket STUN/ICE Mux (`src/ghost/net/stun.rs`, `src/ghost/net/ice.rs`, `src/ghost/net/mesh.rs`, `src/main.rs`):** Eliminated split `nat_socket`; STUN discovery, UPnP/NAT-PMP mapping, ICE checks, ~25s NAT keepalives, and GTF frames now share `nc.socket` via bounded `broadcast` STUN demuxing (`is_stun_packet`, `gather_reflexive_mux`), with `NatHolePuncher::nominated_addr` routing and initiating handshakes on ICE nomination.
- **Decoupled Relay Discovery & `PORT` TLV (`src/ghost/net/fallback.rs`, `src/main.rs`):** Added `known_relays` and `Fallback::{record_relay, relay_candidates}` tracked on every node regardless of `GHOST_RELAY`, plus backward-compatible `PORT` (`BEACON_SECTION_PORT`) TLV for accurate `(src.ip(), advertised_mesh_port)` peer addressing.
- **Primary-Only RS Shard Routing & NAT Pool (`src/ghost/net/mesh.rs`, `src/main.rs`):** Fixed `send3_adaptive` and added `AdaptiveShardRouter::assign_shards_to_primary` so all 3 Reed-Solomon shards target `primary_fp`; added async `DEFAULT_STUN_SERVERS` pool (`resolve_stun_pool`), `NatType` classification, and `WanTelemetrySnapshot`.
- **Unified ML-KEM-768 Handshakes, Safe Exit Defaults & `--relay-only` (`src/main.rs`, `src/cli.rs`, `tests/wan_single_socket.rs`):** Replaced inline ML-KEM-512 `build_handshake_pdu` with `initiate_handshake`, made `resolve_trusted_exits` fail-closed in `GHOST_MODE=public` unless `GHOST_EXIT=1`/`GHOST_EXIT_ALLOWLIST` is set, added `--relay-only` CLI mode, and added `tests/wan_single_socket.rs`.

---

## [1.5.0] - 2026-11-22 - Android Parity, Divergent Sharding, Self-Healing Watchdog, Anti-Abuse, Vouchers & Multi-NAT E2E

- **Android & Mobile Parity (`src/ghost/net/vpn/android_jni.rs`, `android/`):** Upgraded JNI tunnel framing to GTF v2 (`build_gtf_v2_frame`, `V2FrameMeta`, `FLAG_V2`), `parse_packet_counter_u64`, STUN/ICE demux, and `BLND!` DERP relay fallback; added `vb-net://` / `vb://` QR invite scan/import, `GHOST_RENDEZVOUS_URL` support, and live connection path / RTT / handover telemetry in `MainActivity.kt`.
- **Divergent Sharding, Watchdog & Anti-Abuse (`src/main.rs`, `src/ghost/net/{fallback,mesh,relay}.rs`, `tests/wan_resilience_e2e.rs`):** Added `GHOST_DIVERGENT_SHARDS=1` `BLND!` multi-carrier RS sharding in `send3_adaptive`, self-healing network-change & dead-peer/TUN watchdog, and `WanRateLimiter` per-IP token bucket + stateless handshake cookies under load.
- **Guest Exit Vouchers (`src/control.rs`, `assets/wan_dashboard.html`, `tests/control_center_api.rs`):** Added PIN-protected `POST /api/exit/voucher` (`ExitCapability::issue`) and Guest Exit Voucher generator UI.
- **Multi-NAT E2E Harness (`deploy/docker-compose.nat-e2e.yml`, `scripts/wan_nat_e2e.sh`, `tests/multi_nat_e2e.rs`):** Added reproducible Cone/Symmetric/Relay Docker Compose topology and 3-test multi-NAT & multi-hop onion E2E suite.

---

## [1.2.0] - 2026-11-21 - Control Center API v2 & Interactive Mesh View UI

- **Control Center REST API v2 (`src/control.rs`):** Added PIN-protected `GET /api/topology` (with `TopologySelfHint` / `TopologyPeerHint` snapshot structs), `GET /proxy.pac`, `vb://` URI decoding & signature verification in `POST /api/peers/add`, `POST /api/peers/disconnect` (session/carrier teardown with `GHOST_BYE_MAGIC`), `/api/mesh/scan` & `/api/mesh/config` aliases, and dynamic `version`, `multicast_addr` (`239.255.0.1:2270`), and `socks_ports` in `GET /api/status`.
- **Interactive Mesh View & Dashboard Overhaul (`assets/wan_dashboard.html`):** Added zero-CDN inline SVG Ego-Graph (`tab-mesh`) with Ring 1 LAN/WAN & Ring 2 relayed arcs, toggleable Circuit Hop Overlay, `Ego Graph` / `Peer Table` switcher, filter chips, click-to-inspect Peer Drawer, WAN & NAT Readiness Pipeline card, Pairing Studio (`IP:Port` / `vb://`), Multi-Port SOCKS5 (`:1080`–`:1083`) + `/proxy.pac` copy + visual Split-Tunnel Bypass editor, Crypto/RS Pipeline Benchmark, styled in-app PIN Unlock Modal, and keyboard shortcuts (`1–5`, `Esc`).
- **Control Center Integration Tests (`tests/control_center_api.rs`):** Added tests covering `/api/topology`, `/proxy.pac`, `/api/mesh/{scan,config}` aliases, `vb://` URI verification, peer disconnect, and `GHOST_PIN` enforcement.

---

## [1.5.0] - 2026-11-22 - Android Parity, Divergent Sharding, Self-Healing Watchdog, Anti-Abuse, Vouchers & Multi-NAT E2E

- **Android & Mobile Parity (`src/ghost/net/vpn/android_jni.rs`, `android/`):** Upgraded JNI tunnel framing to GTF v2 (`build_gtf_v2_frame`, `V2FrameMeta`, `FLAG_V2`), `parse_packet_counter_u64`, STUN/ICE demux, and `BLND!` DERP relay fallback; added `vb-net://` / `vb://` QR invite scan/import, `GHOST_RENDEZVOUS_URL` support, and live connection path / RTT / handover telemetry in `MainActivity.kt`.
- **Divergent Sharding, Watchdog & Anti-Abuse (`src/main.rs`, `src/ghost/net/{fallback,mesh,relay}.rs`, `tests/wan_resilience_e2e.rs`):** Added `GHOST_DIVERGENT_SHARDS=1` `BLND!` multi-carrier RS sharding in `send3_adaptive`, self-healing network-change & dead-peer/TUN watchdog, and `WanRateLimiter` per-IP token bucket + stateless handshake cookies under load.
- **Guest Exit Vouchers (`src/control.rs`, `assets/wan_dashboard.html`, `tests/control_center_api.rs`):** Added PIN-protected `POST /api/exit/voucher` (`ExitCapability::issue`) and Guest Exit Voucher generator UI.
- **Multi-NAT E2E Harness (`deploy/docker-compose.nat-e2e.yml`, `scripts/wan_nat_e2e.sh`, `tests/multi_nat_e2e.rs`):** Added reproducible Cone/Symmetric/Relay Docker Compose topology and 3-test multi-NAT & multi-hop onion E2E suite.

---

## [1.1.0] - 2026-11-21 - Zero-Knowledge WAN Discovery v2 & Testbed Repairs

- **Random-Nonce Blind Rendezvous (`src/ghost/net/discovery.rs`):** Replaced static AEAD nonce in `BlindRendezvous` with fresh 12-byte `OsRng` nonces prepended to ciphertext, and added fixed-1024B chaff-padded `encrypt_blob`/`decrypt_blob` and `encrypt_descriptor_v2`/`decrypt_descriptor_v2`.
- **Signed PeerDescriptorV2 & Invite Links:** Added Ed25519-signed `PeerDescriptorV2` (`VBP2`), `vb://2.<b64>` and `NetworkInvite` (`vb-net://<b64>`) codecs, and `LocalPeerCache::{save_v2, load_v2}` (`VBPCACHE2`) with expiry and signature pruning while preserving v1 compatibility.
- **Blind Mailbox Client & Cloudflare Worker (`deploy/worker/blind_rendezvous.js`, `deploy/worker/wrangler.toml`):** Added `BlindMailboxClient` (`publish_descriptor`, `fetch_descriptors` with `epoch_hour - 1` rollover/fallback) and a zero-logging KV-backed Cloudflare Worker (1024B max payload, 900s TTL, 32-entry slot cap).
- **Deploy & Smoke-Testbed Repairs (`deploy/docker-compose*.yml`, `scripts/mesh_smoke_test.sh`, `scripts/smoke_test.sh`):** Fixed `docker/Dockerfile.wan` build paths, added headless `--relay-only` relay compose configuration, updated binary discovery (`ggn.exe`/`ggn`/`vantablack.exe`), and replaced stub smoke assertions with real container, socket, netem, and HTTP telemetry checks.

---

## [1.5.0] - 2026-11-22 - Android Parity, Divergent Sharding, Self-Healing Watchdog, Anti-Abuse, Vouchers & Multi-NAT E2E

- **Android & Mobile Parity (`src/ghost/net/vpn/android_jni.rs`, `android/`):** Upgraded JNI tunnel framing to GTF v2 (`build_gtf_v2_frame`, `V2FrameMeta`, `FLAG_V2`), `parse_packet_counter_u64`, STUN/ICE demux, and `BLND!` DERP relay fallback; added `vb-net://` / `vb://` QR invite scan/import, `GHOST_RENDEZVOUS_URL` support, and live connection path / RTT / handover telemetry in `MainActivity.kt`.
- **Divergent Sharding, Watchdog & Anti-Abuse (`src/main.rs`, `src/ghost/net/{fallback,mesh,relay}.rs`, `tests/wan_resilience_e2e.rs`):** Added `GHOST_DIVERGENT_SHARDS=1` `BLND!` multi-carrier RS sharding in `send3_adaptive`, self-healing network-change & dead-peer/TUN watchdog, and `WanRateLimiter` per-IP token bucket + stateless handshake cookies under load.
- **Guest Exit Vouchers (`src/control.rs`, `assets/wan_dashboard.html`, `tests/control_center_api.rs`):** Added PIN-protected `POST /api/exit/voucher` (`ExitCapability::issue`) and Guest Exit Voucher generator UI.
- **Multi-NAT E2E Harness (`deploy/docker-compose.nat-e2e.yml`, `scripts/wan_nat_e2e.sh`, `tests/multi_nat_e2e.rs`):** Added reproducible Cone/Symmetric/Relay Docker Compose topology and 3-test multi-NAT & multi-hop onion E2E suite.

---

## [1.0.0] - 2026-11-09 - Production Release: Formally Verified WAN Mesh

### 🛡️ Formal Verification & Mathematical Guarantees (Keller & ProVerif)
- **Keller SMT Verification Platform:** Verified over 2,500 functions and 1,290+ mathematical assertions across the entire workspace via Z3 SMT solving.
- **Zero SMT Counterexamples:** Resolved all 104 counterexample `FAIL` obligations (integer overflow, underflow, slice boundary violations, division/remainder hazards) across 23 core modules.
- **Symbolic Secrecy & Authentication (ProVerif 2.05):** Formally proved injective agreement, payload secrecy, and forward secrecy against active Dolev-Yao network adversaries (`formal/ghost_session.pv` and `formal/shardsec_space_time.pv`).
- **Absence of Panic Paths:** Hardened all live network packet ingest, PDU framing, and reassembly paths against untrusted payloads (elimination of unmodelled `.unwrap()` / `.expect()` panics in network streams).

### 🔒 Cryptography, Onion Routing & Penetration Fixes
- **PEN-2 Sphynx Shard Onion Nonce Security:** Resolved fixed-nonce keystream reuse in `SphinxShardOnion`. Every hop (Guard, Middle, Exit) now utilizes cryptographically fresh 96-bit ephemeral nonces directly within the 576-byte fixed-size onion frame.
- **GTFv2 High-Entropy Wire Framing:** Elimination of slack-padding null runs; pseudo-random stream filling ensures Shannon entropy $> 7.92\text{ bits/byte}$ across all payload sizes to prevent Deep Packet Inspection (DPI) fingerprinting.
- **Post-Quantum Hybrid Core:** Hybrid ML-KEM-768 + X25519 key encapsulation and ML-DSA-65 post-quantum identity signatures with constant-time SessionGuard (sliding-window anti-replay at 31+ Mpps).
- **Fast-Path Reed-Solomon Reassembly:** Monotone ring-buffer reassembly achieving zero-copy erasure reconstruction ($> 20\text{ GiB/s}$).

### 🌐 System Hardening & Code Hygiene
- **Control Center Origin Security:** Strict localhost binding (`127.0.0.1:2270`) and origin authentication eliminating CSRF and cross-origin DNS rebinding vectors.
- **Strict Lint Compliance:** 100% clean pass under `cargo clippy --all-targets -- -D warnings` across all features (`hardware-tpm`, `pkcs11`, `quic`, `sdr`, `qkd-tls`, `research`).
- **Comprehensive Test Suite:** 451 unit tests passing with zero regressions.
- **Turnkey Multi-Platform Release:** Automated builds for Windows (Inno Setup Installer), Linux (`.deb` + server binaries), macOS (Apple Silicon), and Android (APK).

---

## [1.5.0] - 2026-11-22 - Android Parity, Divergent Sharding, Self-Healing Watchdog, Anti-Abuse, Vouchers & Multi-NAT E2E

- **Android & Mobile Parity (`src/ghost/net/vpn/android_jni.rs`, `android/`):** Upgraded JNI tunnel framing to GTF v2 (`build_gtf_v2_frame`, `V2FrameMeta`, `FLAG_V2`), `parse_packet_counter_u64`, STUN/ICE demux, and `BLND!` DERP relay fallback; added `vb-net://` / `vb://` QR invite scan/import, `GHOST_RENDEZVOUS_URL` support, and live connection path / RTT / handover telemetry in `MainActivity.kt`.
- **Divergent Sharding, Watchdog & Anti-Abuse (`src/main.rs`, `src/ghost/net/{fallback,mesh,relay}.rs`, `tests/wan_resilience_e2e.rs`):** Added `GHOST_DIVERGENT_SHARDS=1` `BLND!` multi-carrier RS sharding in `send3_adaptive`, self-healing network-change & dead-peer/TUN watchdog, and `WanRateLimiter` per-IP token bucket + stateless handshake cookies under load.
- **Guest Exit Vouchers (`src/control.rs`, `assets/wan_dashboard.html`, `tests/control_center_api.rs`):** Added PIN-protected `POST /api/exit/voucher` (`ExitCapability::issue`) and Guest Exit Voucher generator UI.
- **Multi-NAT E2E Harness (`deploy/docker-compose.nat-e2e.yml`, `scripts/wan_nat_e2e.sh`, `tests/multi_nat_e2e.rs`):** Added reproducible Cone/Symmetric/Relay Docker Compose topology and 3-test multi-NAT & multi-hop onion E2E suite.

---

## [0.8.21] - 2026-11-07
- Security hardening sprints 1–4.
- Origin validation in local web control center.
- Coalescing data-plane optimizations.

---

## [1.5.0] - 2026-11-22 - Android Parity, Divergent Sharding, Self-Healing Watchdog, Anti-Abuse, Vouchers & Multi-NAT E2E

- **Android & Mobile Parity (`src/ghost/net/vpn/android_jni.rs`, `android/`):** Upgraded JNI tunnel framing to GTF v2 (`build_gtf_v2_frame`, `V2FrameMeta`, `FLAG_V2`), `parse_packet_counter_u64`, STUN/ICE demux, and `BLND!` DERP relay fallback; added `vb-net://` / `vb://` QR invite scan/import, `GHOST_RENDEZVOUS_URL` support, and live connection path / RTT / handover telemetry in `MainActivity.kt`.
- **Divergent Sharding, Watchdog & Anti-Abuse (`src/main.rs`, `src/ghost/net/{fallback,mesh,relay}.rs`, `tests/wan_resilience_e2e.rs`):** Added `GHOST_DIVERGENT_SHARDS=1` `BLND!` multi-carrier RS sharding in `send3_adaptive`, self-healing network-change & dead-peer/TUN watchdog, and `WanRateLimiter` per-IP token bucket + stateless handshake cookies under load.
- **Guest Exit Vouchers (`src/control.rs`, `assets/wan_dashboard.html`, `tests/control_center_api.rs`):** Added PIN-protected `POST /api/exit/voucher` (`ExitCapability::issue`) and Guest Exit Voucher generator UI.
- **Multi-NAT E2E Harness (`deploy/docker-compose.nat-e2e.yml`, `scripts/wan_nat_e2e.sh`, `tests/multi_nat_e2e.rs`):** Added reproducible Cone/Symmetric/Relay Docker Compose topology and 3-test multi-NAT & multi-hop onion E2E suite.

---

## [0.8.12] - 2026-10-18
- Initial hardened mesh baseline and Android foreground service integration.
