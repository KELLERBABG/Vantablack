# Changelog

All notable changes to the Vantablack project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2026-11-22 - The Everyday Layer: Drop, Expose, Party, Regimes, `.vb` Names & X-Ray

Implements the Tier-1 items of `DEV/v2_roadmap_ranked.md` plus five Tier-2 items,
with an item-by-item status (including what is deliberately deferred and why) in
[`DEV/V2_BUILD_STATUS.md`](DEV/V2_BUILD_STATUS.md). New code is `src/ghost/v2/`.

Evidence build: `target/debug/ggn.exe` SHA-256 `78e9dffdd7c0d6b9c61be6e4c7ebf177d527a4da0fb803b872823a3446f52c84`, built with `--features quic,reality-front,pq-tls` from HEAD `a94f2bddb5eea8e6c70ef3c6125710e621aa032a` plus this worktree.

- **HPEB multipath — `ggn hpeb` (`src/ghost/v2/hpeb.rs`):** Real per-path UDP binding feeding the existing AONT+RS(2,1) scheduler. Live run with a 32,000-byte payload: shard 0/2 left from `127.0.0.2:65368`, shard 1 from `127.0.0.3:65369`; the server recovered 32,000 bytes, reported two distinct sources, and both files hashed to `6cb8e2a8…8ea8`. A `--single-source` run made the server log `distinct_sources=1` and exit 1 with `all shards arrived from one source binding`. No second physical uplink was used for this host test; distinct loopback aliases exercised the real binding path.
- **HTTP/3 MASQUE — `ggn masque` (`src/ghost/v2/masque.rs`, features `quic`/`pq-tls`):** A real RFC 9114 endpoint on quinn: SETTINGS and control/QPACK streams, QPACK header decode (static table + Huffman) and encode, extended CONNECT (RFC 9220) with `:protocol=connect-udp` and `capsule-protocol: ?1`, RFC 9297 capsules and RFC 9221 datagrams. aioquic 1.9.0 observed QUICv1, ALPN h3, TLS_AES_256_GCM_SHA384, `:status 200`, capsule and datagram echoes. SPKI-pinned Chrome 157 loaded the HTTP/3 GET page. `pq-tls` selects aws-lc-rs, which negotiates `X25519MLKEM768` on the TLS front and QUIC. Certificate indistinguishability still needs the borrowed origin's private key; local ACK pacing remains kernel/quinn-owned.
- **REALITY front — `ggn reality` (`src/ghost/v2/front.rs`, feature `reality-front`):** A real rustls TLS 1.3 listener with a ClientHello knock on the SNI label and a byte-for-byte splice to a borrowed origin for everything else. Proven live with OpenSSL and headless Chrome: the decoy completed a genuine `example.com` TLS 1.3 handshake (`CN=example.com`, `X25519MLKEM768`, AES-256-GCM) while the knock terminated locally and carried HTTP, raw echo and an RFC 9297 capsule over TLS 1.3. The tunnel certificate is self-signed and its group is X25519; PQ tunnel identity and HTTP/3 MASQUE remain open.
- **GhostPortal — `ggn drop` (`src/ghost/v2/portal.rs`):** One file served to any browser with the key only in the URL fragment (`#k=…`), 4 MiB AES-256-GCM chunks with `prefix‖index` nonces, plaintext SHA-256 in the manifest, `--once`/TTL expiry, `no-store`/`no-referrer`/`nosniff`, and a recipient page that decrypts with WebCrypto and streams to disk through the File System Access API. Verified in a real browser: the served chunk decrypted to the original bytes and matched the manifest hash. The same page is also a **WebRTC DataChannel sender**: `/f/<id>/recv` is the receiving peer and `/f/<id>/signal/{sender,receiver}` carries SDP only. Proven with two separate headless Chrome processes: the drop server was stopped before the payload was sent, 5 000 000 bytes crossed the DataChannel, and both ends reported the manifest SHA-256.
- **`ggn expose` (`src/ghost/v2/expose.rs`):** Token-gated relay to exactly one local target (path or `X-VB-Expose` header, constant-time compare), same `404` for a wrong token and a wrong path, head forwarded once with the prefix stripped and the rest raw, so WebSocket/SSE work.
- **`ggn party` (`src/ghost/v2/party.rs`):** UDP bridge with `GPY1`-framed sequences, a 1024-sequence dedupe bitmap, a jitter buffer that skips gaps instead of waiting for them, and optional duplicate transmission.
- **Four regimes (`src/ghost/v2/regime.rs`):** `fast`/`shielded`/`ghost`/`vantablack` derive plane, hop class, SOCKS5 port, cover traffic and diversity requirement; strict regimes fail closed with a typed reason instead of silently degrading.
- **`.vb` DNS stub (`src/ghost/v2/vbdns.rs`):** `127.0.0.53` responder for `<name>.vb` → deterministic `fd7b::<NodeID>`, self-certifying hex labels, maintained reverse index, AAAA + PTR, `NXDOMAIN` inside the zone and `REFUSED` outside it.
- **Chronos-Splice (`src/ghost/v2/chronos.rs`):** Bounded ACK pacing that closes the `ARTT − TRTT` gap, with residual reporting and a bounded FIFO pacer (never sends early, counts what it drops).
- **REALITY / MASQUE / SRTP (`src/ghost/v2/reality.rs`):** HMAC knock bound to SNI + ClientHello random with a 60 s window, splice-on-any-unauthenticated-probe (no reject path), RFC 9297 capsule codec across all QUIC varint widths, and RTP/Opus-shaped framing with an inverse. No TLS/QUIC stack is added.
- **Boomerang home-exits, live (`src/ghost/v2/boomerang.rs`, `discovery.rs`, `socks.rs`, `main.rs`, `control.rs`):** A node with `GHOST_EXIT=1 GHOST_HOME_EXIT=1` advertises the distinct `CAP_HOME_EXIT` bit in its signed descriptor; verified descriptors populate a runtime candidate registry; `GET /api/v2/home-exit`, `POST /api/v2/home-exit/select` and `/clear` drive selection; and SOCKS5 pins the exit before any adaptive choice, failing closed (`0x05`) when the pinned exit has no session. The direct exit branch also accepts the client's explicit `STREAM!` CONNECT marker when simultaneous handshakes leave the initiator role, so the selected exit actually opens the tunnel. The proxy also assembles the full guard → middle → home onion when three peers are present: a middle relay now forwards a sealed layer unchanged instead of re-wrapping a header naming itself, and sealed layers carry an `ONS1` marker that a middle opens with its originator session key. Proven by a two-node direct run and a four-node loopback run (`GHOST_ADVERTISE_ADDR` lets each node bind a distinct loopback address) that returned `home-exit-live-path-ok` through both relays, with `GET /api/v2/home-exit` reporting the observed 3-hop route.
- **BTCr / Blind-Pass (`src/ghost/v2/btcr.rs`, `ggn btcr`, `/api/v2/btcr`):** Ristretto255 VOPRF with Chaum–Pedersen DLEQ, 81-byte bearer tickets verified as `N == k·M`, nullifier double-spend refusal, beneficiary-signed `btcr-receipt:v1` work receipts required for issuance, an atomic JSON wallet with union merge, and `ggn btcr --demo` / `POST /api/v2/btcr/{issue,spend}`. Issuance without a configured beneficiary refuses with `400`.
- **Continuum Ladder + GhostCell-Nano (`src/ghost/v2/continuum.rs`, `ggn ladder`, `/api/v2/ladder`):** Fixed 180-byte XChaCha20-Poly1305 cells with deterministic `cell_id‖seq` nonces, a six-rung ladder that names and refuses unavailable rungs (`stealth_web`, `lora_kiss`, non-`sdr` `abos_hf`), a content-addressed mule DTN store with Merkle roots and idempotent CRDT union sync, real UDP send/receive, and `ggn ladder --demo`.
- **RACS / LEDBAT++ (`src/ghost/v2/racs.rs`, `ggn racs`, `/api/v2/racs`):** Four-state burst-shaping PFSM with steady/bursty/Pareto templates, a scavenger whose real-vs-background decision is measured (mean 0.028 µs, p99 0.1 µs over 10 000 preemptions), a 60 ms-target LEDBAT++ controller, and a live `GHOST_RACS=1` gate that pauses the existing cover task for 25 ms after SOCKS traffic.
- **Build hygiene:** two pre-existing `-D warnings` lints fixed (`l0_identity.rs`, `socks.rs`) so the CI lint gate is clean on the current toolchain; `aes-gcm` is now a direct dependency (already in the lockfile via `wry`) for browser-native decryption.
- **HPEB (`src/ghost/v2/hpeb.rs`):** AONT + RS(2,1) across pinned interfaces, recovery from any two shards, a proven no-plaintext-in-one-shard property, and cooldown-bounded handover state.
- **X-Ray / truth ledger (`src/ghost/v2/xray.rs`, `api.rs`, dashboard):** ISP/guard/website views plus invariants with verified/failed/**unknown** states; anonymity is claimed only by `vantablack` and only above 200 public relays, and a failing check changes the headline. Dashboard tab (keyboard `6`) fed by `GET /api/v2/xray`, `/api/v2/regime`, `/api/v2/capabilities`; `POST /api/v2/regime` persists the choice and reports that a restart is needed.
- **Continuum dashboard tab (`assets/wan_dashboard.html`, keyboard `5`):** Live cards for home exits (advertisement, candidates, pin/clear actions, last observed circuit route), BTCr credits (issuer, process counters, wallet), the six-rung ladder with per-rung refusal reasons and mule Merkle root, and RACS state (gate, machine state, real/cover packets, preemption samples or “no live sample yet”). Every value comes from `/api/v2/{home-exit,btcr,ladder,racs}`; API refusals are rendered verbatim, and `/api/v2/capabilities` lists the capabilities that are still deferred.
- **Fleet subkeys (`src/ghost/v2/fleet.rs`):** Offline Ed25519 fleet root, per-device certificates with expiry, 85-byte gossipped revocations merged monotonically, forged entries rejected and counted.
- **Regime wiring (`src/main.rs`, `src/socks.rs`, `src/control.rs`):** A configured `GHOST_V2_REGIME` or persisted regime now replaces the four fixed SOCKS5 ports at daemon startup: one listener on the regime's canonical port with its hop policy, and cover traffic enabled for `ghost`/`vantablack`. Observed: `fast` bound only `:1081` and `GET /api/v2/regime` reported `fast:1081, shielded:1082, ghost:1083, vantablack:1083`.
- **`ggn party` peer listener (`src/ghost/v2/party.rs`, `src/cli.rs`):** The peer-facing socket now binds a known `--peer-listen` address (default game port + 1) instead of an ephemeral port, and incoming frames go to the local game endpoint learned from the game socket rather than back to the sender. Observed with two bridge processes: B's game socket received A's `hello-from-A`.
- **Fleet CLI and `vb-fleet://` onboarding (`src/ghost/v2/fleet.rs`, `src/cli.rs`):** `ggn fleet --init|--issue|--admit|--revoke` issues certificates, prints the `vb-fleet://` QR payload, verifies admission, and prints the 85-byte revocation entry. Observed: issue → admit → revoke → admit refused as revoked.
- **Verification:** 574 library tests pass (98 of them in `v2`), `cargo clippy --all-targets --no-default-features -- -D warnings` is clean, the headless binary builds, and the drop, expose, party, `.vb` DNS, regime, home-exit, BTCr, ladder, RACS and fleet surfaces were exercised against running nodes or the CLI.

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
