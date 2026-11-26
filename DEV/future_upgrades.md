# Future upgrades — what could be added next

**Audience:** contributors and operators planning the next round of work on Vantablack.
**Status of this file:** a planning outline, not a promise. Items below are *possible*
future directions, some of them already hinted at in `ROADMAP.md`, some not. None of them
is scheduled, and several of them touch vendored third-party code whose future is
outside this repository's control.

This file exists so that the repository's "current state" documents (`README.md`,
`docs/SPECIFICATIONS.md`, `docs/OPERATOR_GUIDE.md`, `formal/README.md`) can stay
descriptive of what *is*, while this file holds what *might be*. When an item here
becomes real, move its facts out of here and into the descriptive documents, and leave
a one-line note behind.

---

## 1. Things the current docs already point at

These are not new ideas — they are the open items the existing markdown already
mentions, restated here so they don't get lost. Each one is a candidate for a future
commit that moves it from "documented as open" to "done".

#### 1.1 Packaging and installers
- Per-user Windows installer (`installer/ggn.iss` + `scripts/build_installer.ps1`), Debian `.deb` packaging (`[package.metadata.deb]` in `Cargo.toml` + `packaging/debian/`), and Android APK CI builds (`.github/workflows/release.yml`) are already in-tree.
- Still open from `ROADMAP.md`: Windows Service registration (`windows-service` crate), Authenticode / macOS notarization code-signing, `.rpm` packaging, and Apple Silicon `.dmg` installer.

### 1.2 Self-healing watchdog
- `ROADMAP.md` calls for interface-stall detection and automatic TUN recycling with a
  sub-3-second re-handshake target.
- The current daemon does not implement that; a dead interface is whatever the OS does.

### 1.3 Mobile pairing
- `ROADMAP.md` calls for a 1-click QR pairing flow in the desktop control center.
- The control center already renders a `ggn://pair` QR (that is present today); the
  "1-click" framing in the roadmap is the upgrade: a pairing flow that does not require
  an operator to copy-paste a URI by hand.

### 1.4 Documentation portal and airgap manual
- `ROADMAP.md` calls for a live docs portal and an `docs/AIRGAP_DEPLOYMENT.md`.
- `scripts/build_docs_portal.py` builds `docs/index.html`; `docs/AIRGAP_DEPLOYMENT.md` does not yet exist in-tree.

### 1.5 Research-primitive feature gate
- Landed: the 15 unreachable `ghost::net` modules are gated behind `--features research` (off by default) and verified in CI; see `docs/DORMANT_MODULES.md`.

### 1.6 Formal models
- `formal/README.md` states exactly what the two ProVerif models establish and exactly
  what they do not. The "what is not established" list is the honest inventory of future
  modeling work, if anyone wants to do it. Notably unmodelled: the double ratchet, forward
  secrecy and post-compromise security, key-compromise impersonation, relay/onion/multi-hop
  behaviour, and the wire format.

---

## 2. Vendored third-party code: QEL and ABOS

Vantablack v0.8.11 vendors two external projects:

- **QEL** — the `Quantum Entanglement Link/` directory, a stripped-back snapshot of
  `https://github.com/KELLERBABG/QEL`, used by `src/ghost/layers/l10_qel.rs` as the
  `sim` backend for the L10 quantum anchor.
- **ABOS** — the `abos/` workspace, a copy of `https://github.com/KELLERBABG/ABOS`,
  used (behind the `sdr` cargo feature) by `src/ghost/net/sdr_bridge.rs` as the skywave
  physical layer.

Both are **vendored**, not forked with a live upstream link in-tree, and both are known
to be out of date with their upstream repositories. This section records what that means
for anyone proposing an upgrade.

### 2.1 QEL (`Quantum Entanglement Link/`)

**What v0.8.11 actually uses from it.** The L10 simulated backend talks to the vendored
tree as a Python package: it runs `python -m quantumnet ghost-net ...` and
`python -m quantumnet qkd-derive ...` with `Quantum Entanglement Link/` as the CWD and
`Quantum Entanglement Link/src` prepended to `PYTHONPATH`, and it probes availability by
importing `quantumnet`. That is the entire interface v0.8.11 depends on.

**Measured state of the vendored tree vs upstream.** The vendored tree is a **subset** of
the upstream repo at the time it was dropped in. Upstream ships a much larger surface
(additional protocol/encoding modules, a larger `src/quantumnet/` layout, a larger tests/
tree, and documentation files) that the vendored snapshot does not contain. The vendored
tree keeps the pieces the daemon routes through (`src/quantumnet/{core,protocols,topology}`,
`cli.py`, and the 122-test `tests/` suite) and omits the rest.

**How it loads out-of-the-box.** Because `SimulatedQel` prepends `Quantum Entanglement Link/src`
to `PYTHONPATH` when spawning Python, `import quantumnet` and the CLI subcommands work
directly against the vendored tree whenever Python + `numpy` are installed, without requiring
a separate `pip install -e "Quantum Entanglement Link"`.

**What an upgrade would touch.** Bringing the vendored QEL tree back toward upstream is not a
Vantablack-only change: it is updating vendored third-party code. The parts Vantablack cares
about are narrow (the `quantumnet` package entrypoint, the two CLI commands the anchor runs,
`pyproject.toml`/`poetry.lock`, and whatever the probe's `import quantumnet` resolves). An
upgrade should be checked against at least:

1. Does `import quantumnet` succeed from the vendored tree the way the probe expects?
2. Do `python -m quantumnet ghost-net --json-output` and `python -m quantumnet qkd-derive --json-output`
   still produce the JSON contract `l10_qel.rs` parses (`QuantumRouteResult`)?
3. Does the `qkd-sim/1/...` label contract still round-trip the way `l10_qel.rs::parse_label`
   and the round-trip test expect?

If upstream QEL changed any of those, the Vantablack side (the JSON parsing, the label format,
the seed/fidelity contract, the degraded-logging prose) may also need an update. The current
code documents the simulated-backend limitation honestly in `l10_qel.rs` and in
`docs/SPECIFICATIONS.md` §2.4 (the simulated key is deterministic in `(fidelity, seed)` with a
constant seed, so in a `sim` build the mix contributes epoch agreement, not secrecy). Any
upstream change that alters that contract would need the documentation to follow. The honest
description of what the two anchors actually claim — including the `sim`-only caveat and the
vendored-snapshot state — is in `docs/ANCHORS_CODEBASE_INTEGRATION.md` §1–§2.

### 2.2 ABOS (`abos/`)

**What v0.8.11 actually uses from it.** ABOS is used behind the `sdr` cargo feature, via
`abos::ABOSSystem` in `src/ghost/net/sdr_bridge.rs`. Without that feature (or without SDR
hardware) the bridge runs in synthetic mode. The workspace is compiled as part of the Vantablack
build when the feature is on.

**Measured state of the vendored tree vs upstream.** The vendored `abos/` workspace is a copy
of the upstream ABOS repo that is missing some root-level files the upstream repo carries
(e.g. a `LICENSE` file, `rust-toolchain.toml`, and the HTML index/docs files the upstream repo
serves). The crate layout itself is intact — the 13 workspace crates are present — so the
Vantablack build's ABOS dependency is on the workspace crates, not on the missing root files.

**What an upgrade would touch.** Like QEL, this is updating vendored third-party code. The
Vantablack side depends on `abos::ABOSSystem` and the SDR bridge plumbing. An upgrade should at
minimum confirm that the workspace still compiles with the feature enabled and that the symbols
`sdr_bridge.rs` references still exist. If the upgrade is meant to also bring the repository's
own docs (README, whitepaper, license, toolchain pinning) back in line with upstream, that is a
separate documentation decision for the `abos/` tree, not a Vantablack functional change.

**Honest caveat.** The vendored ABOS tree is a snapshot whose upstream is outside this
repository. If upstream ABOS moves in a way that breaks the `sdr` feature's interface, the
Vantablack `sdr` builds break, and there is no in-tree guarantee that the vendored copy stays
buildable against any particular upstream tip. That is inherent to vendoring.

---

## 3. Possible Vantablack-native additions (no upstream dependency)

These are things that would live entirely in Vantablack code or markdown. They are unordered
and unfunded; they are here as a menu, not a plan.

### 3.1 A single configuration reference
Today the environment-reference story is split: `docs/config.env.example` is the live-ish file
the daemon parses, and `docs/OPERATOR_GUIDE.md` §8 has a table. A dedicated
`docs/CONFIGURATION.md` that is cross-checked against the actual parsed variables (including the
`GHOST_BYPASS_*`, `GHOST_VPN_*`, `GHOST_SKYWAVE_*`, `GHOST_QUANTUM_*`, `GHOST_NO_GUI`,
`GHOST_LOG` family and the per-mode variables) would give operators one place to look. The
risk is staleness: such a file has to be re-verified against `src/` whenever a variable is
added or removed, so it needs an owner or it will drift.

### 3.2 WAN simulation runbook
The 7-node Docker Compose topology and the four scenarios are documented in
`docs/SPECIFICATIONS.md` §8–§9 and `docs/VERIFICATION_AND_BENCHMARKS.md`, but there is no
single `docs/WAN_SIMULATION.md` that is only about reproducing the simulation: exact prerequisites
(Docker, `sch_netem`), exact `docker compose` commands, what to expect in each container's logs,
and how to read the dashboard and the `/api/telemetry` feed. Such a file would be a natural home
for the "how do I run the thing the benchmarks and the spec both point at" question.

### 3.3 Lint and hygiene policy
`ROADMAP.md` and the build docs mention the `-D warnings` clippy gate and the lint-hardening
pass, but there is no dedicated `docs/LINT_POLICY.md` stating what is enforced, what the three
auditable exemptions are, and how to add a new one without weakening the gate. The exemption list
is real (it is enforced by CI), so a document that states it explicitly is more truthful than
leaving it implicit.

### 3.4 Installer and packaging documentation
The README has an "Install on Windows" section and an Inno Setup build note, and
`docs/BUILDING.md` has the compiler/SDK paths, but there is no `docs/INSTALLERS.md` that collects
the installer story (Windows setup, Linux packages, Android APK, Apple Silicon) and the
signing/packaging decisions in one place. That is the natural home for the `ROADMAP.md`
packaging milestone once it starts moving.

### 3.5 ProVerif install/run guidance
`formal/README.md` states how to run the two models and what they establish, but it does not
document how to obtain ProVerif on each platform. `docs/BUILDING.md` gives the Windows download
path for the ProVerif binary; a short note in `formal/README.md` or a cross-reference from it
would keep the formal-model instructions self-contained.

---

## 4. Things to approach carefully

These are not "add this" items; they are "if you touch this, be aware" notes.

- **Do not refreeze the vendored QEL/ABOS snapshots by re-diffing them against a stale upstream
  tip and treating the diff as authoritative.** The vendored trees are snapshots; upstream has
  moved since. Any upgrade needs a real, current upstream checkout and a deliberate choice about
  which upstream state to vendor, not a guess anchored to whatever tip was used the first time.
- **Do not widen the lint exemptions to make a new feature pass.** The three exemptions exist for
  a reason; if a new feature wants one, argue for it explicitly in the commit rather than silently
  enlarging the exception list.
- **Do not let a new configuration variable land without updating at least one of
  `docs/config.env.example` or `docs/OPERATOR_GUIDE.md`, and preferably both.** A variable that
  the daemon parses but no document explains is a future support burden.
- **Do not claim a security property in the descriptive docs that `formal/README.md` does not
  list as a query.** The formal models are the boundary of what "proven" currently means here;
  expanding that boundary means adding a model, not rewriting a paragraph.

---

## 5. How to use this file

- If you are **reviewing** a PR, check whether it silently turns one of the "not landed" items
  above into a claim of completion without the corresponding code or doc change.
- If you are **writing** a new feature, decide whether it belongs in a descriptive document
  (`README.md`, `docs/SPECIFICATIONS.md`, `docs/OPERATOR_GUIDE.md`, `formal/README.md`) or
  whether it is itself a future-looking note that stays here.
- If you are **upgrading vendored QEL or ABOS**, read §2 first, then vendor against a current
  upstream checkout, then update whatever Vantablack contract (JSON, label, probe, bridge symbols)
  the vendor change touches.


---

## 6. Codebase Audit Baseline (2026-11-20) — LAN vs. Real WAN

> Snapshot captured on `v1.0.0` (commit `5bd2e7a`, clean working tree).

### 6.1 Current State of the Project

- **Build & Test Health**:
  - `cargo test --no-fail-fast -- --quiet`: **643 passed, 0 failed, 1 ignored** across unit, crypto, wire, NAT/relay simulation, and VPN integration suites.
  - `cargo clippy --all-targets -- -D warnings`: **passed cleanly** (0 warnings).
- **Scope Cleanup Already Done**: 15 research/experimental modules (`rendezvous`, `dead_drop`, `dtn_reconcile`, `pow`, `sovereign_cloud`, `stego_physics`, `energy_currency`, etc.) are gated behind `#[cfg(feature = "research")]` (off by default in `Cargo.toml:59-61` and `src/ghost/net/mod.rs:12-55`).

### 6.2 Does It Genuinely Function? (LAN vs. Real WAN)

**Short answer**: The **cryptographic core, 1-to-1 LAN tunneling, and VPN Hub ↔ Client path genuinely work**. However, **real WAN (across NATs) and multi-peer (>1 peer) mesh routing will fail today** due to concrete integration gaps between components that currently pass tests only in isolation.

#### What Genuinely Works
- **Post-quantum crypto & framing**: Hybrid ML-KEM-768/512 + X25519 handshake with Ed25519 + ML-DSA-65 identity commitments, GTF v2 576 B privacy frames, ShardSec per-shard AEAD, 64-bit counter anti-replay, proactive double-ratchet rekeying, and Poisson cover traffic.
- **Direct 1-to-1 LAN / routable-IP tunneling**:
  - **VPN Hub ↔ Client (Windows & Android)**: `smoltcp` userspace netstack, UDP/DNS forwarding, TUN integration (`AndroidTun` / `Wintun`), and mobility/re-anchoring all work end-to-end.
  - **1-hop SOCKS5 proxy** (`GHOST_SOCKS5=1`) works when connected to a single peer.
- **Standalone primitives**: `IceAgent`, STUN, TURN, UPnP, `DerpRelay`, `Fallback`, and `RLY!` onion wrapping/return-path are real implementations verified in isolation (`tests/p1_nat.rs`, `tests/p1_relay.rs`, `tests/wan_testbed.rs`). Note that `src/bin/wan_mesh.rs` + `docker-compose.wan.yml` is a separate 7-node simulation binary with hardcoded container topology, not the shipped `ggn` daemon.

#### Concrete Blockers Preventing Real WAN / Multi-Peer Operation

1. **Split-socket NAT/ICE bug (Critical WAN blocker)** — `src/main.rs:5642-5701`, `src/ghost/net/mesh.rs:216-304`
   - STUN, UPnP port mapping, and ICE hole-punching all bind and run on a separate ephemeral `nat_socket` (`0.0.0.0:0`), while actual mesh handshakes and GTF packets run on `nc.socket` (`0.0.0.0:55225`).
   - Even when `punch_hole()` succeeds on `nat_socket`, it only stores `connected = true` and RTT; it never updates `addrs` with the nominated endpoint, and **zero mesh packets ever leave or enter `nat_socket`**. The punched NAT pinhole is never used for data.
2. **ICE offers & relay discovery never leave the LAN (Critical WAN blocker)** — `src/main.rs:5620-5633`, `src/main.rs:6370-6380`, `src/main.rs:6547-6584`
   - `IceOffer` payloads are only attached to IPv4 multicast beacons (`239.255.0.1:2270`), which do not cross routers. Neither `http_bootstrap` nor `send_pex` exchanges ICE offers or NAT metadata.
   - `GHOST_STUN_SERVER` defaults to `None`, so nodes do not discover their public reflexive address unless manually configured.
   - **Relay catch-22**: Storing and reading DERP relay candidates in `src/main.rs:6547-6584` is wrapped inside `if let Some(relay) = relay_role.as_ref()`, which is only `Some` when the local node itself sets `GHOST_RELAY=1`. Normal clients can never discover or use a mesh relay. (It also records `src`—the sender's ephemeral `beacon_sock` port—rather than its mesh port.)
3. **Multi-peer SOCKS5 shard-scattering breaks at ≥ 2–3 peers (Critical mesh bug)** — `src/main.rs:949-1017`, `src/ghost/net/mesh.rs:826-842`
   - With 1 peer (typical LAN test), `send3_adaptive` takes the `else` branch and sends all 3 RS shards to `primary_dst`, so it works.
   - With ≥ 2 peers, `send3_adaptive` splits the 3 RS shards (all encrypted under `primary_fp`'s `session_hash` and session key) across *different* peers via raw `send_gtf_v2` without wrapping them in a forwarding envelope. The other peers have no matching session and drop those shards, leaving `primary_fp` with 0–1 shards (RS(2,1) requires ≥ 2), stalling SOCKS5 streams.
4. **"3-Tier Zero-Knowledge Discovery" is mostly unwired** — `src/main.rs:222-227`, `src/main.rs:5106-5175`
   - **Tier 1**: `LocalPeerCache::load("peers.bin")` is called, but `LocalPeerCache::save` is never called anywhere in `src/` (a separate plaintext `peers.cache` is used instead).
   - **Tier 2**: `vb://` signed URIs (`src/ghost/net/discovery.rs:209-219`) are unused by `/api/peers/add` (raw `IP:Port` only) and the UI.
   - **Tier 3**: `BlindRendezvous` computes `_slot_hex` and discards it (`src/main.rs:5133`), then performs a plaintext GET to hardcoded `https://red-star-512e.papababg02.workers.dev/peers?port=...&id=<fp>&lan=<lan_ip>` (both desktop and Android). `EMBEDDED_SEEDS` is empty.
5. **Security hazard if put on public WAN as-is** — `src/main.rs:5492-5558`
   - Desktop nodes default to `is_exit_node = true`, `trusted_exits = { "any" }`, and VPN Hub allowlist `["any"]`. Convenient on a private home LAN, but unsafe on a public WAN swarm.
6. **UI / API & testbed drift** — `assets/wan_dashboard.html`, `src/control.rs`
   - "Scan LAN" hits `POST /api/mesh/scan` (actual backend route: `POST /api/scan`, `src/control.rs:649`); scan interval hits `POST /api/mesh/config` (actual route: `POST /api/settings`).
   - "Uniform 576B Stealth Framing" and "Poisson Cover Traffic" call a stub `saveSetting` that only logs to console (`assets/wan_dashboard.html:1485`).
   - The 5 "Experimental & Sovereign Layers" toggles persist to `ghost-consumer.json` (`src/ghost/net/consumer.rs:303-311`), but nothing in the packet path reads them.
   - Diagnostics hardcodes `239.255.67.89:2270` (actual multicast group is `239.255.0.1:2270`) and the UI still displays `v0.8.21`.
   - `deploy/docker-compose.yml:18` references `Dockerfile.wan` instead of `docker/Dockerfile.wan` and sets env vars for dormant `research`-gated modules; `scripts/smoke_test.sh` prints hardcoded pass lines.

### 6.3 Baseline Ideas Captured During Audit

- **Mesh View (Initial Concept)**: Render an honest local Ego-Graph (center = self, Ring 1 = direct LAN/WAN peers, Ring 2 = DERP/TURN relays + active onion hops) backed by a new `GET /api/topology` endpoint, with click-to-inspect peer metrics and a compact table toggle.
- **WAN Discovery (Initial Concept)**: First multiplex STUN/ICE + GTF onto `nc.socket`, decouple relay discovery from `GHOST_RELAY=1`, and ship default STUN servers. Then split WAN discovery into **Private WAN Mesh** (fixing the static nonce in `BlindRendezvous::encrypt_descriptor` and turning the Cloudflare Worker into a truly blind encrypted slot mailbox) vs. **Public Swarm** (redundant DNS/DoH/VPS seeds + upgraded signed PEX + persisted `peers.bin` + fail-closed exit defaults).

---

## 7. Expanded Upgrade, Architecture & UI/UX Blueprint

A comprehensive, prioritized backlog extending the audit findings across WAN transport, discovery, security, desktop Control Center UI / Mesh View, mobile parity, and real-world verification.

### Track A — Core WAN & Transport Correctness (P0)

#### A1. Single-Socket UDP Multiplexing (STUN / ICE / GTF on `nc.socket`)
- **Problem**: `nat_socket` (`src/main.rs:5642`) punches NAT pinholes on a different UDP port than `nc.socket`.
- **Upgrade**:
  - Remove the separate `nat_socket`. Run STUN reflexive discovery, UPnP/NAT-PMP mapping, ICE connectivity checks, and GTF data frames on `nc.socket`.
  - In the `nc.socket` receive loop (`src/main.rs:6801-6812`), demux by RFC 8489 framing before calling `rx.ingest`: if `amt >= 20 && (buf[0] & 0xC0) == 0 && buf[4..8] == [0x21, 0x12, 0xA4, 0x42]`, route the packet via a bounded channel to `NatHolePuncher` / `IceAgent`; otherwise pass it to `RxContext::ingest`.
  - Add `NatHolePuncher::nominated_addr(&self, fp: &str) -> Option<SocketAddr>` and write the winning nominated remote address directly into `addrs` upon ICE nomination, plus trigger `initiate_handshake` if no session exists yet.
  - Refresh NAT pinholes on `nc.socket` every 20–25 s for active WAN peers and known relays (well below typical 30 s residential/CGNAT UDP mapping timeouts).

#### A2. Decouple Relay Discovery from Relay Serving
- **Problem**: Clients without `GHOST_RELAY=1` cannot record or select DERP relays (`src/main.rs:6547-6584`), and beacon relay registration stores the ephemeral beacon sender port.
- **Upgrade**:
  - Maintain a separate `known_relays: Arc<DashMap<String, RelayPeerInfo>>` on **every** node regardless of whether `GHOST_RELAY=1` is enabled locally.
  - Only gate *accepting/forwarding* blind relay traffic (`BLND!`) on `relay_role.is_some()`.
  - Advertise the node's real `mesh_port` (plus public reflexive endpoint if known) inside beacons, PEX, and `PeerDescriptor`s instead of trusting the UDP source port of `beacon_sock`.
  - Add relay health probing (periodic RTT + reachability checks) and automatic switchover if the primary DERP relay goes down.

#### A3. Fix Multi-Peer RS(2,1) Shard Scattering (`send3_adaptive`)
- **Problem**: `send3_adaptive` (`src/main.rs:949-1017`) sends raw `primary_fp` shards directly to unrelated peers when `all_peers.len() > 1`, causing 100% stream failure on ≥ 2–3 peers.
- **Upgrade (2-phase)**:
  - **Phase 1 (Immediate correctness fix)**: Always deliver all 3 RS shards to `primary_fp` (or its active `FallbackPath` / QUIC multipath links) unless carrier-forwarding envelopes are explicitly used. That immediately restores 2-hop (`:1082`) and 3-hop (`:1083`) SOCKS5 onion circuits in real multi-peer swarms.
  - **Phase 2 (True divergent multi-carrier sharding)**: To genuinely disperse Shards 0, 1, and 2 across 3 independent carrier peers on the way to `primary_fp`, wrap each non-direct shard in a lightweight `BLND!` (blind relay) envelope addressed to `primary_fp` and encrypted to the carrier peer's session, so each carrier forwards its single opaque GTF shard to `primary_fp` for 2-of-3 RS reconstruction—matching the README architecture honestly.

#### A4. Default STUN Pool, NAT Type Classification & IPv6 Direct Bypass
- **Upgrade**:
  - Ship a default multi-provider STUN server pool (e.g., Cloudflare/Google/Coturn defaults, overridable via `GHOST_STUN_SERVER`, disableable with `GHOST_STUN=off` for strict airgap/LAN-only mode).
  - Run a dual-STUN probe (RFC 5780 style: compare mapped port across two STUN endpoints) at startup and on network change to classify the local NAT accurately: `Direct` (public IP or UPnP mapped), `Endpoint-Independent (Cone)`, `Address/Port-Restricted`, or `Symmetric / CGNAT`.
  - **IPv6 Dual-Stack Fast Path**: Bind dual-stack UDP (`[::]:55225` with `IPV6_V6ONLY = false` or a paired IPv6 socket) and gather global unicast IPv6 candidates alongside IPv4 STUN candidates. Many residential ISPs and 5G carriers put IPv4 behind CGNAT while handing out globally routable IPv6—enabling direct WAN connections with zero relay cost.

#### A5. Modularize `src/main.rs` (9,670-Line Monolith Refactor)
- **Problem**: `src/main.rs` combines CLI bootstrap, handshake handling, receive pipeline, onion/exit routing, SOCKS glue, NAT orchestration, PEX, cover traffic, and tests in one ~9.7k-line file.
- **Upgrade**: Split cleanly into focused internal modules (`src/daemon/bootstrap.rs`, `src/daemon/nat.rs`, `src/daemon/handshake.rs`, `src/daemon/rx.rs`, `src/daemon/tx.rs`, `src/daemon/exit.rs`, `src/daemon/pex.rs`) without changing wire formats. This also lets integration tests drive the real daemon `RxContext`/`Tx` directly instead of duplicating framing helpers.

#### A6. Self-Healing Interface, Mobility & Stale-Session Watchdog
- **Upgrade**:
  - Detect local IP / default-route changes (Wi-Fi ↔ Ethernet, laptop wake from sleep, DHCP renewal) and automatically re-run STUN + UPnP + blind rendezvous publication + ICE re-checks within < 3 s.
  - Add explicit session liveness / dead-peer eviction (evict peers that miss $N$ keepalives and trigger failover for active SOCKS5/VPN exits instead of hanging until TCP timeout).
  - Implement automatic TUN adapter health checks and recycle on driver stall (`Wintun` / `utun`).

---

### Track B — WAN Discovery Architecture (Private Mesh vs. Public Swarm)

#### B1. Fix Critical Nonce-Reuse Vulnerability in `BlindRendezvous`
- **Problem**: `src/ghost/net/discovery.rs:307` uses a hardcoded static nonce (`b"VB_BLND_NO_1"`) with `epoch_key`. If two peers in the same swarm publish in the same hour—or one peer updates its IP within the hour—two ciphertexts reuse `(epoch_key, nonce)` under ChaCha20-Poly1305, breaking confidentiality and Poly1305 authenticity.
- **Upgrade**: Generate a fresh 12-byte random nonce per `encrypt_descriptor` call (or 24-byte XChaCha20-Poly1305 nonce) and prepend it to the ciphertext; update `decrypt_descriptor` accordingly and add a regression test asserting two encryptions of the same descriptor under the same `epoch_key` produce distinct nonces and ciphertexts.

#### B2. Turn the Cloudflare Worker into a Truly Blind Encrypted Mailbox
- **Problem**: `http_bootstrap` (`src/main.rs:5106-5175`) discards `_slot_hex` and leaks plaintext `id=<fp>`, `lan=<ip>:<port>`, and source IP to a hardcoded worker URL.
- **Upgrade**:
  - Define a dead-simple blind KV API:
    - `PUT /v1/slot/<slot_hex>` — body is a fixed-size (e.g., 1024 B padded) opaque ciphertext blob; server stores with TTL = 15 min (max $K$ blobs per swarm slot bucket, rate-limited by IP hash).
    - `GET /v1/slot/<slot_hex>` — returns the list of opaque base64/binary blobs currently in that slot.
  - Version the worker script in-repo (`deploy/worker/blind_rendezvous.js` + `wrangler.toml`) so any user can self-host their own private rendezvous worker on Cloudflare's free tier in 60 seconds and set `GHOST_RENDEZVOUS_URL`.
  - Support **epoch boundary overlap**: query both `epoch_hour` and `epoch_hour - 1` during the first 5 minutes of each hour so nodes never miss each other across clock skew or hour rollovers.

#### B3. Unified Signed `PeerDescriptor` v2 Payload
- **Upgrade**: Extend `PeerDescriptor` (`src/ghost/net/discovery.rs:40`) so one compact, Ed25519-signed struct carries everything a WAN peer needs to connect:
  - `ed25519_pk`, `pq_commitment` (32 B ML-DSA-65 commitment), `ml_kem_hash`
  - `mesh_port` + `lan_endpoints` (for hairpin/same-LAN fast path)
  - `nat_type` (`Direct` / `Cone` / `Restricted` / `Symmetric`)
  - `capabilities` bitflags (`RELAY`, `EXIT`, `VPN_HUB`, `QUIC`)
  - Embedded `IceOffer` (ufrag, pwd, host + srflx + IPv6 + relay candidates)
  - `timestamp` + Ed25519 signature over all fields.
- Encode as compact `vb://<base64url>` (shorter than hex—fits cleanly in a single QR code).

#### B4. True Tier-1 Authenticated Peer Cache (`peers.bin`)
- **Problem**: `LocalPeerCache::load` is called at startup (`src/main.rs:5109`), but `LocalPeerCache::save` is never called; plaintext `peers.cache` is written instead.
- **Upgrade**:
  - Persist verified `PeerDescriptor` v2 entries to `peers.bin` via `LocalPeerCache::save` whenever sessions establish or update via PEX/rendezvous.
  - On reboot, try direct handshakes to cached `peers.bin` entries **first** (Tier 1, zero external calls), and only hit blind rendezvous / seeds if cached peers don't respond within 2 s or peer count is below target.
  - Migrate existing `peers.cache` entries once on upgrade and remove duplicate cache code.

#### B5. Upgraded Encrypted Peer Exchange (`GHOST_PEX_____` v2)
- **Problem**: Current PEX (`src/main.rs:5036-5073`) only gossips `(fp, SocketAddr)` without signatures, NAT type, relay capability, or `IceOffer`s, so PEX cannot help NATed WAN peers punch holes.
- **Upgrade**: Gossip batches of signed `PeerDescriptor` v2 records over established encrypted sessions, capped and freshness-filtered, so once a node reaches **any 1 peer or relay**, it learns the ICE offers and relay candidates of the entire neighborhood over the mesh itself.

#### B6. Multi-Backend Public Swarm Discovery & Zero-SPOF Bootstrapping
- **Upgrade** (for Public Swarm mode):
  - **DNS / DoH TXT Bootstrap Seeds**: Resolve TXT records containing signed `vb://` descriptors for multi-region community bootstrap+DERP relays (e.g., `seeds.vantablack.kellersystems.dev`), using DoH fallback when local DNS is censored.
  - **Optional Ephemeral Nostr Relay Rendezvous**: Promote and harden the `NostrRendezvousEvent` prototype from `src/ghost/net/rendezvous.rs` as an opt-in serverless WAN rendezvous transport publishing encrypted `BlindRendezvous` blobs to public Nostr relays (zero owned infrastructure).
  - **Network Profiles / Namespaces**: Allow users to join multiple isolated private meshes (e.g., `Home Lab`, `Team VPN`, `Public Swarm`) each with its own `swarm_secret` and exit/relay trust policy.

#### B7. Dedicated Stateless DERP Relay Profile (`ggn --relay-only`)
- **Upgrade**: Add a first-class headless VPS deployment mode (`ggn --relay-only` + `deploy/docker-compose.relay.yml` + `systemd` unit) that:
  - Runs as a blind DERP forwarder (`GHOST_RELAY=1`) + embedded STUN reflector + optional encrypted slot cache.
  - Explicitly disables SOCKS5, VPN exit, and desktop GUI (`GHOST_EXIT=0`, `GHOST_NO_GUI=1`).
  - Exposes clean Prometheus relay telemetry (active clients, forwarded Mbps, dropped unauthenticated frames, bandwidth quota utilization).

---

### Track C — Security Hardening for Public WAN Exposure

#### C1. Fail-Closed Trust Zones (Private Mesh vs. Public Swarm)
- **Problem**: `src/main.rs:5492-5558` defaults `is_exit_node = true`, `trusted_exits = { "any" }`, and VPN Hub allowlist `["any"]`.
- **Upgrade**:
  - Split trust into explicit modes persisted in `ghost-consumer.json`:
    - **Private Mesh (default)**: Only peers carrying the shared `swarm_secret` / explicitly paired fingerprints can handshake or use this device as an exit/VPN hub.
    - **Public Swarm**: `is_exit_node` defaults to `false` (relaying blind encrypted frames is safe; exiting plaintext internet traffic is opt-in only with explicit confirmation + `ExitPolicy` domain/port guardrails).
  - Require explicit allowlisting or signed `ExitCapability` vouchers (`EXITAUTH!`) before accepting SOCKS5 `CONNECT` from non-paired peers.

#### C2. Unify All Handshakes onto Suite-Negotiated ML-KEM-768 + PQ Auth
- **Problem**: Bootstrap (`src/main.rs:5967`) and multicast auto-handshake (`src/main.rs:6700`) still craft legacy ML-KEM-512 `build_handshake_pdu` frames directly instead of calling `initiate_handshake` (`src/main.rs:2731`), leaving peers on v1 wire format without ML-KEM-768 or ML-DSA-65 authentication.
- **Upgrade**: Replace all inline handshake senders with `initiate_handshake`, ensuring uniform ML-KEM-768 negotiation, transcript binding, v2 GTF framing, and ShardSec across every discovery path.

#### C3. Reconcile Inert Control-Plane Settings & Feature Honesty
- **Upgrade**:
  - Wire the "Uniform 576B Stealth Framing" and "Poisson Cover Traffic" toggles to real `AtomicBool` runtime controls read by the TX/cover loops (instead of `console.log`).
  - Gate the 5 "Experimental & Sovereign Layers" UI cards dynamically on actual build/runtime capabilities returned by `/api/status` (hide or clearly mark as `Compile with --features research` / `Requires --skywave` / `Requires --quantum` unless active), and wire `jurisdiction_tag` into exit/circuit peer selection when peers advertise signed region/jurisdiction tags.

#### C4. WAN Anti-Abuse & Stateless Handshake Protection
- **Upgrade**:
  - Add a stateless UDP handshake cookie (WireGuard-style MAC over `src_ip + rotating_secret`) or adaptive rate limiter on `ctr == 0` handshakes when `pending_hs` crosses 50% capacity, preventing CPU exhaustion from spoofed ML-KEM-768 handshakes on public WAN relays/exits.
  - Enforce per-source-IP token buckets on incoming unauthenticated beacons and STUN requests.

#### C5. Time-Limited Exit Capability Vouchers (`EXITAUTH!`) UX
- **Upgrade**: Expose the already-implemented `ExitCapability::issue` (`src/ghost/net/relay.rs`) via `POST /api/exit/voucher` in `src/control.rs` so a hub owner can mint a signed, expiring, domain-scoped guest voucher (e.g., "Allow friend's phone to use my exit for 24h") without adding them to permanent allowlists.

---

### Track D — Control Center UI/UX & Interactive Mesh View Overhaul

#### D1. Fix Existing Dashboard / API Bugs Immediately (`assets/wan_dashboard.html` & `src/control.rs`)
- Fix `scanLanNow()` to call `POST /api/scan` (not `/api/mesh/scan`) and `updateScanInterval()` to call `POST /api/settings` with `private_mesh_scan_interval_secs` (not `/api/mesh/config`).
- Inject `env!("CARGO_PKG_VERSION")` from `src/control.rs` into `/api/status` and render it dynamically in the titlebar & footer (removing hardcoded `v0.8.21`).
- Fix Diagnostics multicast display from `239.255.67.89:2270` to `239.255.0.1:2270` (or read dynamically from `/api/status`).
- Standardize copy to one language (or add a clean `EN / DE` selector; currently mixes German pairing labels with English tabs).

#### D2. Live Topology API (`GET /api/topology`) & Real-Time Event Stream (`GET /api/events` SSE)
- **Upgrade**:
  - Add `GET /api/topology` in `src/control.rs` returning genuine runtime telemetry:
    - `self`: `{ fingerprint, name, os, bind_addr, public_addr, nat_type, roles: ["client"|"relay"|"exit"|"vpn_hub"], active_socks_ports, upnp_mapped }`
    - `peers[]`: `{ fingerprint, name, endpoint, scope ("lan"|"wan"), transport ("direct_lan"|"direct_wan_ice"|"quic"|"mesh_relay"|"turn"|"skywave"), via_relay_fp, rtt_ms, loss_pct, fitness, bytes_tx, bytes_rx, tft_forwarded_for, tft_forwarded_by, cipher_suite, pq_verified, ratchet_epoch, capabilities, is_pinned_exit, is_exit_allowed, connected_secs }`
    - `active_circuits[]`: `{ stream_id, socks_port, policy ("1-hop"|"2-hop"|"3-hop"), hops: [fp1, fp2, fp3], target_summary, bytes, age_secs }`
  - Add lightweight Server-Sent Events (`GET /api/events`) for instant peer-join, ICE-punch, relay-failover, and tamper-alert pushes—eliminating 1.2 s polling lag while keeping `/api/status` for simple CLI scripts.

#### D3. New Dedicated **Mesh View** Tab (Interactive Local Ego-Graph)
Build a zero-dependency, crisp SVG/Canvas graph inside `assets/wan_dashboard.html` (works identically in the native `wry` desktop window and remote browser):
- **Honest Ego-Graph Layout**:
  - **Center Node (You)**: Displays device name, short fingerprint, NAT type pill (`Direct` / `Cone` / `Symmetric`), role badges, and an animated outer throughput ring.
  - **Ring 1 — Direct Peers**: Solid cyan edges for `LAN`, solid emerald edges for `WAN Direct (ICE/IPv6)`, solid violet for `QUIC Multipath`. Edge stroke width scales logarithmically with live throughput; edge color/pulse reflects measured RTT & `AdaptiveShardRouter` fitness.
  - **Ring 2 — Relayed & Multi-Hop Nodes**: Dashed amber paths routing visually through the intermediate DERP/TURN relay node (`You ──▶ Relay ──▶ Peer`) so you immediately see *why* latency is higher and which relay is carrying traffic.
  - **Active Circuit Highlighter**: Toggleable overlay tracing active onion circuits (`You → Guard → Middle → Exit`) with hop numbers `1 / 2 / 3` and directional return-path indicator, plus VPN `Phone → Hub` tunnel highlight.
- **View Switcher Bar**: `Graph View` | `Circuit Paths` | `Peer Table` (dense sortable table for 20+ peers) | `Split (Graph + List)`.
- **Filter Chips**: `All` | `LAN` | `WAN Direct` | `Relayed` | `Relays` | `Exits`.
- **Interactive Peer Inspector Drawer (Slide-Over Panel on Node Click)**:
  - Live RTT sparkline (last 60 samples) + loss/fitness gauge.
  - Path breakdown (`Direct ICE 18ms` or `Relayed via EU-Relay-1 64ms`) + button to **Retry Direct ICE Punch**.
  - Crypto card: Cipher suite (`ML-KEM-768 + X25519`), ML-DSA-65 PQ auth status, current ratchet epoch + **Force Rekey** button, ShardSec tamper count.
  - Tit-for-Tat Reciprocity bar (bytes forwarded for them vs. by them).
  - Quick controls: **Rename Device**, **Pin as Default Exit**, **Allow/Revoke Exit Access**, **Copy `vb://` Peer URI**, **Disconnect (`GHOST_BYE`)**.

#### D4. WAN & NAT Readiness Pipeline Widget (Status + Diagnostics Tabs)
- Replace static socket strings with a live 4-stage connectivity pipeline:
  1. **Local Mesh Socket**: Bound port + IPv4/IPv6 status
  2. **Public Reachability (STUN / UPnP)**: Detected public `IP:Port`, NAT type (`Direct` / `Cone` / `Symmetric CGNAT`), UPnP lease status
  3. **Discovery Backbone**: Tier-1 cache count (`peers.bin`), LAN beacon status, Blind Rendezvous slot health (last sync + encrypted slot epoch), active PEX peers
  4. **Relay Safety Net**: Connected DERP/TURN relays ready for CGNAT fallback
- Include a **1-Click "Test WAN Reachability"** button that runs a live STUN + blind-slot roundtrip + relay ping and prints an actionable human-readable diagnosis (e.g., *"Behind Symmetric CGNAT — direct incoming connections blocked; DERP relay connected (34 ms), WAN peers can reach you via relay"*).

#### D5. 1-Click Pairing & Invite Studio (LAN + WAN)
- Replace the LAN-only `IP:Port` text box and manual Android copy-paste card with a unified **Add / Pair Device** modal:
  - **Tab 1 — Pair My Own Device (Private WAN Mesh)**: Displays a real SVG QR code + copyable `vb-net://` invite encoding the network's `swarm_secret` + rendezvous mailbox + your signed `PeerDescriptor`. Scanning on phone or pasting on laptop auto-joins both LAN and WAN.
  - **Tab 2 — Invite External Peer (`vb://`)**: Generates a signed, single-node `vb://` descriptor URI (containing your ICE offer & public key—no `swarm_secret` shared).
  - **Tab 3 — Manual / Paste URI**: Single smart input box in `/api/peers/add` that accepts `IP:Port`, `vb://<base64url>`, or `vb-net://<base64url>` and shows immediate handshake + ICE progress feedback (`Resolving → Punching NAT → ML-KEM-768 Handshake → Connected`).

#### D6. Multi-Port SOCKS5 & Split-Tunnel Control Center
- Show all 4 SOCKS5 ingress ports (`:1080` Auto, `:1081` 1-Hop Fast, `:1082` 2-Hop Circuit, `:1083` Strict 3-Hop Onion) with live readiness badges (e.g., `:1083 Ready — 4 peers online` vs `:1083 Needs 2 more peers`), active stream counts, and 1-click copy for `curl`/browser proxy config or auto-generated local `proxy.pac` URL (`http://127.0.0.1:2270/proxy.pac`).
- Add a clean visual **Split-Tunnel Bypass List** UI wired to the existing `POST /api/settings` (`bypass_add` / `bypass_remove`) backend, with presets (`Local LAN`, `Streaming`, `Gaming`).
- Add a **Node Role Selector** (`Private Client`, `Home Exit Hub`, `Public Relay Contributor`, `Public Exit Node [Advanced]`) that safely updates `trusted_exits`, `GHOST_RELAY`, and VPN Hub policy with clear explanations.

#### D7. Real-Time Diagnostics, Crypto Telemetry & Live Log Console
- Add live throughput & RTT history charts (60 s rolling SVG sparklines for RX/TX Mbps, packet drops, ShardSec rejections, replay blocks, cover traffic overhead).
- Add a **Live Log Viewer** tab/drawer streaming recent `tracing` events (`GET /api/logs` ring buffer in memory, filterable by `INFO` / `WARN` / `ICE` / `HANDSHAKE` / `RELAY`) so Windows GUI users don't have to hunt for `%APPDATA%\GlobalGhostNet\ghost.log`.
- Add a **Built-in Self-Test / Pipeline Probe UI** button wired to the existing `POST /api/pipeline_probe` (`src/control.rs:657`) so users can benchmark local crypto + RS(2,1) + ShardSec throughput right from Diagnostics.

#### D8. Desktop Window, Tray & Accessibility Polish
- Enhance the system tray menu (`src/tray.rs`) with live status line (`Online · 4 Peers · WAN Direct`), quick Connect/Disconnect toggle, quick Exit Node switcher, and "Copy SOCKS5 Proxy".
- Add optional PIN lock modal (styled in-app instead of browser `window.prompt()` in `assets/wan_dashboard.html:1260`).
- Support keyboard navigation (`1–5` to switch tabs, `R` to refresh, `Esc` to close peer drawer) and dark/high-contrast theme consistency.

---

### Track E — Android & Cross-Platform Parity

#### E1. Bring Android JNI Core to WAN & GTF v2 Parity
- **Problem**: `src/ghost/net/vpn/android_jni.rs` still speaks legacy GTF v1 + ML-KEM-512 direct UDP only, and `GhostVpnService.kt:419-420` points at the hardcoded plaintext Cloudflare Worker URL.
- **Upgrade**:
  - Upgrade Android JNI to GTF v2 + negotiated ML-KEM-768 + single-socket STUN/ICE + DERP blind relay fallback so a phone on 5G CGNAT reliably reaches a home PC over WAN with zero port forwarding.
  - Share the exact same `BlindRendezvous` + `PeerDescriptor` v2 client code from `vantablack` library crate on Android instead of duplicating HTTP bootstrap logic in Kotlin.

#### E2. Android QR Pairing & Mini Mesh Status View
- Add camera QR scanner in `MainActivity.kt` for `vb-net://` and `vb://` invites (eliminating manual IP/fingerprint typing).
- Display real connection path (`Wi-Fi Direct LAN`, `5G Direct ICE`, `5G via DERP Relay`), live RTT, handover counter (Wi-Fi ↔ 5G seamless transitions), and exit hub switcher.

#### E3. Desktop System VPN / Wintun Ergonomics
- Add an optional lightweight Windows Service / elevation helper for Wintun mode, with a clear UI toggle between **System VPN (All Apps — Wintun)** and **Zero-Admin Mode (SOCKS5 + PAC)** and an optional **Kill-Switch** indicator when VPN mode is active.

---

### Track F — Real WAN Verification & Testbed Hardening

#### F1. Real-Daemon Multi-NAT Integration Harness (Not Simulation Primitives)
- Build an automated Docker / Linux netns testbed that runs **real `ggn` binaries** across realistic network topologies:
  1. **Cone NAT ↔ Cone NAT** + blind rendezvous worker mock → verify STUN + encrypted slot exchange + single-socket ICE punch + ML-KEM-768 session + SOCKS5 HTTP transfer.
  2. **Symmetric CGNAT ↔ Symmetric CGNAT** + 1 public `ggn --relay-only` node → verify ICE fails honestly, both clients discover the relay without `GHOST_RELAY=1`, and traffic flows end-to-end through the blind DERP relay.
  3. **3-Peer & 4-Peer Multi-Hop Swarm** → verify `send3_adaptive`, 2-hop (`:1082`), and strict 3-hop (`:1083`) SOCKS5 with symmetric return path (`Exit → Middle → Guard → Client`) and chaos kill of 1 peer.

#### F2. Repair Existing Reference Deploy & Smoke Scripts
- Fix `deploy/docker-compose.yml` (`dockerfile: docker/Dockerfile.wan` or add a dedicated `docker/Dockerfile.ggn` that builds the real headless `ggn` binary instead of `wan_mesh`).
- Replace the hardcoded `echo "✓ ..."` assertions in `scripts/smoke_test.sh` with real checks against `/api/status`, `/api/topology`, and `curl --socks5`.
- Update `scripts/mesh_smoke_test.sh` binary discovery (`ggn.exe` in addition to `vantablack.exe`) so it runs cleanly out-of-the-box on Windows and Linux.

---

### Recommended Implementation Sequence (Highest Leverage First)

| Milestone | Scope | Unlocks |
| :--- | :--- | :--- |
| **M1 — Real WAN Transport** | A1 (single-socket STUN/ICE/GTF), A2 (client relay discovery), A3 Phase 1 (`send3_adaptive` fix), A4 (default STUN + NAT classify) | Two real NATed machines + multi-peer 2/3-hop SOCKS5 actually work over WAN |
| **M2 — Blind WAN Discovery & Safety** | B1 (random nonce fix), B2 (blind Worker mailbox), B3 (`PeerDescriptor` v2 + `vb://`), B4 (`peers.bin` save), B5 (PEX v2), C1 (fail-closed exit defaults), C2 (unify ML-KEM-768 handshakes) | Zero-knowledge private WAN mesh + safe public swarm bootstrap |
| **M3 — Mesh View & Control Center v2** | D1 (fix broken UI routes), D2 (`/api/topology` + SSE), D3 (interactive Ego-Graph Mesh View + peer drawer), D4 (WAN/NAT readiness pipeline), D5 (1-click QR `vb-net://` pairing), D6 (SOCKS5/split-tunnel UI) | Honest, live visual mesh control center that reflects real WAN/LAN state |
| **M4 — Mobile WAN & Real-NAT CI** | E1–E2 (Android GTF v2 + ICE/DERP + QR scanner), B7 (`ggn --relay-only` VPS image), F1–F2 (real-`ggn` multi-NAT Docker E2E suite) | Phone on 5G ↔ Home PC over WAN + automated regression proof |
| **M5 — Divergent Sharding & Polish** | A3 Phase 2 (blind-enveloped multi-carrier RS sharding), A5 (`main.rs` modularization), A6 (interface watchdog), C4–C5 (DoS cookies + guest exit vouchers), D7–D8 (log viewer, tray polish) | Production-hardened, maintainable v1.1+ WAN mesh |

---

## Landed Status (`v1.1.0`–`v1.4.0`)

- **`v1.1.0` (`discovery`):** Fixed `BlindRendezvous` nonce reuse with fresh 12B `OsRng` nonces & 1024B chaff padding (B1), shipped `PeerDescriptorV2` (`vb://2.<b64>`), `NetworkInvite` (`vb-net://<b64>`), and `LocalPeerCache::{save_v2, load_v2}` (B3), added `BlindMailboxClient` + KV-backed Cloudflare Worker `deploy/worker/blind_rendezvous.js` (B2), and repaired `deploy/docker-compose*.yml` + `scripts/*smoke_test.sh` (F2/B7).
- **`v1.2.0` (`mesh-ui`):** Shipped Control Center REST API v2 (`GET /api/topology`, `GET /proxy.pac`, `POST /api/peers/disconnect`, `vb://` verification in `POST /api/peers/add`, `/api/mesh/{scan,config}` aliases) and the Interactive SVG Ego-Graph **Mesh View**, Peer Inspector Drawer, WAN/NAT Readiness Pipeline, Multi-Port SOCKS5 / Split-Tunnel UI, Pipeline Benchmark, and styled in-app PIN modal (D1–D7).
- **`v1.3.0` (`wan-core`):** Eliminated split `nat_socket` via single-socket STUN/ICE mux on `nc.socket` + ~25s NAT keepalives (A1), decoupled `known_relays` + `PORT` beacon TLV (A2), fixed `send3_adaptive` primary-only RS shard delivery (A3 Phase 1), added default STUN pool + `NatType` + `WanTelemetrySnapshot` (A4), unified handshakes onto ML-KEM-768 `initiate_handshake` + fail-closed public exit defaults (C1–C2), and added `ggn --relay-only` (B7).
- **`v1.4.0` (`integration`):** Wired Tier-1 `peers.bin` v2, Tier-3 `GHOST_RENDEZVOUS_URL` blind mailbox, and `GHOST_PEX2____` signed gossip into `src/main.rs`; connected live `wan_telemetry_snapshot()` + per-peer telemetry into `GET /api/topology` & `GET /api/status`; added PIN-protected `GET /api/invite` + `vb://2.` / `vb-net://` handling in `POST /api/peers/add` + Pairing Studio "Copy Signed `vb://` Invite" button; verified end-to-end in `tests/wan_full_e2e.rs`.
