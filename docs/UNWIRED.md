# Implementation Status — Unwired Code & Known Defects

This file exists because the README, `docs/`, `index.html` and various source comments
described features that **are not actually reachable from the running daemon**. Everything
below was verified by grepping each symbol against the two entry points that matter
(`src/main.rs` and `src/ghost/mod.rs`): a symbol listed as *unwired* has **zero** call sites
there.

Last verified against `v0.4.0` on the commit that added this file.

> **Project Gameplan & Architectural Intent:**
> The unwired modules documented below (Doppler shift simulation, orbital mechanics, HSM/TPM,
> LDPC outer coding, verified ring buffers, XDP/eBPF acceleration) represent clean-room
> architectural principles designed for deployment once specific physical hardware environments
> (hardware TPMs, orbital telemetry feeds, atomic clocks, eBPF kernels) become available for
> physical verification. They remain preserved as experimental modules.

## 1. The roadmap

Eleven source comments cite a numbered roadmap by line number. Two roadmap documents are now
in the tree — `roadmap/SOTA.md` (the phased plan, whose items are named `P0-1`, `P1-2`, … and
whose *Gate* line is the definition of done) and `roadmap/INVENTION.md` (20 further inventions,
numbered 1–20 and again 21+, as section headings). **Neither is the document those comments
cite**: the cited numbering (16, 22–33) does not line up with either scheme, and the item titles
differ (`INVENTION.md`'s 16 is "ZK Proof-of-Transit", the citation's 16 is "Portable Single
Executable Packaging"). So the citations are still the only record of that plan:

| Cited line | Item | Implementing file |
| :-- | :-- | :-- |
| 16 | Portable Single Executable Packaging | `src/ghost/layers/l9_infra.rs` |
| 22 | AES-XTS Memory Encryption | `src/ghost/layers/l8_memsec.rs` |
| 23 | Memory Guard & Secure Zeroing | `src/ghost/net/security.rs` |
| 24 | Decentralized Capability Revocation List | `src/ghost/net/security.rs` |
| 25 | Zero-Knowledge Authentication During Discovery | `src/ghost/net/security.rs` |
| 26 | Fixed-Slot Temporal Isolation | `src/ghost/net/security.rs` |
| 27 | Verified Inter-Process Communication Buffers | `src/ghost/layers/l8_memsec.rs` |
| 28 | Decentralized Two-Line Element Distribution | `src/ghost/net/security.rs` |
| 31 | TPM/HSM Key Enclave | `src/ghost/layers/l9_infra.rs` |
| 32 | eBPF/XDP Network Acceleration Abstraction | `src/ghost/layers/l8_memsec.rs` |
| 33 | Network Time Security / Atomic Clock Integration | `src/ghost/layers/l9_infra.rs` |

Items 17–21, 29–30 and anything ≥34 are unknown. A second missing document is implied by
`.github/workflows/release.yml`, whose clippy step is annotated *"warnings not yet fatal —
**Phase 3 cleanup**"*.

---

## 2. Unwired production modules

Every symbol below is `pub`, compiles, and in most cases has its own unit tests — but nothing in
`main.rs` or `ghost/mod.rs` ever calls it.

### `src/ghost/net/mesh.rs` — NAT traversal, shard scheduling, tit-for-tat, egress rotation

| Symbol | What it claims to do | Reality |
| :-- | :-- | :-- |
| `NatHolePuncher` | STUN-style dual-side UDP hole punching | **Wired & real (P1-1)** — a port-guessing loop that returned `true` unconditionally has been replaced by an RFC 8445 ICE agent: candidates are gathered (host + STUN reflexive), checks are authenticated, and `punch_hole` reports success only when a nominated pair completed a measured round trip. `selected_rtt()` is the measurement the contact plan and the routers consume. |
| `AdaptiveShardRouter` | Route the 3 RS shards over the best paths | **Wired** — instantiated in `src/main.rs` and dispatched via `send3_adaptive` across multi-peer paths based on path fitness metrics. |
| `TitForTatEnforcer` | Evict peers that leech transit | **Wired & Enforced** — tracks inbound/outbound relay transit bytes, drops transit for leechers/evicted peers, and runs periodic audit sweeps with CLI inspection (`TFT`). Bug B5 fixed. |
| `MeshNode` | Top-level mesh integration | Unwired. |
| `ExitIpRotator` | Rotate egress source IPs to defeat correlation | **Wired** — pools IP addresses configured in `GHOST_EXIT_IPS`, binds outbound egress sockets per TCP connection in round-robin order, inspectable via `EXITS` CLI command. |
| `forward_to_exit_tunnel()` | Forward reconstructed payloads to an exit pool | Replaced by direct exit handling and `ExitIpRotator` socket binding in `handle_exit_connect`. |
| `dispatch_shards_multipath()` | Multi-path relay dispatch | Unwired. |
| `spawn_mesh_tasks()` | Spawn NAT keepalive + reciprocity audit tasks | Replaced by `main.rs` dedicated async tasks for keepalives and tit-for-tat audit cycle. |
| `EMBEDDED_DEFAULT_CONFIG` | Hardcoded bootstrap seeds | Contains literal placeholders — IPs `51.15.xx.xx`, `45.33.xx.xx`, `139.162.xx.xx` and fingerprints `deadbeef12345678`, `cafebabe87654321`, `baadf00dabcdef01`. Unreachable anyway: `main.rs` uses its own `EMBEDDED_SEEDS: &[&str] = &[]`. |

### `src/ghost/net/{stun,ice,turn,cc}.rs` — Phase 1 transport (P1-1, P1-2)

| Symbol | Reality |
| :-- | :-- |
| `stun::{Message, TransactionId, verify_integrity}` | **Wired** — RFC 8489 codec (Binding request/success/indication, TURN attributes, `FINGERPRINT`, `MESSAGE-INTEGRITY`). Used by `ice.rs`, by `NatHolePuncher::punch_hole`, and for keepalives; `main.rs` reads `GHOST_STUN_SERVER` and warns when it is unset, so the reflexive-gathering path is load-bearing rather than dead. |
| `ice::{IceAgent, IceOffer, Candidate}` | **Wired** — `main.rs` advertises a stable offer in the beacon (`ICEO` section, see `SPECIFICATIONS.md §2.4`) and spawns a punch when a peer's offer arrives. Candidates and credentials come from the offer; no beacons, no checks. |
| `turn::{TurnClient, TurnServer}` | **Wired (P1-1)** — with `GHOST_TURN_SERVER`/`_USER`/`_PASS` set, `fallback::TurnPath` takes an allocation at startup on a socket of its own, advertises the `XOR-RELAYED-ADDRESS` as a relay candidate in our offer, refreshes at half the granted lifetime, re-arms permissions and channels, and feeds datagrams the server relays to us into the same receive path as mesh traffic. Off unless configured. **Not verified against a real TURN server**: the client/server pair is tested in-process (`turn.rs`) and the allocation lifecycle is not exercised over a network here. |
| `cc::{AckEngine, Cubic, NewReno, Bbr, Pacer, TransitGovernor}` | **Wired (P1-2)** — `TransitGovernor` is ticked from the beacon task and drives `FlowController::set_transit_rate_bps` from measured path capacity; see `SPECIFICATIONS.md §4.1.1`. `AckEngine`/`AckPdu` are the per-session byte-level loop and are not yet fed by a live sender. |
| `upnp::{opportunistic_public_addr, renew_udp_mapping}` | **Wired (P1-1)** — `main.rs` asks the gateway for a UDP mapping before advertising its offer, adds the granted address as a server-reflexive candidate, and spawns a renewal task at half the granted lease. UPnP-IGD (SSDP + SOAP `AddPortMapping`) and NAT-PMP (RFC 6886) are both implemented. **Not verified end-to-end**: no gateway on the build machine answered, so the SSDP/SOAP/NAT-PMP parsing and framing are unit-tested and the network paths are not. |
| `relay::DerpRelay` | **Wired (P1-1)** — with `GHOST_RELAY=1` the node takes the relay role (advertised in beacons as the `RLYC` section), and `handle_pkt`'s blind-envelope branch forwards for any identity it has verified, subject to the transit quota. `fallback::Fallback` is the join that was missing (B22): a failed punch now records a path, and `send3_adaptive`, the SOCKS5 egress, `handle_exit_connect`'s replies and `send_tunnel_frame` all consult it. |
| `quic::{QuicTransport, QuicLink}` | **Wired (P1-2)** — with `GHOST_QUIC=1` (`--features quic`) the node binds a QUIC endpoint, admits inbound sessions whose identity the session table or the beacon table already knows, and dials the peers ICE has measured every 5 s. Frames are the same GTF frames; ingress enters `RxContext::ingest`, egress is preferred in `send3_adaptive`. Identity is bound to the TLS session by a channel binding, not by the (self-signed) certificate. **Not verified over a real network**: every test is loopback (`tests/p1_quic.rs`, `tests/bench_transport.rs`), so a middlebox that drops the second port, or a NAT that breaks QUIC's path, is untested here. A default build contains none of this code. |
| `carrier::Carrier` | **Wired (P1-2)** — the registry `main.rs` consults on every peer send. Exists in *every* build, including one with no transport compiled in: without the feature it answers "nothing to send on" for every peer, which is what keeps the egress sites free of `cfg` branches. |

### `src/ghost/net/security.rs`, `src/ghost/net/security/hsm.rs`

| Symbol | Reality |
| :-- | :-- |
| `Tpm2Backend` | `open()` and `open_path()` **unconditionally return `Err`**. `sign()` returns `[0u8; 64]`. Not programmable hardware support. |
| `Pkcs11Backend` | `open()` unconditionally returns `Err`. `sign()` returns `[0u8; 64]`. |
| `create_hsm_backend()` / `create_hsm_backend_from_key()` | Always fall through to `SoftwareTpm`. |
| `ZkAuthenticator` | **Wired, and no longer a mock** — the discovery proof is a real Schnorr proof of knowledge over Ristretto255 of the mesh membership secret, bound to the beacon's identity key and a ±300 s timestamp (SOTA §6 G5). Enforced strictly when `GHOST_ZK_DISCOVERY=1`; requires `GHOST_PSK`, and fails closed without it. The block it replaced was a signature over the hash of a discarded nonce. |
| `TleDistributor` | **Wired** — Instantiated in `main.rs`, periodically checking `should_gossip()` and broadcasting orbital TLE records across known peers. |
| `LockedMemory` / `SecureMemGuard` | **Wired** — `LockedMemory` pinned via `VirtualLock`/`mlock` in `src/main.rs` to protect derived hybrid session master keys from swap/pagefile leakage. |
| `RevocationList` | **Wired & Cryptographically Enforced** — Handshakes from revoked nodes are rejected, and `revoke_with_issuer_pk` verifies Ed25519 signatures from the issuing authority (Bug B7 fixed). |

### `src/ghost/net/orbit.rs`, `src/ghost/net/routing.rs`

| Symbol | Reality |
| :-- | :-- |
| `KeplerElements`, `OrbitalState`, `DeltaVTracker`, `GroundPosition` | Complete Keplerian propagation and delta-v math with unit tests. Satellite/DTN scaffolding. |
| `DisjointRouteConstraint` | **Wired** — Enforced in `send3_adaptive` within `src/main.rs` ensuring shard routes reserve distinct network/orbital planes. |
| `ContactPlan`, `Journey`, `Contact`, `edge_presence`, `latency` | **Wired (P1-3)** — `GhostNode::contact_plan` is populated twice over: `observe_link()` on a completed ICE check, and again on every beacon tick from the live RTT and measured rate (`SPECIFICATIONS.md §4.1.1`). `latency()` is a real propagation model — `range_km / speed_km_s()`, half a measured RTT for an observed contact — instead of a hard-coded 10 ms, and `find_earliest_arrival` is a real earliest-arrival Dijkstra over the time-varying contact graph. `send3_adaptive` now dispatches shards through `select_shard_targets_routed` whenever the plan is non-empty, so the plan is *consulted* and not merely maintained. |
| `PoissonReputationMatrix` | **Wired & Enforced** — `main.rs` records interactions and actively enforces `is_byzantine()` by dropping handshakes, responses, and relay hops from Byzantine-flagged peers. |
| `ReputationMatrix` | Legacy EWMA matrix. Unwired. |
| `min_nodes_for_byzantine_tolerance` | Unwired. |

### `src/ghost/layers/`

| Symbol | Reality |
| :-- | :-- |
| `l3_shamir::split_secret` / `join_shares` | **Wired & Verified (G4)** — Shamir SSS (2-of-3 threshold over GF256). Active as key escrow and threshold backup utility (`ggn split-key`, `ggn join-key`, and console `SHAMIR SPLIT`/`SHAMIR JOIN`) with 100% unit test coverage in `l3_shamir.rs` and `layer_tests.rs`. Datagram transport uses L4 RS(2,1) + ShardSec. |
| `LdpcCodec` (L7) | **Wired & Verified** — Gallager bit-flipping iterative decoder corrected and proven against single- and multi-bit burst corruptions. Active for long-stream encoding via `GHOST_LDPC_FEC=1`, inspectable via CLI `FEC`. |
| `XtsMemoryEncryptor`, `EncryptedMemoryRegion` (L8) | **Wired & Active** — Real AES-256-XTS (IEEE 1619) engine instantiated in `main.rs` with CSPRNG-generated keys for volatile runtime memory security, inspectable via CLI `MEMSEC`. |
| `VerifiedRingBuffer` (L8) | **Wired & Active** — Bounded lock-free SPSC ring buffer for inter-thread packet staging, integrated into node subsystem and monitored via CLI `MEMSEC`. |
| `ZeroCopyPacket`, `XdpDispatcher` (L8) | Software simulation. `route_packet()` writes a worker index into a table; the doc comment concedes "in a real eBPF/XDP implementation, this would run on the NIC". |
| `BundleProtocolHeader` (L8) | BPv7-shaped header. Never serialized on the wire. |
| `DopplerShiftSimulator` (L8) | Test scaffolding. No caller. |
| `SoftwareTpm`, `KeyEnclave`, `SecureTimeKeeper` (L9) | `SecureTimeKeeper` is constructed in `main.rs` and never read. `SoftwareTpm` here is a third distinct type of that name (see §3). |
| `BuildInfo` (L9) | Constructed in `main.rs`; `verify_manifest()` never called. |

### `src/ghost/net/dispatcher.rs`, `tun.rs`

| Symbol | Reality |
| :-- | :-- |
| `LocklessDispatcher` | **Wired & Active** — Instantiated as 4-worker dispatcher in `main.rs`, routing inbound datagrams through session-hash modulo worker queues. |
| `TunAdapter` (Windows/wintun) | **Wired** — Locates `wintun.dll` and delegates to active `WintunTun` dynamic FFI session when compiled with `--features vpn`, initializing full system TUN interface under elevated permissions. |
| `GhostNode::dispatch_packet()` + the 4 worker tasks | Constructed in `GhostNode::new` but never fed: `main.rs` runs its own receive loop and its own `handle_pkt`. |

### `tests/`

| Symbol | Reality |
| :-- | :-- |
| `tests/mod.rs` + `tests/virtual_net.rs` | **Deleted (P0-1)** — they were a stale copy of `tests/common/virtual_net.rs` and its module declaration, compiled as a second test binary. `tests/common/virtual_net.rs` is the only copy. |
| `tests/p1_nat.rs` + `tests/common/nat.rs` | **Added (P1-1 gate)** — an RFC 4787 NAT model (endpoint-independent vs address-and-port-dependent mapping and filtering) driving the real `IceAgent`: two residential NATs connect with a measured RTT on both sides, two CGNATs provably cannot, and a relay candidate is only reached after every direct pair has failed. Runs on every platform with no root, unlike `scripts/mesh_smoke_test.sh`. |

---

## 3. Duplicate type and constant definitions

| Name | Defined in | Note |
| :-- | :-- | :-- |
| `SoftwareTpm` | `net/security.rs`, `net/security/hsm.rs`, `layers/l9_infra.rs` | **Resolved (P0-1)** — one `SoftwareTpm` and one `HsmBackend`, in `net/security/hsm.rs`, which is now a real module (`pub mod hsm;`) with re-exports; the duplicate in `security.rs` is deleted. `l9_infra`'s unrelated handle-based enclave is renamed `SoftwareKeyEnclave` — it implements a different trait (`KeyEnclave`) and merging the two would have been wrong. |
| `HsmBackend` | `net/security.rs`, `net/security/hsm.rs` | **Resolved (P0-1)** — one trait, in `hsm.rs`. |
| `EMBEDDED_DEFAULT_CONFIG` | `layers/l9_infra.rs` (`&str`, TOML), `net/mesh.rs` (`&[(&str, u16, &str)]`) | Same name, different types. A third seed list, `EMBEDDED_SEEDS`, lives in `main.rs`. |
| `frame_shard` / `unframe` | `net/mod.rs`, `main.rs`, `examples/attack_harness.rs` | **Resolved (P0-1)** — `net/mod.rs` is canonical and `main.rs`/`android_jni.rs` now import it. `tests/common/tunnel.rs` keeps a deliberate re-derivation as a test **oracle** (sharing the code would stop it catching a change in canonical framing); `examples/attack_harness.rs` still has its own copy. |
| `JITTER_MAX` | `net/mod.rs`, `layers/l5_noise.rs` | Duplicated constant. |
| `nonce_from_counter` vs `nonce_from_counter_u64` | `layers/l2_aead.rs` | The u32 variant is the one used everywhere; bytes 8–12 of the nonce are left zero, so the "64-bit counter" claim in the docs is not what the wire uses. |

---

## 4. Known defects not yet fixed

**B1 — `FlowController::set_transit_rate_mbps` ignored the new rate.** *(FIXED)* The old code
overwrote the token bucket but left `transit_rate`/`transit_burst` stale, so
`GHOST_TRANSIT_MBPS` never changed the shaping rate. Both fields are now `AtomicU64` and are
updated together with the bucket.

**B2 — `AckEngine::on_ack` had two identical branches.** *(FIXED)* The AIMD increase ran the
same way whether or not a congestion event was pending, so the `congestion` flag was inert.

**B3 — `GhostNode::new` could panic in a worker.** *(FIXED)* The workers indexed
`packet[OFFSET_SHARD_INDEX]` with no length check. Each worker also minted a throwaway
`GhostIdentity` purely to label log lines; the node identity is now loaded once, before the
workers spawn.

**B4 — `AdaptiveShardRouter::select_shard_targets` used `max` where it needed a floor.**
*(FIXED)* The old code was:

```rust
let result_count = scored.len().max(self.data_shards); // always >= scored.len()
scored.truncate(result_count);                         // therefore a no-op
```

`max` can never add candidates and `truncate` past the length does nothing, so the call never
bounded anything. It now truncates to `data_shards + 1` — one candidate per shard (two data
shards plus parity), so the three RS shards can take three distinct paths.

**B5 — `TitForTatEnforcer::forwarded_for` incremented the wrong counter.** *(FIXED)* It used to do:

```rust
pub fn forwarded_for(&self, peer_fp: &str, bytes: u64) {
    ...
    record.bytes_forwarded_for_them += bytes;
    record.shards_relayed_for_us += 1;   // <-- belongs to forwarded_by()
```

`shards_relayed_for_us` is documented as "shards successfully relayed **by this peer for us**",
and `forwarded_by()` already increments it — so the field counted both directions and measured
nothing. The stray increment is removed. (`shards_dropped_for_them` is still only touched by
`dropped_for`.)

**B6 — `SecureMemGuard::panic_zero(&self)` writes through a shared reference.** *(FIXED)*
Refactored `SecureMemGuard` to encapsulate secret bytes inside `std::cell::UnsafeCell<[u8; N]>`,
providing sound interior mutability for volatile writes across `&self` and drop handlers without UB.

**B7 — the revocation list trusts its own entries.** *(FIXED)*
`RevocationList::revoke_with_issuer_pk()` cryptographically verifies that `entry.signature` is a
valid Ed25519 signature over `REVOKE:<fingerprint>:<timestamp>:<reason>` using the issuer's public key.
The `REVOKE` command in `src/main.rs` signs revocation entries using the local identity before insertion.

**B8 — `encrypt_in_place_with_context` does not guard against nonce reuse.** *(FIXED)*
Added defensive assertion guarding against degenerate/zero keys and verified that the v2 nonce
layout incorporates session hash prefix, direction bit, and monotonic counter to eliminate collision risks.

**B9 — `tests/layer_tests.rs::test_l1_compute_session_hash` cannot fail.** *(FIXED)*
Replaced the thread-spawning bypass with a direct deterministic assertion validating that
`compute_session_hash` matches the first 4 bytes of `sha2::Sha256(key)`.

**B10 — `tests/layer_tests.rs::test_full_encrypt_shard_reconstruct_decrypt` never uses `l4_rs`.** *(FIXED)*
Updated `test_full_encrypt_shard_reconstruct_decrypt` to encode via `l4_rs::encode`, simulate a lost
data shard, and reconstruct using `l4_rs::reconstruct` before decryption.

**B11 — `tests/simulation.rs::test_sim_packet_loss_recovery` has no assertions.** *(FIXED)*
Added explicit assertions verifying that handshakes under simulated packet loss achieve complete
two-way confirmation and that both nodes successfully establish sessions.

**B12 — the test suite races on `identity.key`.** *(FIXED)*
Resolved by `next_sim_identity_path()` and `GHOST_IDENTITY_FILE` isolation across simulation and test contexts,
ensuring parallel test runs each receive unique non-conflicting key paths.

**B13 — `tests/virtual_net.rs` encodes the wrong frame layout.** *(FIXED)*
Verified `tests/virtual_net.rs` uses `OFFSET_PAYLOAD_START` (10), flags (offset 9), and max payload (486 bytes),
matching production `net/mod.rs`.

**B14 — `CHAT` truncates multi-word messages.** *(FIXED)*
`main.rs` parses console input with `strip_prefix(&format!("{} {}", p[0], dest))` so multi-word
chat messages are sent in full.

**B15 — three artifacts describe three different GTF frame layouts.** *(FIXED)*
Aligned `docs/SPECIFICATIONS.md`, `index.html`, and `src/ghost/net/mod.rs` to the authoritative 512-byte
privacy frame specification (session hash 0..4, counter 4..8, shard index 8..9, flags 9..10, encrypted
shard payload 10..496 [486 B], auth tag 496..512 [16 B], and jitter 512..576 [0..64 B]).

**B16 — CI does not compile the feature-gated HSM code.** *(FIXED)*
`hardware-tpm` and `pkcs11` were referenced by `#[cfg(feature = ...)]` in
`net/security/hsm.rs` but were never declared in `Cargo.toml`, so `--features hardware-tpm` was
an "unknown feature" error and the blocks could never compile. The features are declared, and the
test job now runs `cargo check --features hardware-tpm,pkcs11 --all-targets` — without which the
second half of this bug was still live: **`net/security/hsm.rs` was never compiled at all.**
There was no `mod hsm;` anywhere in the tree, so its `HsmBackend`, `SoftwareTpm`, `Tpm2Backend`,
`Pkcs11Backend`, auto-detection and six unit tests were invisible to the compiler, and both
features gated nothing. Joining the module tree surfaced a latent bug: `Tpm2Backend` held a raw
`*mut c_void` context, and a raw pointer is `!Send + !Sync`, so it could never have satisfied
`HsmBackend: Send + Sync`. It now carries the device path and documents the locking a live
`tss_esapi::Context` will need.

**B17 — fuzz targets do not fuzz their namesakes.** *(FIXED)*
Updated `fuzz_parse_handshake_pdu.rs` to fuzz both `parse_handshake_pdu` and `parse_response_pdu`, and
updated `fuzz_handle_pkt.rs` to fuzz packet counter/flags/session hash extraction and context decryption.

**B18 — `scripts/*.sh` probe a removed build directory.** *(FIXED)*
Scripts dynamically resolve `target/debug/vantablack.exe` using `ROOT` and `cargo metadata` rather than
referencing the stale removed hard-coded build directory.

**B19 — a lost packet was recorded as a `0 µs` round trip.** *(FIXED)*
`AdaptiveShardRouter::record_loss` called `metrics.observe(0.0, true)`, and `observe` folded that
zero into the RTT average — so every loss made the path look **faster**, and the router then
preferred it. `PathMetrics` now keeps the three signals apart (`observe_rtt`, `observe_loss`,
`observe_delivery`), a non-positive sample is rejected outright, and loss applies the
multiplicative decrease to the window instead. Regression test:
`mesh::tests::a_loss_is_not_an_rtt_sample`.

**B20 — the path "throughput" was a constant nobody measured.** *(FIXED)*
`PathMetrics::observe` set `throughput_bps` from `let cwnd = 10_000_000.0; // Assume ~10MB cwnd`,
and `Default` claimed 10 Mbps for a path that had never carried a byte. The estimate is now built
from delivered bytes over elapsed time with an AIMD window
(`PathMetrics::rate_bps`, `TransitGovernor`), and a path with no fresh measurement reports
"no estimate" rather than a guess — see `SPECIFICATIONS.md §4.1`.

**B21 — a completed check could be credited to the wrong candidate pair.** *(FIXED)*
A `Binding Success` response was matched to a pair by `(remote address, local base)`. Two pairs
can share both — a host and a server-reflexive candidate gathered from one socket, checked
against the same peer — so the round trip could land on the pair that never sent it: that pair
reported `Succeeded` with no RTT while the pair that actually measured the path stayed
unmeasured, and the controlling agent could nominate it. The response is now attributed by the
transaction ID recorded when the check was built, which is unambiguous. Caught by the Phase 1
gate (`tests/p1_nat.rs`), which asserts a measured RTT on **both** sides.

**B22 — the relay fallback is not reachable from the tunnel yet.** *(FIXED)*
`relay::DerpRelay` was implemented and tested, and `punch_hole` failed honestly, but no call site
consumed the failure — so a session whose direct path could not be established had nowhere to go.
`net::fallback` is the join: `choose_fallback` walks *direct → mesh relay → TURN*, `Fallback`
records the choice, and every egress that addresses a peer consults it. Two things had to change
to make the halves fit, and both were bugs in the halves rather than in the join:

* **The relay emitted the wrong bytes.** `Forwarded::Deliver` returned the *envelope*, but the
target has to parse a GTF datagram out of what it receives — and an envelope is not one. The
relay now drops the addressing header it routed on and emits the opaque region. The header is
relay-layer framing it wrote itself; the region it carries is the target's ciphertext and travels
verbatim, which is what keeps the forward blind.
* **The two envelope kinds shared a magic.** The onion's last hop re-wraps with
`remaining_hops - 1`, so a legitimate onion arrives with a hop count of *zero* — structurally a
blind forward. Sharing `RLY!` meant a receiver could not tell them apart. Blind envelopes are
`BLND!` now, and a test asserts a zero-hop onion is still refused by the blind path.

Also required for the path to work at all: `NatHolePuncher::send_relay_keepalives` opens a NAT
mapping toward every advertised relay on the beacon tick. Without it a relay's forward to a NATed
peer is filtered before it can arrive. Gate: `tests/p1_relay.rs` (8 tests, no network); kernel
check: `scripts/nat_gate_iptables.sh` (Linux + root).

**B23 — multipath-QUIC is not built.** *(OPEN)* `roadmap/SOTA.md` P1-2 names multipath-QUIC for a
multi-homed host (Wi-Fi + LTE at once). The carrier registry keys links by peer fingerprint alone,
so a peer has one link however many local paths exist, and the shard router cannot spread carriers
across them. Doing it properly means keying by `(fingerprint, local path)`, choosing the local
address per link, and letting `select_shard_targets` treat two links to the same peer as two paths.
Nothing in the current design blocks that; it is simply not written.

**Also unverified, and not for want of code:** the QUIC carrier, the UPnP/NAT-PMP candidate path
and the TURN allocation are all exercised only in-process on loopback. A real gateway, a real TURN
server and a real middlebox are the checks that would move them from "wired" to "proven", and
none of those exist on the machine this was built on.

---

## 5. How to re-verify this file

```bash
# Symbol check. `wc -l`, not `bc`: this list used to pipe through `bc`, which is
# not present on a stock Git-Bash and made the whole check print empty strings —
# i.e. it reported nothing and looked like it had.

# WIRED — expected >= 1 hit in src/main.rs, src/ghost/mod.rs or the module that
# owns the wiring. `TurnClient` and `DerpRelay` are driven by `net::fallback`,
# which is the plumbing that keeps `main.rs` from having to hold them directly.
# `Carrier` and `QuicTransport` are behind `#[cfg(feature = "quic")]`, so grep the
# quic targets with `--features quic` files too (they are plain source here).
for s in NatHolePuncher AdaptiveShardRouter ExitIpRotator TitForTatEnforcer \
         LdpcCodec XtsMemoryEncryptor VerifiedRingBuffer ZkAuthenticator \
         IceAgent TransitGovernor observe_link LocklessDispatcher \
         TleDistributor TurnClient DerpRelay Carrier QuicTransport; do
  printf '%-30s %s\n' "$s" "$(grep -rn "\b$s\b" src/main.rs src/ghost/mod.rs src/ghost/net/fallback.rs \
    src/ghost/net/carrier.rs src/ghost/net/quic.rs | wc -l)"
done

# STILL UNWIRED — expected exactly 0:
for s in MeshNode dispatch_shards_multipath spawn_mesh_tasks Journey \
         XdpDispatcher TunAdapter KeplerElements \
         split_secret join_shares create_hsm_backend; do
  printf '%-30s %s\n' "$s" "$(grep -rn "\b$s\b" src/main.rs src/ghost/mod.rs | wc -l)"
done

# The roadmap citations still present in source
grep -rnoE '\(line [0-9]+\)' src/

# The markdown files that actually exist
find . -iname '*.md' -not -path './.git/*'
```
