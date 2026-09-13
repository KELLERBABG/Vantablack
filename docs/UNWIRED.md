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

## 1. The lost roadmap document

Eleven source comments cite a numbered roadmap by line number. **That document is not in this
repository** — `find . -iname '*.md'` returns only `README.md` and the five files in `docs/`.
The citations are the only surviving record of it:

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
| `NatHolePuncher` | STUN-style dual-side UDP hole punching | **Wired** — instantiated in `main.rs`, peer addresses and endpoints registered on beacon discovery. |
| `AdaptiveShardRouter` | Route the 3 RS shards over the best paths | **Wired** — instantiated in `src/main.rs` and dispatched via `send3_adaptive` across multi-peer paths based on path fitness metrics. |
| `TitForTatEnforcer` | Evict peers that leech transit | **Wired & Enforced** — tracks inbound/outbound relay transit bytes, drops transit for leechers/evicted peers, and runs periodic audit sweeps with CLI inspection (`TFT`). Bug B5 fixed. |
| `MeshNode` | Top-level mesh integration | Unwired. |
| `ExitIpRotator` | Rotate egress source IPs to defeat correlation | **Wired** — pools IP addresses configured in `GHOST_EXIT_IPS`, binds outbound egress sockets per TCP connection in round-robin order, inspectable via `EXITS` CLI command. |
| `forward_to_exit_tunnel()` | Forward reconstructed payloads to an exit pool | Replaced by direct exit handling and `ExitIpRotator` socket binding in `handle_exit_connect`. |
| `dispatch_shards_multipath()` | Multi-path relay dispatch | Unwired. |
| `spawn_mesh_tasks()` | Spawn NAT keepalive + reciprocity audit tasks | Replaced by `main.rs` dedicated async tasks for keepalives and tit-for-tat audit cycle. |
| `EMBEDDED_DEFAULT_CONFIG` | Hardcoded bootstrap seeds | Contains literal placeholders — IPs `51.15.xx.xx`, `45.33.xx.xx`, `139.162.xx.xx` and fingerprints `deadbeef12345678`, `cafebabe87654321`, `baadf00dabcdef01`. Unreachable anyway: `main.rs` uses its own `EMBEDDED_SEEDS: &[&str] = &[]`. |

### `src/ghost/net/security.rs`, `src/ghost/net/security/hsm.rs`

| Symbol | Reality |
| :-- | :-- |
| `Tpm2Backend` | `open()` and `open_path()` **unconditionally return `Err`**. `sign()` returns `[0u8; 64]`. Not programmable hardware support. |
| `Pkcs11Backend` | `open()` unconditionally returns `Err`. `sign()` returns `[0u8; 64]`. |
| `create_hsm_backend()` / `create_hsm_backend_from_key()` | Always fall through to `SoftwareTpm`. |
| `ZkAuthenticator` | **Wired** — `create_proof` and `verify_proof` wired into beacon discovery (208-byte ZK beacons) and strictly enforced when `GHOST_ZK_DISCOVERY=1` is set. |
| `TleDistributor` | **Wired** — Instantiated in `main.rs`, periodically checking `should_gossip()` and broadcasting orbital TLE records across known peers. |
| `LockedMemory` / `SecureMemGuard` | **Wired** — `LockedMemory` pinned via `VirtualLock`/`mlock` in `src/main.rs` to protect derived hybrid session master keys from swap/pagefile leakage. |
| `RevocationList` | **Wired & Cryptographically Enforced** — Handshakes from revoked nodes are rejected, and `revoke_with_issuer_pk` verifies Ed25519 signatures from the issuing authority (Bug B7 fixed). |

### `src/ghost/net/orbit.rs`, `src/ghost/net/routing.rs`

| Symbol | Reality |
| :-- | :-- |
| `KeplerElements`, `OrbitalState`, `DeltaVTracker`, `GroundPosition` | Complete Keplerian propagation and delta-v math with unit tests. Satellite/DTN scaffolding. |
| `DisjointRouteConstraint` | **Wired** — Enforced in `send3_adaptive` within `src/main.rs` ensuring shard routes reserve distinct network/orbital planes. |
| `ContactPlan`, `Journey`, `Contact`, `edge_presence`, `latency` | `ContactPlan` is *constructed* in `GhostNode::new` and never populated or queried. `latency()` returns a hard-coded 10 ms. |
| `PoissonReputationMatrix` | **Wired & Enforced** — `main.rs` records interactions and actively enforces `is_byzantine()` by dropping handshakes, responses, and relay hops from Byzantine-flagged peers. |
| `ReputationMatrix` | Legacy EWMA matrix. Unwired. |
| `min_nodes_for_byzantine_tolerance` | Unwired. |

### `src/ghost/layers/`

| Symbol | Reality |
| :-- | :-- |
| `l3_shamir::split_secret` / `join_shares` | Never called. The transport uses L4 RS(2,1) only. |
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
| `tests/mod.rs` + `tests/virtual_net.rs` | A **second, stale copy** of `tests/common/virtual_net.rs`, compiled as its own test binary. |

---

## 3. Duplicate type and constant definitions

| Name | Defined in | Note |
| :-- | :-- | :-- |
| `SoftwareTpm` | `net/security.rs`, `net/security/hsm.rs`, `layers/l9_infra.rs` | **Three** distinct types, same name, different APIs. |
| `HsmBackend` | `net/security.rs`, `net/security/hsm.rs` | Two incompatible trait definitions. |
| `EMBEDDED_DEFAULT_CONFIG` | `layers/l9_infra.rs` (`&str`, TOML), `net/mesh.rs` (`&[(&str, u16, &str)]`) | Same name, different types. A third seed list, `EMBEDDED_SEEDS`, lives in `main.rs`. |
| `frame_shard` / `unframe` | `net/mod.rs`, `main.rs`, `examples/attack_harness.rs` | Re-implemented per crate/binary. |
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

**B16 — CI does not compile the feature-gated HSM code.** *(PARTIALLY FIXED)*
`hardware-tpm` and `pkcs11` were referenced by `#[cfg(feature = ...)]` in
`net/security/hsm.rs` but were never declared in `Cargo.toml`, so `--features hardware-tpm` was
an "unknown feature" error and the blocks could never compile. The features are now declared and
`README.md` documents `cargo check --features hardware-tpm,pkcs11`. **The CI workflow does not yet
run that check.**

**B17 — fuzz targets do not fuzz their namesakes.** *(FIXED)*
Updated `fuzz_parse_handshake_pdu.rs` to fuzz both `parse_handshake_pdu` and `parse_response_pdu`, and
updated `fuzz_handle_pkt.rs` to fuzz packet counter/flags/session hash extraction and context decryption.

**B18 — `scripts/*.sh` probe a removed build directory.** *(FIXED)*
Scripts dynamically resolve `target/debug/vantablack.exe` using `ROOT` and `cargo metadata` rather than
referencing the stale removed hard-coded build directory.

---

## 5. How to re-verify this file

```bash
# Unwired symbol check — expect 0 for every name below
for s in MeshNode NatHolePuncher AdaptiveShardRouter ExitIpRotator TitForTatEnforcer \
         LdpcCodec XtsMemoryEncryptor VerifiedRingBuffer XdpDispatcher TunAdapter \
         LocklessDispatcher create_hsm_backend ZkAuthenticator TleDistributor \
         KeplerElements Journey dispatch_shards_multipath spawn_mesh_tasks \
         split_secret join_shares; do
  printf '%-28s %s\n' "$s" "$(grep -rc "\b$s\b" src/main.rs src/ghost/mod.rs | paste -sd+ | bc)"
done

# The roadmap citations still present in source
grep -rnoE '\(line [0-9]+\)' src/

# The markdown files that actually exist
find . -iname '*.md' -not -path './.git/*'
```
