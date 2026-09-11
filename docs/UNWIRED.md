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
| `NatHolePuncher` | STUN-style dual-side UDP hole punching | `punch_hole()` blind-sends 6 datagrams to a port range and then sets `connected = true` unconditionally. There is no STUN binding request/response and no verification. `with_stun_server()` stores a server that is never queried. |
| `AdaptiveShardRouter` | Route the 3 RS shards over the best paths | Unwired; also see bug **B4**. |
| `TitForTatEnforcer` | Evict peers that leech transit | Unwired; also see bug **B5**. |
| `MeshNode` | Top-level mesh integration | Unwired. Its constructor takes `Arc<tokio::sync::Mutex<PoissonReputationMatrix>>` while `main.rs` holds `Arc<PoissonReputationMatrix>` — the types do not compose. |
| `ExitIpRotator` | Rotate egress source IPs to defeat correlation | `get_next_socket_addr()` only *constructs* an `SocketAddr`. Nothing binds it. |
| `forward_to_exit_tunnel()` | Forward reconstructed payloads to an exit pool | The rotated egress address it computes is bound to `_egress_addr` and dropped. |
| `dispatch_shards_multipath()` | Multi-path relay dispatch | Unwired. |
| `spawn_mesh_tasks()` | Spawn NAT keepalive + reciprocity audit tasks | Never called. Its third task is an empty loop that only logs a debug line. |
| `EMBEDDED_DEFAULT_CONFIG` | Hardcoded bootstrap seeds | Contains literal placeholders — IPs `51.15.xx.xx`, `45.33.xx.xx`, `139.162.xx.xx` and fingerprints `deadbeef12345678`, `cafebabe87654321`, `baadf00dabcdef01`. Unreachable anyway: `main.rs` uses its own `EMBEDDED_SEEDS: &[&str] = &[]`. |

### `src/ghost/net/security.rs`, `src/ghost/net/security/hsm.rs`

| Symbol | Reality |
| :-- | :-- |
| `Tpm2Backend` | `open()` and `open_path()` **unconditionally return `Err`**. `sign()` returns `[0u8; 64]`. Not programmable hardware support. |
| `Pkcs11Backend` | `open()` unconditionally returns `Err`. `sign()` returns `[0u8; 64]`. |
| `create_hsm_backend()` / `create_hsm_backend_from_key()` | Always fall through to `SoftwareTpm`. |
| `ZkAuthenticator` | Not zero-knowledge. `create_proof` returns `(Ed25519_sign(sha256(nonce)), sha256(nonce))` — a plain signature over a prover-chosen value. `private_fingerprint_comparison` is a non-constant-time `==` on locally computed SHA-256 digests. |
| `TleDistributor` | Orbital-element store + gossip. No transport, no caller. |
| `LockedMemory` / `SecureMemGuard` | mlock/VirtualLock helpers. Unwired. |
| `RevocationList` | **Wired**, but see bug **B7**. |

### `src/ghost/net/orbit.rs`, `src/ghost/net/routing.rs`

| Symbol | Reality |
| :-- | :-- |
| `KeplerElements`, `OrbitalState`, `DeltaVTracker`, `GroundPosition`, `DisjointRouteConstraint` | Complete Keplerian propagation and delta-v math with unit tests. No caller — this is satellite/DTN scaffolding. |
| `ContactPlan`, `Journey`, `Contact`, `edge_presence`, `latency` | `ContactPlan` is *constructed* in `GhostNode::new` and never populated or queried. `latency()` returns a hard-coded 10 ms. |
| `PoissonReputationMatrix` | **Wired** — `main.rs` records interactions. But `is_byzantine()` is only ever read by the `REP` console command; nothing acts on a Byzantine verdict. |
| `ReputationMatrix` | Legacy EWMA matrix. Unwired. |
| `min_nodes_for_byzantine_tolerance` | Unwired. |

### `src/ghost/layers/`

| Symbol | Reality |
| :-- | :-- |
| `l3_shamir::split_secret` / `join_shares` | Never called. The transport uses L4 RS(2,1) only. |
| `LdpcCodec` (L7) | Never called. Its "Sum-Product / Belief Propagation" decoder is actually hard-decision **bit-flipping** — the `_vn_to_cn` and `_cn_to_vn` message arrays are allocated and never used. Its tests assert buffer *lengths*, never that a corrupted block is corrected. |
| `XtsMemoryEncryptor`, `EncryptedMemoryRegion` (L8) | Real AES-256-XTS via `xts-mode`. Never called. |
| `VerifiedRingBuffer` (L8) | SPSC ring buffer. Never called. |
| `ZeroCopyPacket`, `XdpDispatcher` (L8) | Software simulation. `route_packet()` writes a worker index into a table; the doc comment concedes "in a real eBPF/XDP implementation, this would run on the NIC". |
| `BundleProtocolHeader` (L8) | BPv7-shaped header. Never serialized on the wire. |
| `DopplerShiftSimulator` (L8) | Test scaffolding. No caller. |
| `SoftwareTpm`, `KeyEnclave`, `SecureTimeKeeper` (L9) | `SecureTimeKeeper` is constructed in `main.rs` and never read. `SoftwareTpm` here is a third distinct type of that name (see §3). |
| `BuildInfo` (L9) | Constructed in `main.rs`; `verify_manifest()` never called. |

### `src/ghost/net/dispatcher.rs`, `tun.rs`

| Symbol | Reality |
| :-- | :-- |
| `LocklessDispatcher` | `process_packet()` is a `debug!`-only stub whose own comment says it "would call into GhostNode's handle_pkt". Spawns OS threads that are never joined. The receiver in `main.rs` has a comment claiming it "uses LocklessDispatcher for parallel dispatch" — it does not. |
| `TunAdapter` (Windows/wintun) | `new()` **always returns `Err`** — `PermissionDenied` when `wintun.dll` is found, `NotFound` otherwise. `session` is never populated, so `read`/`write` return `NotConnected`. Non-Windows is an `Unsupported` stub. There is no full-system VPN mode. |
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

**B6 — `SecureMemGuard::panic_zero(&self)` writes through a shared reference.** *(OPEN)*
`&self.data as *const u8 as *mut u8` then `write_volatile` — undefined behaviour in Rust. The
sound fix is either an `UnsafeCell<[u8; N]>` or taking `&mut self`.

**B7 — the revocation list trusts its own entries.** *(OPEN)*
`RevocationList::revoke()` compares timestamps only; the `signature` field is never verified, and
the `REVOKE` console command inserts `signature: vec![]`. The list is local to the node and is
never propagated. Any operator can therefore revoke any fingerprint locally with no
authentication — fine as a local blocklist, misleading as "decentralized capability revocation".

**B8 — `encrypt_in_place_with_context` does not guard against nonce reuse.** *(OPEN)*
The receiver-side sliding window contains the damage, but the sender will happily encrypt two
different plaintexts under the same counter. `examples/attack_harness.rs`'s `noncereuse` command
demonstrates this deliberately. All in-tree callers allocate counters from
`Session::next_tx_counter()`, so the hazard requires hand-built frames — but a guard (or a debug
assertion) would make it safe by construction.

**B9 — `tests/layer_tests.rs::test_l1_compute_session_hash` cannot fail.** *(OPEN)*
It runs the call on a spawned thread and, on `Err`, prints "known platform issue" and passes.
Its comment references `ring::hkdf::expand`, but `l1_kem.rs` uses `sha2::Sha256` and the crate
has no `ring` dependency.

**B10 — `tests/layer_tests.rs::test_full_encrypt_shard_reconstruct_decrypt` never uses `l4_rs`.**
*(OPEN)* It hand-XORs a "parity" byte string and concatenates `shard0 + shard1`, so despite its
name it exercises nothing in the Reed-Solomon layer.

**B11 — `tests/simulation.rs::test_sim_packet_loss_recovery` has no assertions.** *(OPEN)*
It loops five times and `break`s; it passes vacuously.

**B12 — the test suite races on `identity.key`.** *(OPEN)*
`GhostNode::new` always reads/writes `identity.key` relative to the current working directory, and
`tests/simulation.rs` calls `cleanup_identity()` (which deletes it) before every node
construction. Cargo runs test binaries in parallel, so the tests race over one file.

**B13 — `tests/virtual_net.rs` encodes the wrong frame layout.** *(OPEN)*
Its `build_test_gtf_packet` puts the payload at offset **9** with a 487-byte maximum, while
production (`net/mod.rs`) puts it at offset **10**, after the flags byte, with a 486-byte maximum.
The corrected copy is `tests/common/virtual_net.rs`.

**B14 — `CHAT` truncates multi-word messages.** *(OPEN)*
`main.rs` parses console input with `splitn(4, ' ')` and `CHAT` takes `p[2]`, so
`CHAT <fp> hello there` sends only `hello`.

**B15 — three artifacts describe three different GTF frame layouts.** *(OPEN)*
`net/mod.rs` (payload `10..495`), `docs/SPECIFICATIONS.md` (same offsets but calls the counter
*LE* while the code writes big-endian), and `index.html`'s wire inspector
(`MAGIC[4] · NONCE[8] · POLY1305[16] · PAYLOAD[452] · NOISE[32]`).

**B16 — CI does not compile the feature-gated HSM code.** *(PARTIALLY FIXED)*
`hardware-tpm` and `pkcs11` were referenced by `#[cfg(feature = ...)]` in
`net/security/hsm.rs` but were never declared in `Cargo.toml`, so `--features hardware-tpm` was
an "unknown feature" error and the blocks could never compile. The features are now declared and
`README.md` documents `cargo check --features hardware-tpm,pkcs11`. **The CI workflow does not yet
run that check.**

**B17 — fuzz targets do not fuzz their namesakes.** *(OPEN)*
`fuzz_handle_pkt` never calls `handle_pkt` (it calls `decrypt_in_place` with a fixed key) and
`fuzz_parse_handshake_pdu` never calls `parse_handshake_pdu` (it calls `parse_rekey_pdu`,
`unframe`, `parse_relay_header`). Two of the six targets test something other than their name.
Neither is run in CI.

**B18 — `scripts/*.sh` probe a removed build directory.** *(OPEN)*
Both scripts search `C:/Users/Public/ggn-target/debug` for the binary. `.cargo/config.toml`
documents that path as removed because it "broke builds on other machines and CI".

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
