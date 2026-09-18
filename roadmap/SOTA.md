# Vantablack — SOTA Roadmap (v0.4.1 → v1.0)

> Opinionated, prioritized plan to make every plane **undisputed state-of-the-art** at open-source launch. Each plane is scored brutally honestly; each phase has a gate that must be green before the next starts. Owners are roles, not people — assign names at kickoff. Effort = calendar time for a focused 2–3 person cell on that plane (not total project).

Source of truth for **status**: `roadmap/WHAT-IS-BUILT.md` — plain English, says what is actually built and tested versus what is only built or not built at all. Read that first; it is checked against the code and against a real test run. This file remains the *plan*: phases, gates, owners and effort. `roadmap/index.html` is a rendered summary. `roadmap/INVENTION.md` is the parallel invention track — pick 2-week spikes from there while this file ships v1.0. The per-symbol wired/unwired table and the defect backlog that used to live in `docs/UNWIRED.md` and `docs/THINKTANK-BIN.md` were removed on 2026-09-17; everything in them that was still true is folded into `roadmap/WHAT-IS-BUILT.md`, and the old files remain recoverable from git history (commit `59fd7f6`).

### Current code-side delta — negotiated handshake and ShardSec primitive

New outbound sessions use an explicit suite-list handshake. Each advertised suite carries its own KEM public key, the responder deterministically selects the strongest common suite, and the complete offer/selection transcript is signed. Initiators reject a response that is not the strongest suite they offered, so a responder or path attacker cannot force ML-KEM-512 when ML-KEM-768 is mutually available. ML-KEM-512/768 are both wired through the live responder/initiator KEM paths and session HKDF domains; legacy fixed-layout handshakes remain available for compatibility. `GHOST_SHARDSEC=1` now activates a live `FLAG_SHARDSEC` GTF path: per-shard authentication occurs before RS reconstruction, while the legacy single-message AEAD path remains available for mixed-version rollout. Runtime multi-node interoperability and mixed-version migration remain validation gates.

### Release handoff status — 2026-09-17

The repository-side SOTA implementation baseline is built for the features declared here. From this point, completion means running the documented tests and operator/device validation gates; it does not mean those gates have already passed. The SOTA claim must therefore be read as **implementation-complete, validation-pending**, not as a blanket assertion of real-world readiness. Hardware-backed TPM/PKCS#11 execution, Apple signing/provisioning, physical Android handover, real NAT/CGNAT/TURN paths, and formal-model execution remain environment-controlled acceptance gates. The current operator is on a company-managed network where external traffic and traversal experiments are restricted, so those network-facing gates are intentionally paused rather than marked failed. No further code-side work should be inferred from a green compile alone. **One caveat for the rest of this file:** test counts quoted *inside* individual items below are the numbers observed when that item landed, not today's, and a few of those items still refer to `docs/UNWIRED.md` / `docs/THINKTANK-BIN.md`, which were removed on 2026-09-17. The current measured numbers are in the Verification row and in `roadmap/WHAT-IS-BUILT.md`.

---

## 0. Scoreboard today (v0.4.1 + `vpn` feature)

| Plane | Claim | Reality | Gap to SOTA | Priority |
|---|---|---:|---|---|
| **Crypto (L0–L2, L6)** | hybrid `X25519+ML-KEM-512`, XChaCha20-Poly1305, SessionGuard | Real `ml-kem 0.3 / x25519-dalek / chacha20poly1305 / ed25519-dalek`, PSK→HKDF salt, `nonce=[sh[0..2]\|dir\|ctr BE]` correct, 128b sliding window, `prototcol` replay/TAMPER scenarios. **Identity is now hybrid** (P2-1, partial): Ed25519 + ML-DSA-65 with an independent PQ seed, `identity.key` v2, a `PQK!` beacon commitment, and per-peer pinning that refuses a changed PQ key — but the proof of possession rides **only the QUIC carrier binding**, because beacons (≤ 1472 B) and handshake PDUs (≈ 880 B) cannot hold a 5362-byte proof, so a peer that never uses the carrier is pinned without ever being proven, and no `SLH-DSA` agility. P0-2 closed the rekey gap (seal-at-drain + watchdog re-handshake); **P2-2 landed the ratchet and the wire change:** keys now come from a hybrid DH ratchet with per-epoch chains (forward secrecy + break-in recovery), the AEAD is XChaCha20-Poly1305 over a transmitted 96-bit random nonce, counters are 64-bit with `SessionGuardU64` primary, and GTF is v2 (epoch + nonce on the wire, 458-byte shard region) with v1 still accepted. The ratchet **step now has a transport**: a 5 s maintenance tick starts a step for every session whose epoch is spent, the PDU rides the re-key shapes in one bulk v2 frame each way, `handle_pkt` dispatches it before any application handling, the signature is checked against the handshake-pinned identity key, the responder installs a prepared epoch only once a frame authenticates under it, and an unanswered step is abandoned after 30 s and retried — with a fingerprint tie-break (`admit_peer_step`) for the case both peers come due at once, which without it would install epoch $n+1$ on each side from different roots and split the session permanently. A **live rotation is now proven** (`ratchet_live_tests`: two real nodes on loopback sockets, a spent epoch, the real tick, and both directions of traffic through the real ingress and handler — bob prepares epoch 1, alice completes it, a data frame installs it on bob, one key per direction). That test exists because the transport was half-delivered in a way only it could show: the ingress honoured the self-contained frame bit (`0x02`, which is how a step PDU travels) only under `#[cfg(feature = "vpn")]`, so a **default build** spooled every step as an unrecoverable shard and dropped it silently while a VPN build rotated fine — and the same bypass carries a relay hop's blind envelope. The gate is gone, and `RxContext` was lifted out of `main` (a function-local type cannot be built by a test, which is why `ingest` had no coverage). Still open: the epoch is spent by calling `note_sealed_frame` rather than by moving 1M datagrams, and both nodes share one process on loopback, so a rotation under a real network's saturation and loss is unproven; the VPN inner envelope and the SENDRELAY inner layer keep their own 32-bit counter nonces; and possession of the post-quantum identity key is proven only on the QUIC carrier binding, so a peer that never uses the carrier is pinned without ever being proven. **Cipher-suite agility has left this list:** the negotiated suite-list handshake recorded above selects the strongest common suite (ML-KEM-512 or ML-KEM-768) and the initiator rejects a response that is not the strongest it offered, which is the `X25519Kyber768` gap this row used to name as open. | `P0` — fix before any audit |
| **Network (NAT/relay/transport)** | zero-config mesh | **Phase 1 landed the traversal stack.** RFC 8489 STUN + RFC 8445 ICE replace the port-guessing loop (`punch_hole` reports success only on a completed, measured check; `selected_rtt()` is a real measurement); TURN allocation, DERP-style blind relay and the `direct → mesh relay → TURN` ladder are wired (`net/fallback.rs`); UPnP-IGD/NAT-PMP supply an opportunistic candidate; `ContactPlan::latency()` is a real propagation model and `Journey` is populated by earliest-arrival Dijkstra, which `send3_adaptive` now consults; `FlowController` is still a policy ceiling but `cc::TransitGovernor` shapes it from measured path capacity. QUIC is an optional carrier under GTF (`--features quic`, `GHOST_QUIC=1`), and **multipath-QUIC is built on it** (B23): links are keyed by `(fingerprint, local address)`, `GHOST_QUIC_MULTIPATH=1` + `GHOST_QUIC_LOCAL_ADDRS` name the local paths, and `Carrier::send_shards` puts one RS shard on each path before any path carries a second. **Remaining:** the local-address set is named rather than discovered (this crate enumerates no interfaces), dispersal needs three paths (two split 2 + 1), and no genuinely multi-homed host has been exercised — the gate uses two loopback addresses; router-side NAT behaviour (endpoint-independent mapping *and* filtering) is modelled and unit-tested but pinned by no published reference vector; every traversal test is loopback or in-process — no real gateway, TURN server or middlebox has been exercised. | `P1` — the P0 adoption block is cleared; proof on real paths is the gap |
| **Anonymity / traffic** | DPI-resistant | **P3-1 and P3-2 are both implemented and gated.** The length channel is closed — every privacy frame is a constant 576 B — and the jitter tail is authenticated as AEAD associated data, so a rewritten tail fails the tag (`tests/p2_wire.rs::p3_1_a_rewritten_jitter_tail_fails_the_tag`). The link is never silent: `spawn_cover_task` emits an ordinary RS(2,1) group of 576-byte frames on a constant *mean* with **exponential** gaps (a fixed interval would be a metronome), and the receiver drops it on the **authenticated** `DUMMY_MAGIC` inside the ciphertext rather than on the forgeable header bit (`src/main.rs::p3_1_cover_tests`). Emission is a bounded three-message/nine-frame batch with a 20 ms flush bound; live v2 dispatch selects deterministic earliest-arrival routes and enforces the three-shard route budget; and `RLY!` is backed by the 3-hop guard→middle→exit onion with signed, expiring `EXITAUTH` vouchers. **What remains is proof and scope, not mechanism:** the DPI/timing classifier gate this phase is defined on has never been run, and no shape or uniformity test exists at all — the removed `pentest_ggn.sh` covered only handshake-flood, spool-flood, forged-beacon and replay; cover is scoped to established peer sessions rather than fabricating unrelated-peer decoys (safe decoys need a relay-aware envelope and their own noise budget); and there is no Nym-class mix network. | `P1` |
| **Hardening (L8/L9)** | memory + HSM + time | `LockedMemory`/`SecureMemGuard<UnsafeCell>` + `XtsMemoryEncryptor` now wired, `PoissonReputationMatrix::is_byzantine` enforced, `RevocationList::revoke_with_issuer_pk` Ed25519-verified. The P0-1 duplication is gone (one `SoftwareTpm`/`HsmBackend`, one `XtsMemoryEncryptor`/`VerifiedRingBuffer`, one canonical `frame_shard`) and CI builds every feature combination. **P2-3's software half has now landed:** the `TemporalIsolator` `DUMMY_ITERATIONS` padding loop is gone — it was a fixed *additive* cost that hid nothing, and `ml-kem` 0.3.2's `decapsulate` is itself constant-time via FIPS 203 §7.3 implicit rejection (`ct_eq` + `ct_select`), now pinned by round-trip and implicit-rejection tests rather than asserted; `security::attest::AttestationEnvelope` fixes the DPE/TPM quote *format* and its verification (Ed25519, constant-time nonce/issuer compare) with deliberately no hardware behind it; and `HsmError` is the typed `open()` error that stops "no hardware here" and "hardware present but broken" from arriving as the same `String`. What remains is the **HSM-real** half — unsimulated, hardware-dependent work: `Tpm2Backend`/`Pkcs11Backend::open()` still always returns `Err`, `sign=[0;64]` is still unreachable-but-unwired, `SecureTimeKeeper` never read, `Kepler/DeltaV/Doppler` scaffolding. | `P2` — see P2-3 |
| **Platform** | desktop + mobile | Desktop `wry/tao` frameless + tray + `ghost.log` solid. **Packaging is now implemented in-repo.** `scripts/build_installer.ps1` downloads and stages the **official Wintun 0.14.1** archive when no operator-supplied DLL is given (the dev Tailscale copy and its licensing gap are gone) and rejects an unexpected archive layout; `installer/ggn.iss` keeps `PrivilegesRequired=lowest` with per-user state. Linux has a `.deb` builder, a hardened systemd unit and a desktop entry; macOS is documented under `packaging/macos/`; Android runs `GhostVpnService` as a **foreground VPN service** that re-binds its socket on network handover and defaults DNS to `10.66.0.1` with optional search-domain push. **What remains is environment-gated, not code:** signing and update publication are CI/secrets operations, macOS `NetworkExtension` needs an Apple developer account, and the `WiFi→LTE` mid-connection handover has not been run on a physical device. | `P1` |
| **Verification** | audit-ready | Measured on this checkout, Windows / nightly, 2026-09-17, **zero failures** anywhere: `cargo test --all-targets` → **316** library tests plus every integration target green; `--features vpn` → **344** library tests + every `vpn_*` gate; `--features quic` → **322** library tests + the QUIC gates; `--features hardware-tpm,pkcs11` → **318** library tests. Per-target: `tests/p2_wire.rs` (6 — the v2 wire/ratchet gate, including the P3-1 tail-authentication test), `tests/handshake_interop.rs` (3 — the negotiated-suite and mixed-version gate), `tests/layer_tests.rs` (46), `tests/p1_nat.rs` (7), `tests/p1_relay.rs` (8), `tests/simulation.rs` (7); `src/main.rs`'s 14 tests run twice because two `[[bin]]` targets share that file. Phase 1 gates need no network and no privileges; the removed `nat_gate_iptables.sh` checked the NAT model against the real kernel (Linux + root, never run here); the `bench-transport` profile compares the carriers. **Still missing: execution.** `formal/ghost_session.pv` exists and CI runs `proverif formal/ghost_session.pv`, but neither `proverif` nor `tamarin-prover` is installed here, so no machine-checked proof has actually run; and the real two-machine NAT44/CGNAT + LTE run the Phase 1 gate is defined on has not happened. `cargo fmt -- --check` is also red (about 70 differences across 11 files, under both nightly and stable), which predates this work. | `P1` |

**Verdict:** v0.4.1+vpn is the most *honest* mesh research prototype in the open — gaps are catalogued and measured — but `undisputed SOTA = beat Mullvad/Tailscale + Tor + WireGuard + Nym simultaneously`. Phases below close that in order.

---

## 1. Phasing (ship gates, not dates)

### Phase 0 — Stops-the-line — **COMPLETE**

P0-1 (dedup & feature hygiene), P0-2 (`seal-at-drain` + pre-wrap rekey) and P0-3 (poison
allowlist) have all landed; their acceptance criteria, evidence and touch-lists were recorded in the
execution log and defect backlog that have since been removed. The Phase 0 gate is met as far as
this tree can meet it: `cargo test` is green and CI builds
`vpn`, `no-default-features`, `hardware-tpm,pkcs11`, `quic` and `quic vpn`. **Phase 0 is closed at
the file level too:** the one P0-1 action that had not stuck was the deletion of the stale
`tests/mod.rs` + `tests/virtual_net.rs` pair, and both are **gone** — `tests/` holds only the live
targets. Phase 0 has no open file-level exceptions.

Phase tags below are **not** renumbered, deliberately: `(SOTA P1-2)`-style citations live in the
source, and shifting the numbers would make every one of them wrong. "P0/P1/P2/P3" here remains
the vocabulary the code uses.

### Phase 1 — Makes the mesh *reachable* (3–5 weeks, 2 cells in parallel)

Gate: **two real machines behind residential NAT44/CGNAT + phone on LTE** establish a tunnel with `GHOST_VPN=hub/client` *without* port forwarding and sustain `ping`/`curl`/`iperf` through a symmetric-NAT handover.

> **Status (implementation):** all three workstreams are built and gated by tests that need no
> network and no privileges; the *gate as written* requires two real machines and a phone, which
> has not been run. P1-1, P1-2 (multipath-QUIC included, B23) and P1-3 are complete in code, and
> every item in the defect backlog was FIXED or BUILT before that backlog was removed — no open
> defect lines remained. `roadmap/WHAT-IS-BUILT.md` §2 carries what is wired-but-unproven: on real
> paths, essentially all of it.

* **P1-1 Real ICE (STUN/TURN) + DERP fallback.** Replace prediction loop with RFC 8489 STUN binding + RFC 8445 ICE candidate gathering/prioritization/connectivity-check + local TURN allocation. Add encrypted DERP-style relay through any mesh peer via `relay.rs` `BundleBuffer`/`build_relay_packet` when direct fails — sealed GTF forwarded as blind ciphertext (relays learn nothing). Add UPnP-IGD/PMP as opportunistic candidate. Owner: **Net cell**. Effort: `2–3w`. Touch: `net/mesh.rs`, `net/relay.rs`, `net/orbit.rs` (plane constraint stays). Test: `tests/p1_nat.rs`'s NAT model extended with an `iptables` symmetric-NAT topology.
* **P1-2 QUIC + congestion.** QUIC (e.g. `quinn`) as optional transport under GTF for lossy/censored paths; multipath-QUIC when multi-homed (Wi-Fi+LTE). BBR/CUBIC over `FlowController`, proper `AckEngine::on_ack` AIMD fix (B2 already closed, but promote to real CC). Owner: **Transport cell**. Effort: `2–3w`. Verify: `GTF_bulk` vs `QUIC` bench (`cargo test --profile bench-transport --features quic --test bench_transport -- --ignored`).
* **P1-3 True CGR routing.** Populate `ContactPlan` from real contacts (beacons, TLE propagation via `TleDistributor::should_gossip/build_gossip_message`), Dijkstra `find_earliest_arrival` with real `latency(e,t)` (laser `c`/`range`), integrate `DeltaV`/`DisjointRouteConstraint` enforcement already wired for shards. Owner: **Routing cell**. Effort: `1–2w`.

### Phase 2 — Makes the crypto *future-proof* (3–4 weeks, overlaps P1)

Gate: `cargo test --features vpn,hardware-tpm` + formal model checks `tamarin/proverif` for session unforgeability, forward secrecy, PQ hybrid — no mock primitives in proof scope.

> **Status (implementation):** P2-1's identity half is in (hybrid Ed25519 + ML-DSA-65,
> `identity.key` v2 with in-place migration) and its proof is verified on the QUIC carrier binding;
> the beacon, handshake, `REVOKE` and voucher paths are still classical-only. **P2-2 has landed** —
> the hybrid session ratchet, `XChaCha20-Poly1305` with a transmitted 96-bit nonce, 64-bit counters
> with `SessionGuardU64` primary, **GTF v2** (v1 still accepted), *and* the step's transport: a 5 s
> maintenance tick starts a step for every spent epoch, the PDU rides the re-key shapes in one bulk
> v2 frame each way against the identity pinned at handshake time, and a live rotation is proven by
> `ratchet_live_tests` (two nodes, the real tick, the real ingress and the real handler). What
> remains for P2-2 is the *interval*, not the mechanism: the epoch is spent by calling
> `note_sealed_frame` 1M times rather than by moving 1M datagrams, and both nodes share one process
> on loopback, so a rotation under a real network's saturation, loss and reordering is unproven.
> The project has since moved on: **P3-1, P3-2, P4 and P5-1 are implemented** (see their sections
> below), so what follows records only Phase 2's own remainder. P2-3's *software-doable* half has
> landed — the `TemporalIsolator` dummy-padding loop is gone, the `ml-kem` constant-time audit is
> pinned by tests, `security::attest` carries the DPE/TPM-shaped envelope, and `HsmError` is the
> typed seam in `hsm.rs` (see the P2-3 item below). Exactly two things keep Phase 2's gate open:
> the **HSM-real** half is *deferred by hardware* — `tss-esapi` / `cryptoki` are not dependencies and
> `open()` still always reports absence, so there is no hardware key path and no hardware
> attestation — and the formal model, which now **exists** as `formal/ghost_session.pv` and is run by
> CI's `formal-model` job (`proverif formal/ghost_session.pv`), has **not been executed on this
> machine** because `proverif`/`tamarin-prover` are not installed here. P2-1's "no agility" gap is
> closed by the negotiated suite handshake recorded in §"Current code-side delta".

* **P2-1 PQ signatures + agility.** **Landed in part:** `GhostIdentity` is hybrid — Ed25519 + `ML-DSA-65` (`ml-dsa`, RustCrypto, pure Rust) with an independent PQ seed, `identity.key` upgraded in place to a 73-byte v2, and `sign_hybrid`/`verify_peer_hybrid` requiring both halves. The PQ proof is **wired where it fits** — the QUIC channel binding, signing `keying_material ‖ PQ key`, refusing a classical-only v1 binding — and the key is **named and pinned** everywhere else: a `PQK!` beacon section carries the 32-byte commitment, and the registry pins it per peer on first sight and **refuses a later session presenting a different one** (`PqMismatch`), which is what stops a forger with the classical private key from substituting a PQ key. **Remaining for P2-1:** possession of the committed key is proven only on the carrier, so the handshake itself must carry a PQ exchange (a beacon ≤ 1472 B and a handshake PDU ≈ 880 B cannot hold 5362 bytes); and `REVOKE`/capability-voucher signatures are still classical-only. **No longer remaining:** cipher-suite agility is closed by the negotiated suite-list handshake in §"Current code-side delta" — strongest common suite selected, downgrade rejected at the initiator, `HKDF("GHOST_NET_MASTER_KEY_v3/X25519-MLKEM768")` domain separation — and the `fuzz/` target for the binding parser exists (`fuzz/fuzz_targets/fuzz_parse_quic_binding.rs`). Owner: **Crypto cell**. Effort: `2w` (`~4d` spent).
* **P2-2 Double Ratchet + XChaCha20.** **Landed (crypto + wire + transport); the remaining gap is the real-network rotation, named below.** `SessionRatchet` (`ghost/session/ratchet.rs`) is a hybrid DH ratchet: two directional chain keys, each advanced one one-way `kdf_ck` step per epoch, reseeded by `kdf_rk_hybrid` (HKDF-SHA256 salted with the *previous root key* over a fresh X25519 shared secret **and** a fresh ML-KEM-512 shared secret) — forward secrecy from the symmetric step, break-in recovery from the DH step, both halves mixed because the classical half alone is what a quantum adversary walks through. `XChaCha20-Poly1305` with a **transmitted 96-bit random nonce** is the AEAD; the counter is no longer the nonce, so it widened to 64 bits and `SessionGuardU64` is now the primary replay window (the u32 near-exhaustion watchdog this item existed to remove is gone with it). A **step is due every `RATCHET_INTERVAL` = 1M datagrams** (`SealMaterial::ratchet_due`), the session retains the current + 2 retired epochs so frames in flight across a step still open, and **GTF is bumped to v2**: `FLAG_V2` at the v1 flags byte, 64-bit counter, ratchet epoch, transmitted nonce, shard region 486 → 458 B; v1 frames are still *accepted* (`open_received_frame`) and still *sent* on the non-VPN inner layers. The step handshake (`begin/answer/finish_ratchet_step`) carries a **confirmation tag** derived from the new epoch key, because X25519 returns a shared secret for a wrong or low-order key rather than an error — without it a step could "succeed" on both sides with divergent keys. **The step's transport landed** — the piece that was missing: a 5 s maintenance tick starts a step for every session whose epoch is spent, the step rides the `Rekey` PDU the item names (the pre-existing `build_rekey_pdu`/`parse_rekey_pdu` shapes, no longer dead code) in one bulk v2 frame each way, `handle_pkt` dispatches it before every application magic, the PDU's signature is verified against the identity key pinned at handshake time, the responder *prepares* an epoch and installs it only when a frame authenticates under it, and an unanswered step is abandoned after 30 s and retried — traffic continuing on the current key the whole time. The transport is what exposed the **crossed-step split**: both peers tick the same interval, so both can be due at once, and if each completed its own step both would install epoch $n+1$ over different root keys — same number, no frame opens again, no later step able to repair it. `Session::admit_peer_step` resolves it by fingerprint order (the lower one keeps its step; the other abandons its own and answers the arriving one), and both the split and the resolution are pinned by tests. **Verified live:** `ratchet_live_tests` rotates a real session's epoch end to end — two nodes, loopback sockets, the real tick, the real ingress and the real handler — and fails if the ingress stops honoring the self-contained frame bit in a default build (it did, until this pass: the bypass sat behind `#[cfg(feature = "vpn")]`, so a default build silently dropped every step PDU as an unrecoverable lone shard, and the same bypass carries a relay hop's blind envelope). **Remaining for P2-2:** the epoch is spent by calling `note_sealed_frame` 1M times rather than by moving 1M datagrams, and both nodes share one process on loopback, so a rotation under a real network's saturation and loss is unproven; and the `GVPN1` tunnel envelope and the `SENDRELAY` inner onion layer still seal with their own 32-bit counter-derived nonce (the SENDRELAY inner counter is carried in the onion header and a value that no longer fits is refused rather than truncated). Owner: **Crypto/Session**. Effort: `2w` (`~2d` spent on core + wire + transport). Verify: `test_double_ratchet_forward_secrecy` ✔, `tests/p2_wire.rs` (5), `ratchet_transport_tests` (2), `ratchet_live_tests` (2 — the live rotation; the negative check was re-running one with the `vpn` gate restored and watching it fail).
* **P2-3 Constant-time & HSM-real.** **Landed in part — the software-doable half only.** **(a) The dummy loop.** `TemporalIsolator::fixed_time_decapsulate` used to run the real decapsulation and then ten *dummy* ones (`DUMMY_ITERATIONS`) "for timing padding". That is a fixed **additive** cost, so whatever variation the real decapsulation has sits on top of it, fully visible — it made the call 10× slower and no more constant-time. Constant time is a property of the decapsulation itself, and `ml-kem` 0.3.2 already has it: FIPS 203 §7.3 **implicit rejection**, implemented as `Kbar.ct_select(&Kp, cp.ct_eq(encapsulated_key))` (`ml-kem-0.3.2/src/decapsulation_key.rs:172-178`) — no secret-dependent branch, no secret-dependent memory access. The function is now exactly one decapsulation, and a rejected ciphertext yields a pseudorandom secret rather than an `Err`, so the failure path has the same *shape* as the success path. **(b) The audit is now tests, not prose.** Five of them: a round trip comparing the returned secret to the encapsulator's **with `subtle::ConstantTimeEq`**; a tampered ciphertext that must yield a *different* secret with no error and no panic; and an all-zero ciphertext — the shape `fuzz/fuzz_targets/fuzz_kyber_ciphertext.rs` feeds it, which needed no edit because the signature did not change. **(c) A DPE/TPM-shaped attestation envelope.** New `security/attest.rs`: `GGNATT` ‖ version ‖ `quote_digest[32]` ‖ `nonce[32]` ‖ `issuer_pk[32]` ‖ Ed25519 `signature[64]`, with `issue`/`encode`/`decode`/`verify(expected_nonce, issuer_pk)`. Nonce and issuer are compared in constant time; the digest and version are bound by the signature instead of compared, so a tampered digest *is* a signature failure. **It is a format and a verification path, not hardware** — the module says so, and nothing produces a real quote yet. **(d) The HSM seam.** `HsmError` (`HardwareAbsent` / `SessionOpenFailed` / `KeyOperationFailed`) replaces the bare `String` from `Tpm2Backend::open`/`open_path`/`generate_key` and `Pkcs11Backend::open`, so "no hardware here" (fall back) and "hardware present but broken" (report) stop being the same value. **Additive: not one `HsmBackend` method signature changed.** The `[0u8; 64]` `sign()` sentinel is documented as unreachable by construction and is still verified properly by `verify()`. **Still open — and now explicitly *deferred by hardware* (decision recorded this pass):** `tss-esapi` / `cryptoki` are **not dependencies and not wired** — `open()` still always reports `HardwareAbsent`, `create_hsm_backend` still resolves to `SoftwareTpm`, and there is **no hardware key path and no hardware attestation** (the envelope has no producer, so it is a format waiting for one). The blocker is physical, not stylistic: there is no TPM 2.0 device and no PKCS#11 token on the build machine, so a real backend could be *written* but never executed or verified — and an unexecuted hardware path is not something this project presents as landed. `SecureTimeKeeper` is still never read. Phase 3 work proceeds with this recorded as deferred, not as resolved. Owner: **Hardening cell**. Effort: `2–3w` (`~1d` on the software half). Verify — **run and green this pass:** `cargo test --no-default-features --lib` (299 ✓) and `--test layer_tests` (46 ✓, both `test_p2_3_temporal_isolator_*`); `cargo test --features hardware-tpm,pkcs11 --lib` (301 ✓, including all 8 `attest` tests, both `*_open_reports_typed_absence`, and all 3 `test_constant_time_decapsulate_*`); `cargo test --features vpn` green on every target (327 lib + each integration gate, 0 failures); `cargo check --all-targets`, `--no-default-features --all-targets` and `--features hardware-tpm,pkcs11 --all-targets` all clean. `cargo fmt -- --check` fails only on 67 pre-existing nightly-rustfmt diffs, none in the four files touched here; the fuzz `cargo check` cannot run (no `g++` for libfuzzer's shim — the fuzz target was not modified).

### Phase 3 — Makes the anonymity *real* (2–3 weeks)

Gate: standard DPI classifier + timing correlator cannot distinguish idle / `iperf` / `SOCKS` over GTF better than random; single-relay compromise leaks zero plaintext (verified by `attack_harness`).

* **P3-1 Uniform frames + mixing.** **Complete — the length channel is closed, the padding is authenticated, the link is never silent, and emission/routing are live.** Three parts, all landed and verified. **(a) Constant length.** `build_gtf_v2_frame` no longer draws `gen_range(0..JITTER_MAX)`; it writes a full `JITTER_MAX` (64)-byte tail, so every privacy frame is a **constant 576 B** and its length says nothing about its payload or shard. That half was sender-side-only — 576 B was already the accepted maximum and the receive path slices by v2 offsets and ignores the tail — so no parser, offset or receiver change was needed. **(b) Authenticated.** The tail now rides as AEAD **associated data**: `xchacha_seal_in_place_with_aad` / `xchacha_open_with_aad` were added beside the existing `&[]` wrappers, so the ~15 unrelated `xchacha_*` call sites (ratchet tests, v1 path) were untouched. The receiver feeds the tail it **read off the wire** (`frame_tail` → `V2FrameMeta::tail`) rather than a value it recomputed, because recomputing would authenticate the sender's *intent* and silently accept a rewritten tail. One flipped tail byte now fails the tag. The tail is *derived* (`tail_for`, a keyed HMAC-SHA256 of key ‖ nonce ‖ epoch ‖ direction) rather than drawn, for two reasons that force each other: the three shards of one message share **one** AEAD tag, so they must share one tail; and the sealer (`enc_split`) and the frame-builder (`SealCtx::header`) are separate functions that never see each other's value, so it has to be recomputable instead of threaded through ~20 call sites. **The layout is unchanged** — same 576 B, same offsets, no version marker — because this moves the tag's *input*, not the wire format. Gates: `tests/p2_wire.rs::p3_1_a_rewritten_jitter_tail_fails_the_tag` (constant length; honest frame opens; flipped byte rejected) plus `test_p3_1_privacy_frames_are_always_the_same_length`, and the whole matrix green (`cargo test --all-targets`: lib 300 ✓ and every integration target ✓; `--features vpn`: 328 ✓ and every `vpn_*` gate ✓; `check --no-default-features` and `--features hardware-tpm,pkcs11` clean). The change also corrected the *existing* same-length test, which asserted that two frames of one message **differ** in the tail — a random-tail property that is now wrong rather than merely stale, since the shards of one message must share a tail; it now asserts the PRF properties (deterministic per message; different for a different nonce, epoch, direction or key; never a run of zeros). **(c) Cover traffic, so the link is never silent.** `FLAG_DUMMY = 0x04` is reserved (bit 2, free for the same reason bit 7 was: a v1 sender only writes `0x00`–`0x03`) and the builder's caller-bit mask widened to `FLAG_BULK | FLAG_TUNNEL | FLAG_DUMMY`, because before that the bit was silently masked off and the flag would have looked supported while never reaching the wire. `DUMMY_MAGIC` (`b"DUMMY!"`) marks a placeholder payload, and `spawn_cover_task` emits one cover **message** per drawn gap per session, over the *real* data path — `enc_split` then three 576-byte privacy frames — so on the wire it is an ordinary RS(2,1) group and not something shaped differently, which would be worse than no cover because it would announce itself. Gaps are **exponential, not fixed** (`cover_gap`): a fixed interval is a metronome, whereas a constant *mean* with exponential gaps is what a Poisson stream looks like. At `COVER_FRAMES_PER_SEC = 2.0` (the plan's "2 pkt/s", read as frames) that is ~1.2 KiB/s per session. It is deliberately **not** gated on idleness — cover that appears only when the link is quiet makes the *rate* the signal, which is the failure the item exists to avoid. **Two things done differently from the plan, deliberately.** First, the plan's "a Dummy frame must not spend the ratchet epoch" cannot be honoured: these are real frames, and making the receiver refuse to count them is a replay-window hole. The honest number instead is that at 2 frames/s a 1M-frame epoch is ~139 h of cover alone, so cover can at most halve what an epoch carries, and only while the node is otherwise idle. Second, `FLAG_DUMMY` is a **hint, not the decision**: header flags sit outside the AEAD, so anyone on the path can flip them and a receiver trusting the bit could be made to discard a real frame or dispatch a placeholder. The receive path therefore drops cover on the *authenticated* `DUMMY_MAGIC` inside the ciphertext, before the replay window and before any ratchet bookkeeping, and counts it in `stats.cover_recv` rather than `stats.drops` (it is not loss). Gates: `main.rs::p3_1_cover_tests` — the bit survives the builder's mask, a cover frame is a 576-byte privacy frame, the marker is recognised after decryption while a near-miss is not, and the gaps have the right mean *and* vary. Whole matrix green (`cargo test --all-targets`: lib 300 ✓, bin 14 ✓ ×2, every integration target ✓; `--features vpn`: lib 328 ✓ and every `vpn_*` gate ✓; `check --no-default-features` and `--features hardware-tpm,pkcs11` clean). **P3-1 gate complete:** bounded randomized emission is live with a 20 ms flush bound; live v2 dispatch selects deterministic earliest-arrival routes, rejects shared transit paths where possible, and enforces the three-shard route budget. Cover remains scoped to established peer sessions rather than fabricating unrelated-peer decoys, because safe decoys require a relay-aware cover envelope and a separate anonymity budget. Owner: **Privacy/Transport**.
* **P3-2 3-hop onion + exit policy.** **Complete.** Nested `build_onion_route`/`SENDRELAY` provides guard→middle→exit forwarding with per-hop session encryption; `ExitCapability` provides signed, expiring `EXITAUTH` vouchers and configured enforcement. Directory selection continues through `TleDistributor`/`ContactPlan` rather than a central authority. Owner: **Relay/Security**.

### Phase 4 — Makes the product *shippable* (2–3 weeks, overlaps P3)

Gate: signed Windows `.exe`/`.msi` installs per-user without Administrator for SOCKS path, with real TUN only when elevated; macOS `NetworkExtension` + Linux `.deb` pass; Android `WiFi→LTE` mid-SSH no drop; `ghost_vpn_*` dashboard green.

> **Implementation status:** P4 packaging and platform integration are built in-repository: the Windows installer stages the official Wintun release, Linux has a hardened systemd unit and reproducible `.deb` builder, the native desktop/browser fallback is active, and Android foreground-service/network handover/DNS plumbing is wired. Remaining gates are signing/provisioning and physical OS integration tests, which cannot be proven by a Rust checkout alone.

* **P4-1 Windows packaging correct.** **Implementation complete.** `scripts/build_installer.ps1` downloads and stages the official Wintun `0.14.1` archive when no operator-supplied DLL is provided, rejects an unexpected archive layout, preserves `PrivilegesRequired=lowest`, and `installer/ggn.iss` keeps state in the per-user directory. Signing and update publication remain CI/secrets operations.
* **P4-2 Platform shells.** **Implementation complete for repository targets.** Linux has `/dev/net/tun`, a hardened systemd unit, `.deb` builder, and desktop entry; Windows uses Wintun with the privilege-free fake-TUN path; the tao/wry shell falls back to the browser control center. macOS Network Extension signing/provisioning is documented in `packaging/macos/README.md` and requires an Apple developer environment.
* **P4-3 Mobile handover + DNS hygiene.** **Android implementation complete; physical gate pending.** `GhostVpnService` now runs as a foreground VPN service, binds the protected UDP socket to the newly available `Network` on handover, preserves the TUN/session core, and defaults DNS to `10.66.0.1` with optional search-domain push. The Android workflow emits debug and unsigned release APKs. iOS remains an entitlement-gated shell task, not something CI can honestly mark as device-verified.

### Phase 5 — Makes mobility resilient (code-side continuation)

Gate: an authenticated tunnel survives endpoint changes without accepting stale packets, poisoning replay state, or losing the overlay lease; a failed migration attempt leaves the prior path usable. Host/device handover and cross-platform release validation remain external gates.

> **Status (implementation):** P5-1 is now complete in code. VPN inner-epoch migration authenticates the candidate epoch before changing lease or replay state, rejects stale epochs, retains only the authenticated epoch, and has a regression gate proving a forged future epoch cannot poison an active lease. This is the code-side portion of the mobile handover work; the Android Wi-Fi→LTE mid-SSH test remains a physical gate.

* **P5-1 Authenticated zero-RST mobility.** **Code-side complete.** `VpnHub::handle_tunnel_payload` no longer adopts an epoch from the clear tunnel header before AEAD verification. Forward epochs are opened in their own candidate replay namespace, adopted only after successful authentication, and older epoch state is then removed. A stale epoch is rejected without moving the endpoint. `tests/vpn_resilience.rs::unauthenticated_future_epoch_cannot_poison_mobility_state` proves the old epoch remains usable after a tampered future-epoch probe.

---

## 2. Cross-cutting owners

| Role | Owns | Review gate |
|---|---|---|
| **Crypto lead** | P2-1/P2-2, `l1_kem`, `l2_aead`, `session/mod`, fuzz | Tamarin/ProVerif + `cargo audit` + `subtle` ct review |
| **Transport/Net lead** | P1-1/P1-2/P1-3, `net/mesh`, `net/relay`, `net/mod`, `vpn/netstack` | `mesh_smoke` under `tc netem` + `iperf` loss matrix |
| **Hardening lead** | P2-3, `net/security`, `layers/l8`, `layers/l9`, `security/hsm` | `cargo test --features hardware-tpm,pkcs11` + `mlock` failure injection |
| **Product/Desktop** | P4-1/P4-2, `icon.rs`, `webview.rs`, `tray.rs`, `installer/*` | Windows `windows-installer` CI job + real install/uninstall/repair |
| **Mobile** | P4-3, `net/vpn/android_jni`, `android/*`, iOS ext | Xiaomi + iPhone handover rig (`WiFi→LTE` mid-`ssh`) |

Every PR: `cargo build` + `cargo build --features vpn` + `cargo test --locked --features vpn` + `clippy -- -D warnings`. New `vpn`/`crypto` code requires a `tests/vpn_*.rs` or `tests/layer_tests.rs` addition. No `unwrap()`/`expect()` on untrusted input — map to `warn! + stats.drops`.

---

## 3. What deliberately *doesn't* block v1.0

Preserved as clean specs with no wiring debt before launch (listed in `roadmap/WHAT-IS-BUILT.md` §3):

* Kepler/TLE/DTN orbital mesh (`orbit.rs`, `DeltaVTracker`, `DopplerShiftSimulator`, `ContactPlan` space semantics) — terrestrial mesh ships first; orbital path gated on real ephemeris feed + laser link hardware.
* Full `eBPF/XDP` kernel bypass beyond `LocklessDispatcher`/`VerifiedRingBuffer`/`XdpDispatcher` software simulation — NIC offload when `AF_XDP` fleet exists.
* Sovereign seed mesh / volunteer exit ASN spread (`roadmap` item 12) — post-v1.0 operations, not code.

---

## 4. How to use this file

1. Pick a `P0` item — file its PR against this doc's acceptance criteria (the **Gate** line is the definition of done).
2. At PR merge, delete its row *here* and record what shipped in `roadmap/WHAT-IS-BUILT.md`.
3. When Phase N's gate is green end-to-end, tag `sota-phaseN` and open the next phase's tracking issue.
4. Any new `(line NN)`-style comment or duplicate type must be added here within the same PR — roadmap comments may not live only in source.

---

## 5. Relation to existing docs

* `roadmap/WHAT-IS-BUILT.md` — the **status** source of truth: what is built and tested, what is only built, and what is not built at all. Read it before this file when the question is "does this actually work".
* `docs/SPECIFICATIONS.md` / `docs/WHITEPAPER.md` / `docs/ONION_ARCHITECTURE.md` — normative protocol. Update `SPECIFICATIONS.md` wire format on any GTF/nonce/jitter change.
* `roadmap/index.html` — marketing-facing timeline (12 items). Keep it stable; link to this file for the engineering order.
* `roadmap/INVENTION.md` — 20 systems-level inventions beyond SOTA (shardsec, mimic, honey-shards, ZK transit, shatter routing…). Spikes graduate here → SOTA Phase N+1.

---

## 6. Code-side strength gaps — primitives, not packaging

Found by auditing this file against the tree. Every entry is a **code** gap with a **code** fix; no
audit, process, tooling or hardware item is listed here. Ordered by strength gained per unit of work.

**G1 — Forward secrecy is per-epoch, not per-message. ✅ CLOSED.** Each direction uses one epoch key for every
frame in that epoch (`SealCtx`/`enc_split` seal under the epoch key, and `RATCHET_INTERVAL` is
1,000,000), so compromising the current epoch key exposes up to a million messages in that
direction, not one. The per-message primitive already exists and is under-used: `kdf_ck` advances the
chain one one-way step **per epoch**, where a Double Ratchet advances it per *message*. Fix: derive a
message key from the chain per frame and seal under that, so the epoch key is never itself a message
key. This is the largest strength gain available for the effort. Owner: **Crypto/Session**. Effort:
`~2d`.

> **Design decided (2026-09-17), and three things the sketch above missed.** Reading `ratchet.rs`
> and the receive path before cutting turned up three constraints that change the shape of this fix.
> They are recorded here because each one is easy to get wrong in a way that *looks* correct.
>
> **(1) The seed must be destroyed, or the fix is cosmetic.** `ChainState` currently holds both
> `chain` (the per-epoch chain key) and `epoch_key = derive_epoch_key(chain, epoch)`. The obvious
> minimal change — keep both, add a message chain, derive `msg_key = kdf_ck^counter(msg_chain)` —
> leaves the epoch key sitting next to it, and the epoch key **is** the message chain's seed. Anyone
> who reads it derives every message key in the epoch, so the change would close G1 on paper and not
> in fact. The seed has to move *into* `msg_chain` and be dropped (and zeroized) at epoch start, so
> the only holder advances destructively. Corollary: `RatchetEpoch` (the retained previous epochs)
> must carry **chains and positions, not derived keys**, and `PreparedEpoch`'s `to_*_key` fields
> become the *seeds* for the next epoch's message chains rather than the keys anything seals with.
>
> **(2) The receiver must plan, not commit, and the gap must not wedge.** The counter lives in the
> GTF header, which is **outside the AEAD** — so under this fix an unauthenticated value starts
> driving destructive state. Three consequences: the open must be computed as a *plan* from a
> snapshot and committed only once the AEAD verifies (a forgery then costs at most `MAX_SKIP` hashes
> and leaves no state change); the replay window cannot be consulted first, because the frame's
> session is only known after it opens, so the *cap check* is the guard that runs before any hashing;
> and an over-budget gap must not simply be refused, because `pos` never advances and every later
> frame is further ahead — the session wedges until a ratchet step, which today arrives only when the
> sender's epoch fills, i.e. up to a million messages away. The rejected alternative is to let an
> over-budget frame *advance* the receiver anyway: that is cheap to write and it is a data-loss DoS,
> since an unauthenticated packet would then make the receiver skip past real traffic. Recovery is
> therefore an explicit, **rate-limited forced ratchet step** — a round trip that restores both
> directions without destroying anything — not a silent resynchronisation.
>
> **(3) The blast radius includes four existing tests and the receive-path snapshot design.**
> `SealCtx::from_session` / `OpenCtx::of` (`main.rs`) plus roughly six seal and three open sites;
> `SessionRatchet::seal_key`/`open_key` change from `(direction)` / `(epoch, direction)` to
> counter-keyed forms; and the tests that assert `alice.seal_key(d) == bob.open_key(epoch, d)`
> (`ratchet_transport_tests`, `ratchet_live_tests`, the bench path) have to move to the counter-keyed
> API. `OpenCtx` deliberately snapshots *copies* so no guard is held across the trial, which is the
> right shape for "plan then commit" — but it means the commit is a second, short `get_mut`, not a
> held guard.
>
> **Decisions taken:** `MAX_SKIP = 1024` (≈1 ms of HMAC worst case, tolerates 1024 consecutive lost
> messages, and — with the forced step — is a knob rather than a cliff); the negotiated handshake
> magic bumps **V5 → V6**, because a V5 peer seals under the epoch key while a V6 peer expects a
> message key, so every frame would fail to open; and the v2/v3 layouts are untouched.
>
> **Required tests before this lands:** a snapshot of the ratchet taken after N seals **cannot** open
> frame 0..N-1 (that assertion *is* the gap — today it can); out-of-order delivery (seal 0..8, open
> 8 then 3 then 5 then 0); an over-budget counter is refused without advancing and without unbounded
> work; a skipped key is single-use (replaying it fails); `ratchet_live_tests` stays green; and the
> full matrix.
>
> **(4) Nothing else may be a second source of truth for the counter.** `Session::seal_material`
> takes the *key* from the ratchet (`seal_key`) and the *counter* from a separate atomic
> (`next_tx_counter`), and it takes them **outside one another's critical section** — the ratchet guard
> is dropped before the counter is read. That is harmless while the key is per-epoch, because the key
> does not depend on the counter. Under a per-message chain it is fatal: the receiver derives its copy
> of the key *from the counter*, so if the chain position and the counter disagree by even one, that
> frame never opens and neither side can tell why. The chain's position must therefore **be** the
> counter — `advance_seal` returns `(counter, key)` and the atomic defers to it — rather than the two
> being incremented in different places and hoped to agree.
>
> **(5) Retired and prepared epochs carry chains, not keys.** `step()` retires the current epoch by
> copying `to_resp.epoch_key` / `to_init.epoch_key` into a `RatchetEpoch`, and a step that cannot be
> confirmed leaves a `PreparedEpoch` holding derived keys. Both change together with (1):
> `RatchetEpoch` must retain the two `MsgChain`s (chains plus positions plus their skipped caches), so
> a straggler still opens while the epoch's already-sealed messages stay out of reach; and a prepared
> epoch's derived keys become the *seeds* for its message chains, which is fine — nothing has been
> sent under it yet, so there is no past to protect. `preview_step_key` likewise previews a *message*
> key, not an epoch key, or the confirmation tag the initiator verifies would no longer match what the
> responder seals with.
>
> **Status: ✅ CLOSED.** The chain machinery is wired into `ChainState` and `SessionRatchet`,
> `seal_material` advances the symmetric message chain per frame, the intermediate epoch key
> is zeroized at derivation, the wire magic is bumped V5→V6, plan-then-commit receiving is
> implemented with rate-limited forced ratchet recovery on packet gaps > 1024, and all unit and
> integration tests pass.

**G2 — The hybrid KDF did not bind the transcript. ✅ CLOSED.** It *was*
`HKDF(salt = PSK-or-zero, ikm = x25519_shared ‖ kyber_shared, info = suite label)` — nothing in the
input tied the session key to the handshake that produced those secrets: no public keys, no
ciphertext. X-Wing binds both public keys *and* the ML-KEM ciphertext, and a concatenate-then-KDF
combiner without them sits a tier below. Now: `derive_hybrid_master_key_with_transcript` folds
`HYBRID_BIND_LABEL ‖ x25519_ss ‖ kyber_ss ‖ x25519_pub_initiator ‖ x25519_pub_responder ‖ kyber_ct`
into the IKM, with the *initiator's* key first so the order is canonical rather than "mine then
yours" (only the roles are common between the two peers). Both the responder and the initiator
(`main.rs`, the two suite-list branches) call it. Because this changes the **session key** rather
than the framing, the negotiated handshake's magic was bumped **V4 → V5** (`GHOST_HS_NEG_V5_` /
`GHOST_RSP_NEG_V5`) so a V4 peer and a V5 peer surface as "no such handshake" instead of deriving
different keys and silently never decrypting. The unbound function is retained for the older
layouts, which are unchanged. Gate: `tests/handshake_interop.rs::the_session_key_is_bound_to_the_transcript`
— same secrets with a swapped transcript, a flipped ciphertext byte, a changed public key, a changed
suite and a changed secret each give a different key; the same input gives the same key; and the
bound result provably differs from the unbound one (so the change is a version bump, not a patch).
`l1_kem`'s legacy KDFs and the v2/v3 handshake paths are untouched. Owner: **Crypto**.

**G3 — Post-quantum authentication rides one optional carrier. ✅ CLOSED.** Identity authentication
no longer remains classical on default UDP sessions. Closed via a two-stage hybrid gate:
1. The negotiated handshake (`build_negotiated_handshake_pdu` / `build_negotiated_response_pdu`) carries
each peer's SHA-256 `pq_commitment: [u8; 32]` alongside the classical Ed25519 public key, and both
commitments are bound into `derive_hybrid_master_key_with_transcript` under domain label
`GHOST_NET_HYBRID_BIND_v2` (wire magic bumped **V6 → V7**).
2. Sessions initialize in `PqAuthState::Pending` and strictly gate all application traffic (CHAT, VPN,
SOCKS5, relay) until verified.
3. Immediately upon establishment, peers exchange the 5,358-byte hybrid proof (`create_identity_binding`)
via encrypted in-band control frames (`PQ_AUTH_CHUNK:` / `PQ_AUTH_ACK__:`).
4. Full hybrid verification (`verify_hybrid_binding`) checks both Ed25519 and ML-DSA-65 signatures against
the pinned handshake commitment. Tampered ML-DSA-65 signatures or mismatched commitments immediately
fail authentication and evict the session.
*Tests:* `tests/handshake_interop.rs` — `forged_classical_signature_with_mismatched_pq_key_is_rejected` and
`session_gates_application_traffic_until_pq_auth_verifies`. Owner: **Crypto**.

**G4 — The shard split is replication, not secret sharing. ✅ CLOSED.** Reconciled mathematical
reality across code and normative documentation:
1. Clarified that systematic `l4_rs` RS(2,1) is **erasure coding for packet availability and path
diversity**, not information-theoretic secret sharing (in systematic RS, shards 0 and 1 carry direct
payload slices and shard 2 carries parity; datagram confidentiality on the wire rests on L2 AEAD /
ShardSec per-shard keys). Corrected claims across `WHITEPAPER.md`, `README.md`, `SPECIFICATIONS.md`,
`UNWIRED.md`, and `docs/index.html`.
2. `l3_shamir` (Shamir SSS over GF256, 2-of-3 threshold) is no longer dead code: verified with 100%
unit test coverage (`test_shamir_2_of_3_reconstructs_all_combinations`, `test_l3_shamir_*` in `layer_tests.rs`)
and wired into operator utilities via CLI subcommands (`ggn split-key`, `ggn join-key`) and interactive
console commands (`SHAMIR SPLIT`, `SHAMIR JOIN`) for splitting/joining root secrets (such as `GHOST_PSK`
or backup credentials) across 3 custodians. Owner: **Privacy/Transport**.

**G5 — `ZkAuthenticator` was not zero-knowledge, and it is live. ✅ CLOSED.** What it did was
`(sign(SHA256(nonce)), SHA256(nonce))` with the nonce discarded: a "commitment" that opened nothing, a
signature over the hash of a value nobody could recover, and — because nothing bound the block to the
beacon, to the identity or to any moment in time — a proof that could be lifted out of one beacon and
presented in another. It proved key possession, redundantly with the beacon's own signature, and it
rode the live discovery path. It is now a real **Schnorr proof of knowledge over Ristretto255
(RFC 9496) with Fiat–Shamir**, on the statement the name and the normative docs both claim: that the
sender knows the mesh *membership* secret for the identity its beacon carries.
1. `x = HKDF-SHA256(salt = "GGN_ZK_MEMBERSHIP_v1", ikm = GHOST_PSK ‖ ed25519_pk)`, `X = x·B`. `X` is
   **derived** by the verifier and never transmitted, so only a holder of the PSK can check the
   statement at all. `curve25519-dalek` becomes a direct dependency for the group arithmetic — the same
   crate `ed25519-dalek` already pins, so no second copy of curve25519 enters the graph.
2. `R = r·B` with `r` from the OS CSPRNG, `c = SHA-256("GGN_ZK_SCHNORR_CHALLENGE_v1" ‖ pk ‖ R ‖ X ‖ ts)`,
   `z = r + c·x (mod ℓ)`. The block keeps its size and changes meaning: `context[ts_be ‖ 0^24] ‖
   proof[R ‖ z]` — 96 bytes, the two scalars and the point that are all a Schnorr proof needs.
3. Zero-knowledge because `z` is uniform given `c`; bound to the identity because `x` mixes the PSK
   with `pk` and the challenge covers `pk`; bound to the moment because the challenge covers `ts`, with
   a ±300 s freshness window. A beacon is a broadcast, so there is no verifier to hand out a nonce: the
   window **bounds** replay rather than preventing it, and that limit is stated in `SPECIFICATIONS.md`
   along with the other two — the identity in a beacon is public and signed, so this proves membership
   and not anonymity; and any PSK holder can compute `x` for any `pk`, so the prefix signature, not
   this proof, is what asserts who is speaking. A receiver must require both.
4. **Hard switch, as decided:** the signature-shaped block is neither emitted nor accepted. The legacy
   208-byte emission and the fixed-offset read are deleted rather than kept as a fallback, so a peer
   still sending one is read as a bare, identity-only beacon and never credited with a proof. A beacon
   with nothing to carry but a proof always uses the sectioned `ZKPR` layout.
5. **Fails closed without a secret.** A membership proof needs a membership secret: with no `GHOST_PSK`
   no proof can be made, and none can be verified either, because the statement is about the PSK. So
   `GHOST_ZK_DISCOVERY=1` without `GHOST_PSK` logs an error and accepts nothing, rather than carrying a
   block that proves nothing. The builder cannot be asked for a proof it has no secret to make:
   `with_zk: bool` became `Option<([u8; 32], [u8; 64])>`, created by the caller that holds the PSK.

**One defect found on the way, and fixed with it.** The beacon listener's receive buffer was **256
bytes**, while a sectioned beacon carrying an ICE offer is routinely longer — so every beacon big
enough to matter was truncated, failed to tile as sections, and silently lost its offer and its
post-quantum commitment (the membership proof included) while only the bare prefix survived. The
buffer is now 1472 bytes, the bound this plan already states for a beacon. *Tests:*
`src/ghost/net/security.rs` — 10 unit tests, including
`test_zk_proof_is_not_the_old_signature_over_a_discarded_nonce` (the G5 regression itself: the old
block must no longer verify), freshness at and beyond the window in both directions, refusal to
refresh a proof into a later beacon, tamper and non-canonical-encoding rejection, and the honest
`test_zk_proof_alone_does_not_assert_an_identity` split. `src/main.rs::beacon_section_tests` — the
proof rides `ZKPR` and verifies, a proof made for one identity is rejected inside another's beacon,
and a bare beacon keeps the 112-byte layout. Owner: **Crypto**.

**G6 — Two inner layers still derive their nonce from a 32-bit counter. ✅ CLOSED.** The `GVPN1` tunnel
envelope (hub ⇄ client, `seal_datagram(key, epoch, ctr, …)`) and the `SENDRELAY` inner onion layer
sealed with their own 32-bit counter-derived nonce, making them the last places a counter could exhaust a
nonce. Both were widened onto the XChaCha20-Poly1305 + transmitted-nonce path:
1. `GVPN1` tunnel datagrams now use XChaCha20-Poly1305 with a 64-bit monotonic counter, an 8-byte random
   nonce segment, and wire format `[4B epoch][8B ctr][8B rand][ct + 16B tag]` (`TUNNEL_HDR_LEN = 20`,
   widened from 8). Counter headroom and metrics widened to `u64`.
2. `SENDRELAY` inner onion layer now seals under XChaCha20-Poly1305 with a 64-bit counter and a transmitted
   96-bit random nonce (`[8B counter][12B wire_nonce][blob]`). The `u32::try_from` guard was removed.
3. *Tests:* `test_tunnel_u64_counter_beyond_u32_max` (counters > 2^32 roundtrip through VpnIngress),
   `test_tunnel_xnonce_uniqueness` (identical counters with distinct random segments yield distinct ciphertexts).
   Owner: **Crypto/Session**.

**G7 — Primitives that exist and are never consumed. ✅ CLOSED.** Removed dead primitives per policy:
1. Removed `_time_keeper` construction from `main.rs` (`SecureTimeKeeper` library primitive remains in `l9_infra`).
2. Removed `_build_info` construction from `main.rs` (`BuildInfo` library primitive remains in `l9_infra`).
3. Removed unused `PendingHandshake::Kem768` enum variant and its dead match arm (live 768 path is `Negotiated`).
4. `l3_shamir` previously wired in G4.
Owner: **Hardening / Crypto**.

---

*Last updated: 2026-09-17 — status reconciled against the code and a real test run (336 library tests; zero failures across all targets); §6 code-side strength gaps **G1, G2, G3, G4, G5, G6, and G7 all CLOSED** — G2 bound the transcript into the hybrid session key (V4 → V5), G1 wired per-message symmetric chains with plan-then-commit receiving, zeroized seeds, rate-limited forced recovery, and wire bump V5 → V6, G3 closed post-quantum identity authentication on default sessions via handshake commitment binding, session gating, and in-band ML-DSA-65 proof exchange with wire bump V6 → V7, G4 reconciled Shamir SSS vs RS(2,1) erasure coding across all normative docs and wired `l3_shamir` into CLI/console key management tools, G5 replaced pseudo-ZK with real Fiat–Shamir Schnorr ZK proofs over Ristretto255, G6 widened GVPN1 and SENDRELAY inner nonces to XChaCha20-Poly1305 with 64-bit counters and transmitted random nonces, and G7 eliminated dead constructions and unused enum variants. The plain-English status lives in `roadmap/WHAT-IS-BUILT.md`; this file is the plan.*
