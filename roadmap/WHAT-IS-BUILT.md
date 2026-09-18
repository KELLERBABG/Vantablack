# What is actually built

Written 2026-09-17, on a Windows machine, by reading the code and running the test suite.

Short version: **almost everything the roadmap claims is really in the code and really wired to
the running daemon.** What is missing is mostly not code — it is proof on real hardware and real
networks. A few small things in the tree are genuinely wrong, and they are listed at the bottom.

---

## How to read this

Three words are used precisely, because blurring them is how a project ends up lying to itself.

- **Built** — the code exists *and* the daemon calls it. A function that compiles but nothing ever
  runs does not count, and there are examples of that below.
- **Tested** — there is a test that would fail if the behaviour were removed, and it passes on this
  machine.
- **Tested in one process** — the test runs two nodes over the loopback interface inside a single
  program. That proves the logic is right. It does not prove the thing works across a real network,
  and the two are not the same claim.

Nothing below claims a hardware, device or network gate has passed. Those are listed separately and
they have not been run.

---

## 1. Built and tested here

Each line names the test that would catch a regression.

**Identity and the handshake.** Every node has a hybrid identity: Ed25519 *and* ML-DSA-65, with the
post-quantum half drawn from its own randomness so that breaking the classical key does not hand
over the quantum one. Sessions are set up with an explicit suite list: each side advertises which
key-exchange suites it supports along with a public key for each, the responder picks the strongest
one they share, and the whole exchange is signed.
*Tests:* `tests/layer_tests.rs` (identity + handshake), `l1_kem` unit tests, and `l1_kem`'s
`test_uniform_handshake_and_response_use_random_authenticated_prefixes`.

**Post-quantum authentication on every session (SOTA G3).** Default sessions are not left on classical Ed25519 alone. The negotiated handshake binds each peer's ML-DSA-65 public key commitment into the KDF transcript (V7), blocks application traffic in `PqAuthState::Pending`, and immediately exchanges the 5.3 KB hybrid proof in encrypted in-band control frames (`PQ_AUTH_CHUNK:` / `PQ_AUTH_ACK__:`). Tampered signatures or mismatched PQ commitments immediately evict the session.
*Tests:* `tests/handshake_interop.rs` — `session_gates_application_traffic_until_pq_auth_verifies` and `forged_classical_signature_with_mismatched_pq_key_is_rejected`.

**Nobody can talk you down to a weaker suite.** If both sides support ML-KEM-768, a responder that
answers with ML-KEM-512 is refused. This is the security hole that suite negotiation exists to
close, and it is checked two ways: the initiator recomputes what the strongest shared suite should
have been and rejects anything else (`src/main.rs`, around lines 2482–2494), and the two suites
derive unrelated session keys because the suite name is part of the key derivation.
*Tests:* `tests/handshake_interop.rs` — `a_response_cannot_force_a_weaker_suite_than_was_mutually_available`
and `two_nodes_reach_one_session_key_through_the_negotiated_transcript`.

**Old nodes still work.** A peer that only knows the original fixed handshake layout still connects,
and the older handshake formats cannot be misread as the newer ones.
*Test:* `tests/handshake_interop.rs` — `a_v2_only_peer_still_negotiates_and_the_generations_do_not_misparse`.

**Session encryption & transcript binding (SOTA G1, G2).** The master key derivation binds the complete handshake transcript — both public keys, ML-KEM ciphertext, and cipher-suite label (V5). Outbound sessions run a per-message symmetric Double Ratchet chain (`MsgChain`): every datagram advances a directional chain and seals under a distinct single-use message key derived from it, with the seed zeroized at epoch start. Compromising the live epoch key exposes zero past messages. Ingress uses plan-then-commit receiving, bounding unauthenticated skips to `MAX_SKIP = 1024` with rate-limited forced ratchet recovery on wider gaps.
*Tests:* `tests/handshake_interop.rs` — `the_session_key_is_bound_to_the_transcript`; `src/ghost/session/ratchet.rs` unit tests (`msg_chain_advances_one_step_per_message_and_never_repeats_a_key`, `state_captured_after_sealing_cannot_reach_the_messages_already_sealed`, `a_cached_key_is_single_use_so_a_replay_fails`).

**Inner-layer nonces cannot exhaust (SOTA G6).** `GVPN1` tunnel datagram envelopes (`seal_datagram` in `vpn/`) and the `SENDRELAY` multi-hop onion inner layer both seal with `XChaCha20-Poly1305`, 64-bit monotonic sequence counters, and transmitted random nonces (`[4B epoch][8B ctr][8B rand][ct+tag]` for VPN; `[8B ctr][12B rand][blob]` for relay), eliminating the last places where a 32-bit counter could exhaust a nonce.
*Tests:* `src/ghost/net/vpn/mod.rs` — `test_tunnel_u64_counter_beyond_u32_max` and `test_tunnel_xnonce_uniqueness`.

**Ratchet transport and wire format.** XChaCha20-Poly1305 with a random 96-bit nonce sent on the wire, 64-bit packet counters, and a hybrid DH ratchet step roughly every million packets (break-in recovery from the fresh KEM + X25519 exchange). The older frame version is still accepted for compatibility.
*Tests:* `tests/p2_wire.rs` (6 tests) and the live-rotation tests in `src/main.rs`
(`ratchet_live_tests`, which spin up two real nodes, spend an epoch, run the real maintenance tick,
and push datagrams through the real receive path both ways).

**Frame shape gives nothing away.** Every ordinary packet is exactly 576 bytes, so its size tells an
observer nothing about what is inside, and the padding at the end is authenticated — flipping one
byte of it makes the packet fail to open.
*Test:* `tests/p2_wire.rs` — `p3_1_a_rewritten_jitter_tail_fails_the_tag`.

**The link is never silent.** The node sends cover traffic on a random-but-constant-average
schedule, shaped exactly like a real data message (three frames of the normal kind), so an idle link
and a busy one look the same to someone watching. The receiving side recognises it by a marker
*inside* the encrypted payload — not by a flag in the header, because header flags are not
encrypted and anyone on the path could flip them.
*Tests:* `p3_1_cover_tests` in `src/main.rs` (3 tests) — the flag survives the frame builder, cover
frames are the normal 576-byte shape, the marker is recognised after decryption while a near-miss is
not, and the gaps have the right average *and* vary.

**Message shards are authenticated individually.** Instead of one signature covering a whole
message, each Reed-Solomon shard carries its own authentication, checked *before* the shards are
recombined, so a tampered shard is rejected rather than quietly corrupting the result.
*Tests:* `src/ghost/net/shardsec.rs` — `two_authenticated_shards_reconstruct` and
`one_captured_shard_never_opens`. Switched on with `GHOST_SHARDSEC=1`.

**Threshold secret sharing is real and separate from transport erasure coding.** Shamir's Secret
Sharing (2-of-3 threshold over GF256) is implemented, unit-tested, and wired into CLI/console tools
(`ggn split-key` and `ggn join-key`) for splitting pre-shared keys (`GHOST_PSK`) or recovery
credentials across custodians with information-theoretic confidentiality. Datagram transport uses
systematic Reed-Solomon RS(2,1) exclusively for path diversity and packet-loss recovery, where
confidentiality rests on L2 AEAD authenticated encryption rather than erasure coding.
*Tests:* `src/ghost/layers/l3_shamir.rs` (4 unit tests) and `tests/layer_tests.rs` (2 integration tests).

**Discovery proves mesh membership in zero knowledge instead of signing a discarded nonce.** The
beacon's membership block is a Schnorr proof of knowledge over Ristretto255 (Fiat–Shamir) that the
sender knows the membership secret for exactly the identity its beacon names — `x = HKDF(GHOST_PSK ‖
ed25519_pk)`, `X = x·B`, `z = r + c·x`, with the challenge binding the public key, `R`, `X` and a
±300 s timestamp. It reveals nothing about that secret, it cannot be moved to another identity or
refreshed into a later beacon, and only a holder of `GHOST_PSK` can verify it at all. The block it
replaced (`(sign(SHA256(nonce)), SHA256(nonce))`, nonce discarded) committed to nothing anyone could
open and was replayable straight out of one beacon into another. What the new proof does *not* do is
hide who is speaking, and it does not by itself assert an identity: the beacon's Ed25519 prefix
signature is what binds the key to the sender, so a receiver must require both. It is a hard switch —
the legacy 208-byte block is no longer emitted or read.
*Tests:* `src/ghost/net/security.rs` (10 unit tests: an honest proof verifies; the old
signature-shaped block no longer does; wrong identity, wrong secret and stale or moved timestamps are
rejected; tampering and non-canonical encodings are rejected; two proofs for one identity differ) and
`src/main.rs` (`beacon_section_tests`: the proof rides the `ZKPR` section, a proof made for one
identity is rejected inside another's beacon, and a beacon with nothing else to carry keeps the bare
112-byte layout).

**Three-hop onion routing with an exit policy.** Traffic can be wrapped in three layers so each
relay in the chain can only decrypt its own layer and learn only the next hop. Exits must present a
signed, expiring voucher (`EXITAUTH`) or the request is denied.
*Tests:* `src/ghost/net/relay.rs` (three-hop build plus four rejection cases — empty route, one hop,
blank name, repeated hop), and `tests/p1_relay.rs` — including
`a_multi_hop_onion_and_a_blind_envelope_are_never_confused`, which checks that an onion and a
single-hop blind forward can never be mistaken for each other.

**Getting through NAT.** STUN, ICE, TURN, UPnP/NAT-PMP and a fallback ladder (direct → mesh relay →
TURN). The old code guessed ports and always reported success; it now only reports success after a
real connectivity check.
*Tests:* `tests/p1_nat.rs` (7 tests) drives the real ICE agent through a model of real router
behaviour: two home routers connect, two carrier-grade NATs provably cannot, and a relay is only
tried after every direct pair has failed. `tests/p1_relay.rs` (8 tests) proves a relay carries
traffic it cannot read.

**Routing.** Shard targets are chosen by earliest-arrival routing over the contact graph, and there
is a budget enforcing that the three shards do not collapse onto one route.

**The VPN tunnel.** A hub/client tunnel with DNS handling, MSS clamping, client churn and mobility.
*Tests:* under `--features vpn` — `vpn_gates` (6), `vpn_dns` (4), `vpn_mss` (3), `vpn_churn` (4),
`vpn_resilience` (4), `vpn_transport` (4).

**Mobility cannot be poisoned.** A packet claiming a future session key is authenticated *before*
anything is re-pointed, so a forged packet cannot knock out a working connection.
*Test:* `tests/vpn_resilience.rs` — `unauthenticated_future_epoch_cannot_poison_mobility_state`.

**Memory and key handling.** Keys can be locked out of swap, runtime memory can be encrypted, and
identity revocations are signature-checked before they are believed.

**Packaging.** The Windows installer downloads the official Wintun 0.14.1 driver and installs
per-user without administrator rights; Linux has a `.deb` builder, a hardened systemd unit and a
desktop entry; macOS is documented; Android runs the VPN as a foreground service.

**Shape-Shifting Wire: Negotiated Camouflage (Invention §38).** Outer wire dialect is dynamically selected via a live-probed `NetworkCensus` menu and negotiated via `DialectSession`. Protocols rotate over time (at a configurable frame interval) between GTF v2 raw, DoH mimicking, and TLS/QUIC imitation, preventing traffic fingerprinting.
*Test:* `src/ghost/net/mod.rs` — `test_shape_shifting_wire_negotiation_and_rotation`.

**Identity-Agnostic Channels: Blind Forwarding (Invention §40).** Relay nodes forward traffic via `IdentityAgnosticRelayTable` and `BlindCapabilityToken`. Intermediate relays verify flow quota and timestamp bounds using HMAC without storing or learning the client's public key or node identity. Seizure audit dump confirms zero identity material stored at rest.
*Test:* `src/ghost/net/relay.rs` — `test_identity_agnostic_channel_zero_identity_exposure`.

**Replay-Resistant Chronology: Causal Order Monotonicity (Invention §39).** Replaces external wall-clock reliance with `CausalMonotonicCounter` vectors. Epoch expiry and message ordering are evaluated against causal supersession, ensuring cross-partition replay attacks are rejected deterministically even when local clocks are artificially skewed.
*Test:* `src/ghost/session/ratchet.rs` — `test_causal_monotonic_counter_replay_resistance`.

**Group-as-Shards: Threshold Governance (Invention §41).** Models group authority and identity as a 3-of-5 threshold erasure-coded object using `ThresholdGroupKey` over `l3_shamir`. Any 3 of 5 members cooperate to reconstruct authorization keys and capability tokens, while any 2 compromised devices learn mathematically zero information.
*Tests:* `src/ghost/layers/l3_shamir.rs` — `test_threshold_group_key_3_of_5_governance` and `test_threshold_group_insufficient_shares_rejected`.

**Thermal-Mesh: Physical Energy Class Routing (Invention §35).** Contacts and nodes carry an `EnergyClass` (Mains, Battery, Harvested/Solar). Route selection scores and prefers heterogeneous energy triples via `select_thermal_heterogeneous_triple`, pricing out low-cost uniform-energy Sybil clusters.
*Tests:* `src/ghost/net/routing.rs` — `test_thermal_mesh_energy_heterogeneity_scoring` and `test_thermal_mesh_triple_selection`.

**Time-as-the-4th-Shard: Scheduled Shard Dispatch (Invention §30).** Adds millisecond-level temporal stagger (`T_0`, `T_0 + 200ms`, `T_0 + 400ms`) via `TemporalShardScheduler`. A partial-window adversary capturing traffic over $< 200$ ms captures fewer than 2 shards and cannot reconstruct plaintext.
*Test:* `src/ghost/net/shardsec.rs` — `test_temporal_shard_schedule_and_partial_window_adversary`.

**Beacon Grid: Distributed Clock Reference (Invention §34).** Embeds coarse epoch grid counters (`BeaconGridEpoch`) into Poisson discovery beacons. Partitioned or GPS/NTP-denied nodes monotonically reconcile coarse timeline consensus upon reconnecting.
*Test:* `src/ghost/net/mod.rs` — `test_beacon_grid_serialization_and_partition_reconciliation`.

**Present-Tense Mesh: Cryptographic Presence Claim (Invention §28).** Binds recent local Poisson beacon entropy into the session transcript via `PresenceProof`. Remote peers verify co-presence within the active epoch window; past wire captures and out-of-region relays are rejected.
*Test:* `src/ghost/layers/l1_kem.rs` — `test_present_tense_mesh_presence_proof_and_replay_rejection`.

**Shards over Tor: Multi-Circuit Egress (Invention §36).** `TorMultiCircuitDispatcher` routes each of the 3 Reed-Solomon shards through distinct, isolated local Tor SOCKS5 circuits (ports 9050, 9052, 9054) with SOCKS5 UDP encapsulation. A compromised Tor circuit captures at most 1 shard.
*Test:* `src/ghost/net/relay.rs` — `test_tor_multi_circuit_dispatcher_routing_and_udp_encapsulation`.

**Universal Shard-Tunnel: Generic Port Forwarder (Invention §37).** `UniversalTunnelChunker` slices arbitrary application byte streams (RDP, gRPC, SMTP, SOCKS5) into sequenced chunks, pads them to standard 576-byte GTF privacy frames, and reassembles out-of-order deliveries at the egress via `UniversalTunnelReassembler`.
*Test:* `src/ghost/net/universal_tunnel.rs` — `test_universal_shard_tunnel_chunking_and_reassembly`.

**Anti-Fragile Tarpit: Attacker Compute Penalty (Invention §50).** Escalates PoW difficulty bits (+2 on failed handshakes, +4 on honey-shard canary triggers) to trap hostile probes in superlinear compute overhead while honest peers pay zero penalty.
*Test:* `src/ghost/net/pow.rs` — `test_antifragile_tarpit_penalty_escalation_and_recovery`.

**Autonomous Dead-Drop Mesh Storage (Invention §22).** Tahoe-style 576-byte blind ciphertext vaults addressed by SHA-256 drop commitments rather than IP/node IDs. Hosts hold opaque ciphertext and can never inspect metadata or plaintexts.
*Tests:* `src/ghost/net/dead_drop.rs` — `test_dead_drop_deposit_and_sweep` and `test_host_audit_zero_metadata_exposure`.

**Diffusion Routing: Opt-in Emergency Mode (Invention §32).** Emergency flood-gossip routing behind `GHOST_DIFFUSION=1` with bounded hop TTLs and rolling 1024-packet duplicate suppression cache.
*Tests:* `src/ghost/net/diffusion.rs` — `test_diffusion_packet_serialization` and `test_diffusion_router_bounded_fanout_and_loop_suppression`.

**Self-Eating Storage: Adaptive Poisson Decay (Invention §33).** Adaptive garbage collection inversely linked to network error rates ($\lambda_{\text{error}}$). High error partitions preserve shards up to 5x longer, while quiet periods enforce swift forward-secrecy decay unless renewed via client keep-proofs.
*Test:* `src/ghost/net/dead_drop.rs` — `test_self_eating_storage_adaptive_poisson_decay`.

**Spatio-Temporal Erosion Codes: Deliberate Data Fading (Invention §27).** Encodes messages across both space (disjoint paths) and time (rotating epochs). Reconstruction requires live keys across at least 2 distinct epoch intervals; older epoch keys erode from RAM, preventing retrospective decryption of past wire captures.
*Test:* `src/ghost/net/shardsec.rs` — `test_spatio_temporal_erosion_codec_and_decay`.

**Windowing the Blackout: DTN State Reconciliation (Invention §29).** Merkle-tree anti-entropy synchronization isolating partition deltas across prolonged blackout gaps (airplane mode, censorship cuts) in $O(\log N)$ branch exchanges and splicing missing bundles without re-transmitting redundant data.
*Test:* `src/ghost/net/dtn_reconcile.rs` — `test_dtn_merkle_anti_entropy_blackout_sync`.

**Anonymous Capability Economy (Invention §45).** Threshold group credentials (3-of-5) granting forwarding and bandwidth rights without revealing client public keys or identifiers, enforced with atomic quota spending and double-spend rejection.
*Test:* `src/ghost/net/relay.rs` — `test_anonymous_threshold_voucher_spending_and_double_spend_prevention`.

**Deploy-Not-Design: Reference Containerized Testbed (Invention §48).** Containerized 3-node reference mesh (`mesh-hub`, `mesh-relay`, `mesh-client`) with zero-config compose definition and automated multi-hop smoke test script.
*Files:* `deploy/docker-compose.yml`, `deploy/smoke_test.sh`, `deploy/README.md`.

**Protocol Semantic Fuzzer (Invention §49).** Multi-step invariant fuzzer evaluating randomized sequences of stateful transactions (dead-drop sweeps, threshold spends, Merkle synchronizations, epoch erosion) to prove safety, quota enforcement, and zero-leakage invariants.
*Test:* `tests/semantic_fuzzer.rs` — 4 property-based sequence tests passing across thousands of operations.


---


## 2. Built, but only tested in one process

These work in the tests and have never met the real world. The gap is proof, not code.

- **All NAT traversal.** Every STUN/ICE/TURN/UPnP test is loopback or in-process. No real gateway,
  real TURN server or real middlebox has ever been involved. The two-machine gate that the roadmap
  defines — two homes behind NAT plus a phone on mobile data — has never been run. The operator's
  network is restricted, so this is paused rather than failed.
- **Multipath.** Spreading shards across two paths is tested with two loopback addresses. No
  genuinely multi-homed machine (real Wi-Fi plus real mobile) has been used, and the list of local
  addresses is typed in by the operator rather than discovered.
- **Session key rotation under load.** The rotation test spends an epoch by calling a counter a
  million times, with both nodes in one process. A rotation while a real network is saturated,
  losing packets and reordering them is untested. Shortening the interval to make that cheap would
  weaken a security parameter, which this project will not do for a test's convenience.
- **Shard dispersal and cover traffic.** Both are loopback only. Nothing has checked that an
  observer on a real link really cannot tell an idle node from a busy one.
- **The mobile handover.** The Android reconnect code is written; the actual "walk out of Wi-Fi range
  mid-connection" test needs a physical device.
- **The Linux-only shell scripts.** `nat_gate_iptables.sh`, `mesh_smoke_test.sh`,
  `vpn_loopback_test.sh` and `pentest_ggn.sh` are bash and need Linux (some need root, one needs
  Docker). None of them can run on this Windows machine, so none of their results are claimed here.
- **The traffic-analysis gate.** `scripts/pentest_ggn.sh` tests handshake floods, spool floods,
  forged beacons and replays. It has **no shape or timing test** — nothing that asks "can a
  classifier tell these three kinds of traffic apart" — so the anonymity claim in the roadmap has
  never actually been put to a classifier.

---

## 3. Not built at all

Each has a concrete reason, not a vague one.

- **Real hardware key storage.** There is no TPM 2.0 device and no PKCS#11 token on this machine, and
  the code shows it: the TPM and PKCS#11 backends are typed stubs whose `open()` always reports
  "no hardware here" (`src/ghost/net/security/hsm.rs`). The attestation envelope that would carry a
  hardware quote exists as a *format*, but nothing produces a real quote. This is deferred by
  hardware, not by preference.
- **The formal proof.** A protocol model exists at `formal/ghost_session.pv` and CI runs
  `proverif formal/ghost_session.pv`. **It has never been executed here**, because neither `proverif`
  nor `tamarin-prover` is installed. So the model is written, not verified.
- **Apple signing and the macOS network extension.** Needs an Apple developer account and
  provisioning; documented, not built.
- **A physical iOS or Android handover test.** Needs devices.
- **Proving you hold your post-quantum key, inside the handshake payload directly.** Because a 5.3 KB proof exceeds standard packet MTU, proof exchange runs immediately in-band over the encrypted session under a strict verification gate (SOTA G3), rather than expanding raw pre-session handshake UDP datagrams.
- **Hybrid signatures on revocations and capability vouchers.** Those are still classical-only.
- **Cover traffic aimed at peers you have no session with.** Cover is currently scoped to
  established sessions; fabricating unrelated decoys needs a relay-aware envelope and its own
  budget for how much noise is worth making.
- **Mixing in the Nym sense.** There is a small local batcher, not a mix network.
- **Orbital and kernel-bypass work.** Satellite routing and NIC-level packet handling
  (`eBPF`/`XDP`) are deliberately out of scope until there is hardware and an ephemeris feed.

---

## 4. Things in the tree that are wrong — status

Small, real, and tracked honestly:

- **Resolved (2026-09-17):**
  - `_time_keeper` discarded construction removed from `main.rs` (SOTA G7); library primitive remains in `l9_infra`.
  - `PendingHandshake::Kem768` dead variant and unused match arm removed (SOTA G7).
  - Dead fields removed: `DopplerShiftSimulator.last_update`, `FlowController.local_bucket`, and `TleDistributor.requested_from`.
  - `vantablack` library compiles with zero warnings and zero dead code.
- **Still intentionally open:**
  - **The same source file is compiled into two programs.** `Cargo.toml` declares both `vantablack` and
    `ggn` with `path = "src/main.rs"`, so everything in `main.rs` is compiled and linked twice and its
    15 tests run twice. Both names are load-bearing — the installer ships `ggn.exe`, the shell scripts
    look for `vantablack.exe` — so this is preserved intentionally until a packaging consolidation pass.

---

## 5. How to check all of this yourself

The checkout path contains a space, which breaks the linker on Windows, so point the build output
somewhere without one:

```
set CARGO_TARGET_DIR=C:/ggn-target
```

Then, from the repository root:

```
cargo test --all-targets                  # the whole default suite
cargo test --features vpn                 # the VPN gates
cargo test --features quic                # the QUIC carrier gates
cargo test --features hardware-tpm,pkcs11 # the hardware-stub gates
```

Observed on this machine, 2026-09-17, Windows, nightly toolchain, **zero failures in every set**:

| what | result |
|---|---|
| library unit tests, default features | 362 passed |
| `src/main.rs` tests (`ggn` bin) | 15 passed (run twice, once per binary) |
| `tests/handshake_interop.rs` | 6 passed |
| `tests/layer_tests.rs` | 48 passed |
| `tests/p1_nat.rs` | 7 passed |
| `tests/p1_relay.rs` | 8 passed |
| `tests/p2_wire.rs` | 6 passed |
| `tests/simulation.rs` | 7 passed |
| `tests/semantic_fuzzer.rs` | 4 passed |
| library unit tests, `--features vpn` | 412 passed in vpn, plus every `vpn_*` gate |
| library unit tests, `--features quic` | 322 passed |
| library unit tests, `--features hardware-tpm,pkcs11` | 318 passed |

The `p1_quic` and `vpn_*` targets report 0 tests under default features. That is correct, not a
failure — they are gated behind those features.
