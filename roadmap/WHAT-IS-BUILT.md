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

**Session encryption.** XChaCha20-Poly1305 with a random 96-bit nonce sent on the wire, 64-bit
packet counters, and a double ratchet that changes the session key roughly every million packets
(forward secrecy from the symmetric step, break-in recovery from the fresh key exchange). The older
frame version is still accepted.
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

## 4. Things in the tree that are wrong

Small, real, and worth knowing about.

- **`SecureTimeKeeper` is built but never used.** It is constructed in `src/main.rs` (around line
  3880) and bound to `_time_keeper` — the underscore means the value is thrown away. The comment
  directly above it says `WIRED:`, which is false. Either it should be used for something or it
  should not be constructed.
- **`PendingHandshake::Kem768` is never constructed** (`src/main.rs`, around line 92). The live
  ML-KEM-768 path is the newer negotiated one, so this is a leftover from the intermediate handshake
  version.
- **Dead fields:** `DopplerShiftSimulator.last_update`, `FlowController.local_bucket` and
  `TleDistributor.requested_from` are written or declared but never read.
- **The same source file is compiled into two programs.** `Cargo.toml` declares both `vantablack` and
  `ggn` with `path = "src/main.rs"`, so everything in `main.rs` is compiled and linked twice and its
  14 tests run twice. Both names are load-bearing — the installer ships `ggn.exe`, the shell scripts
  look for `vantablack.exe` — so this needs a deliberate choice, not a quick deletion.
- **Stale numbers in the roadmap.** `roadmap/SOTA.md` still quotes 282 library tests (actually 316),
  a 5-test `tests/p2_wire.rs` (actually 6), and says no formal model exists (the file does). Its
  scoreboard also says anonymity work has "started" while the item below it says "complete".

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
| library unit tests, default features | 316 passed |
| `src/main.rs` tests | 14 passed (run twice, once per binary) |
| `tests/handshake_interop.rs` | 3 passed |
| `tests/layer_tests.rs` | 46 passed |
| `tests/p1_nat.rs` | 7 passed |
| `tests/p1_relay.rs` | 8 passed |
| `tests/p2_wire.rs` | 6 passed |
| `tests/simulation.rs` | 7 passed |
| library unit tests, `--features vpn` | 344 passed, plus every `vpn_*` gate |
| library unit tests, `--features quic` | 322 passed |
| library unit tests, `--features hardware-tpm,pkcs11` | 318 passed |

The `p1_quic` and `vpn_*` targets report 0 tests under default features. That is correct, not a
failure — they are gated behind those features.

`cargo fmt -- --check` fails on this checkout, and it did before any of the recent work. It reports
around 70 differences across 11 files under both the nightly and stable toolchains, mostly in files
nobody has touched. The committed style and the installed formatter disagree across the whole
repository, so it is listed here rather than quietly fixed by reformatting everything.
