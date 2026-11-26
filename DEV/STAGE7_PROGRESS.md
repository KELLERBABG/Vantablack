# Stage 7 (`v3.0.0`) — Full Epistemic Mesh Release — progress log

Spec: `DEV/V3_PIPELINE.md` Stage 7 (read-only; stayed 9,132 bytes).
Rule: a box is ticked only when the code exists and a test or gate proves it.

## Read and map

- [x] Read Stage 7 spec, `DEV/INVENTIONS_AND_PROOFS.md` (Inventions 7 & 10) and `DEV/UNPRECEDENTED_PRIMITIVES.md` §1–§4, §6–§7
- [x] Map the existing `sharded_compute`, `shardsec::SpatioTemporalErosionCodec`, `btcr` DLEQ/VOPRF, `entropy_beacon`, `l8_memsec` and release-gate scripts

Stage 7 names four optional research tracks to "cleanly gate or promote once
benchmarked". None has a benchmark yet, so all four are gated behind
`--features research` rather than promoted into the production daemon — the same
policy as the other dormant primitives in `Cargo.toml`.

## Deliverables

- [x] **Chrono-Erosion** (`src/ghost/v2/erosion.rs`, `research`) — `(t, n)` Shamir committee over Ristretto255, Chaum–Pedersen DLEQ per partial evaluation, Lagrange interpolation at zero, blinded threshold mask `H(k_tau * M)`, bundle wrap/unwrap bound to `(bundle_id, die_at)`. Shares are held as canonical scalar bytes and wiped with `zeroize`, so expiry is a real wipe. Tests: `a_bundle_is_readable_only_before_its_epoch`, `the_committee_forgetting_is_what_kills_the_bundle`, `fewer_than_threshold_partials_cannot_unblind`, `a_partial_evaluation_not_bound_to_its_commitment_is_refused`, `the_mask_binds_the_bundle_and_its_epoch`, `a_dead_committee_refuses_to_seal`
- [x] **LC-Vantablack** (`src/ghost/net/sharded_compute/lagrange.rs`, `research`) — `K` inputs + `T` masks interpolated into a degree-`K+T-1` Lagrange polynomial over `F_{2^31-1}`, element-wise degree-`d` layer evaluation, Berlekamp–Welch decoding of the degree-`d(K+T-1)` composite codeword, `N >= d(K+T-1) + 1 + S + 2A`. Tests: `the_worker_bound_is_the_theorem_bound`, `a_linear_layer_survives_one_straggler_and_one_liar`, `a_quadratic_layer_needs_and_gets_the_bound`, `one_worker_learns_nothing_about_the_input`, `malformed_jobs_are_refused`, `field_arithmetic_round_trips`
- [x] **Causal Polysemy** (`src/ghost/net/polysemy.rs`, `research`) — `(n, k, r)` additive world code over `F_{2^8}`; one decryptable message per `k`-subset; shard size is exactly `C(n-1, k-1) * r`. Tests: `every_world_collapses_from_its_own_paths`, `a_cut_path_selects_the_world_that_survives`, `a_lost_path_leaves_the_hidden_world_a_bijection`, `the_shard_is_exactly_the_counterfactual_capacity`, `malformed_frames_are_refused`
- [x] **Epistemic Sheaf Cohomology** (`src/ghost/net/sheaf.rs`, `research`) — 1-cochain of authenticated session discrepancies, spanning-forest potential fit, exactness test (`H^1` vanishes iff one global reality fits), and fundamental-cycle witnesses with non-zero holonomy that name the horizon. Tests: `one_consistent_reality_has_no_obstruction`, `a_split_horizon_leaves_a_non_zero_cohomology_class`, `a_single_falsified_session_is_localised_and_quantified`, `holonomy_is_invariant_under_a_gauge_shift`, `malformed_sessions_are_refused`
- [x] **Live census gossip** (`src/ghost/v2/xray.rs::census`, `src/daemon/{discovery,peer_loop}.rs`) — a `GHOST_CENSUS__` PEX frame carries each node's signed epoch announcement; the receiver verifies it, then counts the cell it derives from the observed session address (`/24` v4, `/48` v6) with a value derived from that cell alone. Sybils in one subnet collapse to one cell, the lottery cannot be ground, relayed entries without an endpoint are dropped, and the wire form still carries no address. Tests: `a_live_announcement_counts_the_observed_cell_not_the_claimed_one`, `sybils_in_one_subnet_are_one_cell_whatever_they_claim`, `a_grinded_value_cannot_move_the_census`, `a_stale_or_mislabelled_announcement_is_refused`, `the_pex_batch_round_trips_and_carries_no_address`, `two_hundred_routing_domains_clear_the_anonymity_floor`, `only_the_senders_own_announcement_is_accepted`, `a_frame_without_an_observed_endpoint_counts_nothing`
- [x] **Module registration and docs** — `net::{polysemy, sheaf}`, `v2::erosion`, `sharded_compute::lagrange`; README dormant-module row updated

## Release gate

- [x] **E2E multi-NAT & multi-hop suite** — the existing `tests/multi_nat_e2e.rs`, `wan_full_e2e.rs`, `wan_resilience_e2e.rs` and `tests/p1_*.rs` all run in the full `cargo test --features research --no-fail-fast` gate below
- [x] **Non-vacuous ProVerif pass** — `formal/attestations.json` pins the SHA-256 of all five models and records both the security queries (`true`) *and* their reachability witnesses (`false`); `build.rs` refuses a changed `.pv` without a regenerated attestation, and `xray::tests::formal_attestation_matches_the_committed_models` asserts the hashes and `provenance().all_queries_hold`. Re-run in WSL Ubuntu with ProVerif 2.05 through the new `scripts/formal_verify.sh`: all five models reproduce the attested RESULT lines exactly
- [x] **Reproducible build hashes** — `scripts/reproducible_hash.sh`: deterministic source manifest plus a two-fresh-target-dir release build comparison. Measured on this host: without a linker timestamp flag the two builds differed in exactly 24 bytes (COFF link time); with `-C link-arg=/Brepro` (applied automatically on `windows-msvc`) both release builds hash `5f5cc0a1871b0f3bacf071c0e946f4a212bbef4c5d51a2c680436bc835ba32da`
- [x] **X-Ray live truth ledger** — `cargo test --lib --features research xray` green (ledger, census, witnesses, attestation); no live mesh was attached, so "live" means the witness-gated code path, not a running multi-host deployment

## Controls and tests

- [x] Every new primitive has a test that fails without the code (22 new tests, all `research`-gated: 6 erosion, 6 LC-Vantablack, 5 polysemy, 5 sheaf)
- [x] Negative paths: dead/expired committee, too few partials, forged partial, relabelled bundle, too few workers, a straggler plus a liar, quadratic layer at the bound, censored horizon, malformed shapes/sessions
- [x] Library suite (`research`): `cargo test --lib --features research --no-fail-fast` → **760 passed, 0 failed, 1 ignored** (was 732 before this stage)
- [x] Library suite (default): `cargo test --lib --no-fail-fast` → **720 passed, 0 failed, 1 ignored** (714 before)
- [x] Full all-target suite (`research`): `cargo test --features research --no-fail-fast` → green (lib, bins, every integration suite incl. `multi_nat_e2e`)
- [x] Clippy: `cargo clippy --all-targets --features research -- -D warnings` → clean
- [x] Format: `cargo fmt -- --check` → clean

## Release bookkeeping

- [x] `Cargo.toml` / `Cargo.lock` root at `3.0.0`; `assets/app.rc` at `3,0,0,0` / `"3.0.0"`; Android `versionCode 300`, `versionName "3.0.0"`
- [x] Dated `[3.0.0]` changelog with the evidence above
- [x] `DEV/V3_PIPELINE.md` still 9,132 bytes
- [x] HEAD still `807e37c`; nothing committed/pushed; fuzz corpus and `data/bundles.sled` untouched

## Still open

- **No live mesh run of any of the four tracks.** Polysemy needs a real multi-path link, sheaf needs a live session graph, erosion needs a networked committee, LC-Vantablack needs real workers. The tests exercise the code paths with in-process peers and pinned clocks.
- **Signed packages were not produced.** `packaging/verify_signed_release.sh` is the gate, but this host has no project signing keys (Authenticode, Homebrew bottle, `.deb`, APK), so installers remain withheld and no signed-release claim is made.
- **ProVerif was not re-run.** The binary is absent here; only the committed attestation (and its build-time hash check) was verified.
- **Causal Polysemy is not wired into the transport.** It is a codec with the exact capacity bound, not a scheduler for the live Wi-Fi/5G/HF path set; selecting a world still belongs to the caller.
- **Sheaf blame is detection, not attribution.** A witness proves *a* loop cannot close and names its edges; it does not decide which of two disagreeing peers lied.
- **`/Brepro` is MSVC-specific.** Reproducibility on GNU or macOS hosts relies on the linker not stamping time; the script does not add flags there.
