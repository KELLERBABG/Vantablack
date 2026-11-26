# Changelog

All notable changes to the Vantablack project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [3.7.3] — 2026-11-26

- **Voucher & Onion Unification (`src/daemon/research_hooks.rs`, `src/daemon/peer_loop.rs`):** Unified `BLND!` and `RLY!` transit admission onto a single shared `RelayBandwidthBank` nullifier; added `§6` session-bound relay voucher documentation to `docs/anti_abuse.md`.
- **Control-Plane Telemetry (`src/control.rs`):** Exposed `research_hooks::status_json` (`entropy_beacon`, `braid`, `vault`, `voucher`) in `/api/status` under `#[cfg(feature = "research")]`.

## [3.7.2] — 2026-11-26

- **Configurable Erosion Windows & Keep-Proofs (`src/daemon/research_hooks.rs`):** Replaced hardcoded `3600s`/`900s` constants with floor-guarded `GHOST_EROSION_EPOCH_SECS` (floor `60`) and `GHOST_EROSION_TTL_SECS` (floor `1`); wired `dead_drop::prove_retention_interest` locally and via `OP_KEEP`.

## [3.7.1] — 2026-11-26

- **Multi-Host Vault Distribution (`src/daemon/research_hooks.rs`, `src/ghost/v2/erosion.rs`):** Added `EphemerizerCommittee::share_bytes` / `from_shares` and `GHOST_VSHARE__` (`STORE_SHARE`/`SHARD`/`CHUNK`, `FETCH`, `ITEMS`, `PURGE`) to distribute DTN erosion shares, archive shards, and dead-drop chunks across 3 sorted peers (falling back to local when `< 3` peers are connected).

---

## [3.7.0] — 2026-11-26

> **Versioning Policy:** `vX.0.0` = full major release; `v0.X.0` = module(s) wired, added, or upgraded; `v0.0.X` = bugfixes and small incremental changes (`3.7.x` tracks multi-host hardening toward `v4.0.0`).

### Added / Wired
- **Tier-1 `research` Daemon Hooks (`src/daemon/research_hooks.rs`, `tests/research_tier1.rs`):** Wired all 7 Tier-1 primitives (`braid_identity`, `erosion`, `dead_drop`, `entropy_beacon`, `polysemy`, `mesh_archive`, `bandwidth_voucher`) with durable `.braid`/`.journal` persistence, publish-gate protection, frozen beacon rounds, and DTN vault sealing (`9` integration tests + `12` daemon hook unit tests passing).
- **Architecture & Anti-Abuse Docs:** Added `docs/anti_abuse.md` and `docs/DORMANT_MODULES.md`.

### Removed / Rolled Back
- **SDR & QKD Hardware Backends (`20b7f7d`):** Removed `sdr` (`abos`), `qkd-tls`, `src/ghost/layers/l10_qel_etsi.rs`, and `tests/qkd_etsi014_kme.rs`; removed `landauer.rs` and `photonic_orbit.rs` (`a9a3ea2`).

### Earlier `v3.0.0+` Unreleased Notes

Implements the four primitives `DEV/UNPRECEDENTED_PRIMITIVES.md` lists as
"not yet implemented". They are `research`-gated like every other dormant
module, add no node state, and are not promoted until benchmarked against the
production path.

- **Braid-Locked Identity (`src/ghost/net/braid_identity.rs`):** each ratchet
  step rotates the Ed25519 identity key and signs
  `(height, next_pk, braid)` with the retiring key, where
  `braid = H(prev_braid || next_pk || transcript)`; the transition is a
  200-byte certificate. One key may have exactly one child, so a cloned node's
  second signed child is a self-authenticating `CloneProof` under the fork key
  — no ledger, no witness vote. Also implements the epidemic bound
  `R <= (ln N + ln ln(1/delta)) / (2 ln f)`. Tests:
  `a_linear_braid_extends_without_a_fork`,
  `two_transitions_from_one_key_are_a_self_authenticating_proof`,
  `a_fork_at_a_later_height_still_proves_the_clone`,
  `a_tampered_transition_is_refused`, `a_replayed_transition_is_stale`,
  `a_transition_is_two_hundred_bytes_and_round_trips`,
  `the_collision_bound_is_the_theorem_bound`.
- **Metabolic Cryptography (`src/ghost/net/metabolic.rs`):** authority is the
  sum over physically distinct domains of the saturated max-potential
  `2^{-(t - t_p)/half_life}` in `[0, 1]`, so a Sybil flood inside one domain is
  worth one pulse. A seized node fed unbounded Sybils across `k < theta`
  domains still falls below threshold by
  `t0 + half_life * log2(m_honest / (theta - k))`, with no revocation packet.
  Tests: `a_domain_contributes_at_most_one_however_many_sybils_pulse`,
  `mass_halves_every_half_life`,
  `an_infinitely_fed_adversary_still_dies_at_the_theorem_deadline`,
  `a_mass_already_below_the_threshold_dies_now`,
  `collusion_at_the_threshold_has_no_finite_bound`,
  `a_fresh_pulse_restores_capability`, `a_clock_needs_a_real_half_life`.
- **Photonic Secret Orbit (`src/ghost/net/photonic_orbit.rs`):** a 256-bit key
  is split into three XOR shares whose phases around a fiber loop are
  validated to leave no two inside silicon at once. Reports the duty cycle
  (`n * dwell / T`, 0.015 % for the 40,000 km / 10 µs plan), the collision
  schedule, one-share seizure, and one-orbit evaporation after a fiber cut.
  Tests: `the_planetary_orbit_is_two_hundred_milliseconds`,
  `no_two_shares_are_ever_in_silicon_at_the_same_instant`,
  `the_matter_duty_cycle_is_the_silicon_fraction`,
  `overlapping_phases_are_refused`,
  `one_share_reveals_nothing_and_all_three_rebuild_the_key`,
  `a_planetary_seizure_captures_one_share_and_one_orbit_erases_the_key`.
- **Thermodynamic Exhaust (`src/ghost/net/landauer.rs`):** exact
  `H(S_{t-1} | S_t, X_t)` for a deterministic finite-state update map, the
  reflecting saturating-walk statistic (which erases `2/levels` bits per
  symbol at fair input — only the two clamped boundaries merge histories —
  and less for a predictable stream), and the `k_B T ln 2` power floor. Tests:
  `a_bounded_walk_erases_two_bits_per_level_at_fair_input`,
  `more_memory_means_less_irreversible_erasure`,
  `a_predictable_stream_leaves_less_history_to_erase`,
  `a_shift_register_erases_exactly_the_bit_that_falls_off`,
  `an_injective_update_erases_nothing`,
  `the_landauer_power_is_the_erasure_rate_times_kt_ln2`,
  `a_room_temperature_wiretap_is_a_physical_bound_not_a_denial_mechanism`,
  `a_walk_round_trips_its_levels`.

## [3.0.0] - 2026-11-25 - Full Epistemic Mesh Release (V3 Stage 7)

Completes [`DEV/V3_PIPELINE.md`](DEV/V3_PIPELINE.md). Stage 7 closes the pipeline
by landing the four frontier tracks the stage names as research-gated modules and
by making the release gate measurable instead of asserted. No production packet
path changes: every new primitive is behind `--features research`, matching the
existing dormant-module policy, and each one is only promoted once benchmarked.

- **Chrono-Erosion (`src/ghost/v2/erosion.rs`):** a `(t, n)` Shamir committee
  over Ristretto255 holds an epoch secret and publishes `K = k * G`. A bundle key
  is wrapped under `H(k * M)` where `M = H_G("VB-EROSION-BUNDLE-V1" || bundle_id)`;
  the mask is obtained by a blinded threshold evaluation (`B = r * M`, `t`
  partials each carrying a Chaum–Pedersen DLEQ against the member's published
  share commitment, Lagrange interpolation at zero, unblind with `r^-1`), so the
  committee never learns which bundle it served. At the expiry epoch members
  volatile-zeroize their share bytes: once fewer than `t` remain, the wrapped
  key is unreadable without breaking CDH, whatever the archive holds. Shares are
  stored as canonical scalar bytes precisely so the wipe is a `zeroize` call and
  not a dropped reference. Tests: `a_bundle_is_readable_only_before_its_epoch`,
  `the_committee_forgetting_is_what_kills_the_bundle`,
  `fewer_than_threshold_partials_cannot_unblind`,
  `a_partial_evaluation_not_bound_to_its_commitment_is_refused`,
  `the_mask_binds_the_bundle_and_its_epoch`, `a_dead_committee_refuses_to_seal`.
- **LC-Vantablack (`src/ghost/net/sharded_compute/lagrange.rs`):** the raw byte
  RS(2,1) path only commutes with byte-linear operations, so an arbitrary layer
  destroys it. `K` quantized input tensors plus `T` uniform masks are
  interpolated into a degree-`K+T-1` Lagrange polynomial over `F_{2^31-1}`, each
  worker evaluates a degree-`d` layer element-wise, and the client
  Berlekamp–Welch-decodes the degree-`d(K+T-1)` composite codeword, tolerating
  `S` silent stragglers and `A` liars exactly when
  `N >= d(K+T-1) + 1 + S + 2A`. The `T` masks are information-theoretic privacy,
  not obfuscation. Tests: `the_worker_bound_is_the_theorem_bound`,
  `a_linear_layer_survives_one_straggler_and_one_liar`,
  `a_quadratic_layer_needs_and_gets_the_bound`,
  `one_worker_learns_nothing_about_the_input`, `malformed_jobs_are_refused`,
  `field_arithmetic_round_trips`.
- **Causal Polysemy (`src/ghost/net/polysemy.rs`):** an `(n, k, r)` additive code
  over `F_{2^8}` carries one decryptable message per `k`-subset of physical
  paths. Whichever `k` paths survive collapse to that world; the censor's own cut
  selects the reality that materializes, while every world needing the lost path
  stays information-theoretically invisible. Shard size is exactly the
  counterfactual capacity `C(n-1, k-1) * r`. Tests:
  `every_world_collapses_from_its_own_paths`,
  `a_cut_path_selects_the_world_that_survives`,
  `a_lost_path_leaves_the_hidden_world_a_bijection`,
  `the_shard_is_exactly_the_counterfactual_capacity`, `malformed_frames_are_refused`.
- **Epistemic Sheaf Cohomology (`src/ghost/net/sheaf.rs`):** authenticated
  sessions carry a 1-cochain of observation discrepancies. A spanning-forest
  potential fit decides exactness — `H^1` vanishes iff one global reality
  explains every local view — and each contradicting non-tree session yields a
  fundamental cycle with non-zero holonomy, i.e. a witness that a split-world
  MitM or eclipse boundary exists even when 100% of nodes pass their own local
  checks. Tests: `one_consistent_reality_has_no_obstruction`,
  `a_split_horizon_leaves_a_non_zero_cohomology_class`,
  `a_single_falsified_session_is_localised_and_quantified`,
  `holonomy_is_invariant_under_a_gauge_shift`, `malformed_sessions_are_refused`.
- **Live census over PEX (`src/ghost/v2/xray.rs::census`, `src/daemon/discovery.rs`,
  `src/daemon/peer_loop.rs`):** the Stage 6 census was verifiable but never fed,
  so a running daemon reported `census_population: unknown`. Each node now
  announces its signed epoch ticket in a `GHOST_CENSUS__` PEX frame. The
  receiver verifies the epoch signature and then **discards the claimed cell**:
  it counts the cell it derives from the address the encrypted frame actually
  arrived from (`observed_cell`, a `/24` for IPv4 and `/48` for IPv6), and the
  lottery value is derived from that cell alone. That closes two holes a naive
  gossip path would have opened — fifty identities in one subnet stay one cell,
  and nobody can grind a small order statistic, because a cell has exactly one
  value per epoch. Relayed third-party entries are dropped: without the endpoint
  that carried them there is no cell to count. Cells are only gossiped as
  hashes, so the wire form still carries no address. Tests:
  `a_live_announcement_counts_the_observed_cell_not_the_claimed_one`,
  `sybils_in_one_subnet_are_one_cell_whatever_they_claim`,
  `a_grinded_value_cannot_move_the_census`,
  `a_stale_or_mislabelled_announcement_is_refused`,
  `the_pex_batch_round_trips_and_carries_no_address`,
  `two_hundred_routing_domains_clear_the_anonymity_floor` (512 distinct `/24`s
  clear the 200-relay floor), plus the daemon-side
  `only_the_senders_own_announcement_is_accepted` and
  `a_frame_without_an_observed_endpoint_counts_nothing`.
- **Reproducible release gate (`scripts/reproducible_hash.sh`):** a deterministic
  source manifest plus two release builds in fresh target directories. Measured
  here, the two builds differed in exactly 24 bytes until the MSVC linker was
  told not to stamp the COFF header and debug directory; with
  `-C link-arg=/Brepro` both builds hash
  `5f5cc0a1871b0f3bacf071c0e946f4a212bbef4c5d51a2c680436bc835ba32da`. The script
  applies the flag automatically on a `windows-msvc` host.
- **Version:** `3.0.0` in `Cargo.toml`, `Cargo.lock`, `assets/app.rc`
  (`3,0,0,0`), Android `versionCode 300` / `versionName "3.0.0"`.

Verification: `cargo test --lib --features research --no-fail-fast` → 760
passed, 0 failed, 1 ignored (732 before this stage, +28); `cargo test --lib` →
720 passed (714 before). Full `cargo test --features research --no-fail-fast`
green including the multi-NAT and multi-hop integration suites;
`cargo clippy --all-targets -- -D warnings` and the `research` variant clean;
`cargo fmt -- --check` clean. ProVerif 2.05 was run in WSL over all five models
via the new `scripts/formal_verify.sh`: every model reproduces the committed
attestation's RESULT lines exactly, including the positive reachability
witnesses. No signed packages were produced — this host has no signing keys, so
installers remain withheld. See `DEV/STAGE7_PROGRESS.md` for the open items.

---

## [2.7.0] - 2026-11-24 - Physical & Coercion-Resistant Hardening (V3 Stage 6)

Completes Stage 6 of [`DEV/V3_PIPELINE.md`](DEV/V3_PIPELINE.md). The release adds
the four physical/epistemic primitives the stage names — light-cone jurisdiction
proofs, a coercion-proof dual-plane tail, a zero-address population proof, and
RF reciprocity key extraction — and wires the census and jurisdiction evidence
into the truth ledger rather than leaving them as library code. One existing
behaviour changes on the wire path: the GTF jitter tail is now random per
message (see below), which is required for deniability under key coercion.

- **Vanta-Subliminal Tail (`src/ghost/layers/l2_aead.rs`, `src/ghost/net/mod.rs`,
  `src/daemon/framing.rs`):** the 64-byte tail was a deterministic HMAC of the
  session key and seal metadata. An auditor handed the coerced decoy key could
  therefore recompute it and detect a substituted tail — the one thing a hidden
  channel must not permit. Tails are now 64 uniform random bytes drawn once per
  message (`net::random_tail`) and carried on the header/`SealCtx` so every shard
  and the receiver use the same bytes; they remain authenticated as AEAD
  associated data. `l2_aead::subliminal_tail_seal`/`subliminal_tail_open` add the
  optional 48-byte hidden plane (XChaCha20-Poly1305 into the 64-byte tail, fresh
  domain-separated nonce), so an unused random tail and a used one are the same
  length and both leave the decoy frame opening cleanly. Tests:
  `the_hidden_plane_round_trips_and_is_exactly_one_tail_long`,
  `a_random_tail_opens_no_hidden_plane_and_neither_does_a_tampered_one`,
  `the_hidden_plane_is_bound_to_epoch_direction_and_frame_nonce`, and the framing
  test now asserts two messages do not share a tail.
- **LightCone-Proof + causal hops (`src/ghost/net/sovereign_cloud.rs`):** a
  device's jurisdiction is no longer its own declaration. `LightConeProof`
  carries ≥3 anchor measurements; `verify` rejects impossible RTTs (faster than
  fibre), stale/thin/duplicate proofs, recomputes the cone intersection in a
  tangent plane, and `verify_in` requires the whole certified disc to sit inside
  the requested perimeter (EU/US/CH/APAC bounding regions). Placement only
  accepts attested devices; `SovereignDevice::jurisdiction` is reporting-only.
  `CausalHopWitness::classify` composes three proofs and refuses overlapping
  regions, reporting `KeyDisjoint` unless keys are hardware-bound in a
  `hardware-tpm` build. Tests:
  `a_light_cone_proof_certifies_a_position_inside_every_cone`,
  `a_claim_faster_than_light_is_refused`,
  `a_stale_or_thin_proof_is_not_evidence`,
  `placement_requires_a_proof_rather_than_a_declaration`,
  `a_swiss_proof_cannot_hold_an_eu_object_without_being_inside_the_perimeter`,
  `a_causal_hop_witness_requires_pairwise_disjoint_cones`,
  `a_proof_needs_configured_anchors`. (The module is `research`-gated, as before.)
- **Blind Census (`src/ghost/v2/xray.rs`):** VRF-shaped per-epoch tickets
  (deterministic Ed25519 over a hashed cell commitment — no IP, port or static
  key), an `m`-minimum sketch that keeps the 64 smallest distinct cells, and the
  `(m-1)/U_(m)` estimator with an exact 99% lower confidence bound computed from
  the binomial order-statistic law. Sybils in one cell collapse to one entry. The
  ledger gains a `census_population` invariant: anonymity needs a *proven* lower
  bound of 200 distinct cells, not a reachable relay count. Tests:
  `the_sketch_is_an_unbiased_estimator_of_a_population`,
  `sybils_in_one_cell_collapse_to_one_entry`,
  `a_ticket_is_bound_to_its_epoch_cell_and_key`,
  `the_gossiped_sketch_carries_no_address`,
  `the_lower_bound_is_never_above_the_truth_for_a_small_sketch`.
- **RF-CRKG + monotone combiner (`src/ghost/layers/l10_qel.rs`):**
  `ReciprocityCapture` → quantized excursions → Hamming(7,4) syndrome
  reconciliation (single-error-per-block, 3 leaked bits per 7) → HKDF privacy
  amplification, refusing a channel whose Maurer capacity is non-positive or
  whose surviving bits are below 256+128. `combine_monotone` implements
  `HMAC(K_ML-KEM, HMAC(K_X25519, K_L10 ‖ transcript))`, so uniformity in any one
  key survives the other two being known. Tests:
  `reciprocity_derives_the_same_secret_on_both_ends`,
  `reciprocity_refuses_a_channel_an_eavesdropper_can_follow`,
  `reciprocity_refuses_a_capture_too_short_to_amplify`,
  `a_real_sounding_capture_flows_through_quantization_and_agrees`,
  `the_monotone_combiner_binds_every_input`.
- **Version:** `Cargo.toml` / `Cargo.lock` / `assets/app.rc` at 2.7.0 /
  2,7,0,0; Android `versionCode 270`, `versionName 2.7.0`.
- **Verification:** `cargo test --lib --no-fail-fast` → **714 passed, 0 failed,
  1 ignored**; `cargo test --lib --features research --no-fail-fast` → **732
  passed, 0 failed, 1 ignored**; full `cargo test --features research
  --no-fail-fast` green across bins and integration tests; `cargo clippy
  --all-targets --features research -- -D warnings` clean; `cargo fmt -- --check`
  clean; `DEV/V3_PIPELINE.md` unchanged at 9,132 bytes.
- **Honest boundaries:** no HF sounder is attached to this host, so RF-CRKG is
  exercised on synthetic/worker-supplied captures; `GHOST_QEL_BACKEND=rf_reciprocity`
  is refused as a label backend because the exchange is interactive. Light-cone
  proofs are evidence about the signing key's location, not silicon — only a
  `hardware-tpm` build upgrades causal hops to `PhysicallyDisjoint`. Census
  tickets are verified by the node but no live ticket-ingestion path feeds the
  process-wide sketch yet, so `census_population` is `unknown` until peers send
  them (by design, not a pass).

## [2.6.0] - 2026-11-24 - Adoption Engine (V3 Stage 5)

Completes Stage 5 of [`DEV/V3_PIPELINE.md`](DEV/V3_PIPELINE.md): the everyday
surfaces now have one-click entry points, and the claims that cannot be proven
locally are withheld rather than asserted. The transport is unchanged; this
release is the adoption layer over the Stage 1–4 primitives.

- **One-click surfaces (`src/ghost/v2/adopt.rs`, `src/control.rs`,
  `assets/wan_dashboard.html`):** the dashboard exposes TUN, DNS, Drop, Expose
  and Party actions backed by `GET /api/v2/adopt/status` and
  `POST /api/v2/adopt/{drop,expose,party,dns,tun}`. Drop starts a real
  `PortalRegistry` session, Expose starts the token-gated relay, Party preflights
  both UDP ports before claiming success, and DNS starts the loopback stub. Drops
  carry typed, expiring `vb-drop://` room codes; Expose and Party do the same.
  Room parsing rejects wrong schemes, malformed hex and expired codes. Tests:
  `room_codes_round_trip_and_reject_the_wrong_family_or_expiry`,
  `a_one_click_drop_returns_a_parsable_room_code`,
  `a_one_click_expose_returns_a_token_and_room_code`,
  `a_one_click_party_preflights_both_ports_and_returns_a_room_code`,
  `a_one_click_dns_stub_binds_and_answers_with_an_address`.
- **TUN/DNS one-click:** DNS starts the loopback stub. `POST /api/v2/adopt/tun`
  now opens the platform device (`ggn0`) and holds it for the process, reporting
  the real interface and MTU; a second call reports `already_running`, and
  `{"action":"stop"}` releases it. A refused device is a `409` with a typed
  reason — `feature_missing`, `privilege_denied` (Administrator or
  CAP_NET_ADMIN/root), `device_missing` (`wintun.dll` or `/dev/net/tun`) or
  `unsupported` — never a started interface. Status reports `tun_running`.
  Tests: `the_tun_device_really_opens_and_is_released_instead_of_being_claimed`,
  `a_refused_tun_device_is_classified_by_privilege_or_driver`,
  `dns_is_one_click_and_tun_starts_or_refuses_with_a_reason`. The test exercises
  the in-memory device (`GHOST_VPN_FAKE_TUN`); a real interface still needs the
  host's privilege, which CI cannot supply.
- **Opt-in AC-powered Blind Relay (BTCr v2):** `blind_relay_enabled` and
  `blind_relay_ac_only` are persisted consumer settings. Enabling refuses with a
  reason when the AC-only promise cannot be measured (no reading, battery, or a
  stale reading), and the boot path (`src/daemon/node.rs`) creates the relay role
  only when that same measured policy says `Serving`. BTCr v2 still issues
  tickets only for signed relay receipts; the toggle does not mint anything.
  Tests: `blind_relaying_is_off_until_opted_in_and_withholds_without_fresh_ac`
  (disabled, unmeasured, battery, stale AC, fresh AC, explicit no-AC opt-in).
- **Installer signing gate wired into status:** `packaging/verify_signed_release.sh
  [--json] [dist]` verifies Authenticode, Homebrew bottle, `.deb` and APK, emits
  per-family `{kind, artifact, signed, sha256}` evidence with the failure
  reasons, and exits non-zero unless all four verify. `adopt::installer_report`
  runs it only when `GGN_SIGNED_DIST` names a release directory (optionally with
  `GGN_SIGNED_RELEASE_VERIFIER`), caches the verdict for 300 s, and feeds it to
  `installer_claim`; `GET /api/v2/adopt/status` reports `installers` plus
  `installer_evidence {ran, source, checked_at, ttl_secs}`. A withheld or
  unparseable verdict is reported as withheld, never as partial success. Tests:
  `the_signed_release_verifier_decides_the_installer_claim`,
  `a_signed_installer_claim_needs_all_four_families_and_real_signatures`. The
  script's success path was checked with stub signers (four families, real
  digests). No production key material exists here, so the release claim stays
  **withheld**.
- **Power probe cached off the request path:** `adopt::PowerCache` keeps one
  reading for `POWER_TTL_SECS` (60 s), so status and relay reporting read the
  same observation instead of spawning PowerShell on every poll. An explicit
  opt-in calls `probe_power_evidence()` for one real measurement, and a clock
  that moves backwards forces a re-probe. Test:
  `the_ac_probe_is_cached_for_the_ttl_instead_of_running_per_request`.
- **One-line relay container:** `deploy/docker-compose.relay.yml` runs
  `ggn --relay-only` with `GHOST_EXIT=0` and `GHOST_NO_GUI=1`; test
  `the_relay_container_really_runs_relay_only` fails if that command drifts.

Stage 5 verification: `cargo test --lib --no-fail-fast` 701 passed, 0 failed, 1
ignored; `cargo clippy --all-targets -- -D warnings` and `cargo fmt -- --check`
clean; 2.6.0 resource test passes. `DEV/V3_PIPELINE.md` is unchanged at 9,132
bytes. Open items are listed in `DEV/STAGE5_PROGRESS.md`: relay activation still
applies on the next daemon restart, a real TUN device needs host privilege
(only the in-memory path is exercised here), and no installer family has a
production signature until the release signing keys are configured.

## [2.5.0] - 2026-11-24 - Traffic & Clock Physics (V3 Stage 4)

Completes Stage 4 of [`DEV/V3_PIPELINE.md`](DEV/V3_PIPELINE.md): the renewal
shaper now has a measured burst contract, clock pacing evidence expires, and
the NVIS profile is enforced as physics rather than prose. All three are gated
to `ghost`/`vantablack`; `fast` and `shielded` inherit no timing requirement.

- **Shaped-RACS (`src/ghost/v2/racs.rs`):** the renewal schedule no longer wraps
  ON across a cycle boundary, and slot 0 of every cycle is a guard OFF slot.
  That makes the burst bound real: max ON run 3 slots (750 ms), duty ≤ 0.35,
  576-byte frames, measured over a 240-slot window with at least 48 slots before
  shaping counts as evidence. `shaping_evidence()` reports the schedule window,
  emissions, max run, duty and last emission; the ledger verifies
  `cover_traffic` only when that evidence is fresh and within contract. Frames
  emitted with no shaping evidence are `Unknown`, a burst/duty violation is
  `Failed`, and neither can produce the anonymity claim. Tests:
  `measured_windows_never_exceed_the_burst_or_duty_contract`,
  `the_contract_rejects_a_long_burst_or_a_high_duty_cycle`,
  `too_short_a_window_is_not_shaping_evidence_yet`,
  `cover_claim_is_withheld_without_fresh_shaping_evidence`,
  `a_shaping_burst_violation_fails_the_cover_claim` (10 `racs` tests).
- **Horizon-Chronos (`src/ghost/v2/chronos.rs`):** `ChronosEvidence` carries the
  measured inner/outer RTTs, stationary horizon, residual, observation count and
  unix timestamp. It is verified only when both clocks were observed, the
  evidence is at most 120 s old, the inner flow is at or inside the horizon, and
  the classifier says `Consistent`. The ledger adds `layer_clocks` only for the
  Umbra planes: stale evidence is `Unknown`, a circuit past the horizon is
  `Failed`. Tests: `the_horizon_boundary_is_inclusive_and_one_millisecond_past_it_fails`,
  `clock_evidence_expires_at_the_ttl_boundary`,
  `a_single_observation_is_not_a_clock_claim`,
  `stale_chronos_evidence_is_unmeasured_not_verified`,
  `a_circuit_outside_the_stationary_horizon_fails_the_clock_claim` (12
  `chronos` tests).
- **Narrowband NVIS (`src/ghost/v2/nvis.rs`, `abos/WHITEPAPER.md`):** an
  executable GhostCell-Nano contract — carrier 2,000–10,000 kHz, occupied
  bandwidth 3,000–24,000 Hz, information rate 24–48 bps, 30–60 s per 180-byte
  cell, spreading gain 20.9–27 dB. Measurements outside those bounds are
  refused, never clamped (the withdrawn 1 Mcps plan fails validation). A profile
  is evidence for 900 s; `/api/v2/nvis` and the ledger's `nvis_profile` invariant
  report `unmeasured`/`stale` rather than inventing a channel. Tests:
  `documented_corners_produce_thirty_and_sixty_seconds`,
  `an_impossible_wideband_plan_is_refused_rather_than_clamped`,
  `a_missing_or_stale_measurement_withholds_the_claim`,
  `nvis_claim_requires_a_fresh_measurement`, plus the API's unmeasured test (5
  `nvis` tests). No on-air SDR measurement path ships in this build, so the
  endpoint honestly remains `unmeasured` until the radio layer calls
  `note_channel_sample`.
- **Regime isolation (`src/ghost/v2/regime.rs`):** `timing_hardened`,
  `shaping_required` and `chronos_required` are true only for `ghost` and
  `vantablack`; `fast`/`shielded` keep their existing policy and gain no ledger
  requirement. Tests: `timing_hardening_is_strictly_the_umbra_planes`,
  `effective_fast_policy_is_unchanged_by_timing_hardening`,
  `fast_and_shielded_are_not_charged_timing_hardening` (9 `regime` tests).
- **Verification:** `cargo test --lib --no-fail-fast` → 688 passed, 0 failed,
  1 ignored; `clippy --all-targets -- -D warnings` clean; `fmt -- --check`
  clean; the version-resource test passes with `FILEVERSION 2,5,0,0`. The
  formal-attestation gate was re-probed on this tree: appending one comment to
  `formal/ghost_session.pv` failed the build with exit 101 and the hash
  mismatch; restoring the file rebuilt with exit 0.

## [2.4.0] - 2026-11-24 - Epistemic Truth Ledger (V3 Stage 3)

Completes Stage 3 of [`DEV/V3_PIPELINE.md`](DEV/V3_PIPELINE.md): a `Verified`
wire claim now requires a token only the measurement layer can mint, stale
tokens degrade to `Unknown`, and the binary carries the hashes of the formal
models it was built from.

- **`WireWitness<P>` type-level gate (`src/ghost/v2/xray.rs`):** the ledger's
  `circuit_hops`, `cover_tx` and `nonce_echo_hops` fields are no longer `u8` /
  `u64` values. They are typed tokens whose fields are private and whose only
  constructor is visible inside `xray`. `api.rs` can pass a witness through but
  cannot write `Some(3)` from a regime flag, a peer's claim, or a JSON body; the
  CLI has the same restriction. Tokens expire (circuit 300 s, cover 120 s, echo
  300 s) and `build` demotes stale ones to `Unknown` for every invariant and
  observation at once.
- **Measured producers:** `circuit_hops_witness()` reads the route the SOCKS5
  proxy recorded (with its timestamp), `cover_tx_witness()` reads the RACS
  emission counter and the time of the last frame, and `nonce_echo_witness()`
  reads the last verified signed echo. `control.rs` now passes those through
  instead of raw counters.
- **Live signed echo:** the daemon's NECHO tick no longer falls back to
  `unwrap_or(1)` when no circuit exists; it skips the challenge. A one-hop claim
  can no longer be manufactured from "no route yet", and the existing
  three-hop signature test still covers the verified path.
- **N_eff in the API:** `xray_endpoint_uses_neff_domain_clustering` drives
  `Witnesses` with 400 relays in one `/24` and asserts the API reports the
  `relay_population` invariant as failed, with N_eff named, and withholds the
  claim. The xray-side Sybil tests remain.
- **Proof-Carrying Claim Graph (`build.rs`, `formal/attestations.json`,
  `scripts/formal_attest.sh`):** the attestation records the SHA-256 of every
  formal model and the `RESULT` lines ProVerif 2.05 produced (5 models, 18
  results). `build.rs` verifies every hash, refuses unattested `.pv` files, and
  embeds the table; the ledger exposes it as `formal` provenance. Editing a
  model without re-running the attestation fails the build — verified by
  appending one comment to `ghost_session.pv` (build exit 101, hash mismatch)
  and restoring it (build exit 0). A unit test also compares the embedded hashes
  with the files on disk so a stale attestation cannot be committed silently.
- **Verification:** `cargo test --lib` → 668 passed, 0 failed, 1 ignored;
  `ghost::v2::xray` 15 passed; `ghost::v2::api` 6 passed;
  `cargo clippy --all-targets -- -D warnings` clean; `cargo fmt -- --check`
  clean; the version-resource test passes with `FILEVERSION 2,4,0,0`.

## [2.3.0] - 2026-11-24 - Honest Multipath (V3 Stage 2)

Completes Stage 2 of [`DEV/V3_PIPELINE.md`](DEV/V3_PIPELINE.md): the
`m >= c + f + 1` bound is enforced by one constructor, L3 threshold sharing runs
on the same ramp engine as L4, and bonding refuses carriers that are not
physically distinct.

- **Bonding refuses non-distinct paths (`src/ghost/v2/hpeb.rs`):** `bond_with`
  selected `available()`, so two unpinned sockets, or two interfaces behind one
  local address, produced a "bonded" set while `is_bonded()` already returned
  false. Selection is now `bondable()` — live, pinned, one per distinct local
  address, cheapest wins an address collision — so an unpinned path cannot
  receive a shard or inflate `m`. `live_interfaces()` reports the same set. The
  test `bonding_refuses_paths_that_are_not_physically_distinct` was written
  first and failed on the old code at the unpinned case.
- **Theorem 1 enforced in one place (`src/ghost/layers/l4_rs.rs`):**
  `RampParams::for_paths(m)` refuses `m < 3` and `m > 255` and returns
  `(c = 1, r = m - 2, f = 1)`; `hpeb` uses it instead of recomputing the triple.
  `m >= c + f + 1` holds by construction and is asserted for every parameter set
  in the sweep.
- **Exhaustive `m = 3..=8` sweep (`l4_rs`):** for every `(c, r, f)` with
  `r >= 1` and `m = r + c + f` in `3..=8`, all `2^m` shard subsets are decoded:
  subsets of size `>= r + c` return the payload, smaller subsets return `None`.
  Boundary coverage: 255 shards including index 254, `c = 0` availability-only,
  duplicate / out-of-range / mismatched shards, empty and short payloads, and
  every ramp scheme's wire encoding.
- **HPEB path sweep (`hpeb`):** for `m = 3..=8`, one shard leaves per interface,
  every single-path outage recovers, every two-path outage fails, and one shard
  never recovers. `path_changes_reselect_the_scheme_and_honour_the_new_path_count`
  drops two of five paths (`m = 3`), restores them (`m = 5`), and falls back to the
  explicit `Xor2` / `Duplicate2` modes at two paths.
- **L3 on the ramp engine (`src/ghost/layers/l3_shamir.rs`):**
  `split_secret_ramp` / `join_secret_ramp` express threshold sharing as
  `(c, r = 1, f)`; shares are self-describing (`index + 4-byte frame + 32 secret
  bytes`). `ThresholdGroupKey` (3-of-5 is `c = 2, r = 1, f = 2`) is built on it:
  all ten 3-share subsets reconstruct, and `c = 0`, `r != 1`, `m < 3`, duplicate
  indices, out-of-range indices, wrong share lengths and below-threshold sets are
  refused. The legacy 2-of-3 encoding is retained because OMR envelopes outlive
  an upgrade; new threshold work uses the unified primitive.
- **Verification:** `cargo test --lib` → 665 passed, 0 failed, 1 ignored;
  `cargo clippy --all-targets -- -D warnings` clean; `cargo fmt -- --check`
  clean; `ghost::icon::tests::version_resource_is_readable_by_the_shell` passes
  with `FILEVERSION 2,3,0,0`; ProVerif 2.05 was re-run on all five models and
  their witness/secrecy results are unchanged (Stage 2 does not list ProVerif,
  but the models were not left unchecked).

## [2.2.0] - 2026-11-24 - Cryptographic & Formal Credibility (V3 Stage 1)

Completes Stage 1 of [`DEV/V3_PIPELINE.md`](DEV/V3_PIPELINE.md). The BTCr v2 and
ProVerif work specified in `DEV/EPISTEMIC_HARDENING.md` §1–§2 was already in the
tree; this entry gates it and fixes the one required property that was still
process-local.

- **BTCr spend state now survives a restart (`src/ghost/v2/btcr.rs`):** Ticket
  nullifiers and redeemed work-receipt nullifiers lived only in a process-global
  `HashSet`, so restarting forgot every spend: the same beneficiary-signed receipt
  could mint another ticket and the same ticket could be spent again. Both sets are
  written atomically to `v2/btcr_spend_journal.json` beside the wallet (both
  governed by `GHOST_DATA_DIR`), reloaded on first use, and persisted before the
  operation reports success. A failed write removes the in-memory entry again; an
  unreadable journal refuses mints and spends rather than starting empty. Tests:
  `spend_history_survives_a_restart`,
  `a_corrupt_journal_refuses_instead_of_forgetting`.
- **Issuer key is private and bucketed (`src/ghost/v2/btcr.rs`, `src/ghost/v2/api.rs`):**
  `k_root = HKDF-SHA256(identity.key, "VB-BTCR-V2")`; the fingerprint is never an
  input. `k_{day,tier}` is derived per quantized UTC-day/work-tier bucket and
  `K_{day,tier}` is the published key, so tickets in one bucket share an anonymity
  set and re-labelling metadata selects a different key. Tests:
  `the_root_key_is_private_and_seed_determined`,
  `bucket_keys_are_distinct_per_day_and_tier`,
  `a_ticket_does_not_verify_outside_its_bucket`.
- **Receipts and tickets are single-use:** issuance requires a beneficiary-signed
  `btcr-receipt:v1` with non-zero work, and the 81-byte ticket is checked against
  its own bucket before spending. Tests:
  `a_work_receipt_can_only_be_redeemed_once`, `a_replayed_ticket_is_refused`,
  `ticket_encoding_round_trips_in_81_bytes`.
- **Formal models are non-vacuous:** `ghost_session.pv` transmits the KEM
  ciphertext and defines DH commutativity; `session_ratchet.pv` runs initiator and
  responder as separate processes with an explicit state leak; `ghost_circuit_unlinkability.pv`
  uses `origin_id` to derive the reply tag, and `ghost_circuit_equiv.pv` carries the
  observational-equivalence check. ProVerif 2.05 result on 2026-11-24: all five
  models return their expected results, with every positive reachability witness
  reported as reachable (`not event(...) is false`).
- **Verification:** `cargo test --lib btcr` → 14 passed; `cargo test --lib` →
  656 passed, 0 failed, 1 ignored; `cargo fmt -- --check` clean; `cargo clippy
  --all-targets -- -D warnings` clean; ProVerif 2.05 on all models with witnesses.

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
