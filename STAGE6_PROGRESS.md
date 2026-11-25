# Stage 6 (`v2.7.0`) — Physical & Coercion-Resistant Hardening — progress log

Spec: `DEV/V3_PIPELINE.md` Stage 6 (read-only; stayed 9,132 bytes).
Rule: a box is ticked only when the code exists and a test or gate proves it.

## Read and map

- [x] Read Stage 6 spec, `DEV/INVENTIONS_AND_PROOFS.md` (Inventions 5, 6, 8, 9) and `DEV/UNPRECEDENTED_PRIMITIVES.md` §5
- [x] Map the existing `sovereign_cloud`, GTF tail, `xray` population, `l10_qel` backends and daemon framing paths

## Deliverables

- [x] **LightCone-Proof** (`src/ghost/net/sovereign_cloud.rs`) — ≥3 anchor RTTs, impossible-speed refusal, cone intersection recomputed, whole certified disc must sit in the jurisdiction perimeter; placement ignores the self-declared tag. Tests: `a_light_cone_proof_certifies_a_position_inside_every_cone`, `a_claim_faster_than_light_is_refused`, `a_stale_or_thin_proof_is_not_evidence`, `placement_requires_a_proof_rather_than_a_declaration`, `a_swiss_proof_cannot_hold_an_eu_object_without_being_inside_the_perimeter`, `a_proof_needs_configured_anchors` (all `research`-gated)
- [x] **Causal-hop composition** (`CausalHopWitness`) — three proofs, pairwise-disjoint certified regions, `KeyDisjoint` unless `hardware-tpm` binds keys; test `a_causal_hop_witness_requires_pairwise_disjoint_cones`
- [x] **Vanta-Subliminal Tail** — `net::random_tail()` replaces the deterministic `tail_for`; `SealCtx.tail` is drawn once per message and shared by every shard; `l2_aead::subliminal_tail_seal/open` carry 48 B in the 64 B tail. Tests: `the_hidden_plane_round_trips_and_is_exactly_one_tail_long`, `a_random_tail_opens_no_hidden_plane_and_neither_does_a_tampered_one`, `the_hidden_plane_is_bound_to_epoch_direction_and_frame_nonce`; framing test asserts two messages do not share a tail
- [x] **Blind Census** (`src/ghost/v2/xray.rs::census`) — deterministic Ed25519 tickets over a hashed cell, 64-minimum sketch with per-cell dedupe, `(m-1)/U_(m)` estimator and binomial 99% lower bound; wire form carries no address. Tests: `the_sketch_is_an_unbiased_estimator_of_a_population`, `sybils_in_one_cell_collapse_to_one_entry`, `a_ticket_is_bound_to_its_epoch_cell_and_key`, `the_gossiped_sketch_carries_no_address`, `the_lower_bound_is_never_above_the_truth_for_a_small_sketch`
- [x] **Census in the truth ledger** — `census_population` invariant: `Verified` only when the 99% lower bound ≥ 200 distinct cells; `Failed` below it; `Unknown` with no tickets; `verified_input` now carries a census estimate
- [x] **RF-CRKG** (`src/ghost/layers/l10_qel.rs`) — capture → excursion quantization → Hamming(7,4) syndrome reconciliation → HKDF amplification; refuses non-positive Maurer capacity and <256+128 surviving bits. Tests: `reciprocity_derives_the_same_secret_on_both_ends`, `reciprocity_refuses_a_channel_an_eavesdropper_can_follow`, `reciprocity_refuses_a_capture_too_short_to_amplify`, `a_real_sounding_capture_flows_through_quantization_and_agrees`
- [x] **Monotone nested dual-PRF combiner** — `combine_monotone` implements `HMAC(K_ML-KEM, HMAC(K_X25519, K_L10 ‖ transcript))`; test `the_monotone_combiner_binds_every_input` (formula recomputed, every input and the transcript bound)
- [x] **Honest backend refusal** — `GHOST_QEL_BACKEND=rf_reciprocity` is a typed `Misconfigured` refusal because the syndrome exchange is interactive, not a label lookup

## Controls and tests

- [x] Every new primitive has a test that fails without the code (20 new tests: 13 default, 7 `research`-gated)
- [x] Negative paths: faster-than-light claim, stale/thin/duplicate proof, out-of-perimeter region, overlapping causal hops, unproven device, eavesdropper-followed channel, too-short capture, tampered/random hidden tail
- [x] Full library suite (default): `cargo test --lib --no-fail-fast` → **714 passed, 0 failed, 1 ignored**
- [x] Full library suite (`research`): `cargo test --lib --features research --no-fail-fast` → **732 passed, 0 failed, 1 ignored**
- [x] Full all-target suite: `cargo test --features research --no-fail-fast` → green (bins + integration tests)
- [x] Clippy: `cargo clippy --all-targets --features research -- -D warnings` → clean
- [x] Format: `cargo fmt -- --check` → clean

## Release bookkeeping

- [x] `Cargo.toml` / `Cargo.lock` root / `assets/app.rc` at 2.7.0 / 2,7,0,0; Android `versionCode 270`, `versionName 2.7.0`
- [x] Dated `[2.7.0]` changelog with the real test evidence above
- [x] `DEV/V3_PIPELINE.md` still 9,132 bytes
- [x] HEAD still `807e37c`; nothing committed/pushed; fuzz corpus and `data/bundles.sled` untouched

## Still open

- **~~No live census ingestion.~~ Resolved in `v3.0.0`.** Every node now announces its signed epoch ticket in a `GHOST_CENSUS__` PEX frame, and the receiver counts the cell it derived from the address the frame arrived from (`census::note_announcement` → the process-wide sketch). `census_population` is therefore live; it stays `Unknown` only until the first announcement arrives. See `STAGE7_PROGRESS.md`.
- **No real HF sounder.** RF-CRKG is exercised on captures supplied by tests/operators; the ABOS reciprocity measurement path is not attached on this host.
- **Light cones are evidence about a key, not a die.** `PhysicallyDisjoint` needs `hardware-tpm`; without it the witness reports `KeyDisjoint` even when an operator says the keys are bound.
- **No dashboard surface** for census tickets or per-device jurisdiction proofs yet; the evidence is exposed through the ledger and the sovereign-cloud API only.
- **The tail change is on the wire path.** Old peers that derived the tail from the session key cannot interoperate with this build's frames; the v2 header already carries the tail, so the receiver side needed no format change, but a mixed-version mesh must be upgraded together.
