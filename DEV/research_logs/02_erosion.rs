//! # 02 — `erosion.rs` (Tier 1)
//!
//! Status: **wired**, `feature = "research"`, inside the DTN vault.
//!
//! ## What I did
//!
//! `src/daemon/research_hooks.rs::vault` now seals every queued DTN bundle key
//! under a Chrono-Erosion epoch before the bytes reach dead-drop storage:
//!
//! - `deposit_at(peer, payload, now)` wraps a random 32-byte bundle key with
//!   `erosion::seal_bundle` against a local 2-of-3 `EphemerizerCommittee`.
//! - The bundle `die_at = now + 900 s`; the committee's own deadline is the end
//!   of a 3 600 s epoch.
//! - `open_at` refuses before touching the AEAD when `now >= die_at`, and refuses
//!   when the committee can no longer reach threshold.
//! - Epoch rollover (`with_committee`) calls `committee.expire()`, wiping every
//!   share with `zeroize`, then deals a fresh committee. Every descriptor sealed
//!   in the old epoch becomes unopenable even though its ciphertext is still on
//!   disk — the property the module exists for.
//!
//! Hooked into the live path through `daemon/dtn.rs`:
//!
//! | Hook | Effect |
//! |---|---|
//! | `dtn::queue` | stores a descriptor in the DTN tree instead of plaintext |
//! | `dtn::flush_all` | `vault::open` each descriptor; `Expired`/`Corrupt` is logged and the bundle is marked delivered so it is not retried forever |
//! | `dtn::spawn_flush_loop` | one decay pass per tick |
//!
//! ## How it works
//!
//! 1. `bundle_id = SHA-256("VB-DTN-VAULT-BUNDLE-V1" ‖ peer_fp ‖ payload)`.
//! 2. `sealed = seal_bundle(committee, bundle_id, die_at, key, now)`, where the
//!    mask is the threshold evaluation `k_τ · M` with `M = H_G(bundle_id)`.
//! 3. The payload is sealed with XChaCha20-Poly1305 under `key` (12-byte wire
//!    nonce, epoch 0, `InitiatorToResponder`), because this is at-rest encryption
//!    and not a session direction.
//! 4. Opening collects `t` partial evaluations, `combine_partials` verifies each
//!    Chaum–Pedersen DLEQ against the member commitment before applying its
//!    Lagrange weight, then the tag check distinguishes "wrong epoch" from
//!    "wrong bundle".
//!
//! The daemon plays all three committee members locally. That is a faithful test
//! of the API and the expiry semantics, but it is **not** the distributed
//! threshold: a real deployment must ship one share per host, which is the only
//! thing that turns "the daemon forgot" into "nobody can reconstruct".
//!
//! ## Tests written for it
//!
//! - `daemon::research_hooks::tests::a_dtn_payload_survives_the_vault_and_is_gone_after_its_epoch`
//!   — round-trip, then `open_at(now + 10_000) == Expired`.
//! - `daemon::research_hooks::tests::a_tampered_descriptor_is_corrupt_not_delivered`
//!   — a flipped commitment byte is `Corrupt`, and a legacy plaintext payload
//!   still passes through unchanged.
//! - `tests/research_tier1.rs::erosion_a_bundle_is_readable_only_while_two_of_three_shares_exist`
//!   — threshold, deadline, one-share retirement tolerated, second retirement is oblivion.
//! - `tests/research_tier1.rs::erosion_a_dishonest_partial_evaluation_is_refused_by_its_dleq`
//!   — a relabelled partial fails its proof even though the point is on the curve.
//!
//! ## Test results (2026-11-26)
//!
//! ```text
//! cargo test --no-default-features --bin ggn --features research research_hooks
//!   test result: ok. 7 passed; 0 failed
//!
//! cargo test --no-default-features --features research --test research_tier1
//!   test result: ok. 9 passed; 0 failed
//!
//! cargo test --no-default-features --bin ggn --features research
//!   test result: ok. 90 passed; 0 failed; 0 ignored
//! ```
//!
//! ## Limits / follow-ups
//!
//! - Committee shares must be distributed per host before this is more than a
//!   local expiry gate.
//! - Epoch length (1 h) and bundle TTL (15 min) are constants in
//!   `research_hooks::vault`; they should become operator settings when the vault
//!   is promoted out of `research`.
