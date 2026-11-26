//! # 04 — `entropy_beacon.rs` (Tier 1)
//!
//! Status: **wired**, `feature = "research"`, on the PEX gossip beat.
//!
//! ## What I did
//!
//! Added `research_hooks::beacon_wire` and hooked it into:
//!
//! | Hook | Effect |
//! |---|---|
//! | `daemon/discovery.rs::send_pex` | submits this node's share for the current round and sends `GHOST_EBEACON_` |
//! | `daemon/peer_loop.rs::handle_pkt` | ingests a peer share, reconciles its beacon grid, and finalizes the round at threshold |
//!
//! ## How it works
//!
//! - Round length 30 s, threshold 3 independent contributors.
//! - Contributor id is `SHA-256("VB-ENTROPY-CONTRIBUTOR-V1" ‖ fingerprint)`, so a
//!   peer cannot claim another's contribution by lying about its name.
//! - PDU: `GHOST_EBEACON_` ‖ round `u64` ‖ 32-byte entropy ‖ 32-byte
//!   `BeaconGridEpoch`. The grid rides the share because both are 32-byte
//!   peer-visible state that changes on the same beat.
//! - **Frozen rounds.** The module's `try_finalize_round` recomputes the digest
//!   from whatever shares it currently holds, so a fourth share arriving later
//!   would rewrite the output. The daemon freezes the first threshold completion
//!   per round and ignores later shares for it. This is a wiring fix, not a module
//!   change, and it is what makes "finalized" mean finalized.
//! - Finalizing calls `BeaconGridEpoch::tick(digest)`: the cycle advances per
//!   frozen round and the epoch per ten cycles. A peer whose grid is ahead is
//!   reconciled with `BeaconGridEpoch::reconcile`.
//! - Retention is bounded: `retain_rounds` (added to the module for this hook)
//!   keeps the current and previous round only.
//!
//! ## Tests written for it
//!
//! - `daemon::research_hooks::tests::three_entropy_shares_freeze_a_round_and_advance_the_grid`
//!   — three shares finalize, a fourth cannot rewrite, the grid cycle advances
//!   exactly once.
//! - `tests/research_tier1.rs::entropy_beacon_output_is_threshold_and_contributor_order_independent`
//!   — below threshold, deterministic output independent of arrival order,
//!   `retain_rounds` prunes exactly.
//!
//! ## Test results (2026-11-26)
//!
//! ```text
//! cargo test --no-default-features --bin ggn --features research research_hooks
//!   test result: ok. 7 passed; 0 failed
//!
//! cargo test --no-default-features --features research --test research_tier1
//!   test result: ok. 9 passed; 0 failed
//! ```
//!
//! ## Limits / follow-ups
//!
//! - Two-node meshes never reach threshold 3; the beacon stays dormant until a
//!   third participant contributes, which is correct but should be visible in the
//!   status surface.
//! - The beacon grid is gossiped inside the entropy PDU rather than as a new
//!   beacon section. `BEACON_PREFIX` frames have a fixed signed prefix and adding
//!   an eighth builder parameter would touch every beacon test; the PDU was the
//!   smaller, reversible change.
