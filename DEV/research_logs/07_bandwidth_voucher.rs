//! # 07 — `bandwidth_voucher.rs` (Tier 1)
//!
//! Status: **wired**, `feature = "research"`, relay admission gate.
//!
//! ## What I did
//!
//! Added `research_hooks::voucher` and hooked it into three live points:
//!
//! | Hook | Effect |
//! |---|---|
//! | `daemon/auth.rs` (PQ auth success) | presents a voucher for the current epoch |
//! | `daemon/discovery.rs::send_pex` | re-presents once per hour when a new epoch needs one |
//! | `daemon/peer_loop.rs::handle_pkt` (blind relay branch) | charges the sender's banked voucher before `fallback::relay_hop`; refusal means no forward |
//!
//! ## How it works
//!
//! - Voucher PDU: `GHOST_VOUCHER_` ‖ preimage[32] ‖ epoch `u64` ‖ quota `u32` ‖
//!   proof[32]. The token preimage never leaves the sender/relay pair, and the
//!   nullifier is `SHA-256("VANTABLACK_BANDWIDTH_NULLIFIER_V1" ‖ epoch ‖ preimage)`.
//! - Minting costs work: the proof is the first SHA-256 over
//!   `("VB-VOUCHER-POW-V1" ‖ preimage ‖ epoch ‖ nonce)` with 8 leading zero bits
//!   (≈256 hashes), and the voucher buys 16 MB for that hour.
//! - The relay banks one nullifier per sender fingerprint and charges
//!   `ceil(bytes / 1 MiB).max(1)` per forward. An exhausted voucher is removed from
//!   the active set and recorded as exhausted, so replay cannot re-bank it.
//! - The gate is **off by default** (`GHOST_RELAY_VOUCHERS=1` turns it on). A relay
//!   that started charging before its peers knew how to mint would black-hole
//!   traffic; this keeps the rollout one-sided-safe.
//!
//! ## What the tests cover
//!
//! - `daemon::research_hooks::tests::relay_transit_is_refused_without_a_voucher_and_charged_with_one`
//!   — no voucher ⇒ refused; 8 MB voucher ⇒ two 1 MB charges admitted, an overdraw
//!   refused.
//! - `tests/research_tier1.rs::bandwidth_voucher_a_nullifier_is_single_use_and_credit_is_finite`
//!   — redemption, double-spend refusal, partial consume, overdraw, exhaustion,
//!   re-redemption refusal, epoch-bound nullifier, stale-epoch rejection.
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
//! - The PoW is a local stand-in for a real work function; the module also
//!   supports Proof-of-Erasure-Repair credits, which need the repair ledger to be
//!   wired before they can mint.
//! - Only the blind relay branch (`BLND!`) is charged. The multi-hop onion branch
//!   keeps its tit-for-tat ledger; unifying the two accounting paths is the next
//!   step.
//! - Voucher presentation is bound to the session, not to an on-wire signature, so
//!   a relay only accepts it from a peer whose PQ auth already succeeded. That is
//!   the anti-Sybil assumption and should be stated in `docs/anti_abuse.md`.
