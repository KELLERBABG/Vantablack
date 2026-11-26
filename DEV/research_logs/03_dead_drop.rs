//! # 03 — `dead_drop.rs` (Tier 1)
//!
//! Status: **wired**, `feature = "research"`, as the DTN store of record.
//!
//! ## What I did
//!
//! The store-and-forward queue no longer keeps payload bytes in its Merkle tree.
//! `daemon/dtn.rs::queue` calls `research_hooks::vault::deposit`, which:
//!
//! 1. seals the payload (see `02_erosion.rs`),
//! 2. splits `nonce ‖ ciphertext` into 576-byte blind chunks,
//! 3. derives one commitment per chunk with
//!    `BlindDeadDropBlob::derive_commitment(&bundle_id, chunk_index)`,
//! 4. deposits each chunk into a process-wide `DeadDropVault`,
//! 5. stores only a descriptor (`VBSL` ‖ id ‖ die_at ‖ nonce ‖ wrapped key ‖ tag ‖
//!    commitments) in the DTN tree.
//!
//! `daemon/dtn.rs::flush_all` sweeps the chunks when the peer reconnects;
//! `vault::forget` consumes them once the send actually succeeds.
//!
//! Decay runs once per flush tick (`dtn::spawn_flush_loop` →
//! `vault::collect_decay`), with the observed vault error rate as the input:
//! `λ = expired / (expired + delivered)`, retention multiplier `1 + 4λ`, so a
//! partition stretches retention up to 5× while peace-time decay reclaims cold
//! chunks quickly.
//!
//! ## How it works
//!
//! - A host holds `[commitment ‖ 576-byte opaque ciphertext]` and nothing else.
//!   `host_audit_inspect_raw` never exposes a peer name, fingerprint or address.
//! - Sweeping requires the exact commitment. `sweep` increments the access
//!   counter and leaves the blob in place for retries; `sweep_and_consume` is
//!   only used by `forget`, after delivery.
//! - `prove_retention_interest` is exposed by the module but not yet called from
//!   the daemon; a client keep-proof needs a wire PDU, which is the next step.
//!
//! ## Tests written for it
//!
//! - `daemon::research_hooks::tests::a_dtn_payload_survives_the_vault_and_is_gone_after_its_epoch`
//!   — descriptor deposit, chunk count ≥ 1, exact round-trip, retryable before
//!   `forget`.
//! - `tests/research_tier1.rs::dead_drop_blind_chunks_sweep_only_by_commitment_and_decay_adaptively`
//!   — wrong commitment reveals nothing, partition (λ=0.8) extends retention,
//!   peace-time (λ=0.0) reclaims, single-use consume.
//!
//! ## Test results (2026-11-26)
//!
//! ```text
//! cargo test --no-default-features --bin ggn --features research
//!   test result: ok. 90 passed; 0 failed   (includes dtn::tests through the vault)
//!
//! cargo test --no-default-features --features research --test research_tier1
//!   test result: ok. 9 passed; 0 failed
//! ```
//!
//! ## Limits / follow-ups
//!
//! - The vault is process-local. Distributing chunks to distinct hosts is the
//!   deployment step; the commitment scheme already needs no host identity.
//! - `GHOST_DTN_VAULT=0` reverts DTN to plaintext-in-tree without dropping the
//!   feature, which is how the rollback was tested.
