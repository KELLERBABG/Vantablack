//! # 06 — `mesh_archive.rs` (Tier 1)
//!
//! Status: **wired**, `feature = "research"`, on every vault recovery.
//!
//! ## What I did
//!
//! Every bundle the DTN vault seals also gets an `ArchivalRecord`:
//!
//! - the archived content is `nonce ‖ ciphertext` (the exact stream that is
//!   chunked into blind blobs),
//! - `ArchivalRecord::create` computes the SHA-256 content hash and Reed-Solomon
//!   splits the framed stream into three shards,
//! - `vault::open_at` reconstructs from **two** shards — shard 0 and shard 2,
//!   deliberately withholding shard 1 — and compares the result to the stream it
//!   swept from the dead-drop chunks.
//!
//! A mismatch is `OpenError::Corrupt` and the payload is never handed to the
//! tunnel. This gives the vault an integrity check that is independent of the
//! AEAD: a corrupted chunk fails the archive hash before the key is even
//! unwrapped.
//!
//! ## How it works
//!
//! ```text
//! payload ──XChaCha──► nonce‖ct ──RS(3)──► 3 archive shards
//!                         │
//!                         └──chunk 576 B──► blind dead-drop blobs
//!
//! recovery: sweep chunks → reassemble nonce‖ct
//!           reconstruct(shards 0,2) ──hash──► compare ──► erosion open ──► payload
//! ```
//!
//! The three archive shards are co-located in this process. That is the honest
//! limitation: the module's job is to make any two sufficient and to bind the
//! result to a content hash, and both are exercised on every recovery, but
//! "public archival mirroring across the mesh" still needs a storage backend that
//! puts the shards on distinct hosts.
//!
//! ## Tests written for it
//!
//! - `tests/research_tier1.rs::mesh_archive_any_two_shards_reconstruct_and_tampering_fails_the_hash`
//!   — all three pairs `{0,1}`, `{0,2}`, `{1,2}` reconstruct; one shard is not
//!   enough; two corrupted shards fail even though `reconstruct` succeeds.
//! - `daemon::research_hooks::tests::a_tampered_descriptor_is_corrupt_not_delivered`
//!   — a tampered descriptor cannot reach the archive or the plaintext.
//!
//! ## Test results (2026-11-26)
//!
//! ```text
//! cargo test --no-default-features --features research --test research_tier1
//!   test result: ok. 9 passed; 0 failed
//!
//! cargo test --no-default-features --bin ggn --features research research_hooks
//!   test result: ok. 7 passed; 0 failed
//! ```
//!
//! ## Limits / follow-ups
//!
//! - Shards must be moved to distinct hosts (and indexed by `canonical_uri`) to
//!   make the "public archive" claim true.
//! - The `urn` currently names the vault bundle (`vb:drop:<id>`); a public corpus
//!   needs a stable canonical URI supplied by the publisher.
