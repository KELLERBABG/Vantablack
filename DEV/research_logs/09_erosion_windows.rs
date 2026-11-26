//! # 09 — configurable erosion windows + `prove_retention_interest` PDU (v3.7.2)
//!
//! Status: **wired**, `feature = "research"`.
//!
//! ## What I did
//!
//! Two constants in `research_hooks::vault` were deployment decisions pretending
//! to be facts: `EPOCH_SECS = 3_600` and `TTL_SECS = 900`. Both are now
//! configuration with a floor, and the dead-drop module's keep-proof is reachable
//! over the control channel instead of being dead library API.
//!
//! ```text
//! GHOST_EROSION_EPOCH_SECS   default 3600   floor 60
//! GHOST_EROSION_TTL_SECS     default 900    floor 1
//! ```
//!
//! A value below its floor (or a non-number) is treated as unset and the default
//! applies: an epoch of 0 would retire every committee on every call, which is
//! not a tuning, it is a bug with an env var.
//!
//! The epoch is the unit the whole vault is expressed on:
//!
//! - each deposit deals a fresh 2-of-3 committee whose `deadline` is the next
//!   epoch boundary, so `epoch_secs()` decides when a bundle's key is
//!   mathematically gone;
//! - each bundle's `die_at = now + ttl_secs()`, so `ttl_secs()` decides when the
//!   queue stops retrying;
//! - `reap_expired` uses both to decide what to purge from the hosts.
//!
//! ## Keep-proofs
//!
//! `dead_drop::DeadDropVault::prove_retention_interest(commitment, renewal)` moves
//! a blob's `last_kept_timestamp`, which is what `collect_self_eating_decay`
//! measures its adaptive TTL from. The vault now issues it in two places:
//!
//! - **locally**, for chunks this node holds;
//! - **over the wire**, as `OP_KEEP` (`[bundle 32][count 2][commitment 32 × n]`),
//!   to each host holding one of the bundle's chunks.
//!
//! `keep_hot` runs after a successful distributed `open_mesh`: a bundle that was
//! just delivered is hot, and a host whose decay pass reclaims the chunk before
//! the *next* attempt succeeds turns a retry into permanent loss. The handler
//! answers the same way whether or not the commitment is known — `kept` in the log
//! is the count that actually matched, and an unknown commitment is simply not
//! kept. There is no reply PDU: retention is a hint, not an acknowledgement.
//!
//! ## Tests written for it
//!
//! - `erosion_windows_are_parsed_with_a_floor` — `"120" → 120`,
//!   `" 45 " → 45`, `"10"` below a floor of 60 → default, junk → default,
//!   unset → default; and the live accessors stay above their floors.
//! - `a_keep_proof_pdu_renews_a_hosted_chunks_retention` — place a chunk through
//!   `OP_STORE_CHUNK` (stamp `1000`), assert the host reports `1000`, send a real
//!   `OP_KEEP`, and assert the stamp moved to now. Then purge, so the host map is
//!   clean for the next test.
//!
//! ## Test results (2026-11-26)
//!
//! ```text
//! cargo test --no-default-features --bin ggn --features research research_hooks
//!   test result: ok. 18 passed; 0 failed; 0 ignored
//!   (erosion_windows_are_parsed_with_a_floor ... ok
//!    a_keep_proof_pdu_renews_a_hosted_chunks_retention ... ok)
//!
//! cargo test --no-default-features --bin ggn --features research
//!   test result: ok. 101 passed; 0 failed; 0 ignored
//!
//! cargo clippy --no-default-features --all-targets --features research -- -D warnings
//!   Finished — no warnings
//! ```
//!
//! ## Limits / follow-ups
//!
//! - The windows are read once per process (`OnceLock`), matching how the other
//!   toggles behave; changing them needs a restart, and `status()` reports the
//!   values actually in force so an operator can see that.
//! - A `TTL` longer than an epoch is accepted but pointless: the committee dies at
//!   the epoch boundary, so the bundle becomes `Expired` before its own `die_at`.
//!   Reporting that combination at boot would be a nice guard; it is not enforced.
//! - Keep-proofs are unauthenticated beyond the session seal. Any peer on a
//!   session can name a commitment it knows; the worst it can do is keep a blob
//!   alive, and it must know the commitment (a SHA-256 of bundle id and index) to
//!   do that. Retention is not a paid resource here.
