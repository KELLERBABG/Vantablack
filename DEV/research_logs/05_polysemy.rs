//! # 05 — `polysemy.rs` (Tier 1)
//!
//! Status: **wired**, `feature = "research"`, on the bonded multi-path link.
//!
//! ## What I did
//!
//! Added `research_hooks::worlds` and two hooks in `daemon/bonding.rs`:
//!
//! | Hook | Effect |
//! |---|---|
//! | `bonding::dispatch` | when three physical paths are live, sends one `GBWD` polysemic probe shard on each path alongside its GTF carrier |
//! | `bonding::spawn` receive loop | collects `GBWD` shards per (peer IP, probe id); at `k` distinct paths, collapses the world and logs which subset survived |
//!
//! Only active with `GHOST_BOND_WORLDS=1` **and** `GHOST_BOND=1` with ≥ 3 live
//! paths. It is control traffic, so a two-path bond does not carry it.
//!
//! ## How it works
//!
//! - `PolysemicCode::new(n=3, k=2, r=8)`: `C(3,2)=3` worlds, each path carries
//!   `C(n-1,k-1)·r = 16` bytes.
//! - Each world's message is `[world_index u32][“PROB” 4]`. World `i` exists to be
//!   recovered by exactly one 2-subset of paths.
//! - Sender: shard `i` goes on the socket that carried carrier `i`, so the three
//!   probe shards travel three distinct interfaces.
//! - Receiver: once any `k` shards arrive, it sorts the surviving path indices,
//!   collapses that world, and checks that the recovered `world_index` names the
//!   *same* subset. A message that disagrees with the paths that carried it is
//!   refused and logged — that is the integrity check, not just a label read.
//! - Envelope: `GBWD` ‖ version 1 ‖ n ‖ k ‖ path_index ‖ id[8] ‖ shard.
//!   Groups are bounded (64) and consumed on collapse.
//!
//! ### Why this hook and not the carrier path
//!
//! Polysemy carries **one message per surviving path subset**, so its overhead is
//! `C(n-1,k-1)×` per path. For the 576-byte GTF carrier that is 2× per path on top
//! of Reed-Solomon, and it would duplicate a function HPEB already provides. The
//! control-plane probe fits the primitive exactly: the message *is* which path
//! subset survived, the payload is 8 bytes, and the 2× overhead is 16 bytes per
//! path. Promoting polysemy to bulk payloads is a separate decision, not a wiring
//! detail.
//!
//! ## API added for the hook
//!
//! `PolysemicCode::world_subsets()` and `PolysemicCode::world_index(survivors)`.
//! The code previously exposed only `collapse`, which gives a message but not the
//! name of the world it came from; both sides need that name to build and verify
//! one message per subset.
//!
//! ## Tests written for it
//!
//! - `daemon::research_hooks::tests::a_polysemic_probe_learns_which_paths_survived`
//!   — one shard is not enough; paths `{0,2}` collapse world `{0,2}`, the tag
//!   matches, the group is consumed, and `n=2` is refused.
//! - `tests/research_tier1.rs::polysemy_every_surviving_subset_collapses_its_own_world_and_hides_the_rest`
//!   — every subset collapses its own world, `world_index` agrees, and the
//!   256-candidate blindness check holds for the two surviving shards.
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
//! - The probe is diagnostic: it proves which subset survived, it does not change
//!   path selection. Wiring it into `HpebScheduler` as a per-subset fallback
//!   message set is the Tier 2 step and needs a payload budget decision.
//! - Probe groups are keyed by peer IP; two peers behind one address would share
//!   a group. `GBND` carries no peer fingerprint, so this cannot be fixed without
//!   extending the bond envelope. The id is random per probe, so the collision is
//!   between probes, never a mis-collapse of one peer's shards into another's.
