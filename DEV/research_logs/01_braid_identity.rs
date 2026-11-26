//! # 01 — `braid_identity.rs` (Tier 1)
//!
//! Status: **wired**, `feature = "research"`, durable across restart (own chains,
//! peer verifiers and revocations).
//!
//! ## What I did
//!
//! Added a daemon-side braid registry in `src/daemon/research_hooks.rs::braid` and
//! called it from five live points:
//!
//! | Hook | File | What happens |
//! |---|---|---|
//! | boot | `src/daemon/node.rs::run_node` | `braid::init(fingerprint)` restores every persisted chain, verifier and revocation before anything else runs |
//! | session registration | `src/daemon/beacon.rs::register_peer_session` | a session is the first thing that can advance a chain, so `init` is called here too (production builds) before the advance; every session advances the per-peer chain with the session master key as transcript |
//! | PQ auth success | `src/daemon/auth.rs::handle_pq_auth_pdu` | the current 200-byte transition is sealed and sent (`GHOST_BRAID___`) |
//! | PEX beat | `src/daemon/discovery.rs::send_pex` | the last transition is re-gossiped; a replay is `Stale` at the peer |
//! | packet dispatch | `src/daemon/peer_loop.rs::handle_pkt` | `GHOST_BRAID___` is ingested before tunnel/relay handling; a revoked fingerprint drops every later payload |
//!
//! ### Publish gate: no state directory, no signature
//!
//! `advance_and_tip` now refuses when `init` has not configured a state directory.
//! Before this, a build that had not booted persisted nothing yet still returned a
//! transition, and a restart would have re-signed the same height — the fork this
//! whole module exists to make impossible for an honest node. The refusal happens
//! **before** the chain entry is touched, so a pre-boot packet creates no lock and
//! leaves no tip to gossip. The explicit `advance_with(None, …)` form still exists
//! for tests and in-memory experiments; the daemon path only uses the gated one.
//!
//! ### Boot-path audit
//!
//! There is one production boot function:
//!
//! ```text
//! src/main.rs:231  desktop/webview thread  ─┐
//! src/main.rs:247  headless (no window)    ─┴→ run_daemon → run_node → GhostNode::new
//!                                                            → braid::init(fingerprint)
//!                                                            → Arc::new(node), receive loops
//! ```
//!
//! `init` is the first statement after `GhostNode::new` returns, before `nc` is
//! shared and before any receive/mesh task is spawned. No test calls `run_node`,
//! and no other binary constructs a `GhostNode` outside tests. As a second line of
//! defence, `register_peer_session` calls the idempotent `init` immediately before
//! `advance_and_tip`, so even a datagram that beats the boot sequence cannot sign:
//! either `init` restores first, or the gate refuses.
//!
//! That lazy call is `#[cfg(not(test))]`. A unit test does drive the real receive
//! path (`ratchet_live_tests`), which registers a session; without the guard it
//! pointed the whole test process at the developer's real data directory. Test
//! builds therefore stay in the pre-boot state, which is exactly what the new gate
//! test asserts.
//!
//! ### Restart defect, fixed
//!
//! The first version derived the chain with `BraidLock::from_seed(seed_for(our_fp,
//! peer_fp))` and kept `height`/key in memory only. That seed is deterministic, so
//! an honest process that restarted came back at height 0 holding the genesis key —
//! and the next session signed a **second child of a key its peers had already
//! accepted**. To a peer running `BraidChain` that is byte-for-byte a clone:
//! `BraidVerdict::Fork`, and the node is revoked. An honest restart looked exactly
//! like an attack.
//!
//! `braid_identity` documents this: it performs no I/O, and
//! `BraidLock::secret_state() -> (secret, braid, height)` exists so the caller can
//! persist the **post-advance** state before sending the transition that belongs to
//! it. That is now done:
//!
//! - **Record per peer** under `<data_dir>/braid/<hash>.braid`:
//!   `VBBRAID1 | version 1 | our_fp | peer_fp | height 8 | secret 32 | braid 32 |
//!   has_last 1 | last 200`.
//! - **Write ordering**: encode → write to `<record>.braid.tmp` → `File::sync_all`
//!   → atomic `rename` over the record → fsync the directory on Unix (Windows has
//!   no directory handle to sync; the rename is the durability point there). Mode
//!   `0600` on Unix because the record holds the current signing key.
//! - **Publish gate**: `advance_and_tip` returns the wire payload only after the
//!   record is durable. If the write fails, the transition is withheld (and not
//!   stored as `last`), so a peer never sees a key state that a restart could not
//!   continue. The in-memory chain has moved on, but a later successful advance
//!   persists that state too; the unsent transition is never referenced again.
//! - **Restore at boot**: `init()` reads the directory, keeps only records whose
//!   `our_fp` matches this process's fingerprint, rebuilds `BraidLock::restore`,
//!   and re-installs `last` so the first PEX beat re-gossips the same tip (a
//!   `Stale` at the peer, not a new height).
//! - **Restore validation**: when `last` is present it must verify, its `height`
//!   must equal the record's, and its `next_pk` must equal the restored key's
//!   identity. A record that fails is **quarantined**: that peer gets no further
//!   transition, because continuing an unverifiable chain would either fork the
//!   accepted key or silently rewrite the chain.
//!
//! ### Peer verifier + revocation durability
//!
//! What a peer showed us is journaled separately from our own record: an append-only
//! file per peer at `<data_dir>/braid/peers/<peer_fp>.journal`, one frame per state
//! change:
//!
//! - `1 ‖ 200-byte transition` — a child this verifier accepted (`Extended`).
//! - `2 ‖ 32-byte key` — a fork proof's equivocating key (`Fork`).
//!
//! Each append is `write_all` + `File::sync_all`, so a fork proof is on disk before
//! `handle_pdu` returns. On `init`, `restore_verifiers` replays every journal in
//! order: transitions go back through `BraidChain::accept` (restoring the
//! one-child-per-parent map), revocation frames go through the new
//! `BraidChain::revoke` (added to the primitive, idempotent) and re-arm the
//! per-fingerprint gate in `revoked()`. A torn tail from a crash mid-append ends
//! replay at the last complete frame; a frame that does not verify ends it with an
//! error rather than trusting anything written after it. The peer name is the file
//! stem, validated as a fingerprint shape, so a journal cannot claim to be another
//! peer's and cannot escape the directory.
//!
//! Result: after a restart the daemon still knows that peer X forked (traffic stays
//! dropped), and still remembers which child it accepted for every un-forked parent
//! (so a later sibling is still caught as a fork).
//!
//! ### Lock/chain split
//!
//! The same struct used to hold our `BraidLock`, our last transition and the peer's
//! `BraidChain`, in one map entry created by both directions. `handle_pdu` created
//! that entry with `seed_for("", from_fp)` — a junk seed derived from an empty
//! fingerprint — so merely receiving a peer's transition could seed a chain "of
//! ours", and the next `advance_and_tip` for that peer would advance the junk lock.
//!
//! The state is now two maps:
//!
//! - `ours: DashMap<peer_fp, Mutex<OurBraid { chain: BraidLock, last }>>` — written
//!   only by `advance_with`.
//! - `chains: DashMap<peer_fp, Mutex<BraidChain>>` — written only by `handle_pdu`.
//!
//! Ingesting network input can no longer create, seed or advance a signing key.
//!
//! ## How it works
//!
//! - Chain seed: `SHA-256("VB-BRAID-DAEMON-SEED-V1" ‖ our_fp ‖ peer_fp)`. Both
//!   sides derive different chains; a *clone of one process* derives the same one,
//!   which is what makes a fork possible at all — and what makes persistence
//!   mandatory rather than an optimisation.
//! - On each registered session: `BraidLock::advance(session_master_key)`. The
//!   retiring Ed25519 key signs `(height, next_pk, braid)`, the braid hash folds
//!   `previous ‖ next_pk ‖ transcript`, and the old key is dropped.
//! - Wire: `GHOST_BRAID___` ‖ 200-byte transition. The peer's `BraidChain` allows
//!   exactly one child per parent key. A second, different child is a fork
//!   regardless of claimed height, so a clone cannot skip ahead to dodge it.
//! - Fork result: `CloneProof` (400 bytes, both halves verify under the one
//!   equivocating key) → the peer fingerprint is inserted into a revoked set and
//!   the key is journaled. `handle_pkt` consults the set and drops all traffic from
//!   that fingerprint. Revocation is monotone: replaying the honest half afterwards
//!   answers `Revoked`.
//! - Population bound is logged on every advance:
//!   `gossip_rounds_to_collision(peers, fanout=4, δ=1e-6)`, i.e.
//!   `(ln N + ln ln(1/δ)) / (2 ln f)`.
//! - `durable = true|false` is logged per advance, so an operator can see whether
//!   the boot restore configured a state directory.
//!
//! ## Tests written for it
//!
//! - `daemon::research_hooks::tests::a_transition_before_boot_restore_is_refused_rather_than_signed`
//!   — with no configured root, `advance_and_tip` returns `None`, creates no lock
//!   and leaves no tip.
//! - `daemon::research_hooks::tests::verifier_state_and_fork_proofs_survive_restart_through_the_journal`
//!   — journals a linear child and a fork proof, wipes every in-memory trace,
//!   replays the journals, and asserts the forked peer is still revoked and a
//!   sibling of the linear child is still caught as a fork.
//! - `ghost::net::braid_identity::tests::a_restored_revocation_outranks_an_unknown_child`
//!   — `BraidChain::revoke` restores a revocation without the proof pair, is
//!   idempotent, and refuses a child of the revoked key.
//! - `daemon::research_hooks::tests::a_restarted_node_continues_its_persisted_chain_instead_of_forking`
//!   — advance with a persisted record, drop the in-memory chain, restore, and
//!   assert the next transition is height 2 with `parent_pk == first.next_pk`, that
//!   the peer's verifier says `Extended`, and that the genesis key is never
//!   revoked. Repeats the restart once more at height 3.
//! - `daemon::research_hooks::tests::ingesting_a_peers_transition_never_seeds_or_advances_our_own_chain`
//!   — `handle_pdu` leaves `our_height == None` and no tip; a later advance starts
//!   from our own genesis at height 1 with the deterministic root, not the peer's key.
//! - `daemon::research_hooks::tests::a_transition_whose_state_cannot_be_fsynced_is_not_published`
//!   — a state directory that is actually a file yields no payload and no tip.
//! - `daemon::research_hooks::tests::a_braid_fork_revokes_the_peer_and_a_replay_is_stale`
//!   — two children of one key revoke, replay afterwards answers `Revoked`.
//! - `daemon::research_hooks::tests::a_tampered_braid_transition_never_revokes_an_innocent_peer`
//!   — a flipped child key is `Invalid`, never a revocation.
//! - `tests/research_tier1.rs::braid_identity_a_clone_forks_and_the_pair_is_a_self_authenticating_revocation`
//!   — 400-byte proof, both halves verify, one-child-per-parent, wire round-trip.
//! - `tests/research_tier1.rs::braid_identity_the_collision_bound_is_the_documented_theorem`
//!   — `N=10^6, f=4, δ=10^-6 ⇒ 5.93` rounds.
//!
//! ## Test results (2026-11-26, after gate + verifier journal)
//!
//! ```text
//! cargo test --no-default-features --lib --features research braid_identity
//!   running 8 tests ... test result: ok. 8 passed; 0 failed
//!
//! cargo test --no-default-features --bin ggn --features research research_hooks::tests
//!   running 12 tests ... test result: ok. 12 passed; 0 failed
//!
//! cargo test --no-default-features --features research --test research_tier1
//!   running 9 tests ... test result: ok. 9 passed; 0 failed
//!
//! cargo test --no-default-features --bin ggn --features research
//!   test result: ok. 95 passed; 0 failed; 0 ignored
//!
//! cargo clippy --no-default-features --all-targets --features research -- -D warnings
//!   Finished — no warnings
//!
//! cargo check --no-default-features --bin ggn
//!   Finished — no warnings
//! ```
//!
//! ## Limits / follow-ups
//!
//! - One mutable record per peer, last-writer-wins. A record that decodes but
//!   fails its certificate quarantines that peer (safe: no fork), but a record
//!   damaged below decoding leaves only the error log; an append-only
//!   height-indexed record log would let the previous height survive that.
//! - The verifier journal is append-only and unbounded: every accepted transition
//!   adds 201 bytes and every fork adds 33. It is only reachable from an
//!   established session, and PEX replays are `Stale` (not journaled), but a
//!   long-lived session peer can still grow it with valid rotations. Compaction
//!   (keep the frontier plus revocations) is a separate change.
//! - Directory fsync is Unix-only; on Windows the atomic rename is the durability
//!   point. `File::sync_all` runs on both.
//! - Advances happen on session registration. Because the session master key is
//!   fresh per handshake, two sessions in a row produce two transitions, which is
//!   intended: each session is a transcript step.
//! - If the node's own long-term fingerprint changes, chain records written under
//!   the old one are ignored on restore (they are a different identity's chains).
//!   Verifier journals are keyed by peer only and remain valid.
//! - Before the `#[cfg(not(test))]` guard, a unit test that registered a session
//!   could create `<data_dir>/braid` on the developer's machine. Test builds now
//!   stay pre-boot; a real daemon writes there by design.
