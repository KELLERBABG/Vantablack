//! # 08 — `vault` multi-host distribution (v3.7.1)
//!
//! Status: **wired**, `feature = "research"`. One `GHOST_VSHARE__` control PDU
//! family now spreads a DTN bundle's erosion shares, archive shards and blind
//! chunks over three connected peers instead of keeping all of them here.
//!
//! ## What I did
//!
//! `research_hooks::vault` used to hold the 2-of-3 `EphemerizerCommittee`, all
//! three `mesh_archive` shards and every `dead_drop` chunk in this process. A
//! seizure of one machine therefore had the whole bundle, and the epoch only ever
//! erased a local copy. Two library accessors were missing to change that, so
//! `ghost::v2::erosion` gained exactly two:
//!
//! | API | Why |
//! |---|---|
//! | `EphemerizerCommittee::share_bytes(index)` | how a dealt share reaches the host that will keep it |
//! | `EphemerizerCommittee::from_shares(t, n, deadline, shares)` | rebuild a committee from the shares that came back, recomputing each `C_j = s_j·G` so evaluations still verify |
//!
//! Nothing in the module re-implements Shamir, Reed-Solomon or the dead-drop
//! commitment: it deals with the real committee, the real `ArchivalRecord` and
//! the real `BlindDeadDropBlob`.
//!
//! ## How it works
//!
//! ### Placement (deposit)
//!
//! `deposit` is called from the synchronous `dtn::queue`, so it cannot await a
//! send. `run_node` binds the live session table once
//! (`vault::bind_sessions(Arc::clone(&node.sessions))`), and placement reads it
//! asynchronously-free:
//!
//! ```text
//! connected_hosts() = session fingerprints, sorted, truncated to 3
//!
//! hosts.len() == 3                      hosts.len() < 3
//! ─────────────────                     ────────────────
//! share i  → hosts[i]                   committee + shards + chunks stay local
//! shard i  → hosts[i]                   (no PDU is queued at all)
//! chunk i  → hosts[i % 3]
//! local committee wiped (`expire`)
//! ```
//!
//! With three hosts the dealer keeps **no** share, so this node alone is always
//! below the 2-of-3 threshold. Sorting makes the assignment deterministic for the
//! same population. Each deposit seals under a **fresh** committee whose deadline
//! is the next epoch boundary (`(now / epoch_secs + 1) * epoch_secs`), which is
//! what lets a later open rebuild it from fetched shares; the old shared
//! per-epoch committee could not be distributed without retiring shares that
//! still-live bundles needed.
//!
//! Placement PDUs are queued per host (`outbox`, capped at 64/host) and drained
//! from three places, so a bundle deposited while a host was away still lands:
//! `session_established`, `gossip_beat`, and the 5 s DTN tick
//! (`vault::flush_outbox`, which uses `tunnel::send_payload` and `nc.socket`).
//!
//! ### Fetch (open)
//!
//! `dtn::flush_all` now calls `vault::open_mesh`, not the local opener:
//!
//! ```text
//! open_mesh
//!   ├─ plan.hosts empty  → open_at (local pieces only)
//!   └─ plan.hosts set    → fetch_pieces → complete
//!        shares:  one OP_FETCH per share host   (need >= threshold)
//!        shards:  one OP_FETCH per shard host   (need >= 2 of 3)
//!        chunks:  one OP_FETCH per chunk host   (need all)
//!        each reply: OP_ITEMS, correlated by an 8-byte request id in a
//!                    DashMap<[u8;8], oneshot::Sender<_>>, 700 ms timeout
//! ```
//!
//! A host answers from its own maps and **cannot** open the bundle itself: it
//! holds one share, one shard, or blind ciphertext. The requester reassembles
//! `nonce ‖ ciphertext`, verifies it against the archive content hash, rebuilds
//! the committee with `from_shares`, and only then asks the erosion primitive for
//! the key. A missing quota of shares is `Expired` (the key is unobtainable, not
//! corrupt), and the DTN queue retries on the next tick.
//!
//! ### Oblivion is mesh-wide
//!
//! Two paths now purge the hosts, not just the local map:
//!
//! - **delivered** — `forget(descriptor)` queues `OP_PURGE` to every host and
//!   consumes the local chunks (`sweep_and_consume`).
//! - **expired** — `expired()` / `reap_expired()` drop the bundle and queue the
//!   same purge. `reap_expired` runs on the wall clock from `collect_decay`, and
//!   `expired()` additionally drops only the descriptor it was called with: using
//!   the caller's clock for a global sweep let one far-future open reap every
//!   other bundle in the process (a real defect the DTN test caught).
//!
//! A host's `OP_PURGE` removes its share and shard entries and consumes the
//! chunks it still holds, so a bundle that is gone here is gone everywhere that
//! held a piece of it.
//!
//! ### Wire
//!
//! Every message is `[GHOST_VSHARE__ 14][op 1][request id 8][body]`:
//!
//! | op | body |
//! |---|---|
//! | `STORE_SHARE` | `bundle 32 ‖ index 1 ‖ members 1 ‖ deadline 8 ‖ share 32` |
//! | `STORE_SHARD` | `bundle 32 ‖ index 1 ‖ len 2 ‖ shard` |
//! | `STORE_CHUNK` | `bundle 32 ‖ commitment 32 ‖ deposited_at 8 ‖ ttl 8 ‖ bytes` |
//! | `FETCH` | `kind 1 ‖ bundle 32 ‖ count 2 ‖ index 1…` |
//! | `ITEMS` | `kind 1 ‖ count 2 ‖ { index 1 ‖ len 2 ‖ bytes }…` |
//! | `PURGE` | `bundle 32` |
//! | `KEEP` | `bundle 32 ‖ count 2 ‖ commitment 32…` (see log 09) |
//!
//! `handle_control` changed from `bool` to `Option<Vec<Vec<u8>>>`: the handler is
//! synchronous, so the peer loop delivers the replies on the session the fetch
//! arrived on. Counts are capped at 256 indices per PDU.
//!
//! ## Tests written for it
//!
//! - `three_hosts_hold_every_piece_and_none_stays_local` — deposit with three
//!   hosts, assert the plan names them, that **zero** of the bundle's chunks are in
//!   the local vault, that `open_at` refuses (`Corrupt`, below threshold), that the
//!   queued PDUs reconstruct `(3 shares, 3 shards, 1 chunk)` on the hosts, that the
//!   hosted pieces recover the payload byte for byte, and that `forget` purges the
//!   mesh copy back to `(0, 0, 0)`.
//! - `fewer_than_three_hosts_keeps_the_bundle_local` — two hosts is the documented
//!   fallback: no hosts in the plan, no queued PDU, and the local opener still works.
//!
//! The two host-map tests serialise on a test mutex: the maps are process-global,
//! and clearing each other's pieces would be a flake, not a finding.
//!
//! ## Test results (2026-11-26)
//!
//! ```text
//! cargo test --no-default-features --bin ggn --features research research_hooks
//!   test result: ok. 18 passed; 0 failed; 0 ignored
//!
//! cargo test --no-default-features --bin ggn --features research
//!   test result: ok. 101 passed; 0 failed; 0 ignored
//!
//! cargo test --no-default-features --features research --test research_tier1
//!   test result: ok. 9 passed; 0 failed; 0 ignored
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
//! - Distribution needs three *concurrent* sessions at deposit time. A node with a
//!   rotating peer set deposits locally during a quiet period and distributes
//!   during a busy one; that is the honest reading of "fall back below three".
//! - Placement is best effort. A host that never comes back leaves the bundle
//!   unopenable (`Expired` when shares are short, `Corrupt` when a chunk is), which
//!   is the availability cost of exclusive placement; no re-placement pass exists.
//! - The plan lives in memory only, like the rest of the vault (`stored` is a
//!   `DashMap`), so a restart already loses every queued bundle; persisting the
//!   placement would only make sense together with persisting chunks.
//! - Fetches are sequential per host and kind: up to three round trips for shares,
//!   three for shards, one per chunk host. A batched "all pieces for this bundle"
//!   request would cut that to one per host.
//! - `open_at` is the local opener and deliberately refuses a distributed bundle;
//!   only the DTN flush path (which has a socket) can open one.
