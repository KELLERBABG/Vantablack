//! # 10 — voucher/onion unification + control-plane telemetry (v3.7.3)
//!
//! Status: **wired**, `feature = "research"`.
//!
//! ## What I did
//!
//! ### One bank, two forwarding paths
//!
//! `GHOST_RELAY_VOUCHERS` only charged blind (`BLND!`) hops. A peer could send a
//! multi-hop onion (`RLY!`) through the same relay and forward for free, or worse,
//! alternate envelopes to make the two accounting stories disagree. The gate now
//! sits on both:
//!
//! ```text
//! peer_loop::handle_pkt
//!   ├─ parse_blind_frame(payload)      → voucher::admit_transit(peer, len)
//!   └─ parse_relay_header(payload)
//!        if remaining_hops > 0         → voucher::admit_transit_onion(peer, len)
//! ```
//!
//! Both entry points are wrappers over `admit_transit_as(peer, bytes, Transit)`,
//! which reads and spends the **same** nullifier's quota. Alternating `BLND!` and
//! `RLY!` therefore cannot double a voucher: there is one `RelayBandwidthBank`
//! entry per presented voucher and one bank per process. The counters are split by
//! path (`blind_bytes`, `onion_bytes`) while the cap is shared, so the telemetry
//! can show which path is actually being used without splitting the accounting.
//!
//! The onion check sits before the Tit-for-Tat eviction check, so an unpaid peer
//! is refused before it can consume any other relay state.
//!
//! ### Documentation
//!
//! `docs/anti_abuse.md` gained §6 "Sitzungsgebundene Relay-Voucher". It states the
//! assumption the code actually relies on: a voucher is **not** a bearer
//! certificate. It is presented only after PQ authentication, banked under the
//! sender's nullifier, and charged only for forwards arriving on that session — so
//! replay across relays, replay across an IP change, and anonymous free transit are
//! all structurally excluded without a global nullifier set. It also documents the
//! opt-in default, the 8-bit proof-of-work mint, and the per-epoch quota.
//!
//! ### Control-plane telemetry
//!
//! `research_hooks::status_json(active_sessions)` is inserted into `/api/status`
//! (`src/control.rs`) under `research`:
//!
//! ```json
//! {
//!   "entropy_beacon": {
//!     "threshold": 3,
//!     "participants": <active sessions>,
//!     "peers_per_round": <active sessions / 3>,
//!     "grid_epoch": 0, "grid_cycle": 0, "rounds_frozen": 0
//!   },
//!   "braid": { "tracked_peers": 0, "revoked_peers": 0, "quarantined_peers": 0 },
//!   "vault": { "stored": 0, "distributed": 0, "local_only": 0,
//!              "hosted_shares": 0, "hosted_shards": 0, "hosted_chunks": 0,
//!              "epoch_secs": 3600, "ttl_secs": 900 },
//!   "voucher": { "enabled": false, "admitted": 0, "denied": 0,
//!                "blind_bytes": 0, "onion_bytes": 0 }
//! }
//! ```
//!
//! `peers_per_round` is literally `sessions / 3`: how many full three-share beacon
//! rounds the current population can contribute to. `braid.stats()` and
//! `beacon_wire::snapshot()` lost their `#[cfg(test)]`, and the braid gained
//! `quarantined_count()`, so the API reports the same numbers the tests assert.
//! Nothing here exposes key material: counts, epochs and byte totals only. The
//! block is `#[cfg(feature = "research")]`, so a build without research keeps the
//! exact JSON it had.
//!
//! ## Tests written for it
//!
//! - `onion_and_blind_transit_draw_on_the_same_voucher` — present a 4 MB voucher,
//!   spend 2 MB as onion and 2 MB as blind, assert the third MB is refused, and
//!   that both byte counters moved.
//! - `the_status_document_reports_beacon_and_braid_counters` — `status_json(7)`
//!   reports threshold 3, 7 participants, `peers_per_round == 2`; `status_json(2)`
//!   reports 0; the braid counters are numbers; the vault reports its windows and
//!   the voucher its path counters.
//!
//! ## Test results (2026-11-26)
//!
//! ```text
//! cargo test --no-default-features --bin ggn --features research research_hooks
//!   test result: ok. 18 passed; 0 failed; 0 ignored
//!   (onion_and_blind_transit_draw_on_the_same_voucher ... ok
//!    the_status_document_reports_beacon_and_braid_counters ... ok)
//!
//! cargo test --no-default-features --bin ggn --features research
//!   test result: ok. 101 passed; 0 failed; 0 ignored
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
//! - The charge is per *envelope*, rounded up to whole megabytes with a floor of
//!   one. A peer sending many tiny onions is charged a megabyte each, which is
//!   conservative in the relay's favour; per-peer byte accounting rather than
//!   per-envelope would be fairer and is a small change.
//! - A voucher is bound to a session by *where it is accepted*, not by a signature
//!   over the session id. That is exactly the assumption documented in §6; if
//!   vouchers are ever gossiped between peers, they need a session-id field and a
//!   verifier, and the doc must change with the code.
//! - `/api/status` is PIN-gated for peer details, and the research block is not
//!   treated as peer detail: it is aggregate counters. If an operator considers
//!   `tracked_peers` sensitive, it should move under the same PIN gate.
//! - The beacon's `participants` is the caller's session count, not the number of
//!   shares actually submitted this round; the library keeps the two apart and the
//!   API reports the population figure deliberately.
