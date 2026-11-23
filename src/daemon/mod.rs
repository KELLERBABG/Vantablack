//! Daemon internals, split out of the 11k-line `src/main.rs` entrypoint.
//!
//! `main.rs` stays the thin orchestrator (process bootstrap, tracing tee, CLI/UI
//! wiring); everything with a single responsibility lives here:
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`framing`] | GTFv2 header/seal/open helpers, jitter tail, shard split, mix queue |
//! | [`cover`] | cover-traffic shaping mode, rate, gap and emitter |
//! | [`relay_fallback`] | relay sends, adaptive/fallback/carrier routing, skywave pins, WAN limiter |
//! | [`ingress`] | inbound frame ingest, reorder buffer, tunnel frames |
//! | [`ratchet`] | ratchet maintenance, QEL mix PDUs, topology telemetry |
//! | [`auth`] | post-quantum in-band auth chunks and handshake initiation |
//! | [`beacon`] | beacon sections, packet build/parse, peer-session registration |
//! | [`peer_loop`] | inbound packet dispatch and exit-connect handling |
//! | [`discovery`] | descriptors, PEX, rendezvous, bootstrap, LAN sweep |
//! | [`node`] | `run_daemon` / `run_node` orchestration |
//! | [`srtp`] | opt-in SRTP/RTP carrier shaping for outbound frames |
//!
//! Items are `pub(crate)` rather than private because the orchestrator and the
//! sibling modules share them; nothing here is exported from the library crate.

pub(crate) mod auth;
pub(crate) mod beacon;
pub(crate) mod cover;
pub(crate) mod discovery;
pub(crate) mod framing;
pub(crate) mod ingress;
pub(crate) mod node;
pub(crate) mod peer_loop;
pub(crate) mod ratchet;
#[cfg(feature = "reality-front")]
pub(crate) mod reality_front;
pub(crate) mod relay_fallback;
pub(crate) mod srtp;
