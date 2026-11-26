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
//! | [`bonding`] | HPEB multi-interface bonding: per-OS binders, path choice, loss/handover |
//! | [`experimental`] | daemon-side wiring for the experimental toggles (PoW shield, collective defense) |
//! | [`diffusion`] | emergency epidemic routing for frames no route could carry |
//! | [`tunnel`] | local TCP forwards over the mesh, with exit and target allowlists |
//! | [`dtn`] | per-peer bundle store flushed when a session returns |
//! | [`research_hooks`] | live hooks for the Tier 1 `research` modules (feature `research`) |
//! | [`rendezvous`] | multi-slot blind rendezvous plus a routing table of known contacts |
//!
//! Items are `pub(crate)` rather than private because the orchestrator and the
//! sibling modules share them; nothing here is exported from the library crate.

pub(crate) mod auth;
pub(crate) mod beacon;
pub(crate) mod bonding;
pub(crate) mod cover;
pub(crate) mod diffusion;
pub(crate) mod discovery;
pub(crate) mod dtn;
pub(crate) mod experimental;
pub(crate) mod framing;
pub(crate) mod ingress;
#[cfg(feature = "quic")]
pub(crate) mod masque;
pub(crate) mod node;
pub(crate) mod peer_loop;
pub(crate) mod ratchet;
#[cfg(feature = "reality-front")]
pub(crate) mod reality_front;

/// Carry one frame over a MASQUE stream to `peer`, when this build has the
/// transport and a stream exists.
///
/// Always `false` without `quic`, so an unconditional call site keeps the UDP
/// send it had instead of needing a `cfg` of its own.
pub(crate) fn try_send_masque(peer: &std::net::SocketAddr, frame: &[u8]) -> bool {
    #[cfg(feature = "quic")]
    {
        masque::try_send(peer, frame)
    }
    #[cfg(not(feature = "quic"))]
    {
        let _ = (peer, frame);
        false
    }
}

/// Whether a MASQUE stream already reaches this peer. `false` without `quic`.
pub(crate) fn masque_carries(dst: &std::net::SocketAddr, session: &[u8; 4]) -> bool {
    #[cfg(feature = "quic")]
    {
        masque::carries(dst, session)
    }
    #[cfg(not(feature = "quic"))]
    {
        let _ = (dst, session);
        false
    }
}
pub(crate) mod relay_fallback;
pub(crate) mod rendezvous;
#[cfg(feature = "research")]
pub(crate) mod research_hooks;
pub(crate) mod srtp;
pub(crate) mod tunnel;
