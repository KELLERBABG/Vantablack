//! The optional-transport registry (SOTA P1-2).
//!
//! The tunnel asks one question before every send — *is there a better carrier
//! than UDP to this peer right now?* — and this is where the answer lives. It is
//! deliberately a registry and not a routing layer: it holds established QUIC
//! links by peer fingerprint, sends a frame on one when it has it, and otherwise
//! says nothing, so the caller's existing path (direct, relay, TURN) is
//! untouched.
//!
//! Two rules keep it from becoming a second, worse liveness model:
//!
//! * A link that has already closed is **evicted on lookup**, so a caller cannot
//!   be handed a dead carrier and silently lose frames to it.
//! * Registration is by fingerprint, the identity the mesh already authenticated
//!   — never by address. A peer that reconnects from a new address replaces its
//!   own entry, and no address change can inherit someone else's link.
//!
//! ## One peer, one path — for now
//!
//! The key is the peer fingerprint alone, so a peer has one link however many
//! local addresses this host has. Spreading shards across Wi-Fi *and* LTE is
//! multipath-QUIC, which P1-2 names and which is **not built**: the key would
//! have to become `(fingerprint, local IP)` and `send_shards` would put one shard
//! on each live path before reusing any. See `docs/UNWIRED.md` B23.

use std::sync::Arc;

use dashmap::DashMap;
use tracing::{debug, info};

use super::quic::{QuicLink, QuicTransport};
use super::CarrierPath;

/// Established optional-transport links, keyed by peer fingerprint.
///
/// The transport itself is optional *within* this build too: an operator who has
/// not set `GHOST_QUIC` has no listener, no port and no link — but the tunnel
/// still asks the registry on every frame, so the type it asks must exist either
/// way. A disabled registry answers every question truthfully: nothing to send
/// on.
pub struct Carrier {
    transport: Option<Arc<QuicTransport>>,
    links: DashMap<String, Arc<QuicLink>>,
}

impl std::fmt::Debug for Carrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Carrier")
            .field("enabled", &self.transport.is_some())
            .field("peer_count", &self.links.len())
            .finish()
    }
}

impl Carrier {
    /// A registry with no transport: every frame keeps to the path it had.
    pub fn disabled() -> Self {
        Carrier {
            transport: None,
            links: DashMap::new(),
        }
    }

    pub fn new(transport: Arc<QuicTransport>) -> Arc<Self> {
        info!(
            local = ?transport.local_addr().ok(),
            fingerprint = %transport.local_fingerprint(),
            "carrier: QUIC transport available for peer sessions"
        );
        Arc::new(Carrier {
            transport: Some(transport),
            links: DashMap::new(),
        })
    }

    pub fn enabled(&self) -> bool {
        self.transport.is_some()
    }

    pub fn label(&self) -> &'static str {
        if self.enabled() {
            "quic"
        } else {
            "none"
        }
    }

    pub fn transport(&self) -> Option<&Arc<QuicTransport>> {
        self.transport.as_ref()
    }

    /// Record an established link. Returns the link it displaced, if any — a
    /// caller may want to close the old session rather than leak it.
    pub fn register(&self, fp: String, link: Arc<QuicLink>) -> Option<Arc<QuicLink>> {
        debug!(peer = %fp, "carrier: link registered");
        self.links.insert(fp, link)
    }

    /// The live link for a peer, evicting one that has closed.
    pub fn link(&self, fp: &str) -> Option<Arc<QuicLink>> {
        let entry = self.links.get(fp)?;
        if entry.is_closed() {
            drop(entry);
            self.links.remove(fp);
            debug!(peer = %fp, "carrier: link evicted (closed)");
            return None;
        }
        Some(Arc::clone(entry.value()))
    }

    pub fn peer_count(&self) -> usize {
        self.links.len()
    }

    pub fn forget(&self, fp: &str) {
        if self.links.remove(fp).is_some() {
            debug!(peer = %fp, "carrier: link forgotten");
        }
    }

    /// Send one GTF frame to a peer over the optional transport.
    ///
    /// `None` means "no carrier for this peer" and is not a failure: the caller
    /// falls through to the path it already had. A send error on a *dead* link is
    /// reported as `None` after eviction, for the same reason. An error on a link
    /// that is still open is also `None` — the frame did not go — but the link is
    /// kept, because a single refused frame is not evidence that the transport is
    /// gone, and forgetting it would strand the session on UDP for good.
    pub async fn send_frame(&self, fp: &str, frame: &[u8]) -> Option<CarrierPath> {
        let link = self.link(fp)?;
        match link.send_frame(frame).await {
            Ok(path) => Some(path),
            Err(e) => {
                if link.is_closed() {
                    debug!(peer = %fp, "carrier: link died mid-send, falling back to UDP: {e}");
                    self.forget(fp);
                } else {
                    debug!(peer = %fp, "carrier: frame not sent: {e}");
                }
                None
            }
        }
    }

    /// Send one frame with the framing held fixed (see `QuicLink::send_frame_as`).
    pub async fn send_frame_as(
        &self,
        fp: &str,
        frame: &[u8],
        path: CarrierPath,
    ) -> Option<CarrierPath> {
        let link = self.link(fp)?;
        match link.send_frame_as(frame, path).await {
            Ok(p) => Some(p),
            Err(e) => {
                if link.is_closed() {
                    self.forget(fp);
                }
                debug!(peer = %fp, "carrier: frame not sent: {e}");
                None
            }
        }
    }
}
