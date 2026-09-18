//! The optional-transport registry, and multipath (B23).
//!
//! The tunnel asks one question before every send — *is there a better carrier
//! than UDP to this peer right now?* — and this is where the answer lives. It is
//! deliberately a registry and not a routing layer: it holds established QUIC
//! links by peer and local address, sends a frame on one when it has it, and
//! otherwise says nothing, so the caller's existing path (direct, relay, TURN) is
//! untouched.
//!
//! ## One peer, one path *per local address*
//!
//! A link's identity is the pair **`(peer fingerprint, our local address)`**, and
//! that is what makes multipath possible: a host with Wi-Fi and LTE at once holds
//! *two* links to the same peer, and `send_shards` puts one Reed-Solomon shard on
//! each before any path carries a second. A single-homed host gets exactly the
//! behaviour it had before — one link, all three shards on it — because the pair
//! degenerates to one entry.
//!
//! The local half of the key is the address the link sends from, and where that
//! comes from matters (`QuicLink::local_addr`): a named path is an endpoint bound
//! to one address, so the address is known exactly and before the handshake;
//! a wildcard endpoint's source is the kernel's choice and is only knowable from
//! the connection, which some platforms do not report for clients at all. An
//! address that cannot be named is kept as `0.0.0.0` — a path of its own, never
//! conflated with a named one — which is why multipath configuration *names* the
//! addresses it wants used rather than guessing them.
//!
//! Registration is by fingerprint **and address, never address alone**: the
//! fingerprint is the identity the mesh already authenticated, so a peer that
//! reconnects from a new address replaces its own entry, and no address change
//! can inherit someone else's link.
//!
//! ## What multipath does and does not buy
//!
//! With **three** live paths the property the whitepaper claims holds exactly: an
//! adversary tapping any single transit path sees one shard of a (2,1) code and
//! recovers nothing. With **two** paths three shards cannot be spread thinner
//! than 2 + 1, so the path carrying two shards gives an on-path observer a
//! reconstructable pair — multipath with two paths buys resilience (a dead path
//! costs at most one shard) but not dispersal. `send_shards` is honest about this
//! rather than implying otherwise: it spreads as evenly as the path count allows
//! and reports how many shards each path carried.
//!
//! ## The pin that makes the post-quantum half load-bearing (P2-1)
//!
//! A hybrid binding proves a peer holds *both* keys and that the two are bound to
//! each other — but on its own it would still let an adversary who forges the
//! classical half (which is what a quantum computer gives them) present a
//! post-quantum key of their own, because the pair would be perfectly
//! self-consistent. What stops that is remembering the PQ key the first time a
//! peer proved it and **refusing a later link that presents a different one**
//! (`register`). The commitment arrives either from the binding itself
//! (trust-on-first-use) or from a beacon's `PQK!` section
//! (`pin_commitment`), which is the only thing a 512–1472-byte datagram has room
//! for.
//!
//! Pins live in memory only, so a peer that legitimately rotates its
//! post-quantum key is re-learned on the next restart rather than being locked
//! out forever. A pin is never *updated* by a later session: that is the whole
//! property, and a rotation is an operator decision (restart) rather than
//! something a peer can talk this node into.
//!
//! ## Two more liveness rules
//!
//! A link that has already closed is **evicted on lookup**, so a caller cannot
//! be handed a dead carrier and silently lose frames to it. And two links that
//! nonetheless carry the same address are **one path, not two**: a second link on
//! an address already covered is recorded in place of the first rather than
//! beside it (`register` returns the link it displaced), because sending one shard
//! on each of them would put two shards of a (2,1) code on one wire while claiming
//! they were dispersed.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use dashmap::DashMap;
use tracing::{debug, info, warn};

use super::quic::{QuicLink, QuicTransport};
use super::CarrierPath;

/// A link was refused because the peer's post-quantum key contradicts the one
/// pinned for that fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PqMismatch {
    /// The commitment already pinned for this peer.
    pub pinned: [u8; 32],
    /// The commitment the refused link presented.
    pub presented: [u8; 32],
}

impl std::fmt::Display for PqMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "peer presented post-quantum commitment {} but {} is pinned for it",
            short(&self.presented),
            short(&self.pinned)
        )
    }
}

impl std::error::Error for PqMismatch {}

/// A commitment for a readable log line (hex, truncated to the first 8 bytes).
fn short(commitment: &[u8; 32]) -> String {
    hex::encode(&commitment[..8])
}

/// The identity of one link: a peer, reached over one of *our* local addresses.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LinkKey {
    /// The peer's fingerprint — the identity the mesh authenticated.
    pub fingerprint: String,
    /// Our local address on this link.
    pub local: IpAddr,
}

/// The local address a link sends from — its path.
///
/// A link whose endpoint was bound to one address names it exactly; one that went
/// out a wildcard endpoint may only be able to say `0.0.0.0`, which the registry
/// keeps as a path of its own rather than conflating it with a named one. See
/// `QuicLink::local_addr`.
fn local_of(link: &QuicLink) -> IpAddr {
    link.local_addr()
}

/// Established optional-transport links, keyed by peer and local address.
///
/// The transport itself is optional *within* this build too: an operator who has
/// not set `GHOST_QUIC` has no listener, no port and no link — but the tunnel
/// still asks the registry on every frame, so the type it asks must exist either
/// way. A disabled registry answers every question truthfully: nothing to send
/// on.
pub struct Carrier {
    /// The endpoint that listens, and the dialling endpoint when no local address
    /// has been named (`GHOST_QUIC_LOCAL_ADDRS`).
    transport: Option<Arc<QuicTransport>>,
    /// Additional endpoints, each bound to one named local address: the extra
    /// half of a multi-homed host. Empty on a single-homed one.
    paths: DashMap<IpAddr, Arc<QuicTransport>>,
    links: DashMap<LinkKey, Arc<QuicLink>>,
    /// Post-quantum commitment pinned per peer fingerprint (P2-1).
    pins: DashMap<String, [u8; 32]>,
}

impl std::fmt::Debug for Carrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Carrier")
            .field("enabled", &self.transport.is_some())
            .field("local_paths", &self.paths.len())
            .field("link_count", &self.links.len())
            .field("peer_count", &self.peer_count())
            .finish()
    }
}

impl Carrier {
    /// A registry with no transport: every frame keeps to the path it had.
    pub fn disabled() -> Self {
        Carrier {
            transport: None,
            paths: DashMap::new(),
            links: DashMap::new(),
            pins: DashMap::new(),
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
            paths: DashMap::new(),
            links: DashMap::new(),
            pins: DashMap::new(),
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

    /// Add a named local path: an endpoint bound to one specific local address.
    ///
    /// Returns the endpoint it displaced, if the same address was added twice.
    /// The identity is taken from the listening endpoint, so a path speaks for
    /// the same node the peer already authenticated.
    pub fn add_path(&self, transport: Arc<QuicTransport>) -> Option<Arc<QuicTransport>> {
        let Ok(addr) = transport.local_addr() else {
            return None;
        };
        if addr.ip().is_unspecified() {
            // A wildcard endpoint is not a named path: it cannot be said to be
            // "the Wi-Fi path", because the kernel has not chosen yet.
            debug!("carrier: refusing to add a wildcard endpoint as a named path");
            return None;
        }
        info!(local = %addr, "carrier: local path added");
        self.paths.insert(addr.ip(), transport)
    }

    /// Bind another endpoint for the *same* identity on `ip`: the multipath half
    /// of a multi-homed host (Wi-Fi + LTE at once).
    ///
    /// The listener stays where it is — one port accepts on every interface — so
    /// this is a dialling path only. `Ok(Some(old))` means an endpoint for that
    /// address already existed and was replaced.
    pub fn add_local_path(
        &self,
        ip: IpAddr,
    ) -> Result<Option<Arc<QuicTransport>>, super::quic::QuicError> {
        let Some(primary) = self.transport.clone() else {
            return Ok(None);
        };
        let transport = Arc::new(QuicTransport::client_bound(
            SocketAddr::new(ip, 0),
            Arc::clone(primary.identity()),
        )?);
        Ok(self.add_path(transport))
    }

    /// The named local paths, with the address each is bound to.
    pub fn paths(&self) -> Vec<(IpAddr, Arc<QuicTransport>)> {
        self.paths
            .iter()
            .map(|e| (*e.key(), Arc::clone(e.value())))
            .collect()
    }

    pub fn path_count(&self) -> usize {
        self.paths.len()
    }

    /// Pin a peer's post-quantum commitment, from a beacon's `PQK!` section.
    ///
    /// Trust on first use: the first commitment seen for a fingerprint is the one
    /// that counts, and a later, *different* one is a warning rather than an
    /// update. Pins are per-process (see the module docs), so an operator who
    /// means to rotate a key gets the new pin by restarting.
    pub fn pin_commitment(&self, fp: &str, commitment: [u8; 32]) {
        match self.pins.get(fp) {
            None => {
                self.pins.insert(fp.to_string(), commitment);
                debug!(peer = %fp, "carrier: post-quantum commitment pinned (first sight)");
            }
            Some(existing) if *existing.value() == commitment => {
                tracing::trace!(peer = %fp, "carrier: post-quantum commitment confirmed");
            }
            Some(existing) => {
                // Not an update: a peer does not get to change its post-quantum
                // identity by announcing a new one. Either an operator rotated a key
                // (restart clears the pin) or someone is trying to substitute one.
                warn!(
                    peer = %fp,
                    pinned = %short(existing.value()),
                    presented = %short(&commitment),
                    "carrier: post-quantum commitment contradicts the pin — keeping the pinned one"
                );
            }
        }
    }

    /// The commitment pinned for a peer, if any.
    pub fn pinned_commitment(&self, fp: &str) -> Option<[u8; 32]> {
        self.pins.get(fp).map(|c| *c.value())
    }

    /// Record an established link under `(peer, its local address)`.
    ///
    /// Returns the link it displaced, if any — a caller may want to close the old
    /// session rather than leak it.
    ///
    /// **A link whose post-quantum commitment contradicts the pin is refused**: it
    /// is closed here, nothing is registered, and the caller is told. Without this
    /// check the hybrid binding would prove only that a peer's two keys belong to
    /// each other, which a forger with the classical private key can satisfy with
    /// a post-quantum key of their own.
    pub fn register(
        &self,
        fp: String,
        link: Arc<QuicLink>,
    ) -> Result<Option<Arc<QuicLink>>, PqMismatch> {
        let presented = link.peer_pq_commitment();
        if let Some(pinned) = self.pinned_commitment(&fp) {
            if pinned != presented {
                warn!(
                    peer = %fp,
                    pinned = %short(&pinned),
                    presented = %short(&presented),
                    "carrier: refusing a link whose post-quantum key contradicts the pin"
                );
                link.close();
                return Err(PqMismatch { pinned, presented });
            }
        }
        self.pin_commitment(&fp, presented);
        let key = LinkKey {
            fingerprint: fp,
            local: local_of(&link),
        };
        debug!(peer = %key.fingerprint, local = %key.local, "carrier: link registered");
        Ok(self.links.insert(key, link))
    }

    /// Every live link to a peer, ordered by local address.
    ///
    /// The local address in the key is the *path*: two links to one peer over a
    /// Wi-Fi address and an LTE address are two paths, and shard spreading walks
    /// this list. Closed links are evicted here, so the list is live.
    /// The order is deterministic (lowest local address first) so shard-to-path
    /// assignment is stable across sends rather than race-dependent.
    pub fn links(&self, fp: &str) -> Vec<Arc<QuicLink>> {
        let dead: Vec<LinkKey> = self
            .links
            .iter()
            .filter(|e| e.key().fingerprint == fp && e.value().is_closed())
            .map(|e| e.key().clone())
            .collect();
        for key in &dead {
            self.links.remove(key);
            debug!(peer = %fp, local = %key.local, "carrier: link evicted (closed)");
        }
        let mut live: Vec<(IpAddr, Arc<QuicLink>)> = self
            .links
            .iter()
            .filter(|e| e.key().fingerprint == fp)
            .map(|e| (e.key().local, Arc::clone(e.value())))
            .collect();
        live.sort_by_key(|(local, _)| *local);
        live.into_iter().map(|(_, link)| link).collect()
    }

    /// The link to a peer on one specific local address, evicting a closed one.
    pub fn link_on(&self, fp: &str, local: IpAddr) -> Option<Arc<QuicLink>> {
        let key = LinkKey {
            fingerprint: fp.to_string(),
            local,
        };
        let entry = self.links.get(&key)?;
        if entry.is_closed() {
            drop(entry);
            self.links.remove(&key);
            debug!(peer = %fp, local = %local, "carrier: link evicted (closed)");
            return None;
        }
        Some(Arc::clone(entry.value()))
    }

    /// The link to a peer on the lowest local address, evicting a closed one.
    ///
    /// This is the single-path answer, and the one a caller that does not care
    /// which path is used should ask for.
    pub fn link(&self, fp: &str) -> Option<Arc<QuicLink>> {
        self.links(fp).into_iter().next()
    }

    /// Distinct peers holding at least one live link.
    ///
    /// Counted by fingerprint, not by entry: a peer with two paths is one peer.
    pub fn peer_count(&self) -> usize {
        let peers: HashSet<String> = self
            .links
            .iter()
            .map(|e| e.key().fingerprint.clone())
            .collect();
        peers.len()
    }

    /// Live links across every peer and path.
    pub fn link_count(&self) -> usize {
        self.links.len()
    }

    /// True when no further dialling is worth doing for this peer: it has at least
    /// one live link, and every named local path has one of its own.
    ///
    /// The wildcard endpoint is not a named path, so it is not required here — the
    /// caller dials it when no link exists off a named path (see `dial_paths`).
    pub fn covered(&self, fp: &str) -> bool {
        let live = self.links(fp);
        if live.is_empty() {
            return false;
        }
        let used: HashSet<IpAddr> = live.iter().map(|l| local_of(l)).collect();
        self.paths.iter().all(|path| used.contains(path.key()))
    }

    pub fn forget(&self, fp: &str) {
        let keys: Vec<LinkKey> = self
            .links
            .iter()
            .filter(|e| e.key().fingerprint == fp)
            .map(|e| e.key().clone())
            .collect();
        for key in &keys {
            self.links.remove(key);
        }
        if !keys.is_empty() {
            debug!(peer = %fp, links = keys.len(), "carrier: links forgotten");
        }
    }

    /// Forget one link, by peer and path. A peer with two paths keeps the other.
    pub fn forget_link(&self, fp: &str, local: IpAddr) {
        let key = LinkKey {
            fingerprint: fp.to_string(),
            local,
        };
        if self.links.remove(&key).is_some() {
            debug!(peer = %fp, local = %local, "carrier: link forgotten");
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
                    self.forget_link(fp, local_of(&link));
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
                    self.forget_link(fp, local_of(&link));
                }
                debug!(peer = %fp, "carrier: frame not sent: {e}");
                None
            }
        }
    }

    /// Spread shards across every live path to a peer, one per path before any
    /// path carries a second, and report how many were carried.
    ///
    /// With one path this is exactly the single-link send the registry had before
    /// multipath existed: `frames[i % 1] == frames[0]`, i.e. the whole set on that
    /// link. With two paths the three shards go 2 + 1 — spread as thinly as the
    /// path count allows, which is the honest limit (see the module docs).
    ///
    /// A closed path is already gone by the time this runs (`links` evicts it), so
    /// the retry covers the other failure multipath exists to survive: a path that
    /// is up but will not take this frame *right now* — a congestion wait that ran
    /// out, a datagram buffer with no room in it. That shard moves to the next live
    /// path instead of being lost while a healthy path sits idle. A shard that no
    /// path took is reported as not carried, and the caller falls back to UDP with
    /// its frames intact.
    pub async fn send_shards(&self, fp: &str, frames: &[Vec<u8>]) -> usize {
        let links = self.links(fp);
        if links.is_empty() || frames.is_empty() {
            return 0;
        }
        let n = links.len();
        let mut carried = 0usize;
        for (i, frame) in frames.iter().enumerate() {
            let mut sent = false;
            for attempt in 0..n {
                let link = &links[(i + attempt) % n];
                match link.send_frame(frame).await {
                    Ok(_) => {
                        carried += 1;
                        sent = true;
                        break;
                    }
                    Err(e) => {
                        if link.is_closed() {
                            self.forget_link(fp, local_of(link));
                        }
                        debug!(
                            peer = %fp,
                            local = %local_of(link),
                            attempt,
                            "carrier: shard refused by this path: {e}"
                        );
                    }
                }
            }
            if !sent {
                debug!(peer = %fp, shard = i, "carrier: no path carried this shard");
            }
        }
        if n > 1 {
            debug!(peer = %fp, paths = n, carried, "carrier: shards spread across local paths");
        }
        carried
    }

    /// Dial a peer on every local path that does not already carry it, and report
    /// how many new links that established.
    ///
    /// One link per `(peer, local address)`, so the loop is:
    ///
    /// 1. every **named** path with no link to this peer dials — these are the
    ///    paths the operator named, and each has a link of its own;
    /// 2. the **wildcard** endpoint dials only when the peer has *no* link at all.
    ///
    /// The wildcard is the fallback, not an extra path, and that is deliberate: its
    /// source address is the kernel's choice, so on a platform that does not report
    /// it the registry would be counting a path it cannot name. A provider that
    /// wants that interface used for sending should name its address like any
    /// other, and is then certain which path a shard took.
    pub async fn dial_paths(&self, fp: &str, addr: SocketAddr) -> usize {
        let Some(primary) = self.transport.clone() else {
            return 0;
        };
        let mut established = 0usize;

        for (local, transport) in self.paths() {
            if self.link_on(fp, local).is_some() {
                continue;
            }
            match transport.connect(addr, fp).await {
                Ok(link) => {
                    info!(peer = %fp, %addr, local = %local, "carrier: link established on a named path");
                    match self.register(fp.to_string(), link) {
                        Ok(Some(old)) => old.close(),
                        Ok(None) => {}
                        // A contradiction with the pin: the link is closed and not
                        // counted as a path.
                        Err(e) => {
                            warn!(peer = %fp, local = %local, "carrier: path refused: {e}");
                            continue;
                        }
                    }
                    established += 1;
                }
                Err(e) => {
                    // Expected against a peer running without the transport, or
                    // behind a filter that drops a second port. The UDP path and
                    // the other paths are unaffected.
                    debug!(peer = %fp, %addr, local = %local, "carrier: path dial failed: {e}");
                }
            }
        }

        if !self.links(fp).is_empty() {
            return established;
        }
        match primary.connect(addr, fp).await {
            Ok(link) => {
                info!(
                    peer = %fp,
                    %addr,
                    local = %local_of(&link),
                    "carrier: link established"
                );
                match self.register(fp.to_string(), link) {
                    Ok(Some(old)) => old.close(),
                    Ok(None) => {}
                    Err(e) => {
                        warn!(peer = %fp, "carrier: link refused: {e}");
                        return established;
                    }
                }
                established += 1;
            }
            Err(e) => {
                debug!(peer = %fp, %addr, "carrier: dial failed: {e}");
            }
        }
        established
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// The key is the pair, so two paths to one peer are two entries and one peer.
    #[test]
    fn link_keys_separate_paths_from_peers() {
        let a = LinkKey {
            fingerprint: "peer".into(),
            local: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
        };
        let b = LinkKey {
            fingerprint: "peer".into(),
            local: IpAddr::V4(Ipv4Addr::new(10, 4, 3, 2)),
        };
        assert_ne!(a, b, "two local paths to one peer are different links");
        assert_ne!(
            a,
            LinkKey {
                fingerprint: "other".into(),
                local: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)),
            },
            "the same address for another peer is a different link"
        );
    }

    /// A pin is trust-on-first-use and is never updated by a later claim.
    #[test]
    fn a_pin_is_kept_against_a_later_contradiction() {
        let c = Carrier::disabled();
        let first = [1u8; 32];
        let second = [2u8; 32];
        assert!(c.pinned_commitment("peer").is_none(), "nothing pinned yet");
        c.pin_commitment("peer", first);
        assert_eq!(c.pinned_commitment("peer"), Some(first));
        // Confirming the same value is not a change.
        c.pin_commitment("peer", first);
        assert_eq!(c.pinned_commitment("peer"), Some(first));
        // A different one is logged and *ignored*: a peer does not get to change
        // its post-quantum identity by announcing a new one, and the pin is what
        // makes the hybrid binding load-bearing.
        c.pin_commitment("peer", second);
        assert_eq!(c.pinned_commitment("peer"), Some(first));
        // Per peer, not global.
        c.pin_commitment("other", second);
        assert_eq!(c.pinned_commitment("other"), Some(second));
    }

    /// A disabled registry answers every question without a transport.
    #[tokio::test]
    async fn a_disabled_registry_carries_nothing() {
        let c = Carrier::disabled();
        assert!(!c.enabled());
        assert_eq!(c.label(), "none");
        assert_eq!(c.path_count(), 0);
        assert_eq!(c.link_count(), 0);
        assert!(!c.covered("peer"));
        assert!(c.link("peer").is_none());
        assert!(c.send_frame("peer", b"frame").await.is_none());
        assert_eq!(
            c.send_shards("peer", &[b"one".to_vec(), b"two".to_vec()])
                .await,
            0
        );
        assert_eq!(
            c.dial_paths("peer", "127.0.0.1:1".parse().unwrap()).await,
            0
        );
        // With no endpoint there is no identity to bind a path with; the answer is
        // "nothing added", not an error.
        assert!(c
            .add_local_path(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .unwrap()
            .is_none());
    }
}
