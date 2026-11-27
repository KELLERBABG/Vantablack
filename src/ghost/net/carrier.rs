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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PqMismatch {
    pub pinned: [u8; 32],
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

fn short(commitment: &[u8; 32]) -> String {
    hex::encode(&commitment[..8])
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LinkKey {
    pub fingerprint: String,
    pub local: IpAddr,
}

fn local_of(link: &QuicLink) -> IpAddr {
    link.local_addr()
}

pub struct Carrier {
    transport: Option<Arc<QuicTransport>>,
    paths: DashMap<IpAddr, Arc<QuicTransport>>,
    links: DashMap<LinkKey, Arc<QuicLink>>,
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

    pub fn add_path(&self, transport: Arc<QuicTransport>) -> Option<Arc<QuicTransport>> {
        let Ok(addr) = transport.local_addr() else {
            return None;
        };
        if addr.ip().is_unspecified() {
            debug!("carrier: refusing to add a wildcard endpoint as a named path");
            return None;
        }
        info!(local = %addr, "carrier: local path added");
        self.paths.insert(addr.ip(), transport)
    }

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

    pub fn paths(&self) -> Vec<(IpAddr, Arc<QuicTransport>)> {
        self.paths
            .iter()
            .map(|e| (*e.key(), Arc::clone(e.value())))
            .collect()
    }

    pub fn path_count(&self) -> usize {
        self.paths.len()
    }

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
                warn!(
                    peer = %fp,
                    pinned = %short(existing.value()),
                    presented = %short(&commitment),
                    "carrier: post-quantum commitment contradicts the pin — keeping the pinned one"
                );
            }
        }
    }

    pub fn pinned_commitment(&self, fp: &str) -> Option<[u8; 32]> {
        self.pins.get(fp).map(|c| *c.value())
    }

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

    pub fn link(&self, fp: &str) -> Option<Arc<QuicLink>> {
        self.links(fp).into_iter().next()
    }

    pub fn peer_count(&self) -> usize {
        let peers: HashSet<String> = self
            .links
            .iter()
            .map(|e| e.key().fingerprint.clone())
            .collect();
        peers.len()
    }

    pub fn link_count(&self) -> usize {
        self.links.len()
    }

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

    pub fn forget_link(&self, fp: &str, local: IpAddr) {
        let key = LinkKey {
            fingerprint: fp.to_string(),
            local,
        };
        if self.links.remove(&key).is_some() {
            debug!(peer = %fp, local = %local, "carrier: link forgotten");
        }
    }

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
                        Err(e) => {
                            warn!(peer = %fp, local = %local, "carrier: path refused: {e}");
                            continue;
                        }
                    }
                    established += 1;
                }
                Err(e) => {
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

    #[test]
    fn a_pin_is_kept_against_a_later_contradiction() {
        let c = Carrier::disabled();
        let first = [1u8; 32];
        let second = [2u8; 32];
        assert!(c.pinned_commitment("peer").is_none(), "nothing pinned yet");
        c.pin_commitment("peer", first);
        assert_eq!(c.pinned_commitment("peer"), Some(first));
        c.pin_commitment("peer", first);
        assert_eq!(c.pinned_commitment("peer"), Some(first));
        c.pin_commitment("peer", second);
        assert_eq!(c.pinned_commitment("peer"), Some(first));
        c.pin_commitment("other", second);
        assert_eq!(c.pinned_commitment("other"), Some(second));
    }

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
        assert!(c
            .add_local_path(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .unwrap()
            .is_none());
    }
}
