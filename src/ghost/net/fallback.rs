//! Reachability fallback — what the tunnel does when ICE cannot build a direct
//! path (bug B22).
//!
//! Phase 1 shipped two working halves that were never joined: `mesh::NatHolePuncher`
//! reports honestly when every candidate pair fails, and `relay::DerpRelay` knows
//! how to forward a sealed frame for a peer it holds no key for. Nothing consumed
//! the failure, so a session in that topology had nowhere to go.
//!
//! This module is that join. It has three parts:
//!
//! 1. **The ladder** ([`choose_fallback_with_skywave`]): direct → a mesh peer that
//!    advertises relay capability → a TURN allocation → the ABOS skywave carrier
//!    (only when the SDR bridge is active). Ordered by cost, and deterministic so
//!    two runs of the same topology pick the same path.
//! 2. **The route table** ([`FallbackRoutes`]): which path each unreachable peer is
//!    currently using, read by the shard egress and written when a punch fails or a
//!    path later recovers.
//! 3. **The egress/ingress pair** ([`blind_envelope`], [`relay_hop`], [`TurnPath`]):
//!    the bytes that actually cross the relay, and the two roles that handle them.
//!
//! ## What the relay can see
//!
//! A relayed frame is `[GTF frame sealed to the target]` wrapped in a single-hop
//! envelope. The relay decrypts nothing: it is handed the envelope by
//! [`relay_hop`], which it can only reach with a live session — and the opaque
//! region it forwards byte-for-byte is the target's own AEAD ciphertext. It does
//! learn the 4-byte session hash and the packet counter from the frame header,
//! because those are the target's routing label and the target cannot parse the
//! frame without them. It never learns the payload, the key, or a plaintext byte.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::relay::{self, DerpRelay, DropReason};
use super::turn::{self, TurnClient, TurnError, TurnInbound};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FallbackPath {
    Direct,
    MeshRelay {
        relay_fp: String,
        relay_addr: SocketAddr,
    },
    Turn {
        peer_relayed: SocketAddr,
    },
    Skywave {
        nvis_freq_khz: u32,
    },
    Masque {
        peer: SocketAddr,
    },
}

impl FallbackPath {
    pub fn is_relayed(&self) -> bool {
        !matches!(
            self,
            FallbackPath::Direct | FallbackPath::Skywave { .. } | FallbackPath::Masque { .. }
        )
    }

    pub fn egress_addr(&self) -> Option<SocketAddr> {
        match self {
            FallbackPath::Direct | FallbackPath::Skywave { .. } | FallbackPath::Masque { .. } => {
                None
            }
            FallbackPath::MeshRelay { relay_addr, .. } => Some(*relay_addr),
            FallbackPath::Turn { peer_relayed } => Some(*peer_relayed),
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            FallbackPath::Direct => "direct",
            FallbackPath::MeshRelay { .. } => "mesh-relay",
            FallbackPath::Turn { .. } => "turn",
            FallbackPath::Skywave { .. } => "skywave-nvis",
            FallbackPath::Masque { .. } => "masque-h3",
        }
    }
}

pub(crate) fn is_lan_addr(addr: &SocketAddr) -> bool {
    match addr.ip() {
        std::net::IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        std::net::IpAddr::V6(ip) => ip.is_loopback(),
    }
}

pub fn choose_fallback(
    our_fp: &str,
    target_fp: &str,
    relay_candidates: &[(String, SocketAddr)],
    turn: Option<SocketAddr>,
) -> Option<FallbackPath> {
    choose_fallback_with_skywave(our_fp, target_fp, relay_candidates, turn, None)
}

pub fn choose_fallback_with_skywave(
    our_fp: &str,
    target_fp: &str,
    relay_candidates: &[(String, SocketAddr)],
    turn: Option<SocketAddr>,
    skywave: Option<u32>,
) -> Option<FallbackPath> {
    let candidate = relay_candidates
        .iter()
        .find(|(fp, addr)| fp != our_fp && fp != target_fp && !is_lan_addr(addr))
        .or_else(|| {
            relay_candidates
                .iter()
                .find(|(fp, _)| fp != our_fp && fp != target_fp)
        });

    if let Some((relay_fp, relay_addr)) = candidate {
        return Some(FallbackPath::MeshRelay {
            relay_fp: relay_fp.clone(),
            relay_addr: *relay_addr,
        });
    }
    if let Some(peer_relayed) = turn {
        return Some(FallbackPath::Turn { peer_relayed });
    }
    skywave.map(|nvis_freq_khz| FallbackPath::Skywave { nvis_freq_khz })
}

#[derive(Debug, Default)]
pub struct FallbackRoutes {
    routes: DashMap<String, FallbackPath>,
}

impl FallbackRoutes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, peer_fp: &str, path: FallbackPath) {
        if matches!(path, FallbackPath::Direct) {
            self.clear(peer_fp);
            return;
        }
        self.routes.insert(peer_fp.to_string(), path);
    }

    pub fn clear(&self, peer_fp: &str) {
        self.routes.remove(peer_fp);
    }

    pub fn path(&self, peer_fp: &str) -> Option<FallbackPath> {
        self.routes.get(peer_fp).map(|p| p.clone())
    }

    pub fn is_relayed(&self, peer_fp: &str) -> bool {
        self.routes.contains_key(peer_fp)
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    pub fn snapshot(&self) -> Vec<(String, FallbackPath)> {
        let mut out: Vec<(String, FallbackPath)> = self
            .routes
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    pub fn relayed_via(&self, relay_fp: &str) -> Vec<String> {
        let mut out: Vec<String> = self
            .routes
            .iter()
            .filter(|e| {
                matches!(
                    e.value(),
                    FallbackPath::MeshRelay { relay_fp: r, .. } if r == relay_fp
                )
            })
            .map(|e| e.key().clone())
            .collect();
        out.sort();
        out
    }
}

#[derive(Default)]
pub struct Fallback {
    routes: FallbackRoutes,
    turn: Option<Arc<TurnPath>>,
    known_relays: DashMap<String, SocketAddr>,
}

impl Fallback {
    pub fn new(turn: Option<Arc<TurnPath>>) -> Self {
        Fallback {
            routes: FallbackRoutes::new(),
            turn,
            known_relays: DashMap::new(),
        }
    }

    pub fn record_relay(&self, relay_fp: &str, mesh_addr: SocketAddr) {
        self.known_relays.insert(relay_fp.to_string(), mesh_addr);
    }

    pub fn remove_relay(&self, relay_fp: &str) {
        self.known_relays.remove(relay_fp);
    }

    pub fn relay_candidates(&self) -> Vec<(String, SocketAddr)> {
        let mut out: Vec<(String, SocketAddr)> = self
            .known_relays
            .iter()
            .map(|e| (e.key().clone(), *e.value()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    pub fn relay_count(&self) -> usize {
        self.known_relays.len()
    }

    pub fn set(&self, peer_fp: &str, path: FallbackPath) -> bool {
        if matches!(path, FallbackPath::Turn { .. }) && self.turn.is_none() {
            self.routes.clear(peer_fp);
            return false;
        }
        self.routes.set(peer_fp, path);
        true
    }

    pub fn clear(&self, peer_fp: &str) {
        self.routes.clear(peer_fp);
    }

    pub fn path(&self, peer_fp: &str) -> Option<FallbackPath> {
        self.routes.path(peer_fp)
    }

    pub fn is_relayed(&self, peer_fp: &str) -> bool {
        self.routes.is_relayed(peer_fp)
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    pub fn snapshot(&self) -> Vec<(String, FallbackPath)> {
        self.routes.snapshot()
    }

    pub fn relayed_via(&self, relay_fp: &str) -> Vec<String> {
        self.routes.relayed_via(relay_fp)
    }

    pub fn evict_dead_peer(&self, dead_fp: &str) -> Vec<String> {
        self.remove_relay(dead_fp);
        self.clear(dead_fp);
        let affected = self.routes.relayed_via(dead_fp);
        for peer in &affected {
            self.clear(peer);
        }
        affected
    }

    pub fn turn(&self) -> Option<&Arc<TurnPath>> {
        self.turn.as_ref()
    }

    pub fn turn_relayed_addr(&self) -> Option<SocketAddr> {
        self.turn.as_ref().map(|t| t.relayed_addr())
    }
}

pub fn blind_envelope(target_fp: &str, sealed_frame: &[u8]) -> Vec<u8> {
    relay::wrap_blind_frame(target_fp, sealed_frame)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayHop {
    pub dest: SocketAddr,
    pub bytes: Vec<u8>,
}

pub fn relay_hop(relay: &DerpRelay, from_fp: &str, payload: &[u8]) -> Result<RelayHop, DropReason> {
    match relay.forward(from_fp, payload) {
        relay::Forwarded::Deliver { dest, bytes } => Ok(RelayHop { dest, bytes }),
        relay::Forwarded::Dropped(reason) => Err(reason),
    }
}

enum TurnCmd {
    Send { peer: SocketAddr, frame: Vec<u8> },
}

pub struct TurnPath {
    server: SocketAddr,
    relayed: SocketAddr,
    granted: Duration,
    tx: mpsc::UnboundedSender<TurnCmd>,
    sent: Arc<std::sync::atomic::AtomicU64>,
    refused: Arc<std::sync::atomic::AtomicU64>,
}

impl TurnPath {
    pub async fn establish(
        server: SocketAddr,
        username: impl Into<String>,
        password: impl Into<String>,
        timeout: Duration,
        inbox: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
    ) -> Result<Arc<TurnPath>, TurnError> {
        let sock = Arc::new(UdpSocket::bind(("0.0.0.0", 0)).await?);
        let mut client = TurnClient::new(server, username, password).with_timeout(timeout);
        let relayed = client.allocate(&sock, turn::DEFAULT_LIFETIME, None).await?;
        let granted = client
            .allocation()
            .map(|a| a.lifetime)
            .unwrap_or(turn::DEFAULT_LIFETIME);
        info!(server = %server, relayed = %relayed, "TURN: allocation established");

        let (tx, rx) = mpsc::unbounded_channel();
        let sent = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let refused = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let path = Arc::new(TurnPath {
            server,
            relayed,
            granted,
            tx,
            sent: Arc::clone(&sent),
            refused: Arc::clone(&refused),
        });
        tokio::spawn(turn_task(sock, client, rx, inbox, granted, sent, refused));
        Ok(path)
    }

    pub fn relayed_addr(&self) -> SocketAddr {
        self.relayed
    }

    pub fn server(&self) -> SocketAddr {
        self.server
    }

    pub fn granted_lifetime(&self) -> Duration {
        self.granted
    }

    pub fn stats(&self) -> (u64, u64) {
        (
            self.sent.load(std::sync::atomic::Ordering::Relaxed),
            self.refused.load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    pub fn send_sealed(&self, peer: SocketAddr, frame: Vec<u8>) {
        if self.tx.send(TurnCmd::Send { peer, frame }).is_err() {
            self.refused
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            warn!(peer = %peer, "TURN: allocation task is gone, frame not relayed");
        }
    }
}

async fn turn_task(
    sock: Arc<UdpSocket>,
    mut client: TurnClient,
    mut rx: mpsc::UnboundedReceiver<TurnCmd>,
    inbox: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
    granted: Duration,
    sent: Arc<std::sync::atomic::AtomicU64>,
    refused: Arc<std::sync::atomic::AtomicU64>,
) {
    let refresh_after = (granted / 2).max(Duration::from_secs(30));
    let mut next_refresh = tokio::time::Instant::now() + refresh_after;
    let mut buf = vec![0u8; 2048];
    let mut ready: HashMap<IpAddr, Instant> = HashMap::new();

    loop {
        tokio::select! {
            cmd = rx.recv() => {
                let Some(cmd) = cmd else { return };
                match cmd {
                    TurnCmd::Send { peer, frame } => {
                        let stale = ready
                            .get(&peer.ip())
                            .is_none_or(|t| t.elapsed() > turn::DEFAULT_PERMISSION_LIFETIME / 2);
                        if stale {
                            match client.create_permission(&sock, peer, None).await {
                                Ok(()) => {
                                    ready.insert(peer.ip(), Instant::now());
                                }
                                Err(e) => {
                                    refused.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    warn!(peer = %peer, server = %client.server(), "TURN: permission refused: {e}");
                                    continue;
                                }
                            }
                            if let Err(e) = client.channel_bind(&sock, peer, None).await {
                                debug!(peer = %peer, "TURN: channel bind failed, using indications: {e}");
                            }
                        }
                        match client.send(&sock, peer, &frame).await {
                            Ok(()) => {
                                sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            Err(e) => {
                                refused.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                warn!(peer = %peer, "TURN: send failed: {e}");
                            }
                        }
                    }
                }
            }
            _ = tokio::time::sleep_until(next_refresh) => {
                match client.refresh(&sock, turn::DEFAULT_LIFETIME, None).await {
                    Ok(lifetime) if !lifetime.is_zero() => {
                        next_refresh = tokio::time::Instant::now() + (lifetime / 2).max(Duration::from_secs(30));
                        ready.clear();
                    }
                    Ok(_) => {
                        warn!("TURN: allocation released by the server");
                        return;
                    }
                    Err(e) => {
                        warn!("TURN: refresh failed: {e}");
                        next_refresh = tokio::time::Instant::now() + Duration::from_secs(10);
                    }
                }
            }
            recv = sock.recv_from(&mut buf) => {
                match recv {
                    Ok((n, _from)) => {
                        if let Some(inbound) = client.decode_inbound(&buf[..n]) {
                            let Some((peer, payload)) = inbound_peer(&client, inbound) else {
                                debug!("TURN: ChannelData for an unknown channel");
                                continue;
                            };
                            if inbox.send((peer, payload)).is_err() {
                                debug!("TURN: receive path is gone, stopping");
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("TURN: socket read failed: {e}");
                        return;
                    }
                }
            }
        }
    }
}

fn inbound_peer(client: &TurnClient, inbound: TurnInbound) -> Option<(SocketAddr, Vec<u8>)> {
    match inbound {
        TurnInbound::Data { peer, payload } => Some((peer, payload)),
        TurnInbound::ChannelData { channel, payload } => {
            client.peer_for_channel(channel).map(|peer| (peer, payload))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn a_turn_route_is_refused_without_an_allocation() {
        let fallback = Fallback::new(None);
        assert!(!fallback.set(
            "bob",
            FallbackPath::Turn {
                peer_relayed: addr("198.51.100.9:49152"),
            }
        ));
        assert_eq!(fallback.path("bob"), None);
        assert!(!fallback.is_relayed("bob"));
        assert_eq!(fallback.turn_relayed_addr(), None);

        assert!(fallback.set(
            "bob",
            FallbackPath::MeshRelay {
                relay_fp: "helper".into(),
                relay_addr: addr("203.0.113.77:2270"),
            }
        ));
        assert!(fallback.is_relayed("bob"));
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn relay_candidates() -> Vec<(String, SocketAddr)> {
        vec![
            ("helper".to_string(), addr("203.0.113.77:2270")),
            ("other".to_string(), addr("203.0.113.78:2270")),
        ]
    }

    #[test]
    fn the_ladder_prefers_a_mesh_peer_over_turn() {
        let path = choose_fallback(
            "alice",
            "bob",
            &relay_candidates(),
            Some(addr("198.51.100.9:3478")),
        )
        .expect("a candidate exists");
        assert_eq!(
            path,
            FallbackPath::MeshRelay {
                relay_fp: "helper".into(),
                relay_addr: addr("203.0.113.77:2270"),
            }
        );
        assert!(path.is_relayed());
        assert_eq!(path.label(), "mesh-relay");
    }

    #[test]
    fn turn_is_the_last_resort_and_absence_is_not_a_fallback() {
        let path = choose_fallback("alice", "bob", &[], Some(addr("198.51.100.9:3478"))).unwrap();
        assert_eq!(
            path,
            FallbackPath::Turn {
                peer_relayed: addr("198.51.100.9:3478")
            }
        );
        assert_eq!(path.label(), "turn");
        assert_eq!(choose_fallback("alice", "bob", &[], None), None);
    }

    #[test]
    fn we_are_never_our_own_relay_and_the_target_is_never_a_relay() {
        let candidates = vec![
            ("alice".to_string(), addr("198.51.100.10:30000")),
            ("bob".to_string(), addr("198.51.100.20:40000")),
            ("helper".to_string(), addr("203.0.113.77:2270")),
        ];
        let path = choose_fallback("alice", "bob", &candidates, None).unwrap();
        assert_eq!(
            path.egress_addr(),
            Some(addr("203.0.113.77:2270")),
            "neither us nor the destination may be selected"
        );
    }

    #[test]
    fn a_recovered_path_is_cleared_rather_than_marked_direct() {
        let routes = FallbackRoutes::new();
        routes.set(
            "bob",
            FallbackPath::MeshRelay {
                relay_fp: "helper".into(),
                relay_addr: addr("203.0.113.77:2270"),
            },
        );
        assert!(routes.is_relayed("bob"));
        assert_eq!(routes.relayed_via("helper"), vec!["bob".to_string()]);
        assert!(routes.relayed_via("other").is_empty());

        routes.set("bob", FallbackPath::Direct);
        assert!(!routes.is_relayed("bob"));
        assert!(routes.path("bob").is_none());
        assert!(routes.is_empty());
    }

    #[test]
    fn the_envelope_round_trips_and_keeps_the_frame_verbatim() {
        let sealed = b"\x9a\x11\x7c\x5e\x00\x00\x00\x02 sealed GTF frame";
        let envelope = blind_envelope("bob", sealed);
        let parsed = relay::parse_blind_frame(&envelope).expect("must be a blind frame");
        assert_eq!(parsed.target_fingerprint, "bob");
        assert_eq!(parsed.opaque, sealed, "the frame is what the target parses");
    }

    #[test]
    fn a_relay_forwards_only_for_peers_it_holds_a_session_with() {
        let relay = DerpRelay::new(Arc::new(super::super::FlowController::new(100)));
        relay.authorize("bob", addr("198.51.100.20:40000"));
        let envelope = blind_envelope("bob", b"sealed");

        assert_eq!(
            relay_hop(&relay, "mallory", &envelope),
            Err(DropReason::UnauthorizedSender)
        );
        relay.authorize("alice", addr("198.51.100.10:30000"));
        assert_eq!(
            relay_hop(&relay, "alice", &envelope),
            Ok(RelayHop {
                dest: addr("198.51.100.20:40000"),
                bytes: b"sealed".to_vec(),
            })
        );

        let back = blind_envelope("alice", b"sealed");
        assert_eq!(relay_hop(&relay, "alice", &back), Err(DropReason::Loop));
        assert_eq!(
            relay_hop(&relay, "alice", b"plain mesh traffic"),
            Err(DropReason::NotAnEnvelope)
        );
    }

    #[test]
    fn a_multi_hop_onion_is_not_the_blind_paths_business() {
        let relay = DerpRelay::new(Arc::new(super::super::FlowController::new(100)));
        relay.authorize("alice", addr("198.51.100.10:30000"));
        relay.authorize("bob", addr("198.51.100.20:40000"));
        let onion = relay::build_relay_packet("bob", 2, b"layered");
        assert_eq!(
            relay_hop(&relay, "alice", &onion),
            Err(DropReason::NotBlindForward)
        );
        assert_eq!(relay.stats(), (0, 0, 0));
    }

    #[test]
    fn non_relay_node_tracks_and_selects_discovered_relays() {
        let fb = Fallback::new(None);
        fb.record_relay("relay-vps", addr("203.0.113.50:55225"));
        assert_eq!(fb.relay_count(), 1);
        let candidates = fb.relay_candidates();
        let chosen = choose_fallback("client-a", "client-b", &candidates, None);
        assert_eq!(
            chosen,
            Some(FallbackPath::MeshRelay {
                relay_fp: "relay-vps".to_string(),
                relay_addr: addr("203.0.113.50:55225"),
            })
        );
    }
}
