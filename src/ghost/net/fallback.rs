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
//! 1. **The ladder** ([`choose_fallback`]): direct → a mesh peer that advertises
//!    relay capability → a TURN allocation. Ordered by cost, and deterministic so
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

/// How we are reaching a peer that could not be reached directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FallbackPath {
    /// A validated ICE path — no relay involved.
    Direct,
    /// Through a mesh peer that advertised relay capability.
    MeshRelay {
        relay_fp: String,
        relay_addr: SocketAddr,
    },
    /// Through TURN: `peer_relayed` is the address the peer's own allocation
    /// gave it (advertised as a relay candidate in its ICE offer), and our
    /// allocation is what carries the datagram there.
    Turn { peer_relayed: SocketAddr },
}

impl FallbackPath {
    /// Whether traffic on this path passes a third party.
    pub fn is_relayed(&self) -> bool {
        !matches!(self, FallbackPath::Direct)
    }

    /// The address datagrams for the target must be sent to.
    pub fn egress_addr(&self) -> Option<SocketAddr> {
        match self {
            FallbackPath::Direct => None,
            FallbackPath::MeshRelay { relay_addr, .. } => Some(*relay_addr),
            FallbackPath::Turn { peer_relayed } => Some(*peer_relayed),
        }
    }

    /// A short label for logs and dashboards.
    pub fn label(&self) -> &'static str {
        match self {
            FallbackPath::Direct => "direct",
            FallbackPath::MeshRelay { .. } => "mesh-relay",
            FallbackPath::Turn { .. } => "turn",
        }
    }
}

/// Choose the cheapest fallback that can actually carry traffic to `target_fp`.
///
/// The order is deliberate. A mesh peer is tried before TURN because it is
/// already a member of the same encrypted mesh — using it costs no extra
/// infrastructure and the traffic it forwards is accounted (and repaid) through
/// the tit-for-tat ledger, whereas a TURN server is the operator's last resort.
///
/// A candidate that *is* us, or *is* the target, is never chosen: the first would
/// be a loop and the second is not a relay at all.
/// `turn` is the *peer's* relayed address, taken from the relay candidate it
/// advertises, not our own allocation's address: ours is how we send, theirs is
/// where the datagram has to arrive. A peer that advertises no relay candidate is
/// not reachable through TURN at all, because nothing of ours can create a
/// mapping in its NAT toward a server it never contacted.
pub fn choose_fallback(
    our_fp: &str,
    target_fp: &str,
    relay_candidates: &[(String, SocketAddr)],
    turn: Option<SocketAddr>,
) -> Option<FallbackPath> {
    if let Some((relay_fp, relay_addr)) = relay_candidates
        .iter()
        .find(|(fp, _)| fp != our_fp && fp != target_fp)
    {
        return Some(FallbackPath::MeshRelay {
            relay_fp: relay_fp.clone(),
            relay_addr: *relay_addr,
        });
    }
    turn.map(|peer_relayed| FallbackPath::Turn { peer_relayed })
}

/// The per-peer fallback route table.
///
/// Only peers that cannot be reached directly appear here. Absence means "try
/// direct", which is why a recovered path must be [`Self::clear`]ed rather than
/// overwritten with [`FallbackPath::Direct`] — the two would then be
/// indistinguishable from a peer never seen before.
#[derive(Debug, Default)]
pub struct FallbackRoutes {
    routes: DashMap<String, FallbackPath>,
}

impl FallbackRoutes {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the path a peer is reachable by.
    pub fn set(&self, peer_fp: &str, path: FallbackPath) {
        if matches!(path, FallbackPath::Direct) {
            self.clear(peer_fp);
            return;
        }
        self.routes.insert(peer_fp.to_string(), path);
    }

    /// Forget a peer's fallback — it is direct again (or unknown again).
    pub fn clear(&self, peer_fp: &str) {
        self.routes.remove(peer_fp);
    }

    /// The fallback for a peer, if it needs one.
    pub fn path(&self, peer_fp: &str) -> Option<FallbackPath> {
        self.routes.get(peer_fp).map(|p| p.clone())
    }

    /// Whether a peer's traffic has to be relayed.
    pub fn is_relayed(&self, peer_fp: &str) -> bool {
        self.routes.contains_key(peer_fp)
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Every relayed peer, ordered by fingerprint so a dashboard does not
    /// reshuffle between polls.
    pub fn snapshot(&self) -> Vec<(String, FallbackPath)> {
        let mut out: Vec<(String, FallbackPath)> = self
            .routes
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Peers currently relayed through a specific mesh peer — used to drop the
    /// routes when that relay's session ends.
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

/// Everything the tunnel needs to know about how it currently reaches peers that
/// have no direct path: the route table, and the TURN allocation that carries the
/// routes that need one.
///
/// One value rather than two parameters threaded through the receive path, and it
/// makes one invariant enforceable in a single place: a TURN route is only ever
/// recorded when this node actually holds an allocation to send through.
#[derive(Default)]
pub struct Fallback {
    routes: FallbackRoutes,
    turn: Option<Arc<TurnPath>>,
}

impl Fallback {
    pub fn new(turn: Option<Arc<TurnPath>>) -> Self {
        Fallback {
            routes: FallbackRoutes::new(),
            turn,
        }
    }

    /// Record a peer's fallback path.
    ///
    /// Returns `false` when the path cannot carry a datagram: a TURN route with no
    /// allocation on our side would silently black-hole the peer, so it is refused
    /// here rather than logged at every send.
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

    /// The allocation that carries TURN routes, when one is configured.
    pub fn turn(&self) -> Option<&Arc<TurnPath>> {
        self.turn.as_ref()
    }

    /// Our own relayed address, when we hold an allocation.
    pub fn turn_relayed_addr(&self) -> Option<SocketAddr> {
        self.turn.as_ref().map(|t| t.relayed_addr())
    }
}

/// Wrap an already-sealed frame for delivery to `target_fp` through a relay.
///
/// The input is the *complete* GTF frame, not a payload: the target has to parse
/// it out of the relayed datagram exactly as it would off the wire, so the frame
/// travels intact and the relay only ever handles ciphertext.
pub fn blind_envelope(target_fp: &str, sealed_frame: &[u8]) -> Vec<u8> {
    relay::wrap_blind_frame(target_fp, sealed_frame)
}

/// What a relay should emit for a decrypted datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayHop {
    /// The address the frame is addressed to.
    pub dest: SocketAddr,
    /// The sealed frame, verbatim.
    pub bytes: Vec<u8>,
}

/// Relay role: decide what to do with a decrypted payload.
///
/// Returns the datagram to emit, or the reason to refuse. Refusals are counted by
/// [`DerpRelay`] itself, so this merely surfaces the decision to the caller that
/// owns the socket.
pub fn relay_hop(relay: &DerpRelay, from_fp: &str, payload: &[u8]) -> Result<RelayHop, DropReason> {
    match relay.forward(from_fp, payload) {
        relay::Forwarded::Deliver { dest, bytes } => Ok(RelayHop { dest, bytes }),
        relay::Forwarded::Dropped(reason) => Err(reason),
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// TURN egress
// ═════════════════════════════════════════════════════════════════════════════

/// Commands to the TURN task. All allocation state (permissions, channels, the
/// nonce) lives in that task, so nothing here has to hold a lock across an await.
enum TurnCmd {
    Send { peer: SocketAddr, frame: Vec<u8> },
}

/// A live TURN allocation, driving a socket we own.
///
/// TURN traffic gets its own socket on purpose. An allocation is bound to the
/// 5-tuple that created it, and the mesh socket is a shared resource: running the
/// transactions on it would mean the allocation's replies race the packet
/// receiver, and a transaction would have to hold the socket while it waited.
/// Nothing is lost by separating them — the relayed address the server hands back
/// is an address *we* receive on, and peers are told about it directly.
pub struct TurnPath {
    server: SocketAddr,
    relayed: SocketAddr,
    /// Frames until the allocation expires; half the granted lifetime, refreshed
    /// in the task.
    granted: Duration,
    tx: mpsc::UnboundedSender<TurnCmd>,
    sent: Arc<std::sync::atomic::AtomicU64>,
    refused: Arc<std::sync::atomic::AtomicU64>,
}

impl TurnPath {
    /// Establish an allocation and start the task that owns it.
    ///
    /// `inbox` receives `(peer, sealed frame)` for every datagram the server
    /// relays to us: the caller feeds those into the same receive path as mesh
    /// traffic, because the peer sealed them for us exactly as if they had been
    /// sent directly.
    pub async fn establish(
        server: SocketAddr,
        username: impl Into<String>,
        password: impl Into<String>,
        timeout: Duration,
        inbox: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
    ) -> Result<Arc<TurnPath>, TurnError> {
        let sock = Arc::new(UdpSocket::bind(("0.0.0.0", 0)).await?);
        let mut client = TurnClient::new(server, username, password).with_timeout(timeout);
        // Nothing else reads this socket yet, so no callback is needed: there is
        // no traffic to lose.
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

    /// The address peers should send to for us to receive it through the relay.
    pub fn relayed_addr(&self) -> SocketAddr {
        self.relayed
    }

    pub fn server(&self) -> SocketAddr {
        self.server
    }

    /// The granted allocation lifetime (refreshed at half of it).
    pub fn granted_lifetime(&self) -> Duration {
        self.granted
    }

    /// `(frames handed to the server, frames the server refused)`.
    pub fn stats(&self) -> (u64, u64) {
        (
            self.sent.load(std::sync::atomic::Ordering::Relaxed),
            self.refused.load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    /// Hand a sealed frame to the server for delivery to `peer`.
    ///
    /// Kept synchronous: the send path already holds a `Send` future and should
    /// not also wait on a relay transaction. The frame is dropped, and counted,
    /// if the task has stopped.
    pub fn send_sealed(&self, peer: SocketAddr, frame: Vec<u8>) {
        if self.tx.send(TurnCmd::Send { peer, frame }).is_err() {
            self.refused
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            warn!(peer = %peer, "TURN: allocation task is gone, frame not relayed");
        }
    }
}

/// The task that owns the socket, the client, and therefore all TURN state.
async fn turn_task(
    sock: Arc<UdpSocket>,
    mut client: TurnClient,
    mut rx: mpsc::UnboundedReceiver<TurnCmd>,
    inbox: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
    granted: Duration,
    sent: Arc<std::sync::atomic::AtomicU64>,
    refused: Arc<std::sync::atomic::AtomicU64>,
) {
    // Refresh at half the lifetime: a renewal that arrives late still has half a
    // lifetime of slack, whereas one at 90% has a network hiccup's worth.
    let refresh_after = (granted / 2).max(Duration::from_secs(30));
    let mut next_refresh = tokio::time::Instant::now() + refresh_after;
    let mut buf = vec![0u8; 2048];
    // Peer we have installed a permission and channel for, with when.
    let mut ready: HashMap<IpAddr, Instant> = HashMap::new();

    loop {
        tokio::select! {
            cmd = rx.recv() => {
                let Some(cmd) = cmd else { return };
                match cmd {
                    TurnCmd::Send { peer, frame } => {
                        let stale = ready
                            .get(&peer.ip())
                            .map_or(true, |t| t.elapsed() > turn::DEFAULT_PERMISSION_LIFETIME / 2);
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
                            // A channel costs 4 bytes per datagram where a Send
                            // indication costs ~40, so bind one when the peer
                            // will take more than one frame. Failure here is not
                            // fatal: `send` falls back to a Send indication.
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
                        // Permissions and channels expire independently of the
                        // allocation, so re-arm them rather than assuming the
                        // refresh covered them.
                        ready.clear();
                    }
                    Ok(_) => {
                        warn!("TURN: allocation released by the server");
                        return;
                    }
                    Err(e) => {
                        warn!("TURN: refresh failed: {e}");
                        // Retry sooner than the next scheduled refresh: an
                        // allocation that lapsed is unusable until it is renewed.
                        next_refresh = tokio::time::Instant::now() + Duration::from_secs(10);
                    }
                }
            }
            recv = sock.recv_from(&mut buf) => {
                match recv {
                    Ok((n, _from)) => {
                        // The socket carries only TURN traffic, so an unrecognised
                        // datagram is not ours to interpret — most often a stray
                        // STUN request from the server.
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

/// Resolve an inbound TURN datagram to `(peer address, payload)`.
///
/// A `Data` indication names the peer; ChannelData carries only the channel, so
/// the binding installed by [`TurnClient::channel_bind`] is the only way to
/// attribute it — hence the lookup rather than a guess.
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
        // Without an allocation there is no transport, and recording the route
        // anyway would turn every send to that peer into a silent drop.
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

        // A mesh relay needs no allocation, and is accepted.
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
        // No relay peer and no allocation: nothing can carry this peer's traffic,
        // and inventing a path would be the bug this module exists to fix.
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

        // Direct is the absence of a route, not a route of its own: leaving a
        // `Direct` entry behind would make "needs a relay" and "recovered"
        // indistinguishable at every call site.
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

        // Unknown sender: authorized only if it has a session, which is how the
        // mesh knows a peer at all.
        assert_eq!(
            relay_hop(&relay, "mallory", &envelope),
            Err(DropReason::UnauthorizedSender)
        );
        relay.authorize("alice", addr("198.51.100.10:30000"));
        assert_eq!(
            relay_hop(&relay, "alice", &envelope),
            Ok(RelayHop {
                dest: addr("198.51.100.20:40000"),
                // The frame the target parses, not the relay's envelope: the
                // header is relay-layer addressing and does not travel on.
                bytes: b"sealed".to_vec(),
            })
        );

        // And it refuses to be a reflector.
        let back = blind_envelope("alice", b"sealed");
        assert_eq!(relay_hop(&relay, "alice", &back), Err(DropReason::Loop));
        // A datagram that is not an envelope is not a forwarding request either.
        assert_eq!(
            relay_hop(&relay, "alice", b"plain mesh traffic"),
            Err(DropReason::NotAnEnvelope)
        );
    }

    #[test]
    fn a_multi_hop_onion_is_not_the_blind_paths_business() {
        // The onion path re-encrypts at each hop; the blind path must never touch
        // someone else's ciphertext. Keeping them apart is what makes the relay
        // unable to read the traffic it forwards.
        let relay = DerpRelay::new(Arc::new(super::super::FlowController::new(100)));
        relay.authorize("alice", addr("198.51.100.10:30000"));
        relay.authorize("bob", addr("198.51.100.20:40000"));
        let onion = relay::build_relay_packet("bob", 2, b"layered");
        assert_eq!(
            relay_hop(&relay, "alice", &onion),
            Err(DropReason::NotBlindForward)
        );
        // The drop counter is left alone: it counts relay *requests* that failed
        // (unknown target, no session, quota, a loop). An onion is not a blind
        // request at all, and folding the two together would make a legitimate
        // multi-hop path indistinguishable from abuse on the dashboard.
        assert_eq!(relay.stats(), (0, 0, 0));
    }
}
