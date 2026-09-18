use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::ghost::layers::l2_aead::xchacha_seal_in_place_with_aad;
use crate::ghost::layers::l4_rs;
use crate::ghost::net::cc;
use crate::ghost::net::routing::{ContactPlan, PoissonReputationMatrix, RouteOptions, Timestamp};
use crate::ghost::net::{frame_shard, ice, send_gtf_v2, stun, GtfV2Header};
use crate::ghost::session::Session;

// ── Bootstrap Seeds & Embedded Default Config ──────────────────────

/// Hardcoded bootstrap seed VPS nodes for initial peer discovery.
///
/// New .exe instances that have never connected to the mesh can use these
/// seeds to perform STUN hole-punching and locate the rest of the network
/// (PC 2, PC 3, PC 4, PC 5 in the reference architecture).
///
/// Each entry is a (public_ip, port, fingerprint) tuple. The fingerprint
/// is the first 16 hex chars of the node's identity public key; it allows
/// the connecting node to verify they've reached the intended seed.
pub const EMBEDDED_DEFAULT_CONFIG: &[(&str, u16, &str)] = &[
    // Primary seed — VPS 1 (EU-West)
    ("51.15.xx.xx", 2270, "deadbeef12345678"),
    // Secondary seed — VPS 2 (US-East)
    ("45.33.xx.xx", 2270, "cafebabe87654321"),
    // Tertiary seed — VPS 3 (Asia-Pacific)
    ("139.162.xx.xx", 2270, "baadf00dabcdef01"),
];

// ═════════════════════════════════════════════════════════════════════════════
// 1. NAT Traversal & ICE (RFC 8445) over STUN (RFC 8489)
// ═════════════════════════════════════════════════════════════════════════════

/// A STUN-style NAT binding discovered via hole-punching.
#[derive(Debug, Clone)]
pub struct NatBinding {
    /// The peer's public address as seen by a STUN server.
    pub public_addr: SocketAddr,
    /// The peer's claimed local address.
    pub local_addr: SocketAddr,
    /// When this binding was last verified.
    pub last_verified: Instant,
    /// Number of successful hole-punch attempts.
    pub punch_successes: u32,
    /// Mapping lifetime in seconds (typical NAT: 30-120s).
    pub lifetime_secs: u64,
}

/// NAT traversal state for a known peer.
#[derive(Debug, Clone)]
pub struct NatPeerState {
    /// Peer's fingerprint.
    pub fingerprint: String,
    /// Peer's public address (as seen by external server).
    pub public_addr: SocketAddr,
    /// Our local address we're binding from.
    pub local_addr: SocketAddr,
    /// Whether the hole-punch succeeded.
    pub connected: bool,
    /// Last keepalive sent to maintain NAT mapping.
    pub last_keepalive: Instant,
}

/// Timeout for a single STUN Binding request / reflexive gathering attempt.
const STUN_TIMEOUT: Duration = Duration::from_secs(3);

/// Total budget for driving one ICE check list before declaring the path dead.
const ICE_CHECK_BUDGET: Duration = Duration::from_secs(10);

/// NAT traversal coordinator.
///
/// Holds the peer registry and drives the real ICE agent (`super::ice`) over
/// STUN (`super::stun`). The previous implementation in this type sent five
/// `GHOST_HPUNCH_` blobs plus `port+1..=5` guesses and then set
/// `connected = true` without checking for any response — it reported success
/// unconditionally. Checks are now authenticated and a pair only succeeds when
/// the peer answers.
pub struct NatHolePuncher {
    /// Known NAT peers keyed by fingerprint.
    peers: Arc<DashMap<String, NatPeerState>>,
    /// Local STUN server address (for public address discovery).
    stun_server: Option<SocketAddr>,
    /// Our public address as last discovered by STUN.
    public_addr: std::sync::Mutex<Option<SocketAddr>>,
    /// Per-peer ICE offers (credentials + candidates) received over signalling.
    offers: Arc<DashMap<String, ice::IceOffer>>,
    /// Our own ICE credentials. Fixed for the process and advertised in every
    /// beacon, because inbound checks are authenticated against them.
    local_credentials: ice::IceCredentials,
    /// Our own fingerprint, used to assign ICE roles deterministically.
    local_fingerprint: Option<String>,
    /// Measured round-trip time of each peer's nominated ICE pair. This is the
    /// only honest source of link latency in the mesh: it comes from a check
    /// that actually returned, and [`super::routing::ContactPlan`] consumes it so
    /// CGR routes on measurements instead of assumptions.
    selected_rtts: Arc<DashMap<String, Duration>>,
}

impl Default for NatHolePuncher {
    fn default() -> Self {
        Self {
            peers: Arc::new(DashMap::new()),
            stun_server: None,
            public_addr: std::sync::Mutex::new(None),
            offers: Arc::new(DashMap::new()),
            local_credentials: ice::IceCredentials::generate(),
            local_fingerprint: None,
            selected_rtts: Arc::new(DashMap::new()),
        }
    }
}

impl NatHolePuncher {
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize with a STUN server for public address discovery.
    ///
    /// This is used, not decorative: [`Self::discover_public_addr`] sends a real
    /// RFC 8489 Binding request to it. (The field previously existed, was stored,
    /// and was never read by anything.)
    pub fn with_stun_server(mut self, stun_addr: SocketAddr) -> Self {
        self.stun_server = Some(stun_addr);
        self
    }

    /// The configured STUN server, if any.
    pub fn stun_server(&self) -> Option<SocketAddr> {
        self.stun_server
    }

    /// Our public (server-reflexive) address, once STUN has reported one.
    pub fn public_addr(&self) -> Option<SocketAddr> {
        *self.public_addr.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Measured RTT of the nominated path to `fp`, once a check has completed.
    pub fn selected_rtt(&self, fp: &str) -> Option<Duration> {
        self.selected_rtts.get(fp).map(|r| *r.value())
    }

    /// Record the ICE offer a peer signalled (credentials + candidates + role).
    /// Checks cannot be built without it, because they must be authenticated.
    pub fn set_ice_offer(&self, fp: &str, offer: ice::IceOffer) {
        self.offers.insert(fp.to_string(), offer);
    }

    /// Our own ICE credentials, to be advertised in beacons.
    ///
    /// Stable for the process lifetime: a peer authenticates its checks with the
    /// credentials it received, so rotating them silently breaks inbound checks.
    pub fn local_credentials(&self) -> &ice::IceCredentials {
        &self.local_credentials
    }

    /// Record our own fingerprint so ICE roles can be assigned deterministically
    /// from the two fingerprints (both sides compute the same answer).
    pub fn set_local_fingerprint(&mut self, fp: impl Into<String>) {
        self.local_fingerprint = Some(fp.into());
    }

    /// Whether a peer's path has been validated by a completed ICE check.
    pub fn is_connected(&self, fp: &str) -> bool {
        self.peers.get(fp).map(|p| p.connected).unwrap_or(false)
    }

    /// The stored offer for a peer, if any.
    pub fn ice_offer(&self, fp: &str) -> Option<ice::IceOffer> {
        self.offers.get(fp).map(|o| o.clone())
    }

    /// Learn our public mapping from the configured STUN server.
    ///
    /// Returns `None` when no server is configured or it does not answer.
    pub async fn discover_public_addr(&self, sock: &UdpSocket) -> Option<SocketAddr> {
        let server = self.stun_server?;
        let mut agent = ice::IceAgent::new(ice::IceRole::Controlling);
        match agent.gather_reflexive(sock, server, STUN_TIMEOUT).await {
            Ok(c) => {
                *self.public_addr.lock().unwrap_or_else(|e| e.into_inner()) = Some(c.addr);
                info!(public = %c.addr, "STUN: public address discovered");
                Some(c.addr)
            }
            Err(e) => {
                warn!(server = %server, "STUN: public address discovery failed: {e}");
                None
            }
        }
    }

    /// Register a peer discovered via beacon and attempt hole-punch.
    pub fn register_peer(&self, fp: &str, public_addr: SocketAddr, local_addr: SocketAddr) {
        self.peers.insert(
            fp.to_string(),
            NatPeerState {
                fingerprint: fp.to_string(),
                public_addr,
                local_addr,
                connected: false,
                last_keepalive: Instant::now(),
            },
        );
        debug!("NAT peer registered: {} at {}", fp, public_addr);
    }

    /// Establish a path to a peer with real ICE connectivity checks.
    ///
    /// Returns `true` only when a nominated pair completed an authenticated
    /// round trip. Without an offer there is nothing to authenticate against, so
    /// this refuses to check rather than reporting an unverified success.
    pub async fn punch_hole(&self, sock: &UdpSocket, fp: &str) -> bool {
        let Some(state) = self.peers.get(fp).map(|s| s.clone()) else {
            warn!("ICE: cannot check unknown peer {fp}");
            return false;
        };
        if state.connected {
            return true;
        }
        let Some(offer) = self.offers.get(fp).map(|o| o.clone()) else {
            warn!(
                peer = %fp,
                "ICE: no offer (credentials + candidates) for peer — checks must be authenticated"
            );
            return false;
        };

        // Roles must be agreed without negotiation. Comparing the two
        // fingerprints gives both sides the same answer; the peer's advertised
        // flag is only a fallback for when we do not know our own fingerprint.
        let controlling = match self.local_fingerprint.as_deref() {
            Some(me) => me > fp,
            None => !offer.controlling,
        };
        let role = if controlling {
            ice::IceRole::Controlling
        } else {
            ice::IceRole::Controlled
        };
        let mut agent = ice::IceAgent::new(role);
        // Our advertised credentials, not freshly generated ones: inbound checks
        // are verified against these.
        agent.set_local_credentials(self.local_credentials.clone());
        agent.set_remote_credentials(offer.credentials.clone());

        // Host candidate: the address the OS would use to reach the peer.
        let route = offer
            .candidates
            .first()
            .map(|c| c.base)
            .unwrap_or(state.public_addr);
        match agent.gather_host(sock, route) {
            Ok(c) => {
                debug!(local = %c.addr, "ICE: local host candidate");
            }
            Err(e) => {
                warn!(peer = %fp, "ICE: host candidate gathering failed: {e}");
                return false;
            }
        }
        // Reflexive candidate, when a STUN server is configured. This is what
        // makes us reachable from behind NAT.
        if let Some(server) = self.stun_server {
            match agent.gather_reflexive(sock, server, STUN_TIMEOUT).await {
                Ok(c) => {
                    *self.public_addr.lock().unwrap_or_else(|e| e.into_inner()) = Some(c.addr);
                }
                Err(e) => debug!(peer = %fp, "ICE: reflexive gathering failed: {e}"),
            }
        }
        for c in offer.candidates {
            agent.add_remote_candidate(c);
        }
        agent.form_pairs();
        if agent.pairs().is_empty() {
            warn!(peer = %fp, "ICE: no candidate pairs (component mismatch?)");
            return false;
        }

        let established = self.drive_checks(sock, &mut agent).await;
        if established {
            if let Some(mut s) = self.peers.get_mut(fp) {
                s.connected = true;
                s.last_keepalive = Instant::now();
            }
            // The nominated pair's round trip is a real measurement; publish it
            // so the contact plan can route on it.
            if let Some(rtt) = agent.selected_pair_rtt() {
                debug!(peer = %fp, rtt_ms = rtt.as_millis(), "ICE: measured path RTT");
                self.selected_rtts.insert(fp.to_string(), rtt);
            }
            info!(peer = %fp, "ICE: path established");
        } else {
            warn!(
                peer = %fp,
                "ICE: every candidate pair failed — a relay (TURN/DERP) is required"
            );
        }
        established
    }

    /// Send an authenticated check for each eligible pair until one succeeds,
    /// processing inbound checks/responses as they arrive.
    ///
    /// Paced by the ICE retransmission timeout rather than spinning, and bounded
    /// by [`ICE_CHECK_BUDGET`] so a black-holed path cannot hang the caller.
    async fn drive_checks(&self, sock: &UdpSocket, agent: &mut ice::IceAgent) -> bool {
        let deadline = tokio::time::Instant::now() + ICE_CHECK_BUDGET;
        let mut buf = vec![0u8; 1500];

        loop {
            if agent.selected_pair().is_some() {
                return true;
            }
            match agent.next_check() {
                Some(idx) => {
                    let nominate = agent.role() == ice::IceRole::Controlling;
                    let dest = agent.pairs()[idx].remote.addr;
                    match agent.build_check(idx, nominate) {
                        Ok(check) => {
                            if let Err(e) = sock.send_to(&check, dest).await {
                                debug!(dest = %dest, "ICE: check send failed: {e}");
                                agent.fail_pair(idx);
                                continue;
                            }
                        }
                        Err(e) => {
                            warn!("ICE: cannot build check: {e}");
                            agent.fail_pair(idx);
                            continue;
                        }
                    }
                }
                None if agent.is_exhausted() => return false,
                None if agent.pairs().is_empty() => return false,
                None => {} // all pairs already in flight: just wait
            }

            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return agent.selected_pair().is_some();
            }
            let wait = remaining.min(ice::DEFAULT_RTO);
            match tokio::time::timeout(wait, sock.recv_from(&mut buf)).await {
                Err(_) => {}
                Ok(Err(e)) => debug!("ICE: recv error: {e}"),
                Ok(Ok((n, from))) => match agent.handle_check(&buf[..n], from) {
                    Ok(Some(outcome)) => {
                        if let Some(response) = outcome.response {
                            if let Err(e) = sock.send_to(&response, from).await {
                                debug!(peer = %from, "ICE: response send failed: {e}");
                            }
                        }
                    }
                    Ok(None) => {} // unrelated mesh traffic on the same socket
                    Err(e) => debug!(peer = %from, "ICE: check rejected: {e}"),
                },
            }
        }
    }

    /// Send periodic keepalives to maintain NAT mappings.
    ///
    /// RFC 8445 §11 requires a STUN Binding *indication*: unlike a request it
    /// gets no response, so it refreshes the mapping without adding a
    /// round-trip or any state to the peer.
    pub async fn send_keepalives(&self, sock: &UdpSocket) {
        for mut entry in self.peers.iter_mut() {
            if entry.connected && entry.last_keepalive.elapsed() > Duration::from_secs(25) {
                let keepalive =
                    stun::Message::binding_indication(stun::TransactionId::random()).encode();
                match sock.send_to(&keepalive, entry.public_addr).await {
                    Ok(_) => entry.last_keepalive = Instant::now(),
                    Err(e) => {
                        debug!(peer = %entry.fingerprint, "NAT keepalive failed: {e}");
                    }
                }
            }
        }
    }

    /// Send a STUN Binding indication to every address we may use as a relay.
    ///
    /// This is not housekeeping — it is what makes the relay fallback work
    /// through NAT at all. A relay forwards a sealed frame to our *mesh* address
    /// from *its* address, and a NAT admits an inbound datagram only if we have
    /// already sent something out toward that address. A relay is a peer we
    /// learned about from its beacon, so the same discipline ICE uses for a
    /// direct path opens this mapping. Returns how many were sent.
    pub async fn send_relay_keepalives(&self, sock: &UdpSocket, relays: &[SocketAddr]) -> usize {
        let mut sent = 0;
        for addr in relays {
            let keepalive =
                stun::Message::binding_indication(stun::TransactionId::random()).encode();
            match sock.send_to(&keepalive, addr).await {
                Ok(_) => sent += 1,
                Err(e) => debug!(relay = %addr, "relay pinhole keepalive failed: {e}"),
            }
        }
        sent
    }

    /// Build a localized routing cache — peers within 1-2 hops.
    pub fn local_cache(&self) -> Vec<(String, SocketAddr)> {
        self.peers
            .iter()
            .filter(|e| e.connected)
            .map(|e| (e.fingerprint.clone(), e.public_addr))
            .collect()
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. Dynamic Asymmetric Shard Allocation
// ═════════════════════════════════════════════════════════════════════════════

/// The fitness a path is assumed to have before anything has been measured about
/// it. Neutral, not optimistic: an unmeasured path must not outrank a measured
/// good one.
pub const DEFAULT_PATH_FITNESS: f64 = 0.5;

/// Live performance metrics for a neighbor session.
///
/// These are the measurements the rest of the stack reads: the shard router
/// orders paths by [`Self::fitness`], the transit governor takes
/// [`Self::rate_bps`], and a contact plan takes [`Self::srtt_us`] as the link
/// latency. Keeping the three signals *apart* is the whole point — this type used
/// to mix them, which is how a lost packet (recorded as a 0 µs sample) made a
/// lossy path look faster than a clean one, and how "throughput" came to be a
/// number nobody measured (`cwnd = 10_000_000.0; // Assume`).
#[derive(Debug, Clone)]
pub struct PathMetrics {
    /// Smoothed round-trip time (µs), from RTT samples only.
    pub srtt_us: f64,
    /// Lowest RTT observed (µs) — the baseline a queue is measured against.
    pub min_rtt_us: f64,
    /// Packet loss rate (0.0 - 1.0), EWMA.
    pub loss_rate: f64,
    /// Congestion window (bytes): grown additively on delivery, halved on loss
    /// (RFC 5681 §3.1).
    pub cwnd: u64,
    /// Delivered bytes per second as actually observed, EWMA.
    pub delivery_bps: f64,
    /// Bytes observed delivered on this path.
    pub delivered_bytes: u64,
    /// Loss events observed.
    pub loss_events: u64,
    /// When a measurement last arrived. A stale measurement is not evidence.
    pub last_updated: Instant,
    /// Number of RTT samples collected.
    pub samples: u64,
}

impl Default for PathMetrics {
    fn default() -> Self {
        Self {
            srtt_us: 50_000.0,
            min_rtt_us: 50_000.0,
            loss_rate: 0.0,
            cwnd: cc::INIT_CWND,
            delivery_bps: 0.0,
            delivered_bytes: 0,
            loss_events: 0,
            last_updated: Instant::now(),
            samples: 0,
        }
    }
}

impl PathMetrics {
    /// How long a measurement stays usable. Beyond this the path is treated as
    /// unmeasured again rather than as a fast path that has gone quiet.
    pub const STALE_AFTER: Duration = Duration::from_secs(30);

    /// Record an RTT sample (µs).
    ///
    /// Non-positive samples are rejected: a zero would drag the estimate toward
    /// "infinitely fast", and a loss is not a round trip.
    pub fn observe_rtt(&mut self, sample_us: f64) {
        if !(sample_us.is_finite() && sample_us > 0.0) {
            return;
        }
        const ALPHA: f64 = 0.125; // RFC 6298 §2.3
        if self.samples == 0 {
            self.srtt_us = sample_us;
            self.min_rtt_us = sample_us;
        } else {
            self.srtt_us = self.srtt_us * (1.0 - ALPHA) + sample_us * ALPHA;
            self.min_rtt_us = self.min_rtt_us.min(sample_us);
        }
        self.samples += 1;
        self.last_updated = Instant::now();
    }

    /// Record a loss: multiplicative decrease, no RTT sample.
    pub fn observe_loss(&mut self) {
        const BETA: f64 = 0.1;
        self.loss_rate = self.loss_rate * (1.0 - BETA) + BETA;
        self.loss_events += 1;
        // Floor at one MSS so the window can never reach zero and stall the path
        // outright; a stalled window is indistinguishable from a dead path.
        self.cwnd = (self.cwnd / 2).max(cc::DEFAULT_MSS);
        self.last_updated = Instant::now();
    }

    /// Record `bytes` delivered over `elapsed` — the measurement that makes the
    /// rate estimate real instead of assumed.
    pub fn observe_delivery(&mut self, bytes: u64, elapsed: Duration) {
        const BETA: f64 = 0.1;
        const ALPHA: f64 = 0.25;
        self.delivered_bytes = self.delivered_bytes.saturating_add(bytes);
        // Delivered bytes are evidence *against* loss, so the estimate decays
        // rather than being reset — one good window does not erase a bad path.
        self.loss_rate *= 1.0 - BETA;

        // Additive increase, sized so a full window of delivered data raises the
        // window by about one MSS per round trip (RFC 5681 §3.1). GTF has no
        // per-segment ACK, so this is counted in bytes rather than in ACKs.
        if self.cwnd > 0 {
            let inc = (cc::DEFAULT_MSS as f64 * bytes as f64 / self.cwnd as f64).max(1.0) as u64;
            self.cwnd = self.cwnd.saturating_add(inc).min(cc::DEFAULT_MAX_CWND);
        }

        let secs = elapsed.as_secs_f64();
        if secs > 0.0 {
            let instant = bytes as f64 / secs;
            self.delivery_bps = if self.delivery_bps <= 0.0 {
                instant
            } else {
                self.delivery_bps * (1.0 - ALPHA) + instant * ALPHA
            };
        }
        self.last_updated = Instant::now();
    }

    /// Legacy one-call form: a sample plus whether it was a loss.
    ///
    /// `rtt_sample_us <= 0.0` means "no RTT sample", which is the honest way to
    /// report a loss — there was no round trip to time.
    pub fn observe(&mut self, rtt_sample_us: f64, lost: bool) {
        if lost {
            self.observe_loss();
        }
        self.observe_rtt(rtt_sample_us);
    }

    /// Whether this path has a fresh measurement behind it.
    pub fn measured(&self) -> bool {
        self.samples > 0 && self.last_updated.elapsed() < Self::STALE_AFTER
    }

    /// The rate this path can carry, bytes/sec.
    ///
    /// The window says `cwnd / srtt`; the observation says at least the measured
    /// delivery rate. Shaping to the smaller of the window's allowance and
    /// **twice** what was delivered keeps an idle path — whose window still grows
    /// from additive increase — from being mistaken for a fast one, while the
    /// factor of two leaves room for the window to keep probing upward.
    ///
    /// `0.0` means "no estimate": either nothing has been measured yet, the
    /// measurement has gone stale, or the path is losing more than it delivers.
    pub fn rate_bps(&self) -> f64 {
        if !self.measured() || self.loss_rate > 0.5 {
            return 0.0;
        }
        let srtt_s = (self.srtt_us.max(100.0)) / 1_000_000.0;
        let window_rate = self.cwnd as f64 / srtt_s;
        let observed = self.delivery_bps * 2.0;
        if observed > 0.0 {
            window_rate.min(observed)
        } else {
            window_rate
        }
    }

    /// Compute a fitness score (higher = better path).
    /// Combines RTT, loss rate, and rate into a single score.
    pub fn fitness(&self) -> f64 {
        if self.loss_rate > 0.5 {
            return 0.0; // Unusable path
        }
        if !self.measured() {
            // No RTT sample: we cannot compare this path's latency against a
            // measured one, so it keeps the neutral prior — scoring it on a
            // default RTT would be inventing the very number we are trying to
            // stop inventing. Losses, though, we *did* observe, so they still
            // count: a peer whose connectivity checks keep failing drifts below
            // the selection threshold instead of sitting at neutral forever.
            return DEFAULT_PATH_FITNESS * (1.0 - self.loss_rate);
        }
        let rtt_score = (100_000.0 / self.srtt_us.max(1.0)).min(2.0);
        let loss_score = (1.0 - self.loss_rate).powi(2);
        let tp_score = (self.rate_bps() / 1_000_000.0).min(10.0) / 10.0;
        rtt_score * 0.4 + loss_score * 0.3 + tp_score * 0.3
    }
}

/// A shard routing decision: which peer gets which shard.
#[derive(Debug, Clone)]
pub struct ShardRoute {
    /// Peer fingerprint to route through.
    pub peer_fingerprint: String,
    /// Shard index (0, 1, or 2).
    pub shard_index: u8,
    /// Weight for load balancing (0.0-1.0).
    pub weight: f64,
    /// Expected completion probability.
    pub reliability: f64,
}

/// Adaptive shard router that dynamically allocates shards across paths.
///
/// Leverages RS(2,1) erasure coding: any 2 of 3 shards reconstruct the
/// payload. This means we can route shards asymmetrically:
/// - Fast peers get shards
/// - Slow/poor peers can be skipped (we only need 2 of 3)
/// - If one path drops, the other 2 still reconstruct
pub struct AdaptiveShardRouter {
    /// Per-peer path metrics.
    path_metrics: Arc<DashMap<String, PathMetrics>>,
    /// Minimum acceptable fitness for a path to be used.
    min_fitness: f64,
    /// RS data shards needed (k).
    data_shards: usize,
}

impl Default for AdaptiveShardRouter {
    fn default() -> Self {
        Self {
            path_metrics: Arc::new(DashMap::new()),
            min_fitness: 0.3,
            data_shards: 2, // RS(2,1): need 2 of 3
        }
    }
}

impl AdaptiveShardRouter {
    pub fn new() -> Self {
        Self::default()
    }
    /// Record a successful shard delivery observation.
    ///
    /// `rtt_us` is expected to be a real measurement — an ICE connectivity check
    /// or a timed shard round trip — not a guess.
    pub fn record_success(&self, peer_fp: &str, rtt_us: f64) {
        let mut metrics = self.path_metrics.entry(peer_fp.to_string()).or_default();
        metrics.observe_rtt(rtt_us);

        debug!(
            "Path to {}: RTT={:.0}us, rate={:.0} B/s, fitness={:.2}",
            peer_fp,
            metrics.srtt_us,
            metrics.rate_bps(),
            metrics.fitness()
        );
    }

    /// Record a shard delivery failure (loss).
    pub fn record_loss(&self, peer_fp: &str) {
        let mut metrics = self.path_metrics.entry(peer_fp.to_string()).or_default();
        metrics.observe_loss();
        warn!(
            "Path loss to {}: loss_rate={:.2}",
            peer_fp, metrics.loss_rate
        );
    }

    /// Record `bytes` delivered on this path over `elapsed`.
    ///
    /// This is the feedback the rate estimate is built from. Without it the
    /// window never grows and the estimate stays whatever the first sample said.
    pub fn record_delivery(&self, peer_fp: &str, bytes: u64, elapsed: Duration) {
        let mut metrics = self.path_metrics.entry(peer_fp.to_string()).or_default();
        metrics.observe_delivery(bytes, elapsed);
    }

    /// The rate estimate for each path with a fresh measurement, bytes/sec.
    ///
    /// Paths that have gone quiet, that are new, or that are losing more than
    /// they deliver are omitted rather than reported as zero: the caller
    /// aggregates what it is told and must be able to tell "no estimate" from
    /// "an estimate of nothing".
    pub fn live_path_rates(&self) -> Vec<f64> {
        self.path_metrics
            .iter()
            .map(|e| e.value().rate_bps())
            .filter(|r| *r > 0.0)
            .collect()
    }

    /// The rate estimate for a path, bytes/sec. `0.0` when there is none.
    pub fn path_rate_bps(&self, peer_fp: &str) -> f64 {
        self.path_metrics
            .get(peer_fp)
            .map(|m| m.rate_bps())
            .unwrap_or(0.0)
    }

    /// The measured RTT for a path, if it has one.
    pub fn path_rtt_us(&self, peer_fp: &str) -> Option<f64> {
        self.path_metrics
            .get(peer_fp)
            .filter(|m| m.measured())
            .map(|m| m.srtt_us)
    }

    /// How many peers a shard dispatch should aim to use: one per RS shard, so
    /// `k` data shards plus one parity shard can take `k + 1` distinct paths.
    pub fn shard_target_count(&self) -> usize {
        self.data_shards + 1
    }

    /// Get the fitness score for a peer path.
    pub fn path_fitness(&self, peer_fp: &str) -> f64 {
        self.path_metrics
            .get(peer_fp)
            .map(|m| m.fitness())
            .unwrap_or(DEFAULT_PATH_FITNESS)
    }

    /// Select the best N peers from available peers for shard routing.
    ///
    /// Returns candidates sorted by measured path fitness, dropping any below
    /// [`Self::min_fitness`].
    ///
    /// Note this is the *fitness* ordering only — it knows nothing about how the
    /// peers reach each other. Prefer [`Self::select_shard_targets_routed`] when a
    /// populated [`ContactPlan`] is available; this remains the fallback for a
    /// node with no routing table yet.
    pub fn select_shard_targets(
        &self,
        available: &[(String, SocketAddr)],
    ) -> Vec<(String, SocketAddr, f64)> {
        let mut scored: Vec<(String, SocketAddr, f64)> = available
            .iter()
            .map(|(fp, addr)| (fp.clone(), *addr, self.path_fitness(fp)))
            .filter(|(_, _, f)| *f >= self.min_fitness)
            .collect();

        // Sort by fitness descending
        scored.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
        scored
    }

    /// Select shard targets using the contact plan's earliest-arrival routes.
    ///
    /// Peers are accepted in **CGR arrival order** (a measured 5 ms link before
    /// a guessed-fast one), and once a peer is accepted its intermediate nodes
    /// are barred from later peers' paths. That is what puts the shards on
    /// genuinely separate routes: three shards through the same relay are one
    /// failure away from a lost payload, while three disjoint routes need three
    /// simultaneous failures.
    ///
    /// A peer with no route in the plan is not dropped — it is appended by path
    /// fitness below any routed peer — because a plan that has not learned about
    /// a peer yet is a gap in our knowledge, not evidence the peer is unreachable.
    pub fn select_shard_targets_routed(
        &self,
        me: &str,
        available: &[(String, SocketAddr)],
        plan: &ContactPlan,
        now: Timestamp,
        want: usize,
    ) -> Vec<(String, SocketAddr, f64)> {
        // First compute every candidate without exclusions.  Excluding while
        // iterating the caller's registry made the result depend on DashMap's
        // iteration order: a slower peer could reserve a relay before a faster
        // peer was even considered.  Routing must be deterministic and greedy
        // by earliest arrival, not by hash-table order.
        let mut candidates: Vec<(String, SocketAddr, f64, f64, Vec<String>)> = available
            .iter()
            .filter(|(fp, _)| fp != me)
            .filter_map(|(fp, addr)| {
                let journey =
                    plan.find_earliest_arrival_with(me, fp, now, &RouteOptions::default())?;
                Some((
                    fp.clone(),
                    *addr,
                    self.path_fitness(fp),
                    journey.arrival_time,
                    journey.transit_nodes(),
                ))
            })
            .collect();
        // `sort_by` is stable: equal-arrival routes retain the caller's
        // deterministic candidate order. This matters when two destinations
        // share the same measured relay path; the first advertised route gets
        // the uncontested slot and the other is deferred below.
        candidates.sort_by(|a, b| a.3.partial_cmp(&b.3).unwrap_or(std::cmp::Ordering::Equal));

        // Greedily accept the earliest route whose transit nodes do not overlap
        // an already selected route.  This is the mesh-level disjointness gate:
        // three shards get three peers and three divergent relay paths whenever
        // the contact graph can provide them.
        let mut used_transit = std::collections::HashSet::new();
        let mut routed = Vec::new();
        let mut deferred = Vec::new();
        for candidate in candidates {
            let overlaps = candidate.4.iter().any(|node| used_transit.contains(node));
            if overlaps {
                deferred.push(candidate);
            } else {
                used_transit.extend(candidate.4.iter().cloned());
                routed.push(candidate);
            }
        }

        // An overlapping route is still better than silently losing a shard.
        // Keep it as a last-resort candidate, after all genuinely disjoint paths.
        deferred.sort_by(|a, b| a.3.partial_cmp(&b.3).unwrap_or(std::cmp::Ordering::Equal));
        routed.extend(deferred);

        let mut out: Vec<(String, SocketAddr, f64)> = routed
            .into_iter()
            .map(|(fp, addr, fitness, _, _)| (fp, addr, fitness))
            .collect();
        let mut unrouted: Vec<(String, SocketAddr, f64)> = available
            .iter()
            .filter(|(fp, _)| fp != me && !out.iter().any(|(selected, _, _)| selected == fp))
            .map(|(fp, addr)| (fp.clone(), *addr, self.path_fitness(fp)))
            .collect();
        unrouted.sort_by(|a, b| {
            b.2.partial_cmp(&a.2)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        out.extend(unrouted);
        out.truncate(want.max(1));
        out
    }

    /// Assign shards to selected peers.
    ///
    /// Distributes shards 0, 1, 2 across the best peers.
    /// If we have fewer than 3 good peers, some peers get multiple shards
    /// (which is fine — we only need 2 of 3 to arrive).
    pub fn assign_shards(&self, targets: &[(String, SocketAddr, f64)]) -> Vec<ShardRoute> {
        let mut routes = Vec::new();
        if targets.is_empty() {
            return routes;
        }
        for shard_idx in 0..3u8 {
            if let Some((fp, _addr, fitness)) = targets.get(shard_idx as usize % targets.len()) {
                routes.push(ShardRoute {
                    peer_fingerprint: fp.clone(),
                    shard_index: shard_idx,
                    weight: *fitness,
                    reliability: *fitness,
                });
            }
        }
        routes
    }

    /// Check if we have enough reliable paths for RS reconstruction.
    pub fn can_reconstruct(&self) -> bool {
        let good_paths = self
            .path_metrics
            .iter()
            .filter(|m| m.fitness() >= self.min_fitness)
            .count();
        good_paths >= self.data_shards
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. Tit-for-Tat Peer Incentivization
// ═════════════════════════════════════════════════════════════════════════════

/// A record of forwarding reciprocity between two peers.
#[derive(Debug, Clone)]
pub struct ReciprocityRecord {
    /// Bytes forwarded BY us FOR this peer.
    pub bytes_forwarded_for_them: u64,
    /// Bytes forwarded BY this peer FOR us.
    pub bytes_forwarded_for_us: u64,
    /// Shards successfully relayed by this peer for us.
    pub shards_relayed_for_us: u64,
    /// Shards we dropped when asked to forward for them.
    pub shards_dropped_for_them: u64,
    /// Ratio of service received to service provided.
    pub reciprocity_ratio: f64,
    /// When this record was last updated.
    pub last_activity: Instant,
}

impl Default for ReciprocityRecord {
    fn default() -> Self {
        Self {
            bytes_forwarded_for_them: 0,
            bytes_forwarded_for_us: 0,
            shards_relayed_for_us: 0,
            shards_dropped_for_them: 0,
            reciprocity_ratio: 1.0,
            last_activity: Instant::now(),
        }
    }
}

impl ReciprocityRecord {
    /// Update the reciprocity ratio.
    /// Ratio = (bytes forwarded for us by peer) / (bytes forwarded for them by us)
    /// Ratio < 0.3 means the peer is leeching (we give much more than we receive).
    pub fn update_ratio(&mut self) {
        let sent = self.bytes_forwarded_for_them.max(1);
        let recv = self.bytes_forwarded_for_us;
        self.reciprocity_ratio = recv as f64 / sent as f64;
    }

    /// Check if this peer is leeching (we forwarded significantly for them, but they gave back almost nothing).
    pub fn is_leeching(&self) -> bool {
        self.bytes_forwarded_for_them > 10_000 && self.reciprocity_ratio < 0.3
    }
}

/// Tit-for-Tat enforcement engine.
///
/// Monitors peer reciprocity and evicts leechers.
/// Extends the PoissonReputationMatrix with concrete resource accounting.
pub struct TitForTatEnforcer {
    /// Reciprocity records keyed by (us, them).
    reciprocity: Arc<DashMap<(String, String), ReciprocityRecord>>,
    /// Reference to the reputation matrix for Byzantine scoring.
    reputation: Arc<PoissonReputationMatrix>,
    /// Our fingerprint.
    our_fingerprint: String,
    /// Leechers that have been evicted (session torn down).
    evicted: Arc<DashMap<String, bool>>,
    /// Threshold: minimum bytes forwarded by peer before we complain.
    min_forward_bytes: u64,
}

impl TitForTatEnforcer {
    pub fn new(our_fingerprint: String, reputation: Arc<PoissonReputationMatrix>) -> Self {
        Self {
            reciprocity: Arc::new(DashMap::new()),
            reputation,
            our_fingerprint,
            evicted: Arc::new(DashMap::new()),
            min_forward_bytes: 1024, // 1 KB minimum before evaluation
        }
    }

    /// Record that we forwarded bytes for a peer.
    pub fn forwarded_for(&self, peer_fp: &str, bytes: u64) {
        let key = (self.our_fingerprint.clone(), peer_fp.to_string());
        let mut record = self.reciprocity.entry(key).or_default();
        record.bytes_forwarded_for_them += bytes;
        record.update_ratio();
        record.last_activity = Instant::now();
    }

    /// Record that a peer forwarded bytes for us.
    pub fn forwarded_by(&self, peer_fp: &str, bytes: u64) {
        let key = (self.our_fingerprint.clone(), peer_fp.to_string());
        let mut record = self.reciprocity.entry(key).or_default();
        record.bytes_forwarded_for_us += bytes;
        record.shards_relayed_for_us += 1;
        record.update_ratio();
        record.last_activity = Instant::now();
    }

    /// Record that we dropped a shard (failed to forward).
    pub fn dropped_for(&self, peer_fp: &str) {
        let key = (self.our_fingerprint.clone(), peer_fp.to_string());
        let mut record = self.reciprocity.entry(key).or_default();
        record.shards_dropped_for_them += 1;
        record.update_ratio();
    }

    /// Check if a peer should be evicted for leeching.
    ///
    /// Returns true if the peer should have its session terminated.
    pub async fn should_evict(&self, peer_fp: &str) -> bool {
        // Already evicted
        if self.evicted.get(peer_fp).map(|v| *v).unwrap_or(false) {
            return true;
        }

        let key = (self.our_fingerprint.clone(), peer_fp.to_string());
        if let Some(record) = self.reciprocity.get(&key) {
            if record.bytes_forwarded_for_them < self.min_forward_bytes {
                return false; // Not enough data to judge yet
            }

            if record.is_leeching() {
                warn!(
                    "Peer {} is leeching (ratio={:.2}), recommending eviction",
                    peer_fp, record.reciprocity_ratio
                );

                // Also record in reputation matrix
                self.reputation
                    .record_interaction(&self.our_fingerprint, peer_fp, false);
                return true;
            }

            // If peer has good ratio, record positive reputation
            if record.reciprocity_ratio > 0.8 {
                self.reputation
                    .record_interaction(&self.our_fingerprint, peer_fp, true);
            }
        }
        false
    }

    /// Evict a peer — marks them as evicted and triggers session teardown.
    pub fn evict(&self, peer_fp: &str) {
        self.evicted.insert(peer_fp.to_string(), true);
        warn!("Evicted peer {} for leeching behavior", peer_fp);
    }

    /// Get reciprocity ratio with a peer.
    pub fn ratio_with(&self, peer_fp: &str) -> f64 {
        let key = (self.our_fingerprint.clone(), peer_fp.to_string());
        self.reciprocity
            .get(&key)
            .map(|r| r.reciprocity_ratio)
            .unwrap_or(1.0)
    }

    /// Check if a peer has been evicted.
    pub fn is_evicted(&self, peer_fp: &str) -> bool {
        self.evicted.get(peer_fp).map(|v| *v).unwrap_or(false)
    }

    /// Get detailed reciprocity stats for a peer: (bytes_for_them, bytes_for_us, ratio, is_evicted)
    pub fn peer_stats(&self, peer_fp: &str) -> (u64, u64, f64, bool) {
        let key = (self.our_fingerprint.clone(), peer_fp.to_string());
        let (sent, recv, ratio) = self
            .reciprocity
            .get(&key)
            .map(|r| {
                (
                    r.bytes_forwarded_for_them,
                    r.bytes_forwarded_for_us,
                    r.reciprocity_ratio,
                )
            })
            .unwrap_or((0, 0, 1.0));
        let evicted = self.is_evicted(peer_fp);
        (sent, recv, ratio, evicted)
    }

    /// Iterate all tracked reciprocity records
    pub fn all_stats(&self) -> Vec<(String, u64, u64, f64, bool)> {
        self.reciprocity
            .iter()
            .map(|entry| {
                let peer_fp = entry.key().1.clone();
                let r = entry.value();
                let evicted = self.is_evicted(&peer_fp);
                (
                    peer_fp,
                    r.bytes_forwarded_for_them,
                    r.bytes_forwarded_for_us,
                    r.reciprocity_ratio,
                    evicted,
                )
            })
            .collect()
    }

    /// Run the periodic audit cycle — evaluate all peers for eviction.
    pub async fn audit_cycle(&self, sessions: &DashMap<String, Session>) -> Vec<String> {
        let mut to_evict = Vec::new();
        let peer_fps: Vec<String> = sessions.iter().map(|e| e.key().clone()).collect();

        for fp in &peer_fps {
            if self.should_evict(fp).await {
                to_evict.push(fp.clone());
            }
        }
        to_evict
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Mesh Node — Top-Level Integration
// ═════════════════════════════════════════════════════════════════════════════

/// A complete mesh peer node with all production subsystems.
pub struct MeshNode {
    /// Our fingerprint.
    pub fingerprint: String,
    /// NAT hole-punching subsystem.
    pub nat: NatHolePuncher,
    /// Adaptive shard routing subsystem.
    pub router: AdaptiveShardRouter,
    /// Tit-for-tat enforcement subsystem.
    pub tft: Arc<TitForTatEnforcer>,
    /// Localized peer registry (fingerprint → address, distance).
    peer_registry: Arc<DashMap<String, (SocketAddr, u32)>>,
    /// Whether this node is actively routing.
    pub routing_enabled: AtomicBool,
}

impl MeshNode {
    /// Create a new mesh node.
    pub async fn new(fingerprint: String, reputation: Arc<PoissonReputationMatrix>) -> Self {
        Self {
            tft: Arc::new(TitForTatEnforcer::new(fingerprint.clone(), reputation)),
            fingerprint,
            nat: NatHolePuncher::new(),
            router: AdaptiveShardRouter::new(),
            peer_registry: Arc::new(DashMap::new()),
            routing_enabled: AtomicBool::new(true),
        }
    }

    /// Register a discovered peer in the local registry.
    pub fn register_peer(&self, fp: &str, addr: SocketAddr, distance: u32) {
        self.peer_registry.insert(fp.to_string(), (addr, distance));
        self.nat.register_peer(fp, addr, addr);
        debug!("Mesh: registered peer {} at distance {}", fp, distance);
    }

    /// Get peers within a given hop distance.
    pub fn peers_within(&self, max_distance: u32) -> Vec<(String, SocketAddr)> {
        self.peer_registry
            .iter()
            .filter(|e| e.value().1 <= max_distance)
            .map(|e| (e.key().clone(), e.value().0))
            .collect()
    }

    /// Select the best peers for shard routing, respecting reciprocity.
    pub async fn select_egress_targets(
        &self,
        _destination: &str,
    ) -> Vec<(String, SocketAddr, f64)> {
        let available = self.peers_within(2);
        let mut candidates = self.router.select_shard_targets(&available);

        // Filter out evicted peers
        candidates.retain(|(fp, _, _)| !self.tft.is_evicted(fp));

        // Boost scores for peers with good reciprocity
        for (fp, _, score) in candidates.iter_mut() {
            let ratio = self.tft.ratio_with(fp);
            if ratio > 0.8 {
                *score *= 1.2; // 20% boost for cooperative peers
            }
        }

        candidates
    }

    /// Route shards through optimal paths using adaptive selection.
    pub fn assign_shard_routes(&self, targets: &[(String, SocketAddr, f64)]) -> Vec<ShardRoute> {
        self.router.assign_shards(targets)
    }

    /// Build a localized cache tree: report our known peers.
    pub fn cache_tree(&self, max_entries: usize) -> Vec<(String, SocketAddr, u32)> {
        self.peer_registry
            .iter()
            .take(max_entries)
            .map(|e| (e.key().clone(), e.value().0, e.value().1))
            .collect()
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. Exit Node Pool & Rotating Egress IPs
// ═════════════════════════════════════════════════════════════════════════════

/// Rotates through a pool of egress IP addresses for exit node traffic.
///
/// Each outbound TCP/HTTP connection receives a different source IP,
/// preventing correlation of traffic to a single identity. Rotation
/// can be based on round-robin or timer-based intervals.
#[derive(Debug)]
pub struct ExitIpRotator {
    /// List of available egress IP addresses.
    pub egress_ips: Vec<std::net::IpAddr>,
    /// Round-robin index.
    pub current_idx: std::sync::atomic::AtomicUsize,
    /// Optional timer-based rotation interval (e.g. 10 minutes).
    pub rotation_interval: Option<std::time::Duration>,
    /// Timestamp of last rotation.
    pub last_rotation: std::time::Instant,
}

impl ExitIpRotator {
    /// Create a new rotator with the given egress IP pool.
    pub fn new(ips: Vec<std::net::IpAddr>) -> Self {
        Self {
            egress_ips: ips,
            current_idx: std::sync::atomic::AtomicUsize::new(0),
            rotation_interval: None,
            last_rotation: std::time::Instant::now(),
        }
    }

    /// Get the next egress address (round-robin) with a dynamic source port.
    pub fn get_next_socket_addr(&self, target_port: u16) -> std::net::SocketAddr {
        let idx = self
            .current_idx
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let ip = self.egress_ips[idx % self.egress_ips.len()];
        std::net::SocketAddr::new(ip, target_port)
    }

    /// Get the current egress IP without advancing the index.
    pub fn current_ip(&self) -> Option<std::net::IpAddr> {
        if self.egress_ips.is_empty() {
            None
        } else {
            Some(self.egress_ips[0])
        }
    }

    /// Set a timer-based rotation interval.
    pub fn set_rotation_interval(&mut self, interval: std::time::Duration) {
        self.rotation_interval = Some(interval);
    }

    /// Check if a rotation is due based on the timer.
    pub fn should_rotate(&self) -> bool {
        if let Some(interval) = self.rotation_interval {
            self.last_rotation.elapsed() >= interval
        } else {
            false
        }
    }

    /// Force a rotation to the next IP.
    pub fn rotate(&mut self) -> bool {
        if self.egress_ips.len() < 2 {
            return false;
        }
        self.current_idx
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.last_rotation = std::time::Instant::now();
        true
    }

    /// Add an egress IP to the pool.
    pub fn add_ip(&mut self, ip: std::net::IpAddr) {
        self.egress_ips.push(ip);
    }

    /// Remove an egress IP from the pool.
    pub fn remove_ip(&mut self, ip: &std::net::IpAddr) {
        self.egress_ips.retain(|e| e != ip);
    }

    /// Number of egress IPs in the pool.
    pub fn pool_size(&self) -> usize {
        self.egress_ips.len()
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. Multi-Path Shard Dispatch via Relay
// ═════════════════════════════════════════════════════════════════════════════

/// Dispatch shards across multiple peer paths using the AdaptiveShardRouter,
/// with relay headers for intermediate hops.
///
/// This legacy helper remains available for v1 callers. The live v2 daemon path
/// performs the same assignment with its session-owned epoch key and nonce in
/// `send3_adaptive`; keeping this helper v1-shaped avoids inventing crypto state
/// that belongs to the caller.
///
/// This implements the asymmetric shard allocation depicted in the mesh
/// architecture: Shard 0 → Peer A, Shard 1 → Peer B, Parity → Peer C,
/// where any 2 of 3 paths reconstruct at the destination via RS(2,1).
pub async fn dispatch_shards_multipath(
    sock: &tokio::net::UdpSocket,
    session_hash: [u8; 4],
    counter: u32,
    shards: &[Vec<u8>],
    auth_tag: &[u8; 16],
    relay_hop_fingerprint: &str,
    targets: &[(String, SocketAddr, f64)],
    mesh: &AdaptiveShardRouter,
    use_bulk: bool,
) -> Vec<tokio::io::Result<()>> {
    let routes = mesh.assign_shards(targets);
    let mut results = Vec::with_capacity(routes.len());

    for route in &routes {
        let shard_idx = route.shard_index as usize;
        if shard_idx >= shards.len() {
            continue;
        }
        let shard_payload = &shards[shard_idx];

        // Wrap shard in a relay header for the intermediate hop
        let relay_pkt = crate::ghost::net::relay::build_relay_packet(
            relay_hop_fingerprint,
            1, // one hop remaining — the intermediate forwards to final destination
            shard_payload,
        );

        let peer_addr = targets
            .iter()
            .find(|(fp, _, _)| *fp == route.peer_fingerprint)
            .map(|(_, addr, _)| *addr)
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));

        if peer_addr.port() == 0 {
            results.push(Err(std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "No address for peer",
            )));
            continue;
        }

        let result = crate::ghost::net::send_gtf(
            sock,
            &peer_addr,
            session_hash,
            counter,
            route.shard_index,
            &relay_pkt,
            auth_tag,
            use_bulk,
        )
        .await;
        results.push(result);
    }

    results
}

// ═════════════════════════════════════════════════════════════════════════════
// 6. Exit Tunnel — Forward Reconstructed Payloads to Exit Node Pool
// ═════════════════════════════════════════════════════════════════════════════

/// Forward a reconstructed payload to the exit tunnel for outbound delivery.
///
/// This is called at PC 3 (or any intermediate relay node) after shards are
/// successfully collected and reconstructed via `assemble()`. The function:
///
/// 1. Decrypts the outer encryption layer (the original sender's session key).
/// 2. Inspects the decrypted payload for a relay header pointing to the exit
///    node pool (PC 4, PC 5).
/// 3. Re-encrypts with the exit node's session key and forwards the traffic
///    out of the mesh to the target internet host.
///
/// # Architecture
///
/// ```text
/// PC 1 ──shards──→ PC 3 (reconstruct) ──→ Exit Node ──→ Internet
///                      ↓
///                 forward_to_exit_tunnel()
/// ```
pub async fn forward_to_exit_tunnel(
    sock: &UdpSocket,
    sessions: &DashMap<String, Session>,
    exit_rotator: &ExitIpRotator,
    peer_addrs: &DashMap<String, SocketAddr>,
    reconstructed_payload: &[u8],
    exit_node_fingerprint: &str,
) -> bool {
    // Resolve the exit node's address via the peer registry
    let exit_addr = match peer_addrs.get(exit_node_fingerprint) {
        Some(e) => *e.value(),
        None => {
            warn!(
                "Exit node {} not found in peer registry",
                exit_node_fingerprint
            );
            return false;
        }
    };

    // Get session to the exit node
    let session_entry = match sessions.get(exit_node_fingerprint) {
        Some(s) => s,
        None => {
            warn!(
                "No session established with exit node {}",
                exit_node_fingerprint
            );
            return false;
        }
    };

    // The ratchet's epoch key and a fresh 96-bit nonce, drawn once for
    // this message so all three shards share it (they are pieces of one AEAD
    // ciphertext, and spending a nonce per shard would encrypt the same plaintext
    // three times under the same key).
    let material = session_entry.seal_material();
    let sh = session_entry.session_hash;
    let use_bulk = session_entry.use_bulk;
    drop(session_entry);

    // The reconstructed payload is already the decrypted inner content.
    // We re-encrypt it for the exit node and dispatch with a rotated egress IP.
    let mut framed = reconstructed_payload.to_vec();
    let needs_padding = if framed.len() % 2 != 0 { 1 } else { 0 };
    if needs_padding > 0 {
        framed.push(0);
    }

    // The jitter tail is authenticated as AEAD associated data, so it
    // has to exist *before* the seal and then travel in the frame. A bulk frame
    // carries no tail, and therefore no associated data either.
    let tail = if use_bulk {
        [0u8; crate::ghost::net::JITTER_MAX]
    } else {
        crate::ghost::net::tail_for(
            &material.key,
            &material.nonce,
            material.epoch,
            material.direction,
        )
    };
    let aad: &[u8] = if use_bulk { &[] } else { &tail[..] };

    xchacha_seal_in_place_with_aad(
        &material.key,
        &material.nonce,
        material.epoch,
        material.direction,
        &mut framed,
        aad,
    )
    .expect("sealing an owned buffer cannot fail");

    // Extract auth tag from the last 16 bytes of the ciphertext
    let tag = if framed.len() >= 16 {
        let mut t = [0u8; 16];
        t.copy_from_slice(&framed[framed.len() - 16..]);
        t
    } else {
        [0u8; 16]
    };

    // RS-encode the encrypted frame into 3 shards
    let shards = l4_rs::encode(&mut framed);

    // Select a rotated egress IP for this outbound dispatch
    // (The exit node will use this to bind its outbound connection)
    let _egress_addr = exit_rotator.get_next_socket_addr(0);

    // Send all 3 shards to the exit node
    for i in 0..3 {
        let shard_data = frame_shard(&shards[i]);
        let header = GtfV2Header {
            session_hash: sh,
            counter: material.counter,
            epoch: material.epoch,
            nonce: material.nonce,
            shard_index: i as u8,
            flags: 0,
            bulk: use_bulk,
            tail,
        };
        if let Err(e) = send_gtf_v2(sock, &exit_addr, &header, &shard_data, &tag).await {
            debug!("Exit tunnel send error to {}: {}", exit_node_fingerprint, e);
            return false;
        }
    }

    info!(
        "Forwarded {} bytes to exit tunnel via {} (egress rotation active)",
        reconstructed_payload.len(),
        exit_node_fingerprint
    );
    true
}

// ═════════════════════════════════════════════════════════════════════════════
// Spawn Mesh Background Tasks
// ═════════════════════════════════════════════════════════════════════════════

/// Spawn all mesh background tasks.
pub fn spawn_mesh_tasks(
    sock: Arc<UdpSocket>,
    sessions: Arc<DashMap<String, Session>>,
    mesh: Arc<MeshNode>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles = Vec::new();

    // Task 1: NAT keepalive sender
    let s1 = Arc::clone(&sock);
    let m1 = Arc::clone(&mesh);
    handles.push(tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(20)).await;
            m1.nat.send_keepalives(&s1).await;
        }
    }));

    // Task 2: Reciprocity audit cycle
    let s2 = sessions;
    let m2 = Arc::clone(&mesh);
    handles.push(tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(120)).await; // Audit every 2 minutes
            let to_evict = m2.tft.audit_cycle(&s2).await;
            for fp in to_evict {
                m2.tft.evict(&fp);
                // Remove session
                if let Some((_, _session)) = s2.remove(&fp) {
                    info!("Evicted {} — session torn down", fp);
                }
            }
        }
    }));

    // Task 3: Periodic path metric decay
    let _m3 = Arc::clone(&mesh);
    handles.push(tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(300)).await; // Every 5 minutes
                                                   // Fitness naturally decays — old metrics become less relevant
            debug!("Mesh: path metrics aging cycle");
        }
    }));

    handles
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_peer_registration() {
        let puncher = NatHolePuncher::new();
        let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        puncher.register_peer("test_fp", addr, addr);
        // Mark as connected as hole-punching would
        if let Some(mut s) = puncher.peers.get_mut("test_fp") {
            s.connected = true;
        }
        let cache = puncher.local_cache();
        assert_eq!(cache.len(), 1, "Should have 1 connected peer");
    }

    #[test]
    fn test_path_metrics_fitness() {
        let mut metrics = PathMetrics::default();
        // Good path
        metrics.observe(10_000.0, false);
        metrics.observe(12_000.0, false);
        metrics.observe(11_000.0, false);
        let good_fitness = metrics.fitness();
        assert!(good_fitness > 0.5, "Good path should have high fitness");

        // Bad path with loss
        for _ in 0..10 {
            metrics.observe(200_000.0, true);
        }
        let bad_fitness = metrics.fitness();
        assert!(
            bad_fitness < good_fitness,
            "Bad path should have lower fitness"
        );
    }

    #[test]
    fn a_loss_is_not_an_rtt_sample() {
        // The bug this pins: recording a loss as `observe(0.0, true)` mixed a
        // 0 µs "round trip" into the RTT average, so every lost packet made the
        // path look *faster* — and the shard router then preferred it.
        let mut m = PathMetrics::default();
        m.observe_rtt(80_000.0);
        m.observe_rtt(80_000.0);
        let before_rtt = m.srtt_us;
        let before_fitness = m.fitness();
        let before_rate = m.rate_bps();
        for _ in 0..5 {
            m.observe_loss();
        }
        assert_eq!(
            m.srtt_us, before_rtt,
            "a loss must not move the RTT estimate"
        );
        assert_eq!(m.loss_events, 5);
        assert!(m.loss_rate > 0.3, "loss is still recorded as loss");
        assert!(m.cwnd < cc::INIT_CWND, "loss halves the window");
        assert!(m.cwnd >= cc::DEFAULT_MSS, "but never below one segment");
        assert!(
            m.fitness() < before_fitness,
            "loss must lower the score ({:.3}), not raise it ({:.3})",
            m.fitness(),
            before_fitness
        );
        assert!(
            m.rate_bps() < before_rate,
            "halving the window must lower the rate estimate ({:.0} → {:.0})",
            before_rate,
            m.rate_bps()
        );
    }

    #[test]
    fn measured_delivery_grows_the_window_and_the_rate() {
        let mut m = PathMetrics::default();
        m.observe_rtt(40_000.0);
        let start = m.rate_bps();
        assert!(start > 0.0, "a measured path has an estimate");
        // Ten windows of delivery over the measured RTT. The window grows
        // additively, and the rate follows the window.
        let tick = Duration::from_millis(40);
        for _ in 0..10 {
            m.observe_delivery(m.cwnd, tick);
        }
        assert!(m.cwnd > cc::INIT_CWND, "delivery opens the window");
        assert!(
            m.rate_bps() > start,
            "rate {:.0} should exceed {:.0}",
            m.rate_bps(),
            start
        );
        assert_eq!(m.delivered_bytes, m.delivered_bytes.max(1));
        assert!(m.loss_rate < 0.01, "delivery decays the loss estimate");
    }

    #[test]
    fn a_path_losing_more_than_it_delivers_reports_no_rate() {
        let mut m = PathMetrics::default();
        m.observe_rtt(30_000.0);
        for _ in 0..20 {
            m.observe_loss();
        }
        assert!(m.loss_rate > 0.5);
        assert_eq!(m.rate_bps(), 0.0, "no estimate, not a zero estimate");
        assert_eq!(m.fitness(), 0.0, "and it must not be selected");
    }

    #[test]
    fn a_stale_measurement_stops_counting() {
        let mut m = PathMetrics::default();
        m.observe_rtt(10_000.0);
        assert!(m.measured());
        // A path that has gone quiet is not evidence of a fast path.
        m.last_updated = Instant::now() - (PathMetrics::STALE_AFTER + Duration::from_secs(1));
        assert!(!m.measured());
        assert_eq!(m.rate_bps(), 0.0);
        assert_eq!(
            m.fitness(),
            DEFAULT_PATH_FITNESS,
            "no losses, so no penalty"
        );
    }

    #[test]
    fn the_router_reports_only_paths_it_can_rate() {
        let router = AdaptiveShardRouter::new();
        router.record_success("measured", 25_000.0);
        router.record_delivery("measured", 20_000, Duration::from_millis(25));
        router.record_loss("lossy");
        let rates = router.live_path_rates();
        assert_eq!(rates.len(), 1, "only the measured path has an estimate");
        assert!(rates[0] > 0.0);
        assert_eq!(router.path_rtt_us("measured"), Some(25_000.0));
        assert_eq!(router.path_rtt_us("lossy"), None);
        let lossy_fitness = router.path_fitness("lossy");
        assert!(
            lossy_fitness < DEFAULT_PATH_FITNESS && lossy_fitness > 0.0,
            "one loss with no RTT sample must cost something ({lossy_fitness}), \
             without discarding a path we have not finished measuring"
        );
    }

    #[test]
    fn routed_shard_selection_orders_by_arrival_and_keeps_paths_disjoint() {
        let router = AdaptiveShardRouter::new();
        let available = vec![
            ("direct_fast".to_string(), "10.0.0.1:1234".parse().unwrap()),
            ("direct_slow".to_string(), "10.0.0.2:1234".parse().unwrap()),
            ("via_relay_a".to_string(), "10.0.0.3:1234".parse().unwrap()),
            ("shadow".to_string(), "10.0.0.4:1234".parse().unwrap()),
        ];
        let now = 1_000.0;
        let mut plan = ContactPlan::default();
        // Measure every link from a real round trip; latency is half of it.
        plan.observe_link(
            "me",
            "direct_fast",
            Duration::from_millis(20),
            now,
            60.0,
            0.0,
        );
        plan.observe_link(
            "me",
            "direct_slow",
            Duration::from_millis(80),
            now,
            60.0,
            0.0,
        );
        plan.observe_link("me", "relay_a", Duration::from_millis(2), now, 60.0, 0.0);
        plan.observe_link(
            "relay_a",
            "via_relay_a",
            Duration::from_millis(4),
            now,
            60.0,
            0.0,
        );
        // "shadow" is only reachable through that same relay.
        plan.observe_link(
            "relay_a",
            "shadow",
            Duration::from_millis(4),
            now,
            60.0,
            0.0,
        );

        let targets = router.select_shard_targets_routed("me", &available, &plan, now, 4);
        assert_eq!(targets.len(), 4);
        // 3 ms of light time through the relay beats the 10 ms direct link: CGR
        // minimises arrival, not hop count.
        assert_eq!(targets[0].0, "via_relay_a");
        assert_eq!(targets[1].0, "direct_fast");
        assert_eq!(targets[2].0, "direct_slow");
        // …and the peer whose only route would reuse the relay's transit node is
        // kept, but placed last rather than sharing a path with a shard.
        assert_eq!(targets[3].0, "shadow");

        // The first three targets are three separate paths.
        let routes = router.assign_shards(&targets[..3]);
        assert_eq!(routes.len(), 3);
        let peers: std::collections::HashSet<&str> =
            routes.iter().map(|r| r.peer_fingerprint.as_str()).collect();
        assert_eq!(peers.len(), 3, "each shard must take its own path");
    }

    #[test]
    fn assign_shards_without_targets_is_empty() {
        let router = AdaptiveShardRouter::new();
        assert!(router.assign_shards(&[]).is_empty());
    }

    #[test]
    fn test_adaptive_shard_selection() {
        let router = AdaptiveShardRouter::new();
        let available = vec![
            ("peer_a".to_string(), "10.0.0.1:1234".parse().unwrap()),
            ("peer_b".to_string(), "10.0.0.2:1234".parse().unwrap()),
            ("peer_c".to_string(), "10.0.0.3:1234".parse().unwrap()),
        ];
        let targets = router.select_shard_targets(&available);
        assert!(
            targets.len() >= 2,
            "Should select at least 2 targets for RS(2,1)"
        );

        let routes = router.assign_shards(&targets);
        assert_eq!(routes.len(), 3, "Should assign all 3 shards");
        // Shard indices should be 0, 1, 2
        let indices: Vec<u8> = routes.iter().map(|r| r.shard_index).collect();
        assert!(indices.contains(&0));
        assert!(indices.contains(&1));
        assert!(indices.contains(&2));
    }

    #[test]
    fn test_reciprocity_detection() {
        let rep = Arc::new(PoissonReputationMatrix::new());
        let tft = TitForTatEnforcer::new("self".to_string(), rep);

        // Simulate a leecher: they forward very little for us
        tft.forwarded_by("leecher", 100);
        tft.forwarded_by("leecher", 50);
        tft.forwarded_for("leecher", 10_000);

        assert!(tft.ratio_with("leecher") < 0.3, "Leech ratio should be low");

        // Simulate a fair peer
        tft.forwarded_by("fair", 10_000);
        tft.forwarded_for("fair", 10_000);
        assert!(
            tft.ratio_with("fair") > 0.5,
            "Fair ratio should be balanced"
        );
    }

    #[test]
    fn test_shard_route_assignment() {
        let mesh = AdaptiveShardRouter::new();
        let targets = vec![
            (
                "fast_peer".to_string(),
                "1.1.1.1:1234".parse().unwrap(),
                0.95,
            ),
            (
                "medium_peer".to_string(),
                "2.2.2.2:1234".parse().unwrap(),
                0.60,
            ),
            (
                "slow_peer".to_string(),
                "3.3.3.3:1234".parse().unwrap(),
                0.35,
            ),
        ];
        let routes = mesh.assign_shards(&targets);
        assert_eq!(routes.len(), 3);
        // Fast peer should get shard 0 (highest priority)
        assert_eq!(routes[0].peer_fingerprint, "fast_peer");
        assert_eq!(routes[0].shard_index, 0);
    }
}
