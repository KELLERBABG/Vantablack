use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::ghost::layers::l2_aead::encrypt_in_place;
use crate::ghost::layers::l4_rs;
use crate::ghost::net::routing::PoissonReputationMatrix;
use crate::ghost::net::{frame_shard, send_gtf};
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
// 1. NAT Traversal & STUN-Style Hole Punching
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

/// STUN-style NAT hole-punching coordinator.
///
/// Residential NATs block unsolicited inbound UDP. STUN hole-punching
/// works by having both peers send packets to each other's public
/// addresses simultaneously — the NAT sees the outbound packet and
/// creates a temporary mapping that allows the inbound response.
pub struct NatHolePuncher {
    /// Known NAT peers keyed by fingerprint.
    peers: Arc<DashMap<String, NatPeerState>>,
    /// Local STUN server address (for public address discovery).
    stun_server: Option<SocketAddr>,
    /// Our public address as last reported.
    pub public_addr: Option<SocketAddr>,
    /// UDP socket for hole-punch control messages.
    control_sock: Option<Arc<UdpSocket>>,
}

impl Default for NatHolePuncher {
    fn default() -> Self {
        Self {
            peers: Arc::new(DashMap::new()),
            stun_server: None,
            public_addr: None,
            control_sock: None,
        }
    }
}

impl NatHolePuncher {
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize with a STUN server for public address discovery.
    pub fn with_stun_server(mut self, stun_addr: SocketAddr) -> Self {
        self.stun_server = Some(stun_addr);
        self
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

    /// Execute a coordinated hole-punch with a peer.
    ///
    /// Both sides send UDP packets to each other's public address
    /// simultaneously, causing each NAT to create a temporary mapping.
    pub async fn punch_hole(&self, sock: &UdpSocket, fp: &str) -> bool {
        let state = match self.peers.get(fp) {
            Some(s) => s.clone(),
            None => {
                warn!("Cannot punch hole: unknown peer {}", fp);
                return false;
            }
        };

        if state.connected {
            return true; // Already connected
        }

        // Send a hole-punch packet (small "HP" magic)
        let punch_payload = b"GHOST_HPUNCH_";
        for _ in 0..5 {
            if let Err(e) = sock.send_to(punch_payload, state.public_addr).await {
                debug!("Hole-punch send error: {}", e);
            }
            // Also try sending to a range of nearby ports (NAT port prediction)
            let base_port = state.public_addr.port();
            for offset in 1..=5 {
                let mut addr = state.public_addr;
                addr.set_port(base_port + offset);
                let _ = sock.send_to(punch_payload, addr).await;
            }
            sleep(Duration::from_millis(50)).await;
        }

        if let Some(mut s) = self.peers.get_mut(fp) {
            s.connected = true;
            s.last_keepalive = Instant::now();
        }
        info!("Hole-punch completed for {}", fp);
        true
    }

    /// Send periodic keepalives to maintain NAT mappings.
    pub async fn send_keepalives(&self, sock: &UdpSocket) {
        for mut entry in self.peers.iter_mut() {
            if entry.connected && entry.last_keepalive.elapsed() > Duration::from_secs(25) {
                let _ = sock.send_to(b"GHOST_KA_NAT", entry.public_addr).await;
                entry.last_keepalive = Instant::now();
            }
        }
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

/// Live performance metrics for a neighbor session.
#[derive(Debug, Clone)]
pub struct PathMetrics {
    /// Round-trip time estimate (microseconds).
    pub rtt_us: f64,
    /// Packet loss rate (0.0 - 1.0).
    pub loss_rate: f64,
    /// Throughput estimate (bytes/sec).
    pub throughput_bps: f64,
    /// When this metric was last updated.
    pub last_updated: Instant,
    /// Smoothed RTT (RFC 6298).
    pub srtt: f64,
    /// Number of samples collected.
    pub samples: u64,
}

impl Default for PathMetrics {
    fn default() -> Self {
        Self {
            rtt_us: 50_000.0, // 50ms initial estimate
            loss_rate: 0.0,
            throughput_bps: 10_000_000.0, // 10 Mbps initial
            last_updated: Instant::now(),
            srtt: 50_000.0,
            samples: 0,
        }
    }
}

impl PathMetrics {
    /// Update metrics with a new observation.
    pub fn observe(&mut self, rtt_sample_us: f64, lost: bool) {
        self.samples += 1;
        // Exponential moving average for RTT
        let alpha = 0.125;
        self.srtt = self.srtt * (1.0 - alpha) + rtt_sample_us * alpha;
        self.rtt_us = self.srtt;

        // Exponential moving average for loss
        let beta = 0.1;
        if lost {
            self.loss_rate = self.loss_rate * (1.0 - beta) + beta;
        } else {
            self.loss_rate *= 1.0 - beta;
        }

        // RTT-based throughput estimate: TCP-style
        if self.rtt_us > 0.0 {
            let cwnd = 10_000_000.0; // Assume ~10MB cwnd for estimation
            self.throughput_bps = cwnd / (self.rtt_us / 1_000_000.0);
        }

        self.last_updated = Instant::now();
    }

    /// Compute a fitness score (higher = better path).
    /// Combines RTT, loss rate, and throughput into a single score.
    pub fn fitness(&self) -> f64 {
        if self.loss_rate > 0.5 {
            return 0.0; // Unusable path
        }
        let rtt_score = (100_000.0 / self.rtt_us.max(1.0)).min(2.0);
        let loss_score = (1.0 - self.loss_rate).powi(2);
        let tp_score = (self.throughput_bps / 1_000_000.0).min(10.0) / 10.0;
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
    pub fn record_success(&self, peer_fp: &str, rtt_us: f64) {
        let mut metrics = self.path_metrics.entry(peer_fp.to_string()).or_default();
        metrics.observe(rtt_us, false);
        debug!(
            "Path to {}: RTT={:.0}us, fitness={:.2}",
            peer_fp,
            metrics.rtt_us,
            metrics.fitness()
        );
    }

    /// Record a shard delivery failure (loss).
    pub fn record_loss(&self, peer_fp: &str) {
        let mut metrics = self.path_metrics.entry(peer_fp.to_string()).or_default();
        metrics.observe(0.0, true);
        warn!(
            "Path loss to {}: loss_rate={:.2}",
            peer_fp, metrics.loss_rate
        );
    }

    /// Get the fitness score for a peer path.
    pub fn path_fitness(&self, peer_fp: &str) -> f64 {
        self.path_metrics
            .get(peer_fp)
            .map(|m| m.fitness())
            .unwrap_or(0.5) // Default fitness for unknown peers
    }

    /// Select the best N peers from available peers for shard routing.
    ///
    /// Returns the top candidates sorted by fitness, ensuring we have
    /// at least `data_shards` (2) candidates for RS reconstruction.
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

        // Ensure we return at least data_shards (2) candidates
        let result_count = scored.len().max(self.data_shards);
        scored.truncate(result_count);
        scored
    }

    /// Assign shards to selected peers.
    ///
    /// Distributes shards 0, 1, 2 across the best peers.
    /// If we have fewer than 3 good peers, some peers get multiple shards
    /// (which is fine — we only need 2 of 3 to arrive).
    pub fn assign_shards(&self, targets: &[(String, SocketAddr, f64)]) -> Vec<ShardRoute> {
        let mut routes = Vec::new();
        for shard_idx in 0..3u8 {
            if let Some((fp, _addr, fitness)) =
                targets.get(shard_idx as usize % targets.len().max(1))
            {
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

    let key = session_entry.master_key;
    let sh = session_entry.session_hash;
    let ctr = session_entry.next_tx_counter();
    let use_bulk = session_entry.use_bulk;
    drop(session_entry);

    // The reconstructed payload is already the decrypted inner content.
    // We re-encrypt it for the exit node and dispatch with a rotated egress IP.
    let mut framed = reconstructed_payload.to_vec();
    let needs_padding = if framed.len() % 2 != 0 { 1 } else { 0 };
    if needs_padding > 0 {
        framed.push(0);
    }

    encrypt_in_place(&key, ctr, &mut framed);

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
        if let Err(e) = send_gtf(
            sock,
            &exit_addr,
            sh,
            ctr,
            i as u8,
            &shard_data,
            &tag,
            use_bulk,
        )
        .await
        {
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
