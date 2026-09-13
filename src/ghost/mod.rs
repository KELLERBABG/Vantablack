/// GhostNet: The Global Ghost Net protocol core.
///
/// This module implements the full GHOST protocol stack as described
/// in the Global Ghost Net architecture:
///
/// L0  - Ed25519 Identity / Signing
/// L1  - X25519 + Kyber-512 Hybrid KEM
/// L2  - ChaCha20-Poly1305 AEAD
/// L3  - Shamir Secret Sharing (GF256)
/// L4  - Reed-Solomon Erasure Coding
/// L5  - Noise Injection / Jitter Padding
/// L6  - Session Guard / Replay Protection
///
/// plus the networking layer including the Ghost Transport Frame (GTF),
/// Contact Graph Routing (CGR), and the ACK-based reliable transport.
pub mod icon;
pub mod layers;
pub mod net;
pub mod paths;
pub mod session;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use net::routing::ContactPlan;
use net::{FlowController, ThroughputStats};
use session::Session;

/// Number of worker threads for packet processing.
pub const WORKER_THREADS: usize = 4;

/// Size of the packet processing channel per worker.
pub const CHANNEL_SIZE: usize = 8192;

/// A GhostNet node that bundles identity, session state, and transport.
pub struct GhostNode {
    /// The node's long-term Ed25519 identity
    pub identity: layers::l0_identity::GhostIdentity,
    /// Active sessions keyed by peer fingerprint (concurrent hash map).
    pub sessions: Arc<DashMap<String, Session>>,
    /// Async UDP socket bound to a dynamic port.
    pub socket: Arc<UdpSocket>,
    /// Contact Plan for CGR routing.
    pub contact_plan: RwLock<ContactPlan>,
    /// Node creation timestamp (for uptime tracking).
    pub created_at: Instant,
    /// Local address string for display.
    pub local_addr: String,
    /// Flow controller for traffic shaping.
    pub flow_controller: Arc<FlowController>,
    /// Global throughput statistics.
    pub stats: Arc<ThroughputStats>,
    /// Running flag for graceful shutdown.
    pub running: AtomicBool,
    /// Packet processing workers (channel senders).
    pub workers: Vec<mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>>,
    /// Round-robin worker index.
    pub worker_idx: std::sync::atomic::AtomicUsize,
    /// Whether to send periodic UDP beacon announcements.
    pub beacon_enabled: AtomicBool,
    /// Per-peer keepalive interval in seconds. Node sends an encrypted keepalive
    /// if no data has been exchanged for this duration.
    pub keepalive_interval_secs: AtomicU64,
}

impl GhostNode {
    /// Create a new GhostNet node — loads or generates an Ed25519 identity,
    /// binds a UDP socket, and spawns 4 packet-processing worker tasks.
    pub async fn new(bind_addr: &str) -> anyhow::Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?.to_string();
        let socket = Arc::new(socket);

        let flow_controller = Arc::new(FlowController::new(100)); // 100 Mbps transit cap
        let stats = Arc::new(ThroughputStats::new());
        let running = AtomicBool::new(true);

        // Spawn packet processing workers
        let mut workers = Vec::with_capacity(WORKER_THREADS);
        let sessions: Arc<DashMap<String, Session>> = Arc::new(DashMap::new());
        let sessions_clone = Arc::clone(&sessions);
        let stats_clone = Arc::clone(&stats);

        for i in 0..WORKER_THREADS {
            let (tx, mut rx) = mpsc::unbounded_channel::<(Vec<u8>, SocketAddr)>();
            let sessions = Arc::clone(&sessions_clone);
            let stats = Arc::clone(&stats_clone);
            let identity = layers::l0_identity::GhostIdentity::generate_fresh();

            tokio::spawn(async move {
                let worker_fp = identity.fingerprint();

                while let Some((packet, src_addr)) = rx.recv().await {
                    stats.packets_recv.fetch_add(1, Ordering::Relaxed);
                    stats
                        .bytes_recv
                        .fetch_add(packet.len() as u64, Ordering::Relaxed);

                    let counter = net::parse_packet_counter(&packet);
                    let shard_index = packet[net::OFFSET_SHARD_INDEX] as usize;
                    if shard_index > 2 {
                        continue;
                    }

                    let payload = net::extract_payload(&packet).to_vec();

                    // Dispatch based on counter:
                    // 0 = handshake, 1 = handshake response, 2+ = data
                    if counter == 0 || counter == 1 {
                        debug!("Worker {}: handshake packet from {}", i, src_addr);
                    } else {
                        // Data packet — find the session
                        let session_hash = net::parse_session_hash(&packet);
                        let hash_key = hex::encode(session_hash);

                        // Try to find session by hash prefix
                        let mut found = false;
                        for mut entry in sessions.iter_mut() {
                            let s_hash =
                                hex::encode(&entry.session_hash[..4.min(entry.session_hash.len())]);
                            if s_hash == hash_key {
                                // Verify auth tag
                                let tag = net::extract_auth_tag(&packet);
                                if tag.len() < 16 {
                                    warn!("Worker {}: short auth tag from {}", i, src_addr);
                                    stats.drops.fetch_add(1, Ordering::Relaxed);
                                    break;
                                }

                                // Verify replay guard
                                if !entry.guard.check_and_update(counter) {
                                    warn!(
                                        "Worker {}: replay rejected counter={} from {}",
                                        i, counter, src_addr
                                    );
                                    stats.drops.fetch_add(1, Ordering::Relaxed);
                                    break;
                                }

                                // Decrypt payload
                                let key = entry.master_key;
                                let mut msg = payload.clone();
                                if let Ok(plaintext) =
                                    layers::l2_aead::decrypt_in_place(&key, counter, &mut msg)
                                {
                                    if let Ok(text) = std::str::from_utf8(plaintext) {
                                        let text = text.trim_end_matches('\0');
                                        info!(
                                            "[{}] {}: {}",
                                            worker_fp, entry.peer_fingerprint, text
                                        );
                                    }
                                }
                                found = true;
                                break;
                            }
                        }

                        if !found {
                            debug!(
                                "Worker {}: no session for hash {} from {}",
                                i, hash_key, src_addr
                            );
                        }
                    }
                }
            });

            workers.push(tx);
        }

        let identity = layers::l0_identity::GhostIdentity::load_or_generate(
            &layers::l0_identity::identity_file_path(),
        );

        Ok(Self {
            identity,
            sessions: sessions_clone,
            socket,
            contact_plan: RwLock::new(ContactPlan::default()),
            created_at: Instant::now(),
            local_addr,
            flow_controller,
            stats,
            running,
            workers,
            worker_idx: std::sync::atomic::AtomicUsize::new(0),
            beacon_enabled: AtomicBool::new(true),
            keepalive_interval_secs: AtomicU64::new(120),
        })
    }

    /// Display the node's identity fingerprint (first 8 bytes of Ed25519 public key).
    pub fn fingerprint(&self) -> String {
        self.identity.fingerprint()
    }

    /// Route an incoming packet to a worker thread (round-robin).
    pub fn dispatch_packet(&self, packet: Vec<u8>, src: SocketAddr) {
        let idx = self.worker_idx.fetch_add(1, Ordering::Relaxed) % self.workers.len();
        if let Err(e) = self.workers[idx].send((packet, src)) {
            debug!("Worker channel full: {}", e);
        }
    }

    /// Get throughput report.
    pub fn throughput_report(&self, interval_ms: u64) -> (f64, f64, f64, f64) {
        self.stats
            .report(std::time::Duration::from_millis(interval_ms))
    }

    /// Graceful shutdown signal.
    pub fn shutdown(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}
