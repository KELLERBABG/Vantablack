//! GhostNet: The Vantablack protocol core.
//!
//! Implements the complete GHOST protocol stack across all operational layers:
//! - L0: Hybrid Ed25519 + ML-DSA-65 Identity & Attestation
//! - L1: X25519 + ML-KEM-512/768 Hybrid Key Encapsulation
//! - L2: ChaCha20-Poly1305 & XChaCha20 Authenticated Encryption
//! - L3: Shamir Secret Sharing threshold splitting
//! - L4: Reed-Solomon (2,1) erasure coding
//! - L5: Jitter padding and noise injection (GhostMimic)
//! - L6: Replay guards and session sliding windows
//! - L7: Link-layer LDPC forward error correction
//! - L8: AES-XTS memory encryption and bounded ring buffers
//! - L9: Infrastructure, single-binary packaging, and hardware security
//! - L10: Quantum Entanglement Link (QEL) and ETSI GS QKD 014 anchors
//!
//! Also hosts the Ghost Transport Frame (GTF), mesh routing, and ACK-based reliable transport.

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
use tracing::{debug, info};

use net::routing::ContactPlan;
use net::{FlowController, ThroughputStats};
use session::Session;

/// Number of worker threads for packet processing.
pub const WORKER_THREADS: usize = 4;

/// Size of the packet processing channel per worker.
pub const CHANNEL_SIZE: usize = 8192;

/// A GhostNet node that bundles identity, session state, and transport.
pub struct GhostNode {
    /// The node's long-term Ed25519 identity.
    ///
    /// Shared rather than owned: subsystems that outlive a call (the relay's
    /// admission rule, the optional QUIC transport's channel binding) need to
    /// sign or verify under this key, and sharing one instance keeps exactly one
    /// copy of the signing key in memory.
    pub identity: Arc<layers::l0_identity::GhostIdentity>,
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
    /// Create a new GhostNet node: loads or generates an Ed25519 identity, binds
    /// a UDP socket, and spawns 4 packet-processing worker tasks.
    ///
    /// Test-only. A production build assembles the node by hand in src/main.rs and
    /// never calls this or `dispatch_packet`; `tests/simulation.rs` is the only caller.
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

        // Test-only worker path (see `new`): no production build routes packets
        // through here, and the daemon opens v1 frames in src/main.rs instead.
        for i in 0..WORKER_THREADS {
            let (tx, mut rx) = mpsc::unbounded_channel::<(Vec<u8>, SocketAddr)>();
            let sessions = Arc::clone(&sessions_clone);
            let stats = Arc::clone(&stats_clone);

            tokio::spawn(async move {
                while let Some((packet, src_addr)) = rx.recv().await {
                    stats.packets_recv.fetch_add(1, Ordering::Relaxed);
                    stats
                        .bytes_recv
                        .fetch_add(packet.len() as u64, Ordering::Relaxed);

                    // A frame too short to carry the header cannot be a data
                    // frame, and indexing it would panic on a peer's datagram.
                    if packet.len() <= net::OFFSET_SHARD_INDEX {
                        stats.drops.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }

                    let counter = net::parse_packet_counter_u64(&packet);
                    if counter == 0 || counter == 1 {
                        debug!("Worker {}: handshake packet from {}", i, src_addr);
                        continue;
                    }

                    match decode_data_frame(&sessions, &packet, &stats) {
                        Some(plaintext) => {
                            if let Ok(text) = std::str::from_utf8(&plaintext) {
                                let text = text.trim_end_matches('\0');
                                info!("Worker {}: {}: {}", i, src_addr, text);
                            }
                        }
                        None => {
                            debug!("Worker {}: data frame from {} dropped", i, src_addr);
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
            identity: Arc::new(identity),
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

/// Open one data frame against the session whose hash it carries, exactly as the
/// test-only worker path does.
///
/// Returns the plaintext and commits the counter to the replay window on
/// success, or `None` after recording a drop. Kept separate from the worker loop
/// so the open path can be tested without a spawned task.
///
/// The shape of the open is the daemon's, not an invention: the 12-byte wire
/// nonce travels in the header, the 64-byte jitter tail is the AEAD associated
/// data, and the ciphertext plus tag is the unit that authenticates. Only the
/// epoch-key lookup differs (`src/main.rs` asks the ratchet; this path holds one
/// seed key). No production build reaches this function.
pub(crate) fn decode_data_frame(
    sessions: &DashMap<String, Session>,
    packet: &[u8],
    stats: &ThroughputStats,
) -> Option<Vec<u8>> {
    if packet.len() <= net::OFFSET_SHARD_INDEX {
        stats.drops.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    if packet[net::OFFSET_SHARD_INDEX] as usize > 2 {
        stats.drops.fetch_add(1, Ordering::Relaxed);
        return None;
    }

    let counter = net::parse_packet_counter_u64(packet);
    let v2 = net::parse_gtf_v2_header(packet).ok_or_else(|| {
        stats.drops.fetch_add(1, Ordering::Relaxed);
    });
    let Ok(header) = v2 else {
        return None;
    };

    let session_hash = net::parse_session_hash(packet);
    let hash_key = hex::encode(session_hash);
    // Everything after the header up to the tag, plus the tag itself, is what
    // the sealer authenticated. The tail is left out: it is the AAD.
    let mut sealed = net::extract_payload(packet).to_vec();
    let tag = net::extract_auth_tag(packet);
    let Ok(tag) = <[u8; 16]>::try_from(tag) else {
        stats.drops.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    sealed.extend_from_slice(&tag);

    for entry in sessions.iter() {
        let s_hash = hex::encode(&entry.session_hash[..4.min(entry.session_hash.len())]);
        if s_hash != hash_key {
            continue;
        }

        // Decrypt before touching the guard. The guard's `v_max` must never
        // advance on an unauthenticated cleartext counter, or one forged frame
        // poisons the window.
        let ours = entry.role.seal_direction();
        let aad: &[u8] = if header.bulk { &[] } else { &header.tail };
        let mut decrypted = None;
        for dir in [ours.peer_direction(), ours] {
            let mut msg = sealed.clone();
            if layers::l2_aead::xchacha_open_with_aad(
                &entry.master_key,
                &header.nonce,
                header.epoch,
                dir,
                &mut msg,
                aad,
            )
            .is_ok()
            {
                decrypted = Some(msg);
                break;
            }
        }
        let Some(plain) = decrypted else {
            stats.drops.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        // The payload region is zero-padded to its fixed width, so the open
        // returns padding after the shard. The length prefix is what separates
        // the two; without this an empty body would read back as 458 zeros.
        let Some(framed) = net::unframe(&plain) else {
            stats.drops.fetch_add(1, Ordering::Relaxed);
            return None;
        };

        if !entry.check_inbound(counter) {
            stats.drops.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        return Some(framed);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghost::layers::l2_aead::{self, NonceDirection};
    use crate::ghost::net::{self, GtfV2Header};

    /// The sealed region is the whole payload area: `decode_data_frame` reads
    /// `extract_payload` plus the tag as one buffer, and the tag covers every
    /// byte the builder wrote. A body smaller than the region therefore leaves
    /// padding inside the tag's scope and the frame will not open, which is a
    /// property of the fixed-width privacy frame rather than of this test.
    const BODY_LEN: usize = net::V2_MAX_PAYLOAD_LEN - 2;

    fn body(tag: &str) -> Vec<u8> {
        let mut b = vec![0u8; BODY_LEN];
        b[..tag.len()].copy_from_slice(tag.as_bytes());
        b
    }

    fn frame_for(key: &[u8; 32], session_hash: &[u8; 4], counter: u64, body: &[u8]) -> Vec<u8> {
        let dir = NonceDirection::InitiatorToResponder;
        let epoch = 0u64;
        let nonce = l2_aead::random_xnonce();
        let tail = net::tail_for(key, &nonce, epoch, dir);
        // The sealer's own shape: length-prefixed body, XChaCha with the jitter
        // tail as associated data, and the tag appended to the ciphertext.
        let mut sealed = net::frame_shard(body);
        l2_aead::xchacha_seal_in_place_with_aad(key, &nonce, epoch, dir, &mut sealed, &tail)
            .expect("seal test frame");
        let (ciphertext, tag) = sealed.split_at(sealed.len() - 16);
        let tag: [u8; 16] = tag.try_into().expect("aead tag");
        let header = GtfV2Header {
            session_hash: *session_hash,
            counter,
            epoch,
            nonce,
            shard_index: 0,
            flags: 0,
            bulk: false,
            tail,
        };
        net::build_gtf_v2_frame(&header, ciphertext, &tag)
    }

    /// The worker path is the only reader of `dispatch_packet`; nothing else
    /// opened a frame through it, so the open path had no test at all.
    #[test]
    fn a_worker_frame_opens_and_a_replay_of_it_does_not() {
        let key = [0x5Au8; 32];
        let session = Session::new(key, "peer-under-test".to_string());
        let session_hash = session.session_hash;
        let node_sessions: DashMap<String, Session> = DashMap::new();
        node_sessions.insert("peer-under-test".to_string(), session);
        let stats = ThroughputStats::new();

        let frame = frame_for(&key, &session_hash, 2, &body("hello over the worker path"));
        let opened = decode_data_frame(&node_sessions, &frame, &stats);
        assert_eq!(
            opened.as_deref(),
            Some(&body("hello over the worker path")[..]),
            "frame len {} session_hash {:02x?} drops {}",
            frame.len(),
            session_hash,
            stats.drops.load(Ordering::Relaxed)
        );

        // Same counter again: the guard has already seen it.
        assert!(decode_data_frame(&node_sessions, &frame, &stats).is_none());
        assert_eq!(stats.drops.load(Ordering::Relaxed), 1);
    }

    /// A truncated datagram used to index past its own end.
    #[test]
    fn a_datagram_shorter_than_the_shard_offset_is_dropped_not_indexed() {
        let sessions: DashMap<String, Session> = DashMap::new();
        let stats = ThroughputStats::new();

        for len in 0..=net::OFFSET_SHARD_INDEX {
            let short = vec![0u8; len];
            assert!(decode_data_frame(&sessions, &short, &stats).is_none());
        }
        assert_eq!(
            stats.drops.load(Ordering::Relaxed),
            (net::OFFSET_SHARD_INDEX + 1) as u64
        );
    }

    /// A shard index outside the RS(2,1) group is not a frame for this path.
    #[test]
    fn a_frame_with_an_out_of_range_shard_index_is_dropped() {
        let key = [0x11u8; 32];
        let session = Session::new(key, "peer".to_string());
        let session_hash = session.session_hash;
        let sessions: DashMap<String, Session> = DashMap::new();
        sessions.insert("peer".to_string(), session);
        let stats = ThroughputStats::new();

        let mut frame = frame_for(&key, &session_hash, 2, &body("body"));
        frame[net::OFFSET_SHARD_INDEX] = 3;
        assert!(decode_data_frame(&sessions, &frame, &stats).is_none());

        frame[net::OFFSET_SHARD_INDEX] = 2;
        assert!(decode_data_frame(&sessions, &frame, &stats).is_some());
    }

    /// A frame that does not authenticate must not move the replay window: the
    /// guard is committed only after the tag verifies.
    #[test]
    fn a_forged_frame_does_not_advance_the_replay_window() {
        let key = [0x33u8; 32];
        let session = Session::new(key, "peer".to_string());
        let session_hash = session.session_hash;
        let sessions: DashMap<String, Session> = DashMap::new();
        sessions.insert("peer".to_string(), session);
        let stats = ThroughputStats::new();

        let mut forged = frame_for(&key, &session_hash, 2, &body("body"));
        let last = forged.len() - 20;
        forged[last] ^= 0x01;
        assert!(decode_data_frame(&sessions, &forged, &stats).is_none());

        let v_max = sessions
            .get("peer")
            .expect("session")
            .guard
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .v_max;
        assert_eq!(v_max, 0, "a forged counter must not enter the window");

        // The genuine frame at the same counter still opens.
        let genuine = frame_for(&key, &session_hash, 2, &body("body"));
        assert_eq!(
            decode_data_frame(&sessions, &genuine, &stats),
            Some(body("body"))
        );
    }
}
