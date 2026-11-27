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
pub mod v2;

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

pub const WORKER_THREADS: usize = 4;

pub const CHANNEL_SIZE: usize = 8192;

pub struct GhostNode {
    pub identity: Arc<layers::l0_identity::GhostIdentity>,
    pub sessions: Arc<DashMap<String, Session>>,
    pub socket: Arc<UdpSocket>,
    pub contact_plan: RwLock<ContactPlan>,
    pub created_at: Instant,
    pub local_addr: String,
    pub flow_controller: Arc<FlowController>,
    pub stats: Arc<ThroughputStats>,
    pub running: AtomicBool,
    pub workers: Vec<mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>>,
    pub worker_idx: std::sync::atomic::AtomicUsize,
    pub beacon_enabled: AtomicBool,
    pub keepalive_interval_secs: AtomicU64,
}

impl GhostNode {
    pub async fn new(bind_addr: &str) -> anyhow::Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?.to_string();
        let socket = Arc::new(socket);

        let flow_controller = Arc::new(FlowController::new(100)); // 100 Mbps transit cap
        let stats = Arc::new(ThroughputStats::new());
        let running = AtomicBool::new(true);

        let mut workers = Vec::with_capacity(WORKER_THREADS);
        let sessions: Arc<DashMap<String, Session>> = Arc::new(DashMap::new());
        let sessions_clone = Arc::clone(&sessions);
        let stats_clone = Arc::clone(&stats);

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

    pub fn fingerprint(&self) -> String {
        self.identity.fingerprint()
    }

    pub fn dispatch_packet(&self, packet: Vec<u8>, src: SocketAddr) {
        if self.workers.is_empty() {
            return;
        }
        let idx = self.worker_idx.fetch_add(1, Ordering::Relaxed) % self.workers.len();
        if let Err(e) = self.workers[idx].send((packet, src)) {
            debug!("Worker channel full: {}", e);
        }
    }

    pub fn throughput_report(&self, interval_ms: u64) -> (f64, f64, f64, f64) {
        self.stats
            .report(std::time::Duration::from_millis(interval_ms))
    }

    pub fn shutdown(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

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
        let tail = net::random_tail();
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

        assert!(decode_data_frame(&node_sessions, &frame, &stats).is_none());
        assert_eq!(stats.drops.load(Ordering::Relaxed), 1);
    }

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

        let genuine = frame_for(&key, &session_hash, 2, &body("body"));
        assert_eq!(
            decode_data_frame(&sessions, &genuine, &stats),
            Some(body("body"))
        );
    }
}
