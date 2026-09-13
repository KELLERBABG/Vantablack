/// Session Management Module
///
/// Manages the lifecycle of peer-to-peer sessions in the GhostNet:
/// - Session creation and teardown
/// - Per-peer monotonic counter tracking
/// - Stream multiplexing for concurrent data flows
/// - Replay guard integration
/// - Retransmission state per stream
/// - **Automated session re-keying** when the tx_counter approaches exhaustion
///
/// # Re-keying Protocol
/// When `tx_counter > REKEY_THRESHOLD` (~75% of u32::MAX), a background
/// L1 key exchange is triggered to derive a new master key before the old
/// counter wraps around. This prevents ChaCha20-Poly1305 nonce reuse
/// without dropping the session connection.
pub mod guard;

use crate::ghost::layers::l1_kem::compute_session_hash;
use crate::ghost::layers::l6_session::SessionGuard;
use crate::ghost::net::{AckEngine, ThroughputStats};
use bytes::Bytes;
use dashmap::DashMap;
use ml_kem::kem::KeyExport;
use ml_kem::EncapsulationKey512;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::info;

/// Maximum number of concurrent streams per session.
pub const MAX_STREAMS: u16 = 256;

/// Re-key threshold: trigger background re-keying when tx_counter exceeds this.
/// Set at 75% of u32::MAX to leave adequate headroom for the re-key handshake
/// and old-key packet drain.
pub const REKEY_THRESHOLD: u32 = 0xC000_0000; // 3,221,225,472

/// Counter value reserved for the re-key handshake PDU.
/// The sender sends the re-key request at counter = REKEY_SENTINEL,
/// and the responder replies at counter = REKEY_RESPONSE_SENTINEL.
pub const REKEY_SENTINEL: u32 = 0xFFFF_FFFE;
pub const REKEY_RESPONSE_SENTINEL: u32 = 0xFFFF_FFFD;

/// Number of additional packets allowed with the old key after a re-key completes.
/// During this grace period, packets encrypted with the old key are still accepted
/// to handle in-flight packets.
pub const OLD_KEY_GRACE_PACKETS: u32 = 1000;

/// Magic bytes for the re-key handshake PDU.
pub const REKEY_MAGIC: &[u8; 16] = b"GHOST_REKEY____!";
/// Magic bytes for the re-key response PDU.
pub const REKEY_RESPONSE_MAGIC: &[u8; 16] = b"GHOST_REKEY_RSP!";

/// Size of the re-key handshake PDU: 16 magic + 32 X25519 + 800 Kyber + 64 sig = 912
pub const REKEY_BLOB_LEN: usize = 912;
/// Size of the re-key response PDU: 16 magic + 32 X25519 + 768 ct + 64 sig = 880
pub const REKEY_RESPONSE_BLOB_LEN: usize = 880;

/// Full session state for a peer connection.
pub struct Session {
    /// The hybrid master key (X25519 + Kyber-512 derived).
    pub master_key: [u8; 32],
    /// Per-peer outbound monotonic counter.
    pub tx_counter: AtomicU32,
    /// Per-peer inbound replay guard.
    pub guard: SessionGuard,
    /// Peer's identity fingerprint (first 8 bytes of Ed25519 PK, hex).
    pub peer_fingerprint: String,
    /// When this session was established.
    pub established_at: Instant,
    /// 4-byte session hash for GTF frame headers.
    pub session_hash: [u8; 4],
    /// Which side initiated this session (drives AEAD nonce direction).
    pub role: SessionRole,
    /// ACK engine for reliable delivery (Mutex for &mut access).
    pub ack_engine: Arc<std::sync::Mutex<AckEngine>>,
    /// Active streams for multiplexing.
    pub streams: Arc<DashMap<u16, StreamState>>,
    /// Next available stream ID.
    pub next_stream_id: AtomicU16,
    /// Throughput statistics.
    pub stats: Arc<ThroughputStats>,
    /// Whether to use bulk frames for this session (auto-detected).
    pub use_bulk: bool,

    // ── Re-keying State ──────────────────────────────────────────────
    /// Whether a re-key operation is currently in progress.
    pub rekey_in_progress: AtomicBool,
    /// The old master key, retained during the grace period after re-keying.
    /// Packets encrypted with this key are still accepted until the grace
    /// counter is exhausted.
    pub old_master_key: Option<[u8; 32]>,
    /// Counter at which we accepted the new key. The grace period accepts
    /// old-key packets with counter up to `rekey_grace_deadline`.
    pub rekey_grace_counter: AtomicU32,
    /// The new session hash (valid after re-key completes).
    pub new_session_hash: Option<[u8; 4]>,
    /// Number of packets received with the new key (for monitoring).
    pub new_key_packets: AtomicU32,
}

/// State for an individual multiplexed stream.
pub struct StreamState {
    /// Stream type / purpose identifier.
    pub stream_type: StreamType,
    /// Inbound reassembly buffer (ordered by sequence number).
    pub recv_buf: Vec<Option<Bytes>>,
    /// Next expected sequence number.
    pub next_seq: u32,
    /// When the stream was created.
    pub created_at: Instant,
    /// Total bytes received on this stream.
    pub bytes_recv: u64,
    /// Total bytes sent on this stream.
    pub bytes_sent: u64,
}

/// Classification of stream traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    /// Control messages (handshake, routing updates, reputation).
    Control,
    /// Bulk data transfer (files, database replication).
    Bulk,
    /// Streaming data (video, audio, real-time).
    Stream,
    /// Interactive data (CLI messages, chat).
    Interactive,
}

/// Which side initiated the session. Determines the AEAD nonce direction byte
/// (see `l2_aead::NonceDirection`) so both directions never reuse nonces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    /// We initiated the handshake.
    Initiator,
    /// We answered the handshake.
    Responder,
}

/// Re-key result: whether the packet was accepted with the old key or new key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekeyAcceptResult {
    /// Accepted with the current (new) master key.
    AcceptedNewKey,
    /// Accepted with the old master key (grace period).
    AcceptedOldKey,
    /// Rejected (not a valid re-key packet).
    Rejected,
}

impl Session {
    /// Create a new session for a peer (assumes we are the initiator).
    pub fn new(master_key: [u8; 32], peer_fingerprint: String) -> Self {
        Self::new_with_role(master_key, peer_fingerprint, SessionRole::Initiator)
    }

    /// Create a new session for a peer with an explicit role.
    pub fn new_with_role(
        master_key: [u8; 32],
        peer_fingerprint: String,
        role: SessionRole,
    ) -> Self {
        let session_hash = compute_session_hash(&master_key);
        Self {
            master_key,
            tx_counter: AtomicU32::new(2), // 0=handshake, 1=response, 2+=data
            guard: SessionGuard::new(),
            peer_fingerprint,
            established_at: Instant::now(),
            session_hash,
            role,
            ack_engine: Arc::new(std::sync::Mutex::new(AckEngine::new())),
            streams: Arc::new(DashMap::new()),
            next_stream_id: AtomicU16::new(1),
            stats: Arc::new(ThroughputStats::new()),
            use_bulk: false,
            // Re-keying state
            rekey_in_progress: AtomicBool::new(false),
            old_master_key: None,
            rekey_grace_counter: AtomicU32::new(0),
            new_session_hash: None,
            new_key_packets: AtomicU32::new(0),
        }
    }

    /// Allocate a new stream for multiplexed data.
    pub fn open_stream(&self, stream_type: StreamType) -> u16 {
        let id = self.next_stream_id.fetch_add(1, Ordering::Relaxed);
        let id = if id == 0 { 1 } else { id }; // skip 0 (reserved)
        let id = id % MAX_STREAMS;
        self.streams.insert(
            id,
            StreamState {
                stream_type,
                recv_buf: Vec::new(),
                next_seq: 0,
                created_at: Instant::now(),
                bytes_recv: 0,
                bytes_sent: 0,
            },
        );
        id
    }

    /// Increment and return the next transmit counter.
    ///
    /// Returns `None` if the session has exhausted its counter space and
    /// requires re-keying (caller should trigger a re-key handshake).
    pub fn try_next_tx_counter(&self) -> Option<u32> {
        loop {
            let current = self.tx_counter.load(Ordering::Relaxed);
            // Reserve 0 and 1 for initial handshake PDUs.
            // Reserve REKEY_SENTINEL (0xFFFF_FFFE), REKEY_RESPONSE_SENTINEL (0xFFFF_FFFD),
            // and u32::MAX as sentinel values for the re-key protocol.
            // This makes the last usable counter REKEY_RESPONSE_SENTINEL - 1 = 0xFFFF_FFFC.
            let max_usable = REKEY_RESPONSE_SENTINEL - 1; // 0xFFFF_FFFC
            if current >= max_usable {
                return None; // exhausted
            }
            let next = current + 1;
            if self
                .tx_counter
                .compare_exchange(current, next, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                return Some(next);
            }
        }
    }

    /// Legacy wrapper: panics if counter space is exhausted.
    /// Prefer `try_next_tx_counter()` for production use.
    pub fn next_tx_counter(&self) -> u32 {
        self.try_next_tx_counter().unwrap_or({
            // Return REKEY_SENTINEL as a signal — the sender should
            // stop sending data and initiate a re-key.
            REKEY_SENTINEL
        })
    }

    /// Check whether the session needs re-keying based on tx_counter.
    pub fn needs_rekey(&self) -> bool {
        let tx = self.tx_counter.load(Ordering::Relaxed);
        tx >= REKEY_THRESHOLD || tx >= u32::MAX - 1000 || self.is_rekey_stalled()
    }

    /// Check if a re-key was initiated but never completed within a reasonable
    /// number of packets (stalled detection).
    pub fn is_rekey_stalled(&self) -> bool {
        if !self.rekey_in_progress.load(Ordering::Relaxed) {
            return false;
        }
        // If we've sent more than 5000 packets since initiating re-key
        // and it hasn't completed, consider it stalled.
        self.tx_counter.load(Ordering::Relaxed) > REKEY_THRESHOLD + 5000
    }

    /// Begin the re-key process. Returns the current tx_counter value
    /// to use for the re-key handshake PDU.
    pub fn begin_rekey(&self) -> u32 {
        self.rekey_in_progress.store(true, Ordering::Relaxed);
        REKEY_SENTINEL
    }

    /// Complete the re-key process: swap the master key and set up the
    /// grace period for old-key packets.
    ///
    /// `new_master_key`: the freshly derived hybrid master key.
    /// `current_counter`: the counter at which the new key takes effect.
    pub fn complete_rekey(&mut self, new_master_key: [u8; 32], current_counter: u32) {
        // Save the old key for the grace period
        self.old_master_key = Some(self.master_key);
        self.rekey_grace_counter
            .store(current_counter + OLD_KEY_GRACE_PACKETS, Ordering::Relaxed);

        // Install the new master key
        self.master_key = new_master_key;
        let new_hash = compute_session_hash(&self.master_key);
        self.new_session_hash = Some(new_hash);
        self.session_hash = new_hash;
        self.rekey_in_progress.store(false, Ordering::Relaxed);
        self.new_key_packets.store(0, Ordering::Relaxed);

        // Reset the tx_counter to 2 (0 and 1 are reserved for handshake)
        self.tx_counter.store(2, Ordering::Relaxed);

        // Reset the replay guard for the new key epoch
        self.guard.reset();
    }

    /// Attempt to decrypt a packet using either the current key or the old key
    /// (during grace period). Tries the new key first, then falls back to the
    /// old key if within the grace counter window.
    ///
    /// Returns `Some((plaintext, RekeyAcceptResult))` if decryption succeeded,
    /// `None` if decryption failed with both keys.
    pub fn try_decrypt_with_grace(
        &self,
        counter: u32,
        new_key_data: &mut Vec<u8>,
    ) -> Option<RekeyAcceptResult> {
        // Try the current (new) master key first
        if crate::ghost::layers::l2_aead::decrypt_in_place(&self.master_key, counter, new_key_data)
            .is_ok()
        {
            self.new_key_packets.fetch_add(1, Ordering::Relaxed);
            return Some(RekeyAcceptResult::AcceptedNewKey);
        }

        // Try the old key if within grace period
        if let Some(ref old_key) = self.old_master_key {
            let grace_end = self.rekey_grace_counter.load(Ordering::Relaxed);
            if counter <= grace_end {
                // Clone the data to try old key decryption
                let mut old_data = new_key_data.clone();
                if crate::ghost::layers::l2_aead::decrypt_in_place(old_key, counter, &mut old_data)
                    .is_ok()
                {
                    // Copy old-key plaintext back to caller
                    *new_key_data = old_data;
                    return Some(RekeyAcceptResult::AcceptedOldKey);
                }
            }
        }

        None
    }

    /// Check and update the replay guard for an inbound counter.
    /// This version also handles the re-key grace period counters.
    pub fn check_inbound(&mut self, counter: u32) -> bool {
        // During re-key, the replay guard was reset, so counters >= 2
        // are accepted fresh.
        self.guard.check_and_update(counter)
    }

    /// Check if the session is still valid (no timeout expiry).
    pub fn is_valid(&self) -> bool {
        self.guard.is_valid()
    }

    /// Enable bulk frame mode (MTU-optimized 1472-byte frames).
    pub fn enable_bulk(&mut self) {
        self.use_bulk = true;
    }

    /// Disable bulk frame mode (revert to privacy frames).
    pub fn disable_bulk(&mut self) {
        self.use_bulk = false;
    }

    /// Get the frame size to use for this session.
    pub fn frame_size(&self) -> usize {
        if self.use_bulk {
            crate::ghost::net::GTF_BULK_SIZE
        } else {
            crate::ghost::net::GTF_BASE_SIZE
        }
    }

    /// Expire the old key (called after grace period ends).
    pub fn expire_old_key(&mut self) {
        if self.old_master_key.is_some() {
            // Volatile-zero the old key
            if let Some(ref mut old) = self.old_master_key {
                for b in old.iter_mut() {
                    unsafe {
                        std::ptr::write_volatile(b, 0u8);
                    }
                }
            }
            self.old_master_key = None;
            info!(
                "Session {}: old key expired after grace period",
                self.peer_fingerprint
            );
        }
    }
}

// ── Re-key PDU Construction and Parsing ─────────────────────────────

/// Build a re-key handshake PDU (initiator side).
///
/// Layout:
///   [0..16]   "GHOST_REKEY____"
///   [16..48]  Initiator's X25519 ephemeral public key (32 bytes)
///   [48..848] Initiator's Kyber-512 public key (800 bytes)
///   [848..912] Ed25519 signature over (x_pub || ky_pub)
///
/// The responder's identity is already known from the existing session,
/// so we don't need to send the identity public key again.
pub fn build_rekey_pdu(
    identity_sign: impl Fn(&[u8]) -> [u8; 64],
    x_pub: &x25519_dalek::PublicKey,
    kyber_pub: &EncapsulationKey512,
) -> Vec<u8> {
    let kyber_bytes = kyber_pub.to_bytes();
    let mut pdu = vec![0u8; REKEY_BLOB_LEN];
    pdu[0..16].copy_from_slice(REKEY_MAGIC);
    pdu[16..48].copy_from_slice(x_pub.as_bytes());
    pdu[48..848].copy_from_slice(&kyber_bytes);

    // Signed material is x25519_pub || kyber_pub (32 + 800 = 832 bytes)
    let signed_material = {
        let mut m = Vec::with_capacity(32 + kyber_bytes.len());
        m.extend_from_slice(x_pub.as_bytes());
        m.extend_from_slice(&kyber_bytes);
        m
    };

    let sig = identity_sign(&signed_material);
    pdu[848..912].copy_from_slice(&sig);
    pdu
}

/// Parse a re-key handshake PDU.
pub struct RekeyBlob {
    pub x25519_pub: [u8; 32],
    pub kyber_pub: [u8; 800],
    pub signature: [u8; 64],
}

pub fn parse_rekey_pdu(data: &[u8]) -> Option<RekeyBlob> {
    if data.len() < REKEY_BLOB_LEN || !data.starts_with(REKEY_MAGIC) {
        return None;
    }
    let mut x25519_pub = [0u8; 32];
    x25519_pub.copy_from_slice(&data[16..48]);
    let mut kyber_pub = [0u8; 800];
    kyber_pub.copy_from_slice(&data[48..848]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[848..912]);
    Some(RekeyBlob {
        x25519_pub,
        kyber_pub,
        signature,
    })
}

/// Build a re-key response PDU (responder side).
///
/// Layout:
///   [0..16]   "GHOST_REKEY_RSP"
///   [16..48]  Responder's X25519 ephemeral public key (32 bytes)
///   [48..816] Responder's Kyber-512 ciphertext (768 bytes)
///   [816..880] Ed25519 signature over (x_pub || ct)
pub fn build_rekey_response_pdu(
    identity_sign: impl Fn(&[u8]) -> [u8; 64],
    x_pub: &[u8; 32],
    kyber_ct: &[u8; 768],
) -> Vec<u8> {
    let mut pdu = vec![0u8; REKEY_RESPONSE_BLOB_LEN];
    pdu[0..16].copy_from_slice(REKEY_RESPONSE_MAGIC);
    pdu[16..48].copy_from_slice(x_pub);
    pdu[48..816].copy_from_slice(kyber_ct);

    let signed_material = {
        let mut m = vec![0u8; 800];
        m[0..32].copy_from_slice(x_pub);
        m[32..800].copy_from_slice(kyber_ct);
        m
    };

    let sig = identity_sign(&signed_material);
    pdu[816..880].copy_from_slice(&sig);
    pdu
}

/// Parse a re-key response PDU.
pub struct RekeyResponseBlob {
    pub x25519_pub: [u8; 32],
    pub kyber_ct: [u8; 768],
    pub signature: [u8; 64],
}

pub fn parse_rekey_response_pdu(data: &[u8]) -> Option<RekeyResponseBlob> {
    if data.len() < REKEY_RESPONSE_BLOB_LEN || !data.starts_with(REKEY_RESPONSE_MAGIC) {
        return None;
    }
    let mut x25519_pub = [0u8; 32];
    x25519_pub.copy_from_slice(&data[16..48]);
    let mut kyber_ct = [0u8; 768];
    kyber_ct.copy_from_slice(&data[48..816]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[816..880]);
    Some(RekeyResponseBlob {
        x25519_pub,
        kyber_ct,
        signature,
    })
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghost::layers::l0_identity;

    #[test]
    fn test_session_initial_state() {
        let key = [0x42u8; 32];
        let session = Session::new(key, "test_fp".to_string());
        assert_eq!(session.tx_counter.load(Ordering::Relaxed), 2);
        assert!(!session.needs_rekey());
        assert!(!session.rekey_in_progress.load(Ordering::Relaxed));
        assert!(session.old_master_key.is_none());
        assert!(session.is_valid());
    }

    #[test]
    fn test_next_tx_counter_increment() {
        let key = [0x42u8; 32];
        let session = Session::new(key, "test_fp".to_string());
        let ctr = session.try_next_tx_counter().unwrap();
        assert_eq!(ctr, 3); // started at 2, first call returns 3
        let ctr2 = session.try_next_tx_counter().unwrap();
        assert_eq!(ctr2, 4);
    }

    #[test]
    fn test_next_tx_counter_reserved_sentinels() {
        let key = [0x42u8; 32];
        let session = Session::new(key, "test_fp".to_string());
        // max_usable is REKEY_RESPONSE_SENTINEL - 1 = 0xFFFF_FFFC.
        // Set to one below that to verify it still works.
        let max_usable = REKEY_RESPONSE_SENTINEL - 1;
        session.tx_counter.store(max_usable - 1, Ordering::Relaxed);
        let ctr = session.try_next_tx_counter().unwrap();
        assert_eq!(ctr, max_usable);
        // Next call should fail since we're at max_usable
        assert!(session.try_next_tx_counter().is_none());
    }

    #[test]
    fn test_needs_rekey_at_threshold() {
        let key = [0x42u8; 32];
        let session = Session::new(key, "test_fp".to_string());
        assert!(!session.needs_rekey());
        // Set counter just below threshold
        session
            .tx_counter
            .store(REKEY_THRESHOLD - 1, Ordering::Relaxed);
        assert!(!session.needs_rekey());
        // At threshold
        session.tx_counter.store(REKEY_THRESHOLD, Ordering::Relaxed);
        assert!(session.needs_rekey());
        // Far past threshold
        session
            .tx_counter
            .store(REKEY_THRESHOLD + 50000, Ordering::Relaxed);
        assert!(session.needs_rekey());
    }

    #[test]
    fn test_rekey_complete_and_grace_period() {
        let old_key = [0xABu8; 32];
        let new_key = [0xCDu8; 32];
        let mut session = Session::new(old_key, "test_fp".to_string());

        assert_eq!(session.master_key, old_key);
        assert!(session.old_master_key.is_none());

        // Complete re-key at counter 5000
        session.complete_rekey(new_key, 5000);

        // New key should be installed
        assert_eq!(session.master_key, new_key);
        assert!(session.old_master_key.is_some());
        assert_eq!(session.old_master_key.unwrap(), old_key);
        assert_eq!(
            session.rekey_grace_counter.load(Ordering::Relaxed),
            5000 + OLD_KEY_GRACE_PACKETS
        );
        // Tx counter reset to 2
        assert_eq!(session.tx_counter.load(Ordering::Relaxed), 2);
        // New session hash should be computed
        assert!(session.new_session_hash.is_some());
    }

    #[test]
    fn test_rekey_pdu_roundtrip() {
        let identity = l0_identity::GhostIdentity::generate_fresh();
        let (_x_sec, x_pub) = crate::ghost::layers::l1_kem::generate_x25519_keypair();
        let (ky_pub, _ky_sec) = crate::ghost::layers::l1_kem::generate_kyber_keypair();

        let pdu = build_rekey_pdu(|data| identity.sign(data).to_bytes(), &x_pub, &ky_pub);

        assert_eq!(pdu.len(), REKEY_BLOB_LEN);
        assert!(pdu.starts_with(REKEY_MAGIC));

        let parsed = parse_rekey_pdu(&pdu).expect("Should parse re-key PDU");
        assert_eq!(&parsed.x25519_pub[..], x_pub.as_bytes());
        assert_eq!(&parsed.kyber_pub[..], ky_pub.to_bytes().as_slice());

        // Verify signature using the same signed material construction as build_rekey_pdu
        let signed_material = [x_pub.as_bytes(), ky_pub.to_bytes().as_slice()].concat();
        assert!(l0_identity::verify_peer_signature(
            &identity.public_key_bytes(),
            &signed_material,
            &parsed.signature,
        ));
    }

    #[test]
    fn test_rekey_response_pdu_roundtrip() {
        let identity = l0_identity::GhostIdentity::generate_fresh();
        let x_pub = [0xABu8; 32];
        let kyber_ct = [0xCDu8; 768];

        let pdu =
            build_rekey_response_pdu(|data| identity.sign(data).to_bytes(), &x_pub, &kyber_ct);

        assert_eq!(pdu.len(), REKEY_RESPONSE_BLOB_LEN);
        assert!(pdu.starts_with(REKEY_RESPONSE_MAGIC));

        let parsed = parse_rekey_response_pdu(&pdu).expect("Should parse re-key response");
        assert_eq!(parsed.x25519_pub, x_pub);
        assert_eq!(parsed.kyber_ct, kyber_ct);

        // Verify signature
        let signed_material = {
            let mut m = vec![0u8; 800];
            m[0..32].copy_from_slice(&x_pub);
            m[32..800].copy_from_slice(&kyber_ct);
            m
        };
        assert!(l0_identity::verify_peer_signature(
            &identity.public_key_bytes(),
            &signed_material,
            &parsed.signature,
        ));
    }

    #[test]
    fn test_stalled_rekey_detection() {
        let key = [0x42u8; 32];
        let session = Session::new(key, "test_fp".to_string());
        assert!(!session.is_rekey_stalled());

        session.rekey_in_progress.store(true, Ordering::Relaxed);
        // Not stalled yet — only at REKEY_THRESHOLD
        session.tx_counter.store(REKEY_THRESHOLD, Ordering::Relaxed);
        assert!(!session.is_rekey_stalled());

        // Stalled — more than 5000 packets past threshold
        session
            .tx_counter
            .store(REKEY_THRESHOLD + 5001, Ordering::Relaxed);
        assert!(session.is_rekey_stalled());
    }

    #[test]
    fn test_begin_rekey_returns_sentinel() {
        let key = [0x42u8; 32];
        let session = Session::new(key, "test_fp".to_string());
        let ctr = session.begin_rekey();
        assert_eq!(ctr, REKEY_SENTINEL);
        assert!(session.rekey_in_progress.load(Ordering::Relaxed));
    }
}
