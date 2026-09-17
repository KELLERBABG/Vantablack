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
pub mod ratchet;

use crate::ghost::layers::l1_kem::{compute_session_hash, HybridCipherSuite};
use crate::ghost::layers::l2_aead::NonceDirection;
use crate::ghost::layers::l6_session::SessionGuardU64;
use crate::ghost::net::{AckEngine, ThroughputStats};
use crate::ghost::session::ratchet::{OpenPlan, RatchetStep, SessionRatchet, StepSecrets};
use bytes::Bytes;
use dashmap::DashMap;
use ml_kem::kem::{KeyExport, TryKeyInit};
use ml_kem::EncapsulationKey512;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicU8, Ordering};
use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Maximum number of concurrent streams per session.
pub const MAX_STREAMS: u16 = 256;

/// Re-key threshold for the *legacy* 32-bit counter, kept for the watchdog that
/// reports it. The v2 wire format uses a 64-bit counter and no longer reserves
/// sentinel values in it, so this is a warning line, not a wall.
pub const REKEY_THRESHOLD: u64 = 0xFFFF_FFFF_C000_0000; // 75% of u64::MAX

/// Magic bytes for the re-key handshake PDU.
pub const REKEY_MAGIC: &[u8; 16] = b"GHOST_REKEY____!";
/// Magic bytes for the re-key response PDU.
pub const REKEY_RESPONSE_MAGIC: &[u8; 16] = b"GHOST_REKEY_RSP!";

/// Size of the re-key handshake PDU: 16 magic + 32 X25519 + 800 Kyber + 64 sig = 912
pub const REKEY_BLOB_LEN: usize = 912;
/// Size of the re-key response PDU: 16 magic + 32 X25519 + 768 ct + 32 confirm + 64 sig = 912.
///
/// It grew by the confirmation tag in the P2-2 wiring: the step must be provably
/// agreed *before* either side acts on it, or a step with divergent keys looks like
/// a dead link.
pub const REKEY_RESPONSE_BLOB_LEN: usize = 912;

/// Full session state for a peer connection.
pub struct Session {
    /// The hybrid master key (X25519 + Kyber-512 derived).
    pub master_key: [u8; 32],
    /// Per-peer outbound monotonic counter (64-bit: a wrapping sequence number
    /// would be rejected forever by the peer's sliding window).
    pub tx_counter: AtomicU64,
    /// Per-peer inbound replay guard — the 64-bit sliding window, which is the
    /// primary replay defence now that the wire counter is 64-bit.
    pub guard: Mutex<SessionGuardU64>,
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
    /// KEM suite authenticated by the handshake transcript.
    pub cipher_suite: HybridCipherSuite,

    // ── Ratchet State (SOTA P2-2) ────────────────────────────────────
    /// The hybrid DH ratchet. It owns every AEAD key this session uses: the
    /// master key above is the *seed*, and the epoch ring inside the ratchet is
    /// what actually seals and opens frames.
    ratchet: Mutex<SessionRatchet>,
    /// Ephemeral material for a step we started and are waiting on an answer for.
    /// Held here rather than in the ratchet because a step that is never answered
    /// must be droppable without disturbing the live epoch.
    pending_step: Mutex<Option<RatchetStep>>,
    /// When the in-flight step started, so a lost answer is retried rather than
    /// wedging the session at the current epoch forever.
    ratchet_step_at: Mutex<Option<Instant>>,
    /// How many ratchet steps this session completed, for status output.
    pub ratchet_steps: AtomicU64,
    /// Whether a step is in flight (so a due ratchet does not start a second one).
    pub ratchet_in_progress: AtomicBool,
    /// Forced expedited ratchet requested due to gap > MAX_SKIP or epoch exhaustion.
    pub forced_ratchet_due: AtomicBool,
    /// The peer's Ed25519 identity key, pinned when the session was established.
    ///
    /// A ratchet step has to be authenticated *before* it is acted on: the
    /// responder derives and can then open a new epoch on receipt, so an injected
    /// step would move one side of a session and not the other. The sessions's own
    /// authentication ran at handshake time, so this is where the proof is kept.
    /// `None` means the step is **refused**, never accepted on trust.
    peer_identity_pk: Mutex<Option<[u8; 32]>>,
    // ── Post-Quantum Hybrid Identity Authentication (SOTA G3) ────────
    /// 0 = Pending, 1 = Authenticated, 2 = Failed
    pub pq_auth_state: AtomicU8,
    /// The peer's pinned 32-byte SHA-256 PQ commitment from the handshake negotiation.
    peer_pq_commitment: Mutex<Option<[u8; 32]>>,
    /// The peer's verified ML-DSA-65 public key (1952 bytes).
    peer_pq_pk: Mutex<Option<Vec<u8>>>,
    /// Received chunks of the peer's hybrid identity binding.
    pq_incoming_chunks: Mutex<std::collections::HashMap<u8, Vec<u8>>>,
    /// When PQ auth was initiated.
    pub pq_auth_requested_at: Instant,
}

/// A responder's reply to a ratchet step.
pub struct RatchetAnswer {
    /// The responder's ephemeral X25519 public key.
    pub x_public: [u8; 32],
    /// ML-KEM-512 ciphertext carrying the encapsulated shared secret.
    pub kem_ct: [u8; 768],
    /// Tag derived from the new epoch key, so the initiator can verify agreement.
    pub confirm: [u8; 32],
    /// The epoch the responder prepared. The initiator checks it against its own
    /// preview, so a replayed *older* answer cannot move the ratchet backwards.
    pub epoch: u64,
}

/// The material one v2 message is sealed with (SOTA P2-2).
#[derive(Clone)]
pub struct SealMaterial {
    /// Epoch key for our sending direction.
    pub key: [u8; 32],
    /// Ratchet generation `key` belongs to; goes in the frame header.
    pub epoch: u64,
    /// Monotone sequence number for replay protection.
    pub counter: u64,
    /// Random 96-bit nonce, carried verbatim on the wire.
    pub nonce: [u8; 12],
    /// The direction the key seals in (for the receiver's chain selection).
    pub direction: NonceDirection,
    /// Whether this message filled the epoch: the caller should start a ratchet
    /// step. Traffic continues on the current epoch until that step completes.
    pub ratchet_due: bool,
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

impl SessionRole {
    /// The direction this role *sends* in.
    pub fn seal_direction(self) -> NonceDirection {
        match self {
            Self::Initiator => NonceDirection::InitiatorToResponder,
            Self::Responder => NonceDirection::ResponderToInitiator,
        }
    }
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
            tx_counter: AtomicU64::new(2), // 0=handshake, 1=response, 2+=data
            guard: Mutex::new(SessionGuardU64::new()),
            peer_fingerprint,
            established_at: Instant::now(),
            session_hash,
            role,
            ack_engine: Arc::new(std::sync::Mutex::new(AckEngine::new())),
            streams: Arc::new(DashMap::new()),
            next_stream_id: AtomicU16::new(1),
            stats: Arc::new(ThroughputStats::new()),
            use_bulk: false,
            cipher_suite: HybridCipherSuite::X25519MlKem512V2,
            // Ratchet state: epoch 0's keys are one chain step from the seed, so
            // the handshake key alone does not read epoch 0 either.
            ratchet: Mutex::new(SessionRatchet::new(master_key)),
            pending_step: Mutex::new(None),
            ratchet_step_at: Mutex::new(None),
            ratchet_steps: AtomicU64::new(0),
            ratchet_in_progress: AtomicBool::new(false),
            forced_ratchet_due: AtomicBool::new(false),
            peer_identity_pk: Mutex::new(None),
            pq_auth_state: AtomicU8::new(0),
            peer_pq_commitment: Mutex::new(None),
            peer_pq_pk: Mutex::new(None),
            pq_incoming_chunks: Mutex::new(std::collections::HashMap::new()),
            pq_auth_requested_at: Instant::now(),
        }
    }

    /// Set the suite selected and authenticated during the handshake.
    pub fn set_cipher_suite(&mut self, suite: HybridCipherSuite) {
        self.cipher_suite = suite;
    }

    /// Pin the peer's Ed25519 identity key (done where the handshake verified it).
    pub fn pin_peer_identity(&self, pk: [u8; 32]) {
        *self
            .peer_identity_pk
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(pk);
    }

    /// The peer's pinned identity key, if the handshake recorded one.
    pub fn peer_identity_pk(&self) -> Option<[u8; 32]> {
        *self
            .peer_identity_pk
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Check whether this session has completed post-quantum hybrid identity verification (SOTA G3).
    /// If no PQ commitment was negotiated (e.g. legacy compatibility or uncommitted unit tests),
    /// this returns true. If a PQ commitment was negotiated, the session is gated until verified.
    pub fn is_pq_authenticated(&self) -> bool {
        self.peer_pq_commitment().is_none() || self.pq_auth_state.load(Ordering::Acquire) == 1
    }

    /// Read the raw PQ auth state (0 = Pending, 1 = Authenticated, 2 = Failed).
    pub fn pq_auth_state(&self) -> u8 {
        self.pq_auth_state.load(Ordering::Acquire)
    }

    /// Mark the post-quantum authentication result.
    pub fn set_pq_authenticated(&self, valid: bool) {
        let state = if valid { 1 } else { 2 };
        self.pq_auth_state.store(state, Ordering::Release);
    }

    /// Pin the peer's post-quantum commitment from the handshake transcript.
    pub fn pin_peer_pq_commitment(&self, commitment: [u8; 32]) {
        *self
            .peer_pq_commitment
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(commitment);
    }

    /// The peer's pinned PQ commitment, if recorded during handshake.
    pub fn peer_pq_commitment(&self) -> Option<[u8; 32]> {
        *self
            .peer_pq_commitment
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Pin the verified ML-DSA-65 public key once proof is authenticated.
    pub fn set_peer_pq_pk(&self, pk: Vec<u8>) {
        *self
            .peer_pq_pk
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(pk);
    }

    /// The peer's verified ML-DSA-65 public key.
    pub fn peer_pq_pk(&self) -> Option<Vec<u8>> {
        self.peer_pq_pk
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Store an incoming chunk of the peer's PQ identity binding.
    /// If all chunks have arrived, returns the complete concatenated payload.
    pub fn store_pq_chunk(
        &self,
        chunk_idx: u8,
        total_chunks: u8,
        data: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let mut guard = self
            .pq_incoming_chunks
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        guard.insert(chunk_idx, data);
        if guard.len() == total_chunks as usize {
            let mut assembled = Vec::new();
            for idx in 0..total_chunks {
                if let Some(chunk) = guard.get(&idx) {
                    assembled.extend_from_slice(chunk);
                } else {
                    return None;
                }
            }
            Some(assembled)
        } else {
            None
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
    /// Returns `None` only at the true end of the 64-bit space, which no link can
    /// reach (at 10 Gbit/s of 512-byte frames it is ~2 300 years). v1 reserved
    /// three sentinel values near `u32::MAX` and stopped a million frames early
    /// because those counters would otherwise have collided with the *re-key
    /// protocol* — a 64-bit counter has nothing to reserve.
    pub fn try_next_tx_counter(&self) -> Option<u64> {
        loop {
            let current = self.tx_counter.load(Ordering::Relaxed);
            let next = current.checked_add(1)?;
            if self
                .tx_counter
                .compare_exchange(current, next, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                return Some(next);
            }
        }
    }

    /// The next transmit counter, saturating at the end of the space.
    pub fn next_tx_counter(&self) -> u64 {
        self.try_next_tx_counter().unwrap_or(u64::MAX)
    }

    // ── Ratchet (SOTA P2-2) ─────────────────────────────────────────

    /// Take the next message key for sealing and advance the chain. Returns `(counter, key)`.
    pub fn advance_seal(&self, direction: NonceDirection) -> (u64, [u8; 32]) {
        self.ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .advance_seal(direction)
    }

    /// The AEAD key the *current* epoch would next seal with, for one direction.
    pub fn seal_key(&self, direction: NonceDirection) -> [u8; 32] {
        self.ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .seal_key(direction)
    }

    /// Plan how to open `counter` in `epoch` and `direction`, without mutating state.
    pub fn plan_open(&self, epoch: u64, direction: NonceDirection, counter: u64) -> OpenPlan {
        self.ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .plan_open(epoch, direction, counter)
    }

    /// Apply an open plan after the frame authenticates.
    pub fn commit_open(&self, epoch: u64, direction: NonceDirection, plan: OpenPlan) {
        self.ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .commit_open(epoch, direction, plan);
    }

    /// The AEAD key for a *named* epoch and counter, if it is still openable.
    pub fn open_key(&self, epoch: u64, direction: NonceDirection, counter: u64) -> Option<[u8; 32]> {
        self.ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .open_key(epoch, direction, counter)
    }

    /// Whether an unopenable frame's counter exceeded MAX_SKIP past our chain position.
    pub fn gap_exceeds_max_skip(&self, epoch: u64, direction: NonceDirection, counter: u64) -> bool {
        self.ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .gap_exceeds_max_skip(epoch, direction, counter)
    }

    /// Trigger an expedited, rate-limited ratchet step when the peer's counter drifts beyond MAX_SKIP.
    pub fn trigger_forced_ratchet_step(&self) -> bool {
        if self.ratchet_in_progress.load(Ordering::Relaxed) {
            return false;
        }
        let now = Instant::now();
        let mut last = self.ratchet_step_at.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(prev) = *last {
            if now.duration_since(prev) < Duration::from_secs(15) {
                return false;
            }
        }
        *last = Some(now);
        self.forced_ratchet_due.store(true, Ordering::Relaxed);
        tracing::info!(peer = %self.peer_fingerprint, "forced rate-limited ratchet step requested due to packet gap");
        true
    }

    /// The current ratchet generation.
    pub fn epoch(&self) -> u64 {
        self.ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .epoch()
    }

    /// Epochs this session can still open, newest first.
    pub fn openable_epochs(&self) -> Vec<u64> {
        self.ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .openable_epochs()
    }

    /// Frames this epoch may still seal before a step is due.
    pub fn epoch_capacity_left(&self) -> u64 {
        self.ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .epoch_capacity_left()
    }

    /// Whether the epoch is spent and a ratchet step is owed. Read-only, so the
    /// maintenance task can ask without spending a counter.
    pub fn ratchet_due(&self) -> bool {
        self.epoch_capacity_left() == 0 || self.forced_ratchet_due.load(Ordering::Relaxed)
    }

    /// The epoch a step is prepared for, if one is mid-flight.
    pub fn prepared_epoch(&self) -> Option<u64> {
        self.ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .prepared_epoch()
    }

    /// Install a prepared epoch. Called on the responder side once a frame has
    /// actually authenticated under it.
    pub fn activate_epoch(&self, epoch: u64) -> bool {
        let activated = self
            .ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .activate(epoch);
        if activated {
            self.ratchet_steps.fetch_add(1, Ordering::Relaxed);
            self.guard.lock().unwrap_or_else(|e| e.into_inner()).reset();
            tracing::debug!(
                peer = %self.peer_fingerprint,
                epoch,
                "ratchet step installed after the peer used the new epoch"
            );
        }
        activated
    }

    /// Seal material for a *named* epoch, used to answer a step on the epoch the
    /// peer still holds.
    pub fn seal_material_at(&self, epoch: u64, direction: NonceDirection, counter: u64) -> Option<SealMaterial> {
        let key = self.open_key(epoch, direction, counter)?;
        Some(SealMaterial {
            key,
            epoch,
            counter,
            nonce: crate::ghost::layers::l2_aead::random_xnonce(),
            direction,
            ratchet_due: false,
        })
    }

    /// Whether a step has been in flight longer than `timeout`.
    pub fn ratchet_step_stalled(&self, timeout: Duration) -> bool {
        if !self.ratchet_in_progress.load(Ordering::Relaxed) {
            return false;
        }
        self.ratchet_step_at
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map(|t| t.elapsed() > timeout)
            .unwrap_or(false)
    }

    /// Count a frame sealed in this epoch. `true` means the session is due to
    /// ratchet — the caller should *start* a step and keep sending meanwhile.
    pub fn note_sealed_frame(&self) -> bool {
        self.ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .count_seal()
    }

    /// Apply a completed ratchet step. Returns the new epoch.
    pub fn apply_ratchet_step(&self, secrets: &StepSecrets) -> u64 {
        let epoch = self
            .ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .step(secrets);
        self.ratchet_steps.fetch_add(1, Ordering::Relaxed);
        self.ratchet_in_progress.store(false, Ordering::Relaxed);
        *self.pending_step.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *self
            .ratchet_step_at
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        self.guard.lock().unwrap_or_else(|e| e.into_inner()).reset();
        epoch
    }

    /// Start a ratchet step: generate fresh ephemeral hybrid material and hold it
    /// until the peer answers. Returns `(x25519 public, ML-KEM-512 public)` for the
    /// step PDU, or `None` if a step is already in flight.
    ///
    /// The step is *not* applied here. Nothing about the live epoch changes until
    /// the answer arrives, so an unanswered step costs a PDU and nothing else.
    pub fn begin_ratchet_step(&self) -> Option<([u8; 32], Vec<u8>)> {
        if self.ratchet_in_progress.swap(true, Ordering::SeqCst) {
            return None;
        }
        self.forced_ratchet_due.store(false, Ordering::Relaxed);
        let step = RatchetStep::generate();
        let x = step.x_public_bytes();
        let kem = step.kem_public_bytes();
        *self.pending_step.lock().unwrap_or_else(|e| e.into_inner()) = Some(step);
        *self
            .ratchet_step_at
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
        Some((x, kem))
    }

    /// Finish a step we started, from the peer's answer. Returns the new epoch.
    ///
    /// **The confirmation tag is verified before the step is applied**, and a
    /// mismatch means the step failed — not that it should be retried with the same
    /// material, which is consumed either way. Without this check a step can
    /// "succeed" on both sides with different keys (X25519 happily returns a shared
    /// secret for a wrong or low-order public key), and the divergence only shows up
    /// later as traffic nobody can open.
    pub fn finish_ratchet_step(&self, answer: &RatchetAnswer) -> Option<u64> {
        let step = self
            .pending_step
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()?;
        let secrets = step.finish(&answer.x_public, &answer.kem_ct)?;
        let direction = self.seal_direction();
        let (previewed_epoch, key) = self
            .ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .preview_step_key(&secrets, direction);
        if answer.epoch != previewed_epoch {
            // A stale answer from an epoch we have already passed cannot be
            // allowed to name an old generation as the next one.
            tracing::warn!(
                peer = %self.peer_fingerprint,
                answer_epoch = answer.epoch,
                expected = previewed_epoch,
                "ratchet answer names the wrong epoch — refused"
            );
            self.ratchet_in_progress.store(false, Ordering::Relaxed);
            return None;
        }
        use subtle::ConstantTimeEq;
        if !bool::from(
            crate::ghost::layers::l1_kem::ratchet_confirm(&key)
                .as_slice()
                .ct_eq(answer.confirm.as_slice()),
        ) {
            tracing::warn!(
                peer = %self.peer_fingerprint,
                "ratchet step confirmation failed — refusing to advance the epoch"
            );
            self.ratchet_in_progress.store(false, Ordering::Relaxed);
            return None;
        }
        Some(self.apply_ratchet_step(&secrets))
    }

    /// Answer a peer's step: encapsulate against their material and **prepare** the
    /// new epoch (without sealing on it yet). Returns the material to send back,
    /// including the tag that lets the initiator verify the two sides landed on one
    /// key.
    ///
    /// Preparing rather than installing is what makes a lost answer survivable: the
    /// responder can *open* the new epoch immediately but keeps *sealing* on the old
    /// one until a frame authenticates under the new one, so it can never run an
    /// epoch ahead of a peer that never committed.
    pub fn answer_ratchet_step(
        &self,
        peer_x: &[u8; 32],
        peer_kem_pub: &[u8],
    ) -> Option<RatchetAnswer> {
        let step = RatchetStep::generate();
        let our_x = step.x_public_bytes();
        let (secrets, kem_ct) = step.respond(peer_x, peer_kem_pub)?;
        // The initiator verifies against the key it will *send* with, which is our
        // receiving direction — the same chain, viewed from the other side.
        let initiator_direction = self.seal_direction().peer_direction();
        let (epoch, key) = self
            .ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .prepare_step(&secrets, initiator_direction);
        Some(RatchetAnswer {
            x_public: our_x,
            kem_ct,
            confirm: crate::ghost::layers::l1_kem::ratchet_confirm(&key),
            epoch,
        })
    }

    /// Whether an arriving step PDU should be **answered**, resolving a *crossed*
    /// pair of steps.
    ///
    /// Both peers can become due in the same interval, and a crossed pair is not a
    /// duplicate to shrug at. If both sides answered *and completed* their own step,
    /// each would install epoch `n+1` derived from its own secrets: the same epoch
    /// number over two different root keys, so every frame fails to open from then
    /// on and no later step can repair it, because the roots have already diverged.
    /// A silent, permanent split reachable from two ordinary saturated links.
    ///
    /// The tie-break has to be a total order both sides compute from public data
    /// with no extra round trip, and the fingerprints are exactly that: the side
    /// whose fingerprint sorts lower keeps its own step, and the other side abandons
    /// the step it already sent and answers the arriving one. Both sides compute the
    /// same comparison with the labels swapped, so exactly one yields.
    ///
    /// `our_fingerprint` is passed in rather than stored: this type knows the
    /// *peer's* fingerprint (it is the sessions's map key) and deliberately does not
    /// carry a copy of our own identity's.
    ///
    /// Returns `true` to answer the arriving step (`false` means ours wins and the
    /// arriving one is dropped).
    pub fn admit_peer_step(&self, our_fingerprint: &str) -> bool {
        if !self.ratchet_in_progress.load(Ordering::Relaxed) {
            return true; // nothing crossed — the ordinary case
        }
        if our_fingerprint < self.peer_fingerprint.as_str() {
            tracing::debug!(
                peer = %self.peer_fingerprint,
                "crossed ratchet steps — our step wins, the arriving one is dropped"
            );
            return false;
        }
        tracing::debug!(
            peer = %self.peer_fingerprint,
            "crossed ratchet steps — yielding our step to answer the peer's"
        );
        self.abandon_ratchet_step();
        true
    }

    /// Drop an in-flight step (the answer never came). The live epoch is untouched.
    pub fn abandon_ratchet_step(&self) {
        *self.pending_step.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *self
            .ratchet_step_at
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        self.ratchet_in_progress.store(false, Ordering::Relaxed);
    }

    /// Check and update the replay guard for an inbound counter.
    pub fn check_inbound(&self, counter: u64) -> bool {
        self.guard
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .check_and_update(counter)
    }

    /// Check if the session is still valid (no timeout expiry, and PQ auth not failed/timed-out).
    pub fn is_valid(&self) -> bool {
        let pq_state = self.pq_auth_state.load(Ordering::Acquire);
        if pq_state == 2 {
            return false;
        }
        if self.peer_pq_commitment().is_some()
            && pq_state == 0
            && self.pq_auth_requested_at.elapsed() > Duration::from_secs(5)
        {
            return false;
        }
        self.guard
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_valid()
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

    /// The direction this side *sends* in — which decides which of the ratchet's
    /// two directional chains seals our frames.
    pub fn seal_direction(&self) -> NonceDirection {
        self.role.seal_direction()
    }

    /// Everything a v2 frame header needs to be sealed, taken in one consistent
    /// snapshot: the epoch key, the epoch it belongs to, the sequence number, and a
    /// fresh nonce.
    ///
    /// Taking these together matters — reading the key and the epoch separately
    /// could straddle a ratchet step and seal a frame under one epoch's key with
    /// another epoch's number, which no receiver could open.
    ///
    /// **One `SealMaterial` per message, not per frame.** The three Reed-Solomon
    /// shards of a message travel in three frames that share this nonce, because
    /// they are three pieces of *one* AEAD ciphertext: the receiver reassembles
    /// them and opens once. Spending a new nonce per shard would be a nonce reuse
    /// of a different kind — three separate encryptions of the same plaintext.
    pub fn seal_material(&self) -> SealMaterial {
        let mut ratchet = self.ratchet.lock().unwrap_or_else(|e| e.into_inner());
        let epoch = ratchet.epoch();
        let (counter, key) = ratchet.advance_seal(self.seal_direction());
        let due = ratchet.count_seal();
        drop(ratchet);
        self.tx_counter.store(counter + 1, Ordering::Relaxed);
        if due {
            self.forced_ratchet_due.store(true, Ordering::Relaxed);
        }
        SealMaterial {
            key,
            epoch,
            counter,
            nonce: crate::ghost::layers::l2_aead::random_xnonce(),
            direction: self.seal_direction(),
            ratchet_due: due,
        }
    }

    /// Zeroize the session's seed key. (The ratchet zeroizes its own chains and
    /// retired epoch keys on drop.)
    pub fn zeroize_keys(&mut self) {
        for b in self.master_key.iter_mut() {
            unsafe {
                std::ptr::write_volatile(b, 0u8);
            }
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

/// Build a ratchet-step PDU from **raw bytes** — the form a session's
/// `begin_ratchet_step` hands out.
///
/// [`build_rekey_pdu`] takes the wire types; this is the same message with the
/// conversion done once, so no caller has to know that a 32-byte array and an 800
/// byte array are really an `X25519` public key and an ML-KEM encapsulation key.
/// Returns `None` for material that will not parse, which for our own freshly
/// generated keypair means a bug rather than bad input — but returning `None`
/// keeps that a dropped step instead of a panic on the send path.
pub fn build_ratchet_step_pdu(
    identity_sign: impl Fn(&[u8]) -> [u8; 64],
    x_pub_bytes: &[u8; 32],
    kem_pub_bytes: &[u8],
) -> Option<Vec<u8>> {
    let ek = EncapsulationKey512::new_from_slice(kem_pub_bytes).ok()?;
    let x_pub = x25519_dalek::PublicKey::from(*x_pub_bytes);
    Some(build_rekey_pdu(identity_sign, &x_pub, &ek))
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

/// Build a re-key / ratchet-step **answer** PDU (responder side).
///
/// Layout:
///   [0..16]   "GHOST_REKEY_RSP"
///   [16..48]  Responder's X25519 ephemeral public key (32 bytes)
///   [48..816] Responder's Kyber-512 ciphertext (768 bytes)
///   [816..848] Confirmation tag derived from the new epoch key
///   [848..912] Ed25519 signature over (x_pub || ct || confirm)
///
/// The confirm is inside the signed material, not beside it: otherwise anyone who
/// could rewrite the PDU in flight could substitute their own tag and make the
/// initiator commit to an epoch the responder never derived.
pub fn build_rekey_response_pdu(
    identity_sign: impl Fn(&[u8]) -> [u8; 64],
    x_pub: &[u8; 32],
    kyber_ct: &[u8; 768],
    confirm: &[u8; 32],
) -> Vec<u8> {
    let mut pdu = vec![0u8; REKEY_RESPONSE_BLOB_LEN];
    pdu[0..16].copy_from_slice(REKEY_RESPONSE_MAGIC);
    pdu[16..48].copy_from_slice(x_pub);
    pdu[48..816].copy_from_slice(kyber_ct);
    pdu[816..848].copy_from_slice(confirm);

    let signed_material = {
        let mut m = vec![0u8; 832];
        m[0..32].copy_from_slice(x_pub);
        m[32..800].copy_from_slice(kyber_ct);
        m[800..832].copy_from_slice(confirm);
        m
    };

    let sig = identity_sign(&signed_material);
    pdu[848..912].copy_from_slice(&sig);
    pdu
}

/// Parse a re-key response PDU.
pub struct RekeyResponseBlob {
    pub x25519_pub: [u8; 32],
    pub kyber_ct: [u8; 768],
    pub confirm: [u8; 32],
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
    let mut confirm = [0u8; 32];
    confirm.copy_from_slice(&data[816..848]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[848..912]);
    Some(RekeyResponseBlob {
        x25519_pub,
        kyber_ct,
        confirm,
        signature,
    })
}

/// The bytes a ratchet-step PDU's signature covers on the initiator side.
pub fn rekey_init_signed_material(x_pub: &[u8; 32], kyber_pub: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(32 + kyber_pub.len());
    m.extend_from_slice(x_pub);
    m.extend_from_slice(kyber_pub);
    m
}

/// The bytes a ratchet-step answer's signature covers.
pub fn rekey_answer_signed_material(
    x_pub: &[u8; 32],
    kyber_ct: &[u8; 768],
    confirm: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(832);
    m.extend_from_slice(x_pub);
    m.extend_from_slice(kyber_ct);
    m.extend_from_slice(confirm);
    m
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghost::layers::l0_identity;

    use crate::ghost::session::ratchet::RATCHET_INTERVAL;

    #[test]
    fn test_session_initial_state() {
        let key = [0x42u8; 32];
        let session = Session::new(key, "test_fp".to_string());
        assert_eq!(session.tx_counter.load(Ordering::Relaxed), 2);
        assert!(!session.ratchet_in_progress.load(Ordering::Relaxed));
        assert_eq!(session.epoch(), 0);
        assert_eq!(session.ratchet_steps.load(Ordering::Relaxed), 0);
        assert_eq!(session.epoch_capacity_left(), RATCHET_INTERVAL);
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
    fn test_tx_counter_is_64_bit_and_does_not_wrap_early() {
        // The property v1 could not offer: values that were sentinel-colliding
        // reserved territory in v1 are ordinary counters in v2.
        let session = Session::new([0x42u8; 32], "test_fp".to_string());
        session
            .tx_counter
            .store(0xFFFF_FFFC, Ordering::Relaxed); // v1's last usable counter
        assert_eq!(session.try_next_tx_counter(), Some(0xFFFF_FFFD));
        assert_eq!(session.try_next_tx_counter(), Some(0xFFFF_FFFE));
        assert_eq!(session.try_next_tx_counter(), Some(0xFFFF_FFFF));
        assert_eq!(session.try_next_tx_counter(), Some(0x1_0000_0000));
        // And it only stops at the true end of the space.
        session.tx_counter.store(u64::MAX, Ordering::Relaxed);
        assert!(session.try_next_tx_counter().is_none());
    }

    #[test]
    fn test_seal_key_is_per_epoch_and_open_key_follows_the_grace_window() {
        let session = Session::new([0xABu8; 32], "test_fp".to_string());
        let epoch0 = session.seal_key(NonceDirection::InitiatorToResponder);
        assert_eq!(session.epoch(), 0);

        // A step the peer answered: both sides mixed the same secrets.
        let secrets =
            crate::ghost::session::ratchet::StepSecrets::new([0x01u8; 32], vec![0x02u8; 32]);
        assert_eq!(session.apply_ratchet_step(&secrets), 1);
        assert_eq!(session.epoch(), 1);
        assert_eq!(session.ratchet_steps.load(Ordering::Relaxed), 1);
        assert_ne!(session.seal_key(NonceDirection::InitiatorToResponder), epoch0);
        // The retired epoch still opens, which is the grace window that keeps
        // frames in flight across the step readable.
        assert_eq!(
            session.open_key(0, NonceDirection::InitiatorToResponder, 0),
            Some(epoch0)
        );
        // And an epoch the ratchet never had is refused rather than guessed at.
        assert!(session.open_key(4242, NonceDirection::InitiatorToResponder, 0).is_none());
    }

    #[test]
    fn test_ratchet_step_exchange_between_two_sessions() {
        // The whole step handshake, through the API the node actually uses. The two
        // sides must hold complementary roles: the confirmation is checked against
        // the chain the *initiator sends on*, and with both sides "initiator" that
        // is the same chain on both ends, which a real session never is.
        let a = Session::new_with_role([0x11u8; 32], "a".into(), SessionRole::Initiator);
        let b = Session::new_with_role([0x11u8; 32], "b".into(), SessionRole::Responder);

        let (a_x, a_kem) = a.begin_ratchet_step().expect("a starts a step");
        // A second step does not start while one is in flight.
        assert!(a.begin_ratchet_step().is_none());
        let answer = b
            .answer_ratchet_step(&a_x, &a_kem)
            .expect("b answers the step");
        // Answering *prepares* the epoch, it does not install it. The responder
        // must be able to open the new epoch but must keep sealing on the old one
        // until a frame actually authenticates under the new key, or a step whose
        // answer was lost would leave it an epoch ahead of a peer that never moved.
        assert_eq!(b.epoch(), 0, "the responder seals on the old epoch until it commits");
        assert_eq!(b.prepared_epoch(), Some(1));
        let old_seal = b.seal_key(NonceDirection::ResponderToInitiator);

        assert_eq!(a.finish_ratchet_step(&answer), Some(1));
        assert_eq!(a.epoch(), 1);
        assert!(!a.ratchet_in_progress.load(Ordering::Relaxed));
        // One exchange, two ratchets, one key — for both directions. Bob holds the
        // new epoch as prepared, so the keys already agree while he has not moved.
        assert_eq!(
            a.seal_key(NonceDirection::InitiatorToResponder),
            b.open_key(1, NonceDirection::InitiatorToResponder, 0).unwrap()
        );
        assert_eq!(
            b.open_key(1, NonceDirection::ResponderToInitiator, 0)
                .expect("b holds the new epoch as prepared"),
            a.open_key(1, NonceDirection::ResponderToInitiator, 0).unwrap()
        );
        assert_eq!(
            b.seal_key(NonceDirection::ResponderToInitiator),
            old_seal,
            "preparing must not move what b seals with"
        );
        // Only a frame that authenticated under epoch 1 installs it — which in the
        // node is `activate_epoch`, called from the receive path.
        assert!(b.activate_epoch(1));
        assert_eq!(b.epoch(), 1);
        assert_eq!(b.prepared_epoch(), None);
        assert_eq!(
            b.seal_key(NonceDirection::ResponderToInitiator),
            a.open_key(1, NonceDirection::ResponderToInitiator, 0).unwrap()
        );
    }

    #[test]
    fn test_ratchet_step_with_a_forged_confirmation_is_refused() {
        // The gap this check closes: X25519 returns a shared secret even for a
        // wrong peer public key, so without confirmation both sides "succeed" on
        // different keys and the split only surfaces as unopenable traffic.
        let a = Session::new_with_role([0x11u8; 32], "a".into(), SessionRole::Initiator);
        let b = Session::new_with_role([0x11u8; 32], "b".into(), SessionRole::Responder);
        let (a_x, a_kem) = a.begin_ratchet_step().unwrap();
        let answer = b.answer_ratchet_step(&a_x, &a_kem).unwrap();
        let forged = RatchetAnswer {
            x_public: [0u8; 32], // a substituted X25519 half
            kem_ct: answer.kem_ct,
            confirm: answer.confirm,
            epoch: answer.epoch,
        };
        assert!(a.finish_ratchet_step(&forged).is_none());
        assert_eq!(a.epoch(), 0, "a refused step must not advance the epoch");
        assert!(
            !a.ratchet_in_progress.load(Ordering::Relaxed),
            "a refused step must not wedge the session either"
        );

        // And a tampered tag is refused even with the right public key.
        let a2 = Session::new_with_role([0x11u8; 32], "a2".into(), SessionRole::Initiator);
        let b2 = Session::new_with_role([0x11u8; 32], "b2".into(), SessionRole::Responder);
        let (x2, kem2) = a2.begin_ratchet_step().unwrap();
        let mut answer2 = b2.answer_ratchet_step(&x2, &kem2).unwrap();
        answer2.confirm[0] ^= 0x01;
        assert!(a2.finish_ratchet_step(&answer2).is_none());
        assert_eq!(a2.epoch(), 0);
    }

    #[test]
    fn test_unresolved_crossed_steps_would_split_the_session() {
        // Why `admit_peer_step` exists, shown rather than asserted: when both peers
        // start a step at once and each completes its *own*, both land on epoch 1 —
        // from different secrets. Same epoch number, different keys, nothing opens.
        let a = Session::new_with_role([0x11u8; 32], "bob".into(), SessionRole::Initiator);
        let b = Session::new_with_role([0x11u8; 32], "alice".into(), SessionRole::Responder);
        let (a_x, a_kem) = a.begin_ratchet_step().unwrap();
        let (b_x, b_kem) = b.begin_ratchet_step().unwrap();
        let answer_for_b = a.answer_ratchet_step(&b_x, &b_kem).unwrap();
        let answer_for_a = b.answer_ratchet_step(&a_x, &a_kem).unwrap();

        assert_eq!(a.finish_ratchet_step(&answer_for_a), Some(1));
        assert_eq!(b.finish_ratchet_step(&answer_for_b), Some(1));
        assert_eq!(a.epoch(), b.epoch(), "both call themselves epoch 1");
        assert_ne!(
            a.seal_key(NonceDirection::InitiatorToResponder),
            b.open_key(1, NonceDirection::InitiatorToResponder, 0).unwrap(),
            "...over different keys: this is the split the tie-break prevents"
        );
    }

    #[test]
    fn test_crossed_ratchet_steps_are_resolved_by_fingerprint() {
        // The same cross with the rule applied the way the receive path applies it:
        // one side yields, one step completes, both sides agree on epoch 1.
        let a = Session::new_with_role([0x11u8; 32], "bob".into(), SessionRole::Initiator);
        let b = Session::new_with_role([0x11u8; 32], "alice".into(), SessionRole::Responder);
        let (a_x, a_kem) = a.begin_ratchet_step().unwrap();
        let _ = b.begin_ratchet_step().unwrap();

        // "alice" < "bob", and each side compares its own fingerprint against the
        // peer's — so alice keeps her step and bob yields to hers.
        assert!(!a.admit_peer_step("alice"), "the lower fingerprint keeps its step");
        assert!(b.admit_peer_step("bob"), "the higher fingerprint answers instead");
        assert!(
            !b.ratchet_in_progress.load(Ordering::Relaxed),
            "yielding must clear the step, not leave it wedging the session"
        );

        let answer = b.answer_ratchet_step(&a_x, &a_kem).unwrap();
        assert_eq!(a.finish_ratchet_step(&answer), Some(1));
        assert_eq!(a.epoch(), 1);
        assert!(b.activate_epoch(1), "the frame that opens under epoch 1 installs it");
        assert_eq!(b.epoch(), 1);
        // One exchange, one epoch, one key per direction — the property the cross
        // would have broken.
        assert_eq!(
            a.seal_key(NonceDirection::InitiatorToResponder),
            b.open_key(1, NonceDirection::InitiatorToResponder, 0).unwrap()
        );
        assert_eq!(
            b.seal_key(NonceDirection::ResponderToInitiator),
            a.open_key(1, NonceDirection::ResponderToInitiator, 0).unwrap()
        );
    }

    #[test]
    fn test_abandoned_ratchet_step_leaves_the_epoch_alone() {
        let a = Session::new([0x11u8; 32], "a".into());
        let before = a.seal_key(NonceDirection::InitiatorToResponder);
        assert!(a.begin_ratchet_step().is_some());
        a.abandon_ratchet_step();
        assert_eq!(a.epoch(), 0);
        assert_eq!(a.seal_key(NonceDirection::InitiatorToResponder), before);
        assert!(
            !a.ratchet_in_progress.load(Ordering::Relaxed),
            "an abandoned step must not wedge the session"
        );
    }

    #[test]
    fn test_inbound_counter_uses_the_64_bit_window() {
        let session = Session::new([0x33u8; 32], "test_fp".to_string());
        let big = 1u64 << 40; // far beyond any 32-bit counter
        assert!(session.check_inbound(big));
        assert!(!session.check_inbound(big), "a replay must be refused");
        assert!(session.check_inbound(big + 1));
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
        let confirm = [0xEEu8; 32];

        let pdu = build_rekey_response_pdu(
            |data| identity.sign(data).to_bytes(),
            &x_pub,
            &kyber_ct,
            &confirm,
        );

        assert_eq!(pdu.len(), REKEY_RESPONSE_BLOB_LEN);
        assert!(pdu.starts_with(REKEY_RESPONSE_MAGIC));

        let parsed = parse_rekey_response_pdu(&pdu).expect("Should parse re-key response");
        assert_eq!(parsed.x25519_pub, x_pub);
        assert_eq!(parsed.kyber_ct, kyber_ct);
        assert_eq!(parsed.confirm, confirm);

        // The confirmation is inside the signed material.
        let signed_material = rekey_answer_signed_material(&x_pub, &kyber_ct, &confirm);
        assert!(l0_identity::verify_peer_signature(
            &identity.public_key_bytes(),
            &signed_material,
            &parsed.signature,
        ));
        // And a substituted confirm invalidates that signature: nobody can swap
        // the tag in flight and make the initiator commit to a foreign epoch.
        let tampered = rekey_answer_signed_material(&x_pub, &kyber_ct, &[0x11u8; 32]);
        assert!(!l0_identity::verify_peer_signature(
            &identity.public_key_bytes(),
            &tampered,
            &parsed.signature,
        ));
    }

    #[test]
    fn test_rekey_init_signed_material_matches_the_builder() {
        let identity = l0_identity::GhostIdentity::generate_fresh();
        let (_x_sec, x_pub) = crate::ghost::layers::l1_kem::generate_x25519_keypair();
        let (ky_pub, _ky_sec) = crate::ghost::layers::l1_kem::generate_kyber_keypair();
        let pdu = build_rekey_pdu(|d| identity.sign(d).to_bytes(), &x_pub, &ky_pub);
        let parsed = parse_rekey_pdu(&pdu).expect("parse");
        let material = rekey_init_signed_material(&parsed.x25519_pub, &parsed.kyber_pub);
        assert!(l0_identity::verify_peer_signature(
            &identity.public_key_bytes(),
            &material,
            &parsed.signature,
        ));
    }

    #[test]
    fn test_ratchet_due_after_a_full_epoch_of_frames() {
        // The trigger P2-2 specifies: one ratchet step per RATCHET_INTERVAL frames.
        let session = Session::new([0x42u8; 32], "test_fp".to_string());
        {
            let mut r = session.ratchet.lock().unwrap();
            for _ in 0..(RATCHET_INTERVAL - 2) {
                r.count_seal();
            }
        }
        assert!(!session.note_sealed_frame(), "not due one frame early");
        assert!(session.note_sealed_frame(), "due at the interval");
    }
}
