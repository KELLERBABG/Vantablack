//! Session Management Module.
//!
//! Manages the lifecycle of peer-to-peer sessions in the GhostNet:
//! - Session creation, state tracking, and teardown
//! - Per-peer monotonic counter and replay guard integration
//! - Stream multiplexing for concurrent data flows
//! - Automated session re-keying and quantum-ratchet epoch synchronization

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
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;

pub const MAX_STREAMS: u16 = 256;

/// Re-key threshold for the *legacy* 32-bit counter, kept for the watchdog that
/// reports it. The v2 wire format uses a 64-bit counter and no longer reserves
/// sentinel values in it, so this is a warning line, not a wall.
pub const REKEY_THRESHOLD: u64 = 0xFFFF_FFFF_C000_0000; // 75% of u64::MAX

pub const REKEY_MAGIC: &[u8; 16] = b"GHOST_REKEY____!";
pub const REKEY_RESPONSE_MAGIC: &[u8; 16] = b"GHOST_REKEY_RSP!";

/// Magic for the L10 quantum-anchor mix PDU.
///
/// The initiator names the epoch it prepared and the **label** of the key it is
/// using; the peer turns that label back into the *same* 32 bytes instead of being
/// sent them, so key material never crosses the link it protects. The label is
/// opaque here on purpose, because the two backends name their keys differently:
/// the simulated one writes a versioned `qkd-sim/1/…` derivation label, and a real
/// ETSI GS QKD 014 appliance supplies a key ID that the peer redeems with
/// `dec_keys`. Either way exactly one non-secret value travels.
pub const QEL_MIX_MAGIC: &[u8; 16] = b"GHOST_QEL_MIX___";
/// The peer's acceptance of a quantum mix, carrying the tag that proves agreement.
pub const QEL_MIX_RESPONSE_MAGIC: &[u8; 16] = b"GHOST_QEL_MIX_OK";

/// Longest key label the mix PDU can carry.
///
/// Generous for both backends: a simulated label is 45 bytes, and a UUID key ID is
/// 36. A fixed field (rather than a length-followed-by-more-bytes layout) keeps the
/// PDU one frame long, and the signer covers the length as well as the bytes so a
/// truncated label cannot be re-framed into a different one.
pub const QEL_MIX_MAX_LABEL: usize = 128;

/// Size of the quantum-mix PDU: 16 magic + 8 epoch + 2 label length
/// + 128 label + 32 confirmation tag + 64 Ed25519 signature = 250.
pub const QEL_MIX_BLOB_LEN: usize = 250;
/// Size of the quantum-mix answer: 16 magic + 8 epoch + 32 tag + 64 signature = 120.
pub const QEL_MIX_RESPONSE_BLOB_LEN: usize = 120;

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
    pub peer_fingerprint: String,
    pub established_at: Instant,
    pub session_hash: [u8; 4],
    /// Which side initiated this session (drives AEAD nonce direction).
    pub role: SessionRole,
    pub ack_engine: Arc<std::sync::Mutex<AckEngine>>,
    pub streams: Arc<DashMap<u16, StreamState>>,
    pub next_stream_id: AtomicU16,
    pub stats: Arc<ThroughputStats>,
    pub use_bulk: bool,
    pub cipher_suite: HybridCipherSuite,
    pub wire_v1: AtomicBool,

    // ── Ratchet State ────────────────────────────────────
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
    pub ratchet_steps: AtomicU64,
    pub ratchet_in_progress: AtomicBool,
    pub forced_ratchet_due: AtomicBool,
    /// The peer's Ed25519 identity key, pinned when the session was established.
    ///
    /// A ratchet step has to be authenticated *before* it is acted on: the
    /// responder derives and can then open a new epoch on receipt, so an injected
    /// step would move one side of a session and not the other. The sessions's own
    /// authentication ran at handshake time, so this is where the proof is kept.
    /// `None` means the step is **refused**, never accepted on trust.
    peer_identity_pk: Mutex<Option<[u8; 32]>>,
    // ── Post-Quantum Hybrid Identity Authentication ────────
    /// 0 = Pending, 1 = Authenticated, 2 = Failed
    pub pq_auth_state: AtomicU8,
    /// The peer's pinned 32-byte SHA-256 PQ commitment from the handshake negotiation.
    peer_pq_commitment: Mutex<Option<[u8; 32]>>,
    /// The peer's verified ML-DSA-65 public key (1952 bytes).
    peer_pq_pk: Mutex<Option<Vec<u8>>>,
    /// Received chunks of the peer's hybrid identity binding.
    pq_incoming_chunks: Mutex<std::collections::HashMap<u8, Vec<u8>>>,
    pub pq_auth_requested_at: Instant,

    // ── L10 Quantum-Anchor Mix State ─────────────────────
    /// The quantum mix we started and are waiting on an answer for. Held outside
    /// the ratchet so a mix that is never answered can be dropped without
    /// disturbing the live epoch (the same split as `pending_step`).
    pending_quantum_mix: Mutex<Option<PendingQuantumMix>>,
    /// When the in-flight mix started, so an unanswered one is abandoned rather
    /// than wedging the session against a later attempt.
    quantum_mix_at: Mutex<Option<Instant>>,
    /// When this session last *tried* to start a mix, successful or not. This is
    /// the throttle: deriving a key costs a python subprocess (seconds), so a
    /// peer whose route never resolves must not be retried on every maintenance
    /// tick. See [`Session::quantum_mix_due`].
    quantum_mix_attempt_at: Mutex<Option<Instant>>,
    /// Whether a quantum mix is mid-exchange. A mix and a DH ratchet step both
    /// consume the prepared-epoch slot and both advance the generation, so at most
    /// one of them may be in flight at a time.
    pub quantum_mix_in_progress: AtomicBool,
    /// Whether this session has completed a quantum mix. The anchor is applied
    /// once per session, so this is what the maintenance task checks before it
    /// starts one (a *failed* attempt leaves it clear, so a retry can follow).
    pub quantum_mixed: AtomicBool,
}

/// A quantum mix we started and are waiting on an answer for.
#[derive(Debug, Clone)]
pub struct PendingQuantumMix {
    /// The epoch the mix prepared (one ahead of the live generation).
    pub epoch: u64,
    /// Tag over the key we will seal in the new epoch. The peer computes the same
    /// bytes from the same quantum key, so equality is the proof that both sides
    /// derived one key and are safe to advance together.
    pub confirm: [u8; 32],
    /// The opaque name of the key this mix uses. Travels in the PDU; never
    /// key material.
    pub label: String,
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

/// The material one v2 message is sealed with.
#[derive(Clone)]
pub struct SealMaterial {
    pub key: [u8; 32],
    pub epoch: u64,
    pub counter: u64,
    pub nonce: [u8; 12],
    pub direction: NonceDirection,
    /// Whether this message filled the epoch: the caller should start a ratchet
    /// step. Traffic continues on the current epoch until that step completes.
    pub ratchet_due: bool,
}

/// State for an individual multiplexed stream.
pub struct StreamState {
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
            pending_quantum_mix: Mutex::new(None),
            quantum_mix_at: Mutex::new(None),
            quantum_mix_attempt_at: Mutex::new(None),
            quantum_mix_in_progress: AtomicBool::new(false),
            quantum_mixed: AtomicBool::new(false),
            wire_v1: AtomicBool::new(false),
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

    /// Check whether this session has completed post-quantum hybrid identity verification.
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

    /// Whether this peer is using the legacy GTF v1 wire protocol (e.g. Android client).
    pub fn is_v1_wire(&self) -> bool {
        self.wire_v1.load(Ordering::Relaxed)
    }

    /// Set whether this peer is using the legacy GTF v1 wire protocol.
    pub fn set_v1_wire(&self, v1: bool) {
        self.wire_v1.store(v1, Ordering::Relaxed);
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
        *self.peer_pq_pk.lock().unwrap_or_else(|e| e.into_inner()) = Some(pk);
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

    // ── Ratchet ─────────────────────────────────────────

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
    pub fn open_key(
        &self,
        epoch: u64,
        direction: NonceDirection,
        counter: u64,
    ) -> Option<[u8; 32]> {
        self.ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .open_key(epoch, direction, counter)
    }

    /// Whether an unopenable frame's counter exceeded MAX_SKIP past our chain position.
    pub fn gap_exceeds_max_skip(
        &self,
        epoch: u64,
        direction: NonceDirection,
        counter: u64,
    ) -> bool {
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
        let mut last = self
            .ratchet_step_at
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
        // Increment `ratchet_steps` *inside* the ratchet lock so that any
        // observer who acquires the lock and sees `epoch() == N` is guaranteed
        // to also see the updated counter (mutex release establishes
        // happens-before for all writes done before the unlock).
        let activated = {
            let mut g = self.ratchet.lock().unwrap_or_else(|e| e.into_inner());
            let a = g.activate(epoch);
            if a {
                self.ratchet_steps.fetch_add(1, Ordering::Relaxed);
            }
            a
        };
        if activated {
            self.guard.lock().unwrap_or_else(|e| e.into_inner()).reset();
            // A *quantum-prepared* epoch landing here is the L10 mix completing.
            // On the answering side that happens when the starter's first frame in
            // the new epoch authenticates; on the starting side `finish_quantum_mix`
            // calls this directly once the answer confirmed the derivation.
            let was_quantum_mix = {
                let mut pending = self
                    .pending_quantum_mix
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if pending.as_ref().map(|p| p.epoch) == Some(epoch) {
                    *pending = None;
                    true
                } else {
                    false
                }
            };
            if was_quantum_mix {
                self.quantum_mix_in_progress.store(false, Ordering::Relaxed);
                *self
                    .quantum_mix_at
                    .lock()
                    .unwrap_or_else(|e| e.into_inner()) = None;
                self.quantum_mixed.store(true, Ordering::Relaxed);
                tracing::info!(
                    peer = %self.peer_fingerprint,
                    epoch,
                    "quantum entropy mixed into the session ratchet"
                );
            }
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
    pub fn seal_material_at(
        &self,
        epoch: u64,
        direction: NonceDirection,
        counter: u64,
    ) -> Option<SealMaterial> {
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
        // Publish the new epoch and the bookkeeping that describes it under one
        // lock, for the same reason `activate_epoch` does: a reader who acquires
        // the ratchet lock and sees `epoch() == N` must also see `ratchet_steps`
        // counted and the step no longer in flight. Incrementing *after* the
        // guard was dropped let an observer watch the epoch turn while the
        // counter was still a step behind — there is no other way for the live
        // epoch to advance, so a reader could see epoch 1 with zero steps.
        let epoch = {
            let mut g = self.ratchet.lock().unwrap_or_else(|e| e.into_inner());
            let epoch = g.step(secrets);
            self.ratchet_steps.fetch_add(1, Ordering::Relaxed);
            self.ratchet_in_progress.store(false, Ordering::Relaxed);
            epoch
        };
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
        if self.quantum_mix_in_progress.load(Ordering::Relaxed) {
            // The quantum mix owns the next epoch; a DH step now would prepare a
            // second one over different inputs.
            return None;
        }
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

    /// Start a quantum-anchor mix: derive the next epoch from a QEL/QKD key
    /// **without installing it**, and hand back what the mix PDU must carry.
    ///
    /// `label` is the backend's opaque name for the key. It is carried in the mix
    /// PDU so the answering peer can fetch the *same* material from the same
    /// source — a simulated derivation label, or an appliance's key ID.
    ///
    /// Refuses when a DH ratchet step or another quantum mix is already in flight.
    /// Both advance the generation and both consume the prepared-epoch slot, so two
    /// in flight at once would each prepare an epoch `n+1` over different inputs.
    pub fn begin_quantum_mix(
        &self,
        quantum_key: &[u8; 32],
        label: &str,
    ) -> Option<PendingQuantumMix> {
        if self.ratchet_in_progress.load(Ordering::Relaxed) {
            tracing::debug!(
                peer = %self.peer_fingerprint,
                "quantum mix deferred: a ratchet step owns the next epoch"
            );
            return None;
        }
        if self.quantum_mix_in_progress.swap(true, Ordering::SeqCst) {
            return None; // one attempt at a time
        }
        let direction = self.seal_direction();
        let (epoch, key) = self
            .ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .prepare_quantum_mix(quantum_key, direction);
        let pending = PendingQuantumMix {
            epoch,
            confirm: crate::ghost::layers::l1_kem::ratchet_confirm(&key),
            label: label.to_string(),
        };
        *self
            .pending_quantum_mix
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(pending.clone());
        *self
            .quantum_mix_at
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
        Some(pending)
    }

    /// Answer a peer's quantum mix: install the key the peer's label names,
    /// confirm that our key reproduces *its* tag, and prepare the same epoch.
    ///
    /// The caller has already resolved the label into `quantum_key` (a derivation
    /// on the simulated backend, `dec_keys` on an appliance); this method does not
    /// know or care which. It records the label so a re-answer after a stall
    /// carries the same one.
    ///
    /// Returns the tag to send back, or `None` when the mix must be refused — the
    /// peer named an epoch that is not the next one, or the two sides hold
    /// different keys. Checking *before* preparing is the point of the tag: an epoch
    /// prepared over a key the peer does not share would move this side's generation
    /// alone, and nothing on the link would open from then on.
    pub fn answer_quantum_mix(
        &self,
        quantum_key: &[u8; 32],
        peer_epoch: u64,
        peer_confirm: &[u8; 32],
        label: &str,
    ) -> Option<[u8; 32]> {
        if self.ratchet_in_progress.load(Ordering::Relaxed) {
            tracing::debug!(
                peer = %self.peer_fingerprint,
                "quantum mix refused: a ratchet step is in flight"
            );
            return None;
        }
        // The peer started the mix, so it seals in the direction complementary to
        // ours — which is the chain its tag is over (the same mapping the rekey
        // step's answer uses).
        let starter_direction = self.seal_direction().peer_direction();
        let (epoch, key) = self
            .ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .preview_quantum_mix_key(quantum_key, starter_direction);
        if epoch != peer_epoch {
            tracing::warn!(
                peer = %self.peer_fingerprint,
                peer_epoch,
                expected = epoch,
                "quantum mix names the wrong epoch — refused"
            );
            return None;
        }
        let confirm = crate::ghost::layers::l1_kem::ratchet_confirm(&key);
        use subtle::ConstantTimeEq;
        if !bool::from(confirm.ct_eq(peer_confirm)) {
            tracing::warn!(
                peer = %self.peer_fingerprint,
                epoch,
                "quantum mix confirmation failed — the peers derived different keys; \
                 refusing to advance the epoch"
            );
            return None;
        }
        // Both sides derived one key. Preparing (not installing) means a lost
        // answer cannot leave this side sealing a generation ahead of the peer.
        let (prepared_epoch, prepared_key) = self
            .ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .prepare_quantum_mix(quantum_key, starter_direction);
        *self
            .pending_quantum_mix
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(PendingQuantumMix {
            epoch: prepared_epoch,
            // The tag *we* send is over the same chain, so it is the value we just
            // verified -- returning it lets the starter check the round trip.
            confirm: crate::ghost::layers::l1_kem::ratchet_confirm(&prepared_key),
            label: label.to_string(),
        });
        *self
            .quantum_mix_at
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
        Some(confirm)
    }

    /// Complete a mix we started, from the peer's answer.
    ///
    /// The answer's epoch *and* confirmation tag are both checked; either mismatch
    /// drops the attempt and leaves the live epoch exactly as it was.
    pub fn finish_quantum_mix(&self, epoch: u64, confirm: &[u8; 32]) -> Option<u64> {
        let pending = self
            .pending_quantum_mix
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()?;
        if pending.epoch != epoch {
            tracing::warn!(
                peer = %self.peer_fingerprint,
                answer_epoch = epoch,
                expected = pending.epoch,
                "quantum mix answer names the wrong epoch — refused"
            );
            self.abandon_quantum_mix();
            return None;
        }
        use subtle::ConstantTimeEq;
        if !bool::from(pending.confirm.ct_eq(confirm)) {
            tracing::warn!(
                peer = %self.peer_fingerprint,
                "quantum mix answer did not confirm the derivation — \
                 refusing to advance the epoch"
            );
            self.abandon_quantum_mix();
            return None;
        }
        if !self.activate_epoch(epoch) {
            tracing::warn!(
                peer = %self.peer_fingerprint,
                epoch,
                "quantum mix prepared epoch is gone — refused"
            );
            self.abandon_quantum_mix();
            return None;
        }
        Some(epoch)
    }

    /// Whether an arriving quantum mix should be **answered**, resolving a*both
    /// sides started one* the way [`Session::admit_peer_step`] resolves a crossed
    /// DH step.
    ///
    /// The quantum mix is what the *starter* drives, so the ordinary case is that
    /// only one side is in flight and this returns `true`. It still has to be
    /// asked, because the two sides do not start from a shared clock: the
    /// initiator rule is the fingerprint order (the lower-fingerprint peer drives
    /// the mix), but a session that started a mix while the peer's rule still had
    /// *it* as the driver can see a mix arrive while its own is in flight — for
    /// instance when a peer's fingerprint is repinned by a re-handshake.
    ///
    /// A crossed pair here is the same hazard as a crossed step: both sides would
    /// install epoch `n+1` from *different* quantum keys, so every frame after
    /// that fails to open and no later exchange can repair it. The tie-break is
    /// identical to the step's — lowest fingerprint wins — and it needs no extra
    /// round trip, because both sides compute it from public data with the labels
    /// swapped.
    ///
    /// Returns `true` to answer the arriving mix (`false` means ours wins and the
    /// arriving one is dropped).
    pub fn admit_peer_quantum_mix(&self, our_fingerprint: &str) -> bool {
        if !self.quantum_mix_in_progress.load(Ordering::Relaxed) {
            return true; // nothing crossed — the ordinary case
        }
        if our_fingerprint < self.peer_fingerprint.as_str() {
            tracing::debug!(
                peer = %self.peer_fingerprint,
                "crossed quantum mixes — our mix wins, the arriving one is dropped"
            );
            return false;
        }
        tracing::debug!(
            peer = %self.peer_fingerprint,
            "crossed quantum mixes — yielding our mix to answer the peer's"
        );
        self.abandon_quantum_mix();
        true
    }

    /// Whether this session is due to *start* a quantum mix.
    ///
    /// Deliberately conservative: never while a mix or a DH step is in flight
    /// (both own the prepared-epoch slot), never once one has been applied, and
    /// never more often than `interval` — deriving a key costs a python
    /// subprocess, so a peer whose route does not resolve is retried on the
    /// interval, not on every tick.
    pub fn quantum_mix_due(&self, interval: Duration) -> bool {
        if self.quantum_mixed.load(Ordering::Relaxed)
            || self.quantum_mix_in_progress.load(Ordering::Relaxed)
            || self.ratchet_in_progress.load(Ordering::Relaxed)
        {
            return false;
        }
        self.quantum_mix_attempt_at
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map(|t| t.elapsed() >= interval)
            .unwrap_or(true)
    }

    /// Record that a mix attempt was made, so the throttle above can measure it.
    pub fn note_quantum_mix_attempt(&self) {
        *self
            .quantum_mix_attempt_at
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
    }

    /// Whether a quantum mix is mid-exchange on this session.
    pub fn quantum_mix_in_progress(&self) -> bool {
        self.quantum_mix_in_progress.load(Ordering::Relaxed)
    }

    /// Whether this session has already applied a quantum mix.
    pub fn quantum_mixed(&self) -> bool {
        self.quantum_mixed.load(Ordering::Relaxed)
    }

    /// Whether a quantum mix has been waiting on an answer for longer than `timeout`.
    pub fn quantum_mix_stalled(&self, timeout: Duration) -> bool {
        if !self.quantum_mix_in_progress.load(Ordering::Relaxed) {
            return false;
        }
        self.quantum_mix_at
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map(|t| t.elapsed() > timeout)
            .unwrap_or(false)
    }

    /// Drop an in-flight quantum mix (the answer never came). The live epoch is
    /// untouched, and a later attempt starts from the same root and the same
    /// parameters, so the retry derives the same key.
    ///
    /// What this deliberately does **not** do is discard the epoch the ratchet
    /// already prepared. That is the same choice the DH step makes, and it is the
    /// forgiving one: an answer that arrives after the stall bound — a slow route
    /// computation on the peer, not a lost peer — still opens under the prepared
    /// epoch and completes the exchange, instead of being dropped and leaving the
    /// peer sealing on a generation this side cannot open. A retry prepares the
    /// identical epoch anyway, so nothing is at risk by keeping it.
    pub fn abandon_quantum_mix(&self) {
        *self
            .pending_quantum_mix
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        *self
            .quantum_mix_at
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        self.quantum_mix_in_progress.store(false, Ordering::Relaxed);
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

// ── L10 Quantum-Anchor Mix PDUs ───────────────────────────────────────

/// Field offsets inside the mix PDU, named so the builder and the parser cannot
/// drift apart.
const QEL_MIX_EPOCH_AT: usize = 16;
const QEL_MIX_LABEL_LEN_AT: usize = 24;
const QEL_MIX_LABEL_AT: usize = 26;
const QEL_MIX_CONFIRM_AT: usize = QEL_MIX_LABEL_AT + QEL_MIX_MAX_LABEL; // 154
const QEL_MIX_SIG_AT: usize = QEL_MIX_CONFIRM_AT + 32; // 186

/// Build the quantum-mix PDU: the epoch prepared and the *label* naming the key.
///
/// Layout:
///   [0..16]    "GHOST_QEL_MIX___"
///   [16..24]   Epoch the mix is prepared for (u64 BE)
///   [24..26]   Label length in bytes (u16 BE), ≤ [`QEL_MIX_MAX_LABEL`]
///   [26..154]  Label, zero-padded to a fixed field
///   [154..186] Confirmation tag over the starter's new-epoch sealing key
///   [186..250] Ed25519 signature over `[16..186]`
///
/// The label, not the key: the answering peer resolves it against the same
/// backend and arrives at the same material, so nothing secret crosses the link
/// the key protects. Opaque here because the two backends name keys differently.
///
/// The length is carried *and* signed, so a label that filled its field could not
/// be extended by a trailing byte, nor a shorter one re-framed as a longer one.
/// The signature covers the confirmation tag too: a tag outside the signed region
/// could be rewritten in flight, and the initiator would then commit to an epoch
/// the responder never derived.
pub fn build_qel_mix_pdu(
    identity_sign: impl Fn(&[u8]) -> [u8; 64],
    epoch: u64,
    label: &str,
    confirm: &[u8; 32],
) -> Vec<u8> {
    let mut pdu = vec![0u8; QEL_MIX_BLOB_LEN];
    pdu[0..16].copy_from_slice(QEL_MIX_MAGIC);
    pdu[QEL_MIX_EPOCH_AT..QEL_MIX_LABEL_LEN_AT].copy_from_slice(&epoch.to_be_bytes());
    // Callers are contract-bound to `QEL_MIX_MAX_LABEL` (the controller's own test
    // pins that), but truncating here would silently point the peer at a different
    // key, so refuse to build a PDU the peer could not decode identically.
    let bytes = label.as_bytes();
    assert!(
        bytes.len() <= QEL_MIX_MAX_LABEL,
        "quantum key label is {} bytes, over the {QEL_MIX_MAX_LABEL}-byte PDU field",
        bytes.len()
    );
    pdu[QEL_MIX_LABEL_LEN_AT..QEL_MIX_LABEL_AT]
        .copy_from_slice(&(bytes.len() as u16).to_be_bytes());
    pdu[QEL_MIX_LABEL_AT..QEL_MIX_LABEL_AT + bytes.len()].copy_from_slice(bytes);
    pdu[QEL_MIX_CONFIRM_AT..QEL_MIX_SIG_AT].copy_from_slice(confirm);
    let sig = identity_sign(&qel_mix_signed_material(epoch, label, confirm));
    pdu[QEL_MIX_SIG_AT..QEL_MIX_BLOB_LEN].copy_from_slice(&sig);
    pdu
}

/// A parsed quantum-mix PDU.
pub struct QelMixBlob {
    pub epoch: u64,
    /// The name of the key, not the key itself. Resolve it against the backend
    /// that produced it; an unrecognised label is refused by that backend.
    pub label: String,
    pub confirm: [u8; 32],
    pub signature: [u8; 64],
}

pub fn parse_qel_mix_pdu(data: &[u8]) -> Option<QelMixBlob> {
    if data.len() < QEL_MIX_BLOB_LEN || !data.starts_with(QEL_MIX_MAGIC) {
        return None;
    }
    let epoch = u64::from_be_bytes(
        data[QEL_MIX_EPOCH_AT..QEL_MIX_LABEL_LEN_AT]
            .try_into()
            .ok()?,
    );
    let label_len = u16::from_be_bytes(
        data[QEL_MIX_LABEL_LEN_AT..QEL_MIX_LABEL_AT]
            .try_into()
            .ok()?,
    ) as usize;
    // Out-of-range length is a malformed or hostile PDU: the field is fixed-size,
    // so a length past it would either read the padding or the tag as label bytes.
    if label_len == 0 || label_len > QEL_MIX_MAX_LABEL {
        return None;
    }
    let label_bytes = &data[QEL_MIX_LABEL_AT..QEL_MIX_LABEL_AT + label_len];
    let label = std::str::from_utf8(label_bytes).ok()?.to_string();
    let mut confirm = [0u8; 32];
    confirm.copy_from_slice(&data[QEL_MIX_CONFIRM_AT..QEL_MIX_SIG_AT]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[QEL_MIX_SIG_AT..QEL_MIX_BLOB_LEN]);
    Some(QelMixBlob {
        epoch,
        label,
        confirm,
        signature,
    })
}

/// The bytes a quantum-mix PDU's signature covers: epoch, label length, label and
/// the confirmation tag.
pub fn qel_mix_signed_material(epoch: u64, label: &str, confirm: &[u8; 32]) -> Vec<u8> {
    let bytes = label.as_bytes();
    let mut m = Vec::with_capacity(8 + 2 + bytes.len() + 32);
    m.extend_from_slice(&epoch.to_be_bytes());
    // The length is inside the signed region so a label cannot be re-framed.
    m.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    m.extend_from_slice(bytes);
    m.extend_from_slice(confirm);
    m
}

/// Build the peer's answer to a quantum mix.
///
/// Layout:
///   [0..16]   "GHOST_QEL_MIX_OK"
///   [16..24]  Epoch the mix prepared (u64 BE)
///   [24..56]  Confirmation tag over the same new-epoch key
///   [56..120] Ed25519 signature over `[16..56]`
pub fn build_qel_mix_response_pdu(
    identity_sign: impl Fn(&[u8]) -> [u8; 64],
    epoch: u64,
    confirm: &[u8; 32],
) -> Vec<u8> {
    let mut pdu = vec![0u8; QEL_MIX_RESPONSE_BLOB_LEN];
    pdu[0..16].copy_from_slice(QEL_MIX_RESPONSE_MAGIC);
    pdu[16..24].copy_from_slice(&epoch.to_be_bytes());
    pdu[24..56].copy_from_slice(confirm);
    let sig = identity_sign(&qel_mix_response_signed_material(epoch, confirm));
    pdu[56..120].copy_from_slice(&sig);
    pdu
}

/// A parsed quantum-mix answer.
pub struct QelMixResponseBlob {
    pub epoch: u64,
    pub confirm: [u8; 32],
    pub signature: [u8; 64],
}

pub fn parse_qel_mix_response_pdu(data: &[u8]) -> Option<QelMixResponseBlob> {
    if data.len() < QEL_MIX_RESPONSE_BLOB_LEN || !data.starts_with(QEL_MIX_RESPONSE_MAGIC) {
        return None;
    }
    let epoch = u64::from_be_bytes(data[16..24].try_into().ok()?);
    let mut confirm = [0u8; 32];
    confirm.copy_from_slice(&data[24..56]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[56..120]);
    Some(QelMixResponseBlob {
        epoch,
        confirm,
        signature,
    })
}

/// The bytes a quantum-mix answer's signature covers.
pub fn qel_mix_response_signed_material(epoch: u64, confirm: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(40);
    m.extend_from_slice(&epoch.to_be_bytes());
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
        session.tx_counter.store(0xFFFF_FFFC, Ordering::Relaxed); // v1's last usable counter
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
        assert_ne!(
            session.seal_key(NonceDirection::InitiatorToResponder),
            epoch0
        );
        // The retired epoch still opens, which is the grace window that keeps
        // frames in flight across the step readable.
        assert_eq!(
            session.open_key(0, NonceDirection::InitiatorToResponder, 0),
            Some(epoch0)
        );
        // And an epoch the ratchet never had is refused rather than guessed at.
        assert!(session
            .open_key(4242, NonceDirection::InitiatorToResponder, 0)
            .is_none());
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
        assert_eq!(
            b.epoch(),
            0,
            "the responder seals on the old epoch until it commits"
        );
        assert_eq!(b.prepared_epoch(), Some(1));
        let old_seal = b.seal_key(NonceDirection::ResponderToInitiator);

        assert_eq!(a.finish_ratchet_step(&answer), Some(1));
        assert_eq!(a.epoch(), 1);
        assert!(!a.ratchet_in_progress.load(Ordering::Relaxed));
        // One exchange, two ratchets, one key — for both directions. Bob holds the
        // new epoch as prepared, so the keys already agree while he has not moved.
        assert_eq!(
            a.seal_key(NonceDirection::InitiatorToResponder),
            b.open_key(1, NonceDirection::InitiatorToResponder, 0)
                .unwrap()
        );
        assert_eq!(
            b.open_key(1, NonceDirection::ResponderToInitiator, 0)
                .expect("b holds the new epoch as prepared"),
            a.open_key(1, NonceDirection::ResponderToInitiator, 0)
                .unwrap()
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
            a.open_key(1, NonceDirection::ResponderToInitiator, 0)
                .unwrap()
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
            b.open_key(1, NonceDirection::InitiatorToResponder, 0)
                .unwrap(),
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
        assert!(
            !a.admit_peer_step("alice"),
            "the lower fingerprint keeps its step"
        );
        assert!(
            b.admit_peer_step("bob"),
            "the higher fingerprint answers instead"
        );
        assert!(
            !b.ratchet_in_progress.load(Ordering::Relaxed),
            "yielding must clear the step, not leave it wedging the session"
        );

        let answer = b.answer_ratchet_step(&a_x, &a_kem).unwrap();
        assert_eq!(a.finish_ratchet_step(&answer), Some(1));
        assert_eq!(a.epoch(), 1);
        assert!(
            b.activate_epoch(1),
            "the frame that opens under epoch 1 installs it"
        );
        assert_eq!(b.epoch(), 1);
        // One exchange, one epoch, one key per direction — the property the cross
        // would have broken.
        assert_eq!(
            a.seal_key(NonceDirection::InitiatorToResponder),
            b.open_key(1, NonceDirection::InitiatorToResponder, 0)
                .unwrap()
        );
        assert_eq!(
            b.seal_key(NonceDirection::ResponderToInitiator),
            a.open_key(1, NonceDirection::ResponderToInitiator, 0)
                .unwrap()
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

    // ── L10 quantum-anchor mix: the session half ────────────────────────────
    //
    // What the maintenance tick has to get right before it spends a python
    // subprocess: one mix at a time, never alongside a DH step, and no more
    // often than the retry interval.

    /// A session that has a peer, so the mix methods have somewhere to put state.
    fn mixable_session(seed: u8, peer: &str) -> Session {
        Session::new_with_role([seed; 32], peer.to_string(), SessionRole::Initiator)
    }

    /// Some backend's key label. These tests only care that the same string comes
    /// back out, so the shape is arbitrary — the simulated backend's own test pins
    /// the real format, and one that is too long for the PDU is refused by
    /// [`build_qel_mix_pdu`].
    const LABEL: &str = "qkd-sim/1/f=3feccccc00000000/s=00000000000051ee";

    #[test]
    fn a_mix_and_a_dh_step_are_mutually_exclusive() {
        // Both advance the generation and both take the prepared-epoch slot, so
        // two in flight would each prepare an epoch `n+1` from different inputs.
        let session = mixable_session(0x31, "peer_a");
        assert!(session.begin_quantum_mix(&[0x11u8; 32], LABEL).is_some());
        assert!(
            session.begin_ratchet_step().is_none(),
            "a DH step must not start while a quantum mix owns the next epoch"
        );
        session.abandon_quantum_mix();
        assert!(
            session.begin_ratchet_step().is_some(),
            "once abandoned, the slot is free again"
        );
        session.abandon_ratchet_step();

        // And the other way round.
        assert!(session.begin_ratchet_step().is_some());
        assert!(
            session.begin_quantum_mix(&[0x11u8; 32], LABEL).is_none(),
            "and a mix must not start over an in-flight DH step"
        );
        session.abandon_ratchet_step();
        assert!(session.begin_quantum_mix(&[0x11u8; 32], LABEL).is_some());
    }

    #[test]
    fn a_crossed_mix_is_resolved_by_the_fingerprint_order() {
        // Both sides started one. Each computes the same comparison with the
        // labels swapped, so exactly one yields — and the yielding side must
        // *drop* its own mix, not answer on top of it.
        let interval = Duration::from_secs(60);

        let ours_wins = mixable_session(0x41, "zzz_peer");
        assert!(ours_wins.begin_quantum_mix(&[0x11u8; 32], LABEL).is_some());
        assert!(
            !ours_wins.admit_peer_quantum_mix("aaa_us"),
            "the lower-fingerprint peer keeps its own mix"
        );
        assert!(
            ours_wins.quantum_mix_in_progress(),
            "and the arriving one is dropped rather than replacing it"
        );

        let theirs_wins = mixable_session(0x42, "aaa_peer");
        assert!(theirs_wins
            .begin_quantum_mix(&[0x11u8; 32], LABEL)
            .is_some());
        assert!(
            theirs_wins.admit_peer_quantum_mix("zzz_us"),
            "the higher-fingerprint peer answers instead"
        );
        assert!(
            !theirs_wins.quantum_mix_in_progress(),
            "yielding means our own mix is abandoned"
        );
        assert_eq!(
            theirs_wins.epoch(),
            0,
            "an abandoned mix never moved the live epoch"
        );
        assert!(
            theirs_wins.quantum_mix_due(interval),
            "and the arriving mix is free to prepare the epoch instead"
        );

        // With nothing in flight there is nothing to resolve.
        assert!(mixable_session(0x43, "free_peer").admit_peer_quantum_mix("any_us"));
    }

    #[test]
    fn the_mix_attempt_is_throttled_by_the_retry_interval() {
        // An attempt can cost a python subprocess, so a peer whose route never
        // resolves must not be retried on every tick.
        let session = mixable_session(0x51, "peer_t");
        let interval = Duration::from_secs(60);
        assert!(session.quantum_mix_due(interval), "a fresh session is due");
        session.note_quantum_mix_attempt();
        assert!(
            !session.quantum_mix_due(interval),
            "a recorded attempt suppresses the next one"
        );
        assert_eq!(session.epoch(), 0, "and nothing was advanced by trying");

        // A mix in flight is never re-attempted, however long ago the attempt
        // was recorded: the stall path owns that case.
        let in_flight = mixable_session(0x52, "peer_f");
        assert!(in_flight.begin_quantum_mix(&[0x11u8; 32], LABEL).is_some());
        assert!(!in_flight.quantum_mix_due(Duration::ZERO));
        in_flight.abandon_quantum_mix();
        assert!(
            in_flight.quantum_mix_due(interval),
            "an abandoned attempt does not block the retry forever"
        );

        // A completed mix is applied once per session and never revisited.
        let mixed = mixable_session(0x53, "peer_m");
        assert!(mixed.begin_quantum_mix(&[0x11u8; 32], LABEL).is_some());
        assert!(mixed.activate_epoch(1));
        assert!(mixed.quantum_mixed());
        assert!(!mixed.quantum_mix_due(Duration::ZERO));
    }

    #[test]
    fn an_unanswered_mix_stalls_without_touching_the_epoch() {
        let session = mixable_session(0x61, "peer_s");
        let first_confirm = session
            .begin_quantum_mix(&[0x11u8; 32], LABEL)
            .expect("a mix to stall on")
            .confirm;
        // Not stalled yet — the bound is what stops a wedged session, not a clock
        // tick, so a zero-length window is the only way to observe it here.
        assert!(!session.quantum_mix_stalled(Duration::from_secs(90)));
        assert!(session.quantum_mix_stalled(Duration::ZERO));
        session.abandon_quantum_mix();
        assert!(!session.quantum_mix_stalled(Duration::ZERO));
        assert_eq!(session.epoch(), 0, "the live epoch was never touched");

        // The retry is not just allowed, it is *identical*: same root, same
        // quantum key, so the same epoch and the same confirmation tag. That is
        // what makes abandoning a mix safe — a slow peer and a lost peer look the
        // same here, and neither costs the session its place in the generation.
        let retry = session
            .begin_quantum_mix(&[0x11u8; 32], LABEL)
            .expect("a retry after a stall");
        assert_eq!(retry.epoch, 1);
        assert_eq!(retry.confirm, first_confirm);
        assert_eq!(session.epoch(), 0);
    }
}
