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
use ml_kem::EncapsulationKey768;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;

pub const MAX_STREAMS: u16 = 256;

pub const REKEY_THRESHOLD: u64 = 0xFFFF_FFFF_C000_0000; // 75% of u64::MAX

pub const REKEY_MAGIC: &[u8; 16] = b"GHOST_REKEY____!";
pub const REKEY_RESPONSE_MAGIC: &[u8; 16] = b"GHOST_REKEY_RSP!";

pub const QEL_MIX_MAGIC: &[u8; 16] = b"GHOST_QEL_MIX___";
pub const QEL_MIX_RESPONSE_MAGIC: &[u8; 16] = b"GHOST_QEL_MIX_OK";

pub const QEL_MIX_MAX_LABEL: usize = 128;

pub const QEL_MIX_BLOB_LEN: usize = 250;
pub const QEL_MIX_RESPONSE_BLOB_LEN: usize = 120;

pub const REKEY_BLOB_LEN: usize = 1296;
pub const REKEY_RESPONSE_BLOB_LEN: usize = 1232;

pub struct Session {
    pub master_key: [u8; 32],
    pub tx_counter: AtomicU64,
    pub guard: Mutex<SessionGuardU64>,
    pub peer_fingerprint: String,
    pub established_at: Instant,
    pub session_hash: [u8; 4],
    pub role: SessionRole,
    pub ack_engine: Arc<std::sync::Mutex<AckEngine>>,
    pub streams: Arc<DashMap<u16, StreamState>>,
    pub next_stream_id: AtomicU16,
    pub stats: Arc<ThroughputStats>,
    pub use_bulk: bool,
    pub cipher_suite: HybridCipherSuite,
    pub wire_v1: AtomicBool,

    ratchet: Mutex<SessionRatchet>,
    pending_step: Mutex<Option<RatchetStep>>,
    ratchet_step_at: Mutex<Option<Instant>>,
    pub ratchet_steps: AtomicU64,
    pub ratchet_in_progress: AtomicBool,
    pub forced_ratchet_due: AtomicBool,
    peer_identity_pk: Mutex<Option<[u8; 32]>>,
    pub pq_auth_state: AtomicU8,
    peer_pq_commitment: Mutex<Option<[u8; 32]>>,
    peer_pq_pk: Mutex<Option<Vec<u8>>>,
    pq_incoming_chunks: Mutex<std::collections::HashMap<u8, Vec<u8>>>,
    pub pq_auth_requested_at: Instant,

    pending_quantum_mix: Mutex<Option<PendingQuantumMix>>,
    quantum_mix_at: Mutex<Option<Instant>>,
    quantum_mix_attempt_at: Mutex<Option<Instant>>,
    pub quantum_mix_in_progress: AtomicBool,
    pub quantum_mixed: AtomicBool,
}

#[derive(Debug, Clone)]
pub struct PendingQuantumMix {
    pub epoch: u64,
    pub confirm: [u8; 32],
    pub label: String,
}

pub struct RatchetAnswer {
    pub x_public: [u8; 32],
    pub kem_ct: [u8; 1088],
    pub confirm: [u8; 32],
    pub epoch: u64,
}

#[derive(Clone)]
pub struct SealMaterial {
    pub key: [u8; 32],
    pub epoch: u64,
    pub counter: u64,
    pub nonce: [u8; 12],
    pub direction: NonceDirection,
    pub ratchet_due: bool,
}

pub struct StreamState {
    pub stream_type: StreamType,
    pub recv_buf: Vec<Option<Bytes>>,
    pub next_seq: u32,
    pub created_at: Instant,
    pub bytes_recv: u64,
    pub bytes_sent: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    Control,
    Bulk,
    Stream,
    Interactive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    Initiator,
    Responder,
}

impl SessionRole {
    pub fn seal_direction(self) -> NonceDirection {
        match self {
            Self::Initiator => NonceDirection::InitiatorToResponder,
            Self::Responder => NonceDirection::ResponderToInitiator,
        }
    }
}

impl Session {
    pub fn new(master_key: [u8; 32], peer_fingerprint: String) -> Self {
        Self::new_with_role(master_key, peer_fingerprint, SessionRole::Initiator)
    }

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

    pub fn set_cipher_suite(&mut self, suite: HybridCipherSuite) {
        self.cipher_suite = suite;
    }

    pub fn pin_peer_identity(&self, pk: [u8; 32]) {
        *self
            .peer_identity_pk
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(pk);
    }

    pub fn peer_identity_pk(&self) -> Option<[u8; 32]> {
        *self
            .peer_identity_pk
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    pub fn is_pq_authenticated(&self) -> bool {
        self.peer_pq_commitment().is_none() || self.pq_auth_state.load(Ordering::Acquire) == 1
    }

    pub fn pq_auth_state(&self) -> u8 {
        self.pq_auth_state.load(Ordering::Acquire)
    }

    pub fn set_pq_authenticated(&self, valid: bool) {
        let state = if valid { 1 } else { 2 };
        self.pq_auth_state.store(state, Ordering::Release);
    }

    pub fn is_v1_wire(&self) -> bool {
        self.wire_v1.load(Ordering::Relaxed)
    }

    pub fn set_v1_wire(&self, v1: bool) {
        self.wire_v1.store(v1, Ordering::Relaxed);
    }

    pub fn pin_peer_pq_commitment(&self, commitment: [u8; 32]) {
        *self
            .peer_pq_commitment
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(commitment);
    }

    pub fn peer_pq_commitment(&self) -> Option<[u8; 32]> {
        *self
            .peer_pq_commitment
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    pub fn set_peer_pq_pk(&self, pk: Vec<u8>) {
        *self.peer_pq_pk.lock().unwrap_or_else(|e| e.into_inner()) = Some(pk);
    }

    pub fn peer_pq_pk(&self) -> Option<Vec<u8>> {
        self.peer_pq_pk
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

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
                {
                    let chunk = guard.get(&idx)?;
                    assembled.extend_from_slice(chunk);
                }
            }
            Some(assembled)
        } else {
            None
        }
    }

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

    pub fn next_tx_counter(&self) -> u64 {
        self.try_next_tx_counter().unwrap_or(u64::MAX)
    }

    pub fn advance_seal(&self, direction: NonceDirection) -> (u64, [u8; 32]) {
        self.ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .advance_seal(direction)
    }

    pub fn seal_key(&self, direction: NonceDirection) -> [u8; 32] {
        self.ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .seal_key(direction)
    }

    pub fn plan_open(&self, epoch: u64, direction: NonceDirection, counter: u64) -> OpenPlan {
        self.ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .plan_open(epoch, direction, counter)
    }

    pub fn commit_open(&self, epoch: u64, direction: NonceDirection, plan: OpenPlan) {
        self.ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .commit_open(epoch, direction, plan);
    }

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

    pub fn epoch(&self) -> u64 {
        self.ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .epoch()
    }

    pub fn openable_epochs(&self) -> Vec<u64> {
        self.ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .openable_epochs()
    }

    pub fn epoch_capacity_left(&self) -> u64 {
        self.ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .epoch_capacity_left()
    }

    pub fn ratchet_due(&self) -> bool {
        self.epoch_capacity_left() == 0 || self.forced_ratchet_due.load(Ordering::Relaxed)
    }

    pub fn prepared_epoch(&self) -> Option<u64> {
        self.ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .prepared_epoch()
    }

    pub fn activate_epoch(&self, epoch: u64) -> bool {
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

    pub fn note_sealed_frame(&self) -> bool {
        self.ratchet
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .count_seal()
    }

    pub fn apply_ratchet_step(&self, secrets: &StepSecrets) -> u64 {
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

    pub fn begin_ratchet_step(&self) -> Option<([u8; 32], Vec<u8>)> {
        if self.quantum_mix_in_progress.load(Ordering::Relaxed) {
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

    pub fn answer_ratchet_step(
        &self,
        peer_x: &[u8; 32],
        peer_kem_pub: &[u8],
    ) -> Option<RatchetAnswer> {
        let step = RatchetStep::generate();
        let our_x = step.x_public_bytes();
        let (secrets, kem_ct) = step.respond(peer_x, peer_kem_pub)?;
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
            confirm: crate::ghost::layers::l1_kem::ratchet_confirm(&prepared_key),
            label: label.to_string(),
        });
        *self
            .quantum_mix_at
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
        Some(confirm)
    }

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

    pub fn note_quantum_mix_attempt(&self) {
        *self
            .quantum_mix_attempt_at
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
    }

    pub fn quantum_mix_in_progress(&self) -> bool {
        self.quantum_mix_in_progress.load(Ordering::Relaxed)
    }

    pub fn quantum_mixed(&self) -> bool {
        self.quantum_mixed.load(Ordering::Relaxed)
    }

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

    pub fn abandon_ratchet_step(&self) {
        *self.pending_step.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *self
            .ratchet_step_at
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        self.ratchet_in_progress.store(false, Ordering::Relaxed);
    }

    pub fn check_inbound(&self, counter: u64) -> bool {
        self.guard
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .check_and_update(counter)
    }

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

    pub fn enable_bulk(&mut self) {
        self.use_bulk = true;
    }

    pub fn disable_bulk(&mut self) {
        self.use_bulk = false;
    }

    pub fn frame_size(&self) -> usize {
        if self.use_bulk {
            crate::ghost::net::GTF_BULK_SIZE
        } else {
            crate::ghost::net::GTF_BASE_SIZE
        }
    }

    pub fn seal_direction(&self) -> NonceDirection {
        self.role.seal_direction()
    }

    pub fn seal_material(&self) -> SealMaterial {
        let mut ratchet = self.ratchet.lock().unwrap_or_else(|e| e.into_inner());
        let epoch = ratchet.epoch();
        let (counter, key) = ratchet.advance_seal(self.seal_direction());
        let due = ratchet.count_seal();
        drop(ratchet);
        self.tx_counter
            .store(counter.wrapping_add(1), Ordering::Relaxed);
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

    pub fn zeroize_keys(&mut self) {
        for b in self.master_key.iter_mut() {
            unsafe {
                std::ptr::write_volatile(b, 0u8);
            }
        }
    }
}

pub fn build_rekey_pdu(
    identity_sign: impl Fn(&[u8]) -> [u8; 64],
    x_pub: &x25519_dalek::PublicKey,
    kyber_pub: &EncapsulationKey768,
) -> Vec<u8> {
    let kyber_bytes = kyber_pub.to_bytes();
    let mut pdu = vec![0u8; REKEY_BLOB_LEN];
    pdu[0..16].copy_from_slice(REKEY_MAGIC);
    pdu[16..48].copy_from_slice(x_pub.as_bytes());
    pdu[48..1232].copy_from_slice(&kyber_bytes);

    let signed_material = {
        let mut m = Vec::with_capacity(32 + kyber_bytes.len());
        m.extend_from_slice(x_pub.as_bytes());
        m.extend_from_slice(&kyber_bytes);
        m
    };

    let sig = identity_sign(&signed_material);
    pdu[1232..1296].copy_from_slice(&sig);
    pdu
}

pub fn build_ratchet_step_pdu(
    identity_sign: impl Fn(&[u8]) -> [u8; 64],
    x_pub_bytes: &[u8; 32],
    kem_pub_bytes: &[u8],
) -> Option<Vec<u8>> {
    let ek = EncapsulationKey768::new_from_slice(kem_pub_bytes).ok()?;
    let x_pub = x25519_dalek::PublicKey::from(*x_pub_bytes);
    Some(build_rekey_pdu(identity_sign, &x_pub, &ek))
}

pub struct RekeyBlob {
    pub x25519_pub: [u8; 32],
    pub kyber_pub: [u8; 1184],
    pub signature: [u8; 64],
}

pub fn parse_rekey_pdu(data: &[u8]) -> Option<RekeyBlob> {
    if data.len() < REKEY_BLOB_LEN || !data.starts_with(REKEY_MAGIC) {
        return None;
    }
    let mut x25519_pub = [0u8; 32];
    x25519_pub.copy_from_slice(&data[16..48]);
    let mut kyber_pub = [0u8; 1184];
    kyber_pub.copy_from_slice(&data[48..1232]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[1232..1296]);
    Some(RekeyBlob {
        x25519_pub,
        kyber_pub,
        signature,
    })
}

pub fn build_rekey_response_pdu(
    identity_sign: impl Fn(&[u8]) -> [u8; 64],
    x_pub: &[u8; 32],
    kyber_ct: &[u8; 1088],
    confirm: &[u8; 32],
) -> Vec<u8> {
    let mut pdu = vec![0u8; REKEY_RESPONSE_BLOB_LEN];
    pdu[0..16].copy_from_slice(REKEY_RESPONSE_MAGIC);
    pdu[16..48].copy_from_slice(x_pub);
    pdu[48..1136].copy_from_slice(kyber_ct);
    pdu[1136..1168].copy_from_slice(confirm);

    let signed_material = {
        let mut m = vec![0u8; 1152];
        m[0..32].copy_from_slice(x_pub);
        m[32..1120].copy_from_slice(kyber_ct);
        m[1120..1152].copy_from_slice(confirm);
        m
    };

    let sig = identity_sign(&signed_material);
    pdu[1168..1232].copy_from_slice(&sig);
    pdu
}

pub struct RekeyResponseBlob {
    pub x25519_pub: [u8; 32],
    pub kyber_ct: [u8; 1088],
    pub confirm: [u8; 32],
    pub signature: [u8; 64],
}

pub fn parse_rekey_response_pdu(data: &[u8]) -> Option<RekeyResponseBlob> {
    if data.len() < REKEY_RESPONSE_BLOB_LEN || !data.starts_with(REKEY_RESPONSE_MAGIC) {
        return None;
    }
    let mut x25519_pub = [0u8; 32];
    x25519_pub.copy_from_slice(&data[16..48]);
    let mut kyber_ct = [0u8; 1088];
    kyber_ct.copy_from_slice(&data[48..1136]);
    let mut confirm = [0u8; 32];
    confirm.copy_from_slice(&data[1136..1168]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[1168..1232]);
    Some(RekeyResponseBlob {
        x25519_pub,
        kyber_ct,
        confirm,
        signature,
    })
}

pub fn rekey_init_signed_material(x_pub: &[u8; 32], kyber_pub: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(32 + kyber_pub.len());
    m.extend_from_slice(x_pub);
    m.extend_from_slice(kyber_pub);
    m
}

pub fn rekey_answer_signed_material(
    x_pub: &[u8; 32],
    kyber_ct: &[u8; 1088],
    confirm: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(1152);
    m.extend_from_slice(x_pub);
    m.extend_from_slice(kyber_ct);
    m.extend_from_slice(confirm);
    m
}

const QEL_MIX_EPOCH_AT: usize = 16;
const QEL_MIX_LABEL_LEN_AT: usize = 24;
const QEL_MIX_LABEL_AT: usize = 26;
const QEL_MIX_CONFIRM_AT: usize = QEL_MIX_LABEL_AT + QEL_MIX_MAX_LABEL; // 154
const QEL_MIX_SIG_AT: usize = QEL_MIX_CONFIRM_AT + 32; // 186

pub fn build_qel_mix_pdu(
    identity_sign: impl Fn(&[u8]) -> [u8; 64],
    epoch: u64,
    label: &str,
    confirm: &[u8; 32],
) -> Vec<u8> {
    let mut pdu = vec![0u8; QEL_MIX_BLOB_LEN];
    pdu[0..16].copy_from_slice(QEL_MIX_MAGIC);
    pdu[QEL_MIX_EPOCH_AT..QEL_MIX_LABEL_LEN_AT].copy_from_slice(&epoch.to_be_bytes());
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

pub struct QelMixBlob {
    pub epoch: u64,
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

pub fn qel_mix_signed_material(epoch: u64, label: &str, confirm: &[u8; 32]) -> Vec<u8> {
    let bytes = label.as_bytes();
    let mut m = Vec::with_capacity(8 + 2 + bytes.len() + 32);
    m.extend_from_slice(&epoch.to_be_bytes());
    m.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    m.extend_from_slice(bytes);
    m.extend_from_slice(confirm);
    m
}

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

pub fn qel_mix_response_signed_material(epoch: u64, confirm: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(40);
    m.extend_from_slice(&epoch.to_be_bytes());
    m.extend_from_slice(confirm);
    m
}

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
        let session = Session::new([0x42u8; 32], "test_fp".to_string());
        session.tx_counter.store(0xFFFF_FFFC, Ordering::Relaxed); // v1's last usable counter
        assert_eq!(session.try_next_tx_counter(), Some(0xFFFF_FFFD));
        assert_eq!(session.try_next_tx_counter(), Some(0xFFFF_FFFE));
        assert_eq!(session.try_next_tx_counter(), Some(0xFFFF_FFFF));
        assert_eq!(session.try_next_tx_counter(), Some(0x1_0000_0000));
        session.tx_counter.store(u64::MAX, Ordering::Relaxed);
        assert!(session.try_next_tx_counter().is_none());
    }

    #[test]
    fn test_seal_key_is_per_epoch_and_open_key_follows_the_grace_window() {
        let session = Session::new([0xABu8; 32], "test_fp".to_string());
        let epoch0 = session.seal_key(NonceDirection::InitiatorToResponder);
        assert_eq!(session.epoch(), 0);

        let secrets =
            crate::ghost::session::ratchet::StepSecrets::new([0x01u8; 32], vec![0x02u8; 32]);
        assert_eq!(session.apply_ratchet_step(&secrets), 1);
        assert_eq!(session.epoch(), 1);
        assert_eq!(session.ratchet_steps.load(Ordering::Relaxed), 1);
        assert_ne!(
            session.seal_key(NonceDirection::InitiatorToResponder),
            epoch0
        );
        assert_eq!(
            session.open_key(0, NonceDirection::InitiatorToResponder, 0),
            Some(epoch0)
        );
        assert!(session
            .open_key(4242, NonceDirection::InitiatorToResponder, 0)
            .is_none());
    }

    #[test]
    fn test_ratchet_step_exchange_between_two_sessions() {
        let a = Session::new_with_role([0x11u8; 32], "a".into(), SessionRole::Initiator);
        let b = Session::new_with_role([0x11u8; 32], "b".into(), SessionRole::Responder);

        let (a_x, a_kem) = a.begin_ratchet_step().expect("a starts a step");
        assert!(a.begin_ratchet_step().is_none());
        let answer = b
            .answer_ratchet_step(&a_x, &a_kem)
            .expect("b answers the step");
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
        let a = Session::new_with_role([0x11u8; 32], "bob".into(), SessionRole::Initiator);
        let b = Session::new_with_role([0x11u8; 32], "alice".into(), SessionRole::Responder);
        let (a_x, a_kem) = a.begin_ratchet_step().unwrap();
        let _ = b.begin_ratchet_step().unwrap();

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
        let (ky_pub, _ky_sec) = crate::ghost::layers::l1_kem::generate_kyber768_keypair();

        let pdu = build_rekey_pdu(|data| identity.sign(data).to_bytes(), &x_pub, &ky_pub);

        assert_eq!(pdu.len(), REKEY_BLOB_LEN);
        assert!(pdu.starts_with(REKEY_MAGIC));

        let parsed = parse_rekey_pdu(&pdu).expect("Should parse re-key PDU");
        assert_eq!(&parsed.x25519_pub[..], x_pub.as_bytes());
        assert_eq!(&parsed.kyber_pub[..], ky_pub.to_bytes().as_slice());

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
        let kyber_ct = [0xCDu8; 1088];
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

        let signed_material = rekey_answer_signed_material(&x_pub, &kyber_ct, &confirm);
        assert!(l0_identity::verify_peer_signature(
            &identity.public_key_bytes(),
            &signed_material,
            &parsed.signature,
        ));
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
        let (ky_pub, _ky_sec) = crate::ghost::layers::l1_kem::generate_kyber768_keypair();
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

    fn mixable_session(seed: u8, peer: &str) -> Session {
        Session::new_with_role([seed; 32], peer.to_string(), SessionRole::Initiator)
    }

    const LABEL: &str = "qkd-sim/1/f=3feccccc00000000/s=00000000000051ee";

    #[test]
    fn a_mix_and_a_dh_step_are_mutually_exclusive() {
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

        assert!(mixable_session(0x43, "free_peer").admit_peer_quantum_mix("any_us"));
    }

    #[test]
    fn the_mix_attempt_is_throttled_by_the_retry_interval() {
        let session = mixable_session(0x51, "peer_t");
        let interval = Duration::from_secs(60);
        assert!(session.quantum_mix_due(interval), "a fresh session is due");
        session.note_quantum_mix_attempt();
        assert!(
            !session.quantum_mix_due(interval),
            "a recorded attempt suppresses the next one"
        );
        assert_eq!(session.epoch(), 0, "and nothing was advanced by trying");

        let in_flight = mixable_session(0x52, "peer_f");
        assert!(in_flight.begin_quantum_mix(&[0x11u8; 32], LABEL).is_some());
        assert!(!in_flight.quantum_mix_due(Duration::ZERO));
        in_flight.abandon_quantum_mix();
        assert!(
            in_flight.quantum_mix_due(interval),
            "an abandoned attempt does not block the retry forever"
        );

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
        assert!(!session.quantum_mix_stalled(Duration::from_secs(90)));
        assert!(session.quantum_mix_stalled(Duration::ZERO));
        session.abandon_quantum_mix();
        assert!(!session.quantum_mix_stalled(Duration::ZERO));
        assert_eq!(session.epoch(), 0, "the live epoch was never touched");

        let retry = session
            .begin_quantum_mix(&[0x11u8; 32], LABEL)
            .expect("a retry after a stall");
        assert_eq!(retry.epoch, 1);
        assert_eq!(retry.confirm, first_confirm);
        assert_eq!(session.epoch(), 0);
    }
}
