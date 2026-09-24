//! Session ratchet — hybrid DH ratchet with per-epoch AEAD keys.
//!
//! # Why a ratchet at all
//!
//! A session key that never changes is a liability with a measurable shelf life:
//! one recorded key opens every frame the session ever carried, and one stolen key
//! opens every frame it will ever carry. The ratchet bounds both losses.
//!
//! * **Forward secrecy** comes from the symmetric ratchet. Each epoch's key is
//!   derived from a chain key by a one-way step ([`kdf_ck`]), and the key the epoch
//!   actually used is discarded when the epoch retires — so an attacker who reads
//!   the session's memory today cannot reconstruct yesterday's traffic. The chain
//!   only steps forward.
//! * **Break-in recovery** comes from the DH ratchet. Every [`RATCHET_INTERVAL`]
//!   datagrams the session performs a *fresh* hybrid exchange — a new X25519
//!   ephemeral and a new ML-KEM-512 encapsulation — and mixes the result into the
//!   root key. An attacker who held the whole state at epoch `n` is locked out
//!   again at epoch `n+1`, because the secrets that produced `n+1` did not exist
//!   when they took their copy.
//!
//! Both halves are hybrid because the classical sole is exactly the half a
//! quantum adversary walks through: a ratchet secured only by X25519 lets a
//! CRQC recover every root key from recorded traffic, which would turn
//! "forward secrecy" into a claim about the *present* rather than the past.
//!
//! # Why the epoch is on the wire
//!
//! Each frame names the epoch that sealed it (GTF v2 `RATCHET_EPOCH`). The
//! alternative — deriving the epoch from the packet counter — only works if both
//! sides step at exactly the same frame, and the alternative the previous design
//! used — trial decryption against the current and previous key — answers "which
//! key?" by *timing*, leaks two AEAD attempts per frame, and cannot tell a stale
//! epoch from a forged one. Naming the epoch costs 8 bytes and makes the question
//! answerable from a packet capture.

use crate::ghost::layers::l1_kem::{
    derive_epoch_key, generate_kyber_keypair, generate_x25519_keypair, kdf_ck, kdf_rk_hybrid,
    seed_ratchet_chains,
};
use crate::ghost::layers::l2_aead::NonceDirection;
use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::{Ciphertext, DecapsulationKey512, EncapsulationKey512, MlKem512};
use std::collections::VecDeque;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use zeroize::Zeroize;

/// Datagrams one epoch key may seal before the session is due to ratchet.
///
/// This is the number that bounds the wire nonce's collision risk: with a random
/// 96-bit nonce, `n` frames under one key collide with probability `n²/2^97`, so
/// one million frames give ~2⁻⁷⁰ — far below the 2⁻³² that would matter, and the
/// ratchet replaces the key long before a real link could accumulate the 2⁴⁸
/// frames where a random-96-bit-nonce birthday collision becomes likely.
pub const RATCHET_INTERVAL: u64 = 1_000_000;

/// How many *previous* epochs keep their keys so frames in flight across a step
/// still open. One is enough for a step; two covers a step that raced with a
/// retransmission and keeps the window honest when an ACK is lost.
pub const RATCHET_RETAINED_EPOCHS: usize = 2;

/// The largest forward jump an open will pay for.
pub const MAX_SKIP: u64 = 1024;

/// What opening one counter should do, computed **without mutating anything**.
///
/// The receive path needs "plan, then commit": because the counter is unauthenticated,
/// the derivation is computed first and applied only once the AEAD has verified the
/// frame. A plan that is never committed leaves the chain exactly as it was, so a
/// forgery costs at most [`MAX_SKIP`] hashes and changes nothing.
pub enum OpenPlan {
    /// Derive forward. Use `key`; on commit install `new_chain`/`new_pos` and cache the
    /// keys passed over, so a straggler arriving later can still open.
    Forward {
        key: [u8; 32],
        new_chain: [u8; 32],
        new_pos: u64,
        cache: Vec<(u64, [u8; 32])>,
    },
    /// A key already held for an out-of-order counter. Commit consumes (deletes) it, so
    /// a second frame claiming the same counter cannot open.
    Cached { counter: u64, key: [u8; 32] },
    /// Too far ahead to pay for, or a past counter whose key is already gone.
    Refused,
}

/// One direction's **per-message** chain.
///
/// An epoch key used to seal every frame of its epoch — up to a million messages under
/// one key. This advances once per *message* instead: the key a frame is sealed under is
/// a [`kdf_ck`] step key, and the chain moves past it, so a compromise of the state
/// cannot reach a message already sealed. That only holds if the epoch key is the seed
/// and is **not** retained beside the chain — a seed kept in the same struct would derive
/// every message key and make this cosmetic.
#[derive(Clone)]
pub struct MsgChain {
    chain: [u8; 32],
    pos: u64,
    /// Keys for counters jumped over, kept so out-of-order arrivals still open. Bounded
    /// by [`MAX_SKIP`] entries, oldest evicted.
    skipped: std::collections::BTreeMap<u64, [u8; 32]>,
}

impl Drop for MsgChain {
    fn drop(&mut self) {
        self.chain.zeroize();
        for key in self.skipped.values_mut() {
            key.zeroize();
        }
    }
}

impl MsgChain {
    /// Start a chain for one epoch from that epoch's derived seed key.
    pub fn seed(seed: &[u8; 32]) -> Self {
        Self {
            chain: *seed,
            pos: 0,
            skipped: std::collections::BTreeMap::new(),
        }
    }

    pub fn pos(&self) -> u64 {
        self.pos
    }

    pub fn skipped_len(&self) -> usize {
        self.skipped.len()
    }

    pub fn advance(&mut self) -> [u8; 32] {
        let (next, key) = kdf_ck(&self.chain);
        self.chain.zeroize();
        self.chain = next;
        self.pos += 1;
        key
    }

    /// Work out how to open `counter`, changing nothing.
    pub fn plan(&self, counter: u64) -> OpenPlan {
        if counter < self.pos {
            return match self.skipped.get(&counter) {
                Some(key) => OpenPlan::Cached { counter, key: *key },
                // Gone: either already consumed or never held. Either way the honest
                // answer is that the key is not here, rather than a guess.
                None => OpenPlan::Refused,
            };
        }
        let gap = counter - self.pos;
        if gap > MAX_SKIP {
            // Bounded work, and *no* advance: refusing must not move the state, or an
            // unauthenticated packet could walk the receiver past real traffic.
            return OpenPlan::Refused;
        }
        let mut chain = self.chain;
        let mut cache = Vec::with_capacity(gap as usize);
        let mut key = [0u8; 32];
        for i in 0..=gap {
            let (next, step) = kdf_ck(&chain);
            chain = next;
            if i < gap {
                cache.push((self.pos + i, step));
            } else {
                key = step;
            }
        }
        OpenPlan::Forward {
            key,
            new_chain: chain,
            new_pos: counter + 1,
            cache,
        }
    }

    /// Apply a plan. The caller does this only *after* the frame has authenticated.
    pub fn commit(&mut self, plan: OpenPlan) {
        match plan {
            OpenPlan::Forward {
                new_chain,
                new_pos,
                cache,
                ..
            } => {
                if new_pos > self.pos {
                    self.chain.zeroize();
                    self.chain = new_chain;
                    self.pos = new_pos;
                    for (counter, key) in cache {
                        if !self.skipped.contains_key(&counter) {
                            self.skipped.insert(counter, key);
                        }
                    }
                }
                // Evict oldest if > MAX_SKIP
                while self.skipped.len() > MAX_SKIP as usize {
                    let oldest = *self.skipped.keys().next().expect("non-empty");
                    if let Some(mut dead) = self.skipped.remove(&oldest) {
                        dead.zeroize();
                    }
                }
            }
            OpenPlan::Cached { counter, .. } => {
                // Single use: consuming it is what makes a replay of the same counter
                // fail rather than open twice.
                if let Some(mut spent) = self.skipped.remove(&counter) {
                    spent.zeroize();
                }
            }
            OpenPlan::Refused => {}
        }
    }
}

/// One direction's chain: the one-way key it advances from, and its per-message chain.
#[derive(Clone)]
struct ChainState {
    /// The chain key. Every epoch key is derived from it and it never goes back.
    chain: [u8; 32],
    /// Per-message chain for this direction.
    msg_chain: MsgChain,
}

impl ChainState {
    /// Seed a chain and start its message chain, zeroizing the intermediate epoch key.
    fn seed(chain_key: [u8; 32], epoch: u64) -> Self {
        let (chain, _) = kdf_ck(&chain_key);
        let mut epoch_seed = derive_epoch_key(&chain, epoch);
        let msg_chain = MsgChain::seed(&epoch_seed);
        epoch_seed.zeroize();
        Self { chain, msg_chain }
    }
}

impl Drop for ChainState {
    fn drop(&mut self) {
        self.chain.zeroize();
    }
}

/// A retired epoch's message chains, retained only so frames already on the wire can open.
#[derive(Clone)]
pub struct RatchetEpoch {
    pub epoch: u64,
    /// Message chain for initiator→responder traffic in this epoch.
    pub to_resp: MsgChain,
    /// Message chain for responder→initiator traffic in this epoch.
    pub to_init: MsgChain,
}

/// A ratchet step that has been derived but **not installed**.
#[derive(Clone)]
struct PreparedEpoch {
    epoch: u64,
    root_key: [u8; 32],
    to_resp: ChainState,
    to_init: ChainState,
}

impl Drop for PreparedEpoch {
    fn drop(&mut self) {
        self.root_key.zeroize();
    }
}

/// The live ratchet state of one session.
pub struct SessionRatchet {
    /// Root key: re-mixed by every DH step. The next step's salt.
    root_key: [u8; 32],
    /// Chain for initiator→responder traffic.
    to_resp: ChainState,
    /// Chain for responder→initiator traffic.
    to_init: ChainState,
    /// Current ratchet generation, counted from 0.
    epoch: u64,
    /// How many ratchet steps this session has taken (monotonic, for status).
    steps: u64,
    /// Frames sealed in the current epoch, which is what triggers the step.
    frames_in_epoch: u64,
    /// Retired epochs, newest first.
    retired: VecDeque<RatchetEpoch>,
    /// A step derived but not installed (see [`PreparedEpoch`]).
    pending: Option<PreparedEpoch>,
}

impl SessionRatchet {
    /// Start a ratchet from the hybrid handshake's master key.
    ///
    /// Epoch 0's keys are already one chain step away from the handshake key, so
    /// compromising the handshake secret alone does not immediately read epoch 0.
    pub fn new(master_key: [u8; 32]) -> Self {
        let (to_resp, to_init) = seed_ratchet_chains(&master_key);
        Self {
            root_key: master_key,
            to_resp: ChainState::seed(to_resp, 0),
            to_init: ChainState::seed(to_init, 0),
            epoch: 0,
            steps: 0,
            frames_in_epoch: 0,
            retired: VecDeque::new(),
            pending: None,
        }
    }

    /// The current ratchet generation.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Steps taken in this session's lifetime.
    pub fn steps(&self) -> u64 {
        self.steps
    }

    /// Frames sealed under the current epoch key.
    pub fn frames_in_epoch(&self) -> u64 {
        self.frames_in_epoch
    }

    /// The root key a step is about to mix into. Exposed because the step PDU has
    /// to be signed over it by the caller.
    pub fn root_key(&self) -> [u8; 32] {
        self.root_key
    }

    /// Take the next message key for sealing and advance the chain. Returns `(counter, key)`.
    pub fn advance_seal(&mut self, direction: NonceDirection) -> (u64, [u8; 32]) {
        let chain = match direction {
            NonceDirection::InitiatorToResponder => &mut self.to_resp.msg_chain,
            NonceDirection::ResponderToInitiator => &mut self.to_init.msg_chain,
        };
        let counter = chain.pos();
        let key = chain.advance();
        (counter, key)
    }

    /// The key the current epoch would next seal under (without advancing).
    pub fn seal_key(&self, direction: NonceDirection) -> [u8; 32] {
        let chain = match direction {
            NonceDirection::InitiatorToResponder => &self.to_resp.msg_chain,
            NonceDirection::ResponderToInitiator => &self.to_init.msg_chain,
        };
        match chain.plan(chain.pos()) {
            OpenPlan::Forward { key, .. } => key,
            OpenPlan::Cached { key, .. } => key,
            OpenPlan::Refused => [0u8; 32],
        }
    }

    /// Plan how to open `counter` in `epoch` and `direction`, without mutating state.
    pub fn plan_open(&self, epoch: u64, direction: NonceDirection, counter: u64) -> OpenPlan {
        if let Some(p) = self.pending.as_ref() {
            if p.epoch == epoch {
                return match direction {
                    NonceDirection::InitiatorToResponder => p.to_resp.msg_chain.plan(counter),
                    NonceDirection::ResponderToInitiator => p.to_init.msg_chain.plan(counter),
                };
            }
        }
        if epoch == self.epoch {
            return match direction {
                NonceDirection::InitiatorToResponder => self.to_resp.msg_chain.plan(counter),
                NonceDirection::ResponderToInitiator => self.to_init.msg_chain.plan(counter),
            };
        }
        if let Some(e) = self.retired.iter().find(|e| e.epoch == epoch) {
            return match direction {
                NonceDirection::InitiatorToResponder => e.to_resp.plan(counter),
                NonceDirection::ResponderToInitiator => e.to_init.plan(counter),
            };
        }
        OpenPlan::Refused
    }

    /// Apply an open plan after the frame authenticates.
    pub fn commit_open(&mut self, epoch: u64, direction: NonceDirection, plan: OpenPlan) {
        if let Some(p) = self.pending.as_mut() {
            if p.epoch == epoch {
                match direction {
                    NonceDirection::InitiatorToResponder => p.to_resp.msg_chain.commit(plan),
                    NonceDirection::ResponderToInitiator => p.to_init.msg_chain.commit(plan),
                }
                return;
            }
        }
        if epoch == self.epoch {
            match direction {
                NonceDirection::InitiatorToResponder => self.to_resp.msg_chain.commit(plan),
                NonceDirection::ResponderToInitiator => self.to_init.msg_chain.commit(plan),
            }
            return;
        }
        if let Some(e) = self.retired.iter_mut().find(|e| e.epoch == epoch) {
            match direction {
                NonceDirection::InitiatorToResponder => e.to_resp.commit(plan),
                NonceDirection::ResponderToInitiator => e.to_init.commit(plan),
            }
        }
    }

    /// The AEAD key for a *named* epoch, direction, and counter — what to *open* with.
    pub fn open_key(
        &self,
        epoch: u64,
        direction: NonceDirection,
        counter: u64,
    ) -> Option<[u8; 32]> {
        match self.plan_open(epoch, direction, counter) {
            OpenPlan::Forward { key, .. } => Some(key),
            OpenPlan::Cached { key, .. } => Some(key),
            OpenPlan::Refused => None,
        }
    }

    /// Whether an unopenable frame's counter exceeded MAX_SKIP past our chain position.
    pub fn gap_exceeds_max_skip(
        &self,
        epoch: u64,
        direction: NonceDirection,
        counter: u64,
    ) -> bool {
        let pos = if let Some(p) = self.pending.as_ref() {
            if p.epoch == epoch {
                match direction {
                    NonceDirection::InitiatorToResponder => p.to_resp.msg_chain.pos(),
                    NonceDirection::ResponderToInitiator => p.to_init.msg_chain.pos(),
                }
            } else if epoch == self.epoch {
                match direction {
                    NonceDirection::InitiatorToResponder => self.to_resp.msg_chain.pos(),
                    NonceDirection::ResponderToInitiator => self.to_init.msg_chain.pos(),
                }
            } else {
                return false;
            }
        } else if epoch == self.epoch {
            match direction {
                NonceDirection::InitiatorToResponder => self.to_resp.msg_chain.pos(),
                NonceDirection::ResponderToInitiator => self.to_init.msg_chain.pos(),
            }
        } else {
            return false;
        };
        counter > pos && (counter - pos) > MAX_SKIP
    }

    /// Derive a step's epoch **without installing it**, and return the key the
    /// *peer* will seal in, for the confirmation tag.
    pub fn prepare_step(
        &mut self,
        secrets: &StepSecrets,
        peer_direction: NonceDirection,
    ) -> (u64, [u8; 32]) {
        let (root_key, chain_to_resp, chain_to_init) =
            kdf_rk_hybrid(&self.root_key, &secrets.dh, &secrets.kem);
        let epoch = self.epoch + 1;
        let to_resp = ChainState::seed(chain_to_resp, epoch);
        let to_init = ChainState::seed(chain_to_init, epoch);
        let key = match peer_direction {
            NonceDirection::InitiatorToResponder => match to_resp.msg_chain.plan(0) {
                OpenPlan::Forward { key, .. } => key,
                _ => unreachable!(),
            },
            NonceDirection::ResponderToInitiator => match to_init.msg_chain.plan(0) {
                OpenPlan::Forward { key, .. } => key,
                _ => unreachable!(),
            },
        };
        self.pending = Some(PreparedEpoch {
            epoch,
            root_key,
            to_resp,
            to_init,
        });
        (epoch, key)
    }

    /// Install a prepared epoch. Returns `false` if nothing is prepared for it.
    pub fn activate(&mut self, epoch: u64) -> bool {
        if self.pending.as_ref().map(|p| p.epoch) != Some(epoch) {
            return false;
        }
        let p = self
            .pending
            .take()
            .expect("the pending epoch was checked immediately above");

        self.retired.push_front(RatchetEpoch {
            epoch: self.epoch,
            to_resp: self.to_resp.msg_chain.clone(),
            to_init: self.to_init.msg_chain.clone(),
        });
        while self.retired.len() > RATCHET_RETAINED_EPOCHS {
            self.retired.pop_back();
        }

        self.root_key.zeroize();
        self.root_key = p.root_key;
        self.to_resp = p.to_resp.clone();
        self.to_init = p.to_init.clone();

        self.epoch = p.epoch;
        self.steps += 1;
        self.frames_in_epoch = 0;
        true
    }

    /// The epoch a step is prepared for, if any.
    pub fn prepared_epoch(&self) -> Option<u64> {
        self.pending.as_ref().map(|p| p.epoch)
    }

    /// The epoch this ratchet is *sealing* on.
    pub fn sealed_epoch(&self) -> u64 {
        self.epoch
    }

    /// Count a frame sealed in the current epoch; `true` means the session is due
    /// to ratchet.
    pub fn count_seal(&mut self) -> bool {
        self.frames_in_epoch += 1;
        self.frames_in_epoch >= RATCHET_INTERVAL
    }

    /// Frames still available under the current epoch key.
    pub fn epoch_capacity_left(&self) -> u64 {
        RATCHET_INTERVAL.saturating_sub(self.frames_in_epoch)
    }

    /// The message key a step *would* produce at counter 0, without applying it.
    pub fn preview_step_key(
        &self,
        secrets: &StepSecrets,
        direction: NonceDirection,
    ) -> (u64, [u8; 32]) {
        let (_root, chain_to_resp, chain_to_init) =
            kdf_rk_hybrid(&self.root_key, &secrets.dh, &secrets.kem);
        let epoch = self.epoch + 1;
        let chain = match direction {
            NonceDirection::InitiatorToResponder => chain_to_resp,
            NonceDirection::ResponderToInitiator => chain_to_init,
        };
        let (next_chain, _) = kdf_ck(&chain);
        let mut epoch_seed = derive_epoch_key(&next_chain, epoch);
        let (_, msg_key_0) = kdf_ck(&epoch_seed);
        epoch_seed.zeroize();
        (epoch, msg_key_0)
    }

    /// Perform a DH-ratchet step: mix `secrets` into the root key, reseed both
    /// directional chains, and open a new epoch.
    pub fn step(&mut self, secrets: &StepSecrets) -> u64 {
        self.pending = None;
        let (new_root, chain_to_resp, chain_to_init) =
            kdf_rk_hybrid(&self.root_key, &secrets.dh, &secrets.kem);

        self.retired.push_front(RatchetEpoch {
            epoch: self.epoch,
            to_resp: self.to_resp.msg_chain.clone(),
            to_init: self.to_init.msg_chain.clone(),
        });
        while self.retired.len() > RATCHET_RETAINED_EPOCHS {
            self.retired.pop_back();
        }

        self.root_key.zeroize();
        self.root_key = new_root;

        self.epoch += 1;
        self.steps += 1;
        self.frames_in_epoch = 0;
        let next = self.epoch;

        self.to_resp = ChainState::seed(chain_to_resp, next);
        self.to_init = ChainState::seed(chain_to_init, next);

        next
    }

    /// Epochs still openable: the sealed one, a prepared one (if a step is mid-
    /// flight), then the retained grace window. Newest first.
    pub fn openable_epochs(&self) -> Vec<u64> {
        let mut v = vec![self.epoch];
        if let Some(p) = self.pending.as_ref() {
            v.push(p.epoch);
        }
        v.extend(self.retired.iter().map(|e| e.epoch));
        v
    }
}

impl Drop for SessionRatchet {
    fn drop(&mut self) {
        self.root_key.zeroize();
    }
}

/// The shared secrets one ratchet step contributes: an X25519 Diffie-Hellman
/// output and an ML-KEM-512 shared secret.
pub struct StepSecrets {
    pub dh: [u8; 32],
    pub kem: Vec<u8>,
}

impl StepSecrets {
    pub fn new(dh: [u8; 32], kem: Vec<u8>) -> Self {
        Self { dh, kem }
    }
}

impl Drop for StepSecrets {
    fn drop(&mut self) {
        self.dh.zeroize();
        self.kem.zeroize();
    }
}

/// One side's ephemeral material for a ratchet step.
///
/// The exchange is the same hybrid shape as the handshake — X25519 plus ML-KEM-512
/// — but *ephemeral and per-step*, which is what makes it a ratchet rather than a
/// second handshake: nothing here is signed by the long-term identity, because the
/// session that carries it is already authenticated, and re-signing every million
/// datagrams would make the identity key a hot key.
pub struct RatchetStep {
    x_secret: Option<EphemeralSecret>,
    x_public: X25519PublicKey,
    kem_ek: EncapsulationKey512,
    kem_dk: DecapsulationKey512,
}

impl RatchetStep {
    /// Generate fresh ephemeral X25519 and ML-KEM-512 material.
    pub fn generate() -> Self {
        let (x_secret, x_public) = generate_x25519_keypair();
        let (kem_ek, kem_dk) = generate_kyber_keypair();
        Self {
            x_secret: Some(x_secret),
            x_public,
            kem_ek,
            kem_dk,
        }
    }

    /// This side's X25519 ephemeral public key, to go in the step PDU.
    pub fn x_public_bytes(&self) -> [u8; 32] {
        *self.x_public.as_bytes()
    }

    /// This side's ML-KEM-512 encapsulation key, to go in the step PDU.
    pub fn kem_public_bytes(&self) -> Vec<u8> {
        self.kem_ek.to_bytes().to_vec()
    }

    /// *Responder* side of a step: take the initiator's material, encapsulate
    /// against it, and return `(secrets, ciphertext_to_return)`.
    ///
    /// The responder encapsulates rather than the initiator because that is the
    /// direction the existing re-key PDU already moves key material, and reusing
    /// the shape keeps one parser instead of two.
    pub fn respond(
        mut self,
        peer_x_pub: &[u8; 32],
        peer_kem_pub: &[u8],
    ) -> Option<(StepSecrets, [u8; 768])> {
        let secret = self.x_secret.take()?;
        let dh = secret.diffie_hellman(&X25519PublicKey::from(*peer_x_pub));
        let (ct, kem) = crate::ghost::layers::l1_kem::kyber_encapsulate(peer_kem_pub).ok()?;
        Some((StepSecrets::new(*dh.as_bytes(), kem), ct))
    }

    /// *Initiator* side of a step: open the responder's ciphertext and produce the
    /// same secrets the responder did.
    pub fn finish(mut self, peer_x_pub: &[u8; 32], kem_ct: &[u8; 768]) -> Option<StepSecrets> {
        let secret = self.x_secret.take()?;
        let dh = secret.diffie_hellman(&X25519PublicKey::from(*peer_x_pub));
        let ct = Ciphertext::<MlKem512>::from(*kem_ct);
        let kem = self.kem_dk.decapsulate(&ct).as_slice().to_vec();
        Some(StepSecrets::new(*dh.as_bytes(), kem))
    }
}

/// Replay-Resistant Chronology — Causal Order Monotonicity.
///
/// Replaces external wall-clock time with a causal monotonic counter vector for
/// cross-partition replay rejection and epoch expiry. Even under arbitrary clock skew
/// or time-rollback attacks, frames or epoch supersessions that are causally obsolete
/// are rejected deterministically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CausalMonotonicCounter {
    /// Local node causal sequence component
    local_seq: u64,
    /// Highest observed causal sequence from remote peer
    observed_remote_seq: u64,
    /// Causal epoch generation
    causal_epoch: u64,
}

impl CausalMonotonicCounter {
    /// Create a new causal counter at epoch 0
    pub fn new() -> Self {
        Self {
            local_seq: 0,
            observed_remote_seq: 0,
            causal_epoch: 0,
        }
    }

    /// Monotonically advance local causal sequence for an outbound event/message
    pub fn advance_local(&mut self) -> (u64, u64, u64) {
        self.local_seq = self.local_seq.saturating_add(1);
        (self.causal_epoch, self.local_seq, self.observed_remote_seq)
    }

    /// Advance the causal epoch (superseding all previous causal epochs)
    pub fn advance_epoch(&mut self) -> u64 {
        self.causal_epoch = self.causal_epoch.saturating_add(1);
        self.local_seq = 0;
        self.observed_remote_seq = 0;
        self.causal_epoch
    }

    /// Verify an inbound message's causal chronology.
    /// Returns Ok(()) and records observed sequence if causal order is preserved,
    /// or Err(&'static str) if the event is causally obsolete (replay / stale partition).
    pub fn verify_and_observe(
        &mut self,
        msg_causal_epoch: u64,
        msg_seq: u64,
    ) -> Result<(), &'static str> {
        // 1. Reject if from an older, superseded causal epoch
        if msg_causal_epoch < self.causal_epoch {
            return Err("Causally obsolete epoch: rejected");
        }

        // 2. If same epoch, sequence must strictly advance beyond what was observed
        if msg_causal_epoch == self.causal_epoch {
            if msg_seq <= self.observed_remote_seq {
                return Err("Causally obsolete sequence: replay detected");
            }
            self.observed_remote_seq = msg_seq;
            Ok(())
        } else {
            // New epoch observed causally forward
            self.causal_epoch = msg_causal_epoch;
            self.observed_remote_seq = msg_seq;
            Ok(())
        }
    }

    /// Get current causal state: (epoch, local_seq, observed_remote_seq)
    pub fn state(&self) -> (u64, u64, u64) {
        (self.causal_epoch, self.local_seq, self.observed_remote_seq)
    }
}

impl Default for CausalMonotonicCounter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghost::layers::l1_kem::derive_hybrid_master_key;
    use crate::ghost::layers::l2_aead::{xchacha_open, xchacha_seal};

    fn master() -> [u8; 32] {
        // A real handshake produces this; for ratchet tests any fixed key is fine
        // as long as every participant derives it the same way.
        [0x5Au8; 32]
    }

    // ── Per-message chains ─────────────────────────────────────

    #[test]
    fn msg_chain_advances_one_step_per_message_and_never_repeats_a_key() {
        let mut chain = MsgChain::seed(&master());
        let k0 = chain.advance();
        let k1 = chain.advance();
        let k2 = chain.advance();
        assert_ne!(k0, k1);
        assert_ne!(k1, k2);
        assert_ne!(k0, k2);
        assert_ne!(k0, master(), "a message key must not be the seed itself");
        assert_eq!(
            chain.pos(),
            3,
            "three messages sealed, chain positioned at 3"
        );
    }

    #[test]
    fn state_captured_after_sealing_cannot_reach_the_messages_already_sealed() {
        // This *is* per-message chaining. Under the old scheme a snapshot of the epoch key opened every
        // frame of the epoch; here the keys were derived and dropped, and the one-way
        // chain has no route back to them.
        let mut chain = MsgChain::seed(&master());
        let sent: Vec<[u8; 32]> = (0..8).map(|_| chain.advance()).collect();
        for counter in 0..8u64 {
            assert!(
                matches!(chain.plan(counter), OpenPlan::Refused),
                "counter {counter} was sealed by us and is now unreachable"
            );
        }
        // What it can produce from here is new material, not the old keys.
        let next = chain.advance();
        assert!(!sent.contains(&next));
    }

    #[test]
    fn msg_chain_opens_out_of_order_and_caches_the_gap_it_jumped() {
        let mut sender = MsgChain::seed(&master());
        let keys: Vec<[u8; 32]> = (0..8).map(|_| sender.advance()).collect();

        let mut receiver = MsgChain::seed(&master());
        // Counter 5 arrives first.
        let plan = receiver.plan(5);
        let OpenPlan::Forward { key, .. } = plan else {
            panic!("5 is ahead of 0, so it is a forward plan")
        };
        assert_eq!(key, keys[5]);
        receiver.commit(plan);
        assert_eq!(receiver.pos(), 6, "the chain now expects 6");

        // 2 and 3 were jumped over, so they must come from the cache.
        for counter in [2u64, 3] {
            let plan = receiver.plan(counter);
            let OpenPlan::Cached { key, .. } = plan else {
                panic!("{counter} should have been cached by the walk to 5")
            };
            assert_eq!(key, keys[counter as usize]);
            receiver.commit(plan);
        }

        // And 6, now in order, needs no cache at all.
        let plan = receiver.plan(6);
        let OpenPlan::Forward { key, .. } = plan else {
            panic!("6 is the next counter")
        };
        assert_eq!(key, keys[6]);
        receiver.commit(plan);
    }

    #[test]
    fn a_cached_key_is_single_use_so_a_replay_fails() {
        let mut sender = MsgChain::seed(&master());
        let keys: Vec<[u8; 32]> = (0..5).map(|_| sender.advance()).collect();

        let mut receiver = MsgChain::seed(&master());
        receiver.commit(receiver.plan(3)); // jumps over 0..3

        let plan = receiver.plan(1);
        let OpenPlan::Cached { key, .. } = plan else {
            panic!("1 was jumped over and should be held")
        };
        assert_eq!(key, keys[1]);
        receiver.commit(plan);

        // Consuming it is what makes the replay fail rather than open twice.
        assert!(matches!(receiver.plan(1), OpenPlan::Refused));
    }

    #[test]
    fn a_gap_beyond_the_cap_is_refused_without_advancing() {
        let receiver = MsgChain::seed(&master());
        assert!(matches!(receiver.plan(MAX_SKIP + 1), OpenPlan::Refused));
        // Refusing must not move the chain: an unauthenticated packet must not be able
        // to walk the receiver past real traffic.
        assert_eq!(receiver.pos(), 0, "a refused plan changes nothing");
        // The boundary itself is payable, so the cap is not off by one.
        assert!(matches!(receiver.plan(MAX_SKIP), OpenPlan::Forward { .. }));
    }

    #[test]
    fn committing_a_maximum_gap_keeps_the_cache_within_the_cap() {
        let mut receiver = MsgChain::seed(&master());
        receiver.commit(receiver.plan(MAX_SKIP));
        assert_eq!(receiver.pos(), MAX_SKIP + 1);
        assert!(
            receiver.skipped_len() <= MAX_SKIP as usize,
            "the skipped cache is bounded by the cap"
        );
    }

    #[test]
    fn an_uncommitted_plan_leaves_the_chain_exactly_where_it_was() {
        // Tentative commit: a forged counter may be *planned* and cost bounded work, but
        // it must not persist anything.
        let receiver = MsgChain::seed(&master());
        let plan = receiver.plan(500);
        assert!(matches!(plan, OpenPlan::Forward { .. }));
        drop(plan);
        assert_eq!(receiver.pos(), 0);
    }

    /// Both peers, each stepped the same number of times.
    fn stepped(n: usize) -> SessionRatchet {
        let mut r = SessionRatchet::new(master());
        for i in 0..n {
            r.step(&StepSecrets::new([i as u8; 32], vec![i as u8; 32]));
        }
        r
    }

    #[test]
    fn test_epoch_zero_key_differs_from_handshake_key() {
        let ratchet = SessionRatchet::new(master());
        let k = ratchet.seal_key(NonceDirection::InitiatorToResponder);
        assert_ne!(k, master());
        assert_eq!(ratchet.epoch(), 0);
        assert_eq!(ratchet.steps(), 0);
    }

    #[test]
    fn test_directions_never_share_a_key() {
        let ratchet = SessionRatchet::new(master());
        assert_ne!(
            ratchet.seal_key(NonceDirection::InitiatorToResponder),
            ratchet.seal_key(NonceDirection::ResponderToInitiator),
        );
    }

    #[test]
    fn test_step_advances_epoch_and_changes_the_key() {
        let mut r = SessionRatchet::new(master());
        let before = r.seal_key(NonceDirection::InitiatorToResponder);
        let epoch = r.step(&StepSecrets::new([0x11u8; 32], vec![0x22u8; 32]));
        assert_eq!(epoch, 1);
        assert_eq!(r.epoch(), 1);
        assert_eq!(r.steps(), 1);
        assert_ne!(r.seal_key(NonceDirection::InitiatorToResponder), before);
        // The retired epoch is still openable, and answers with the *old* key —
        // that is the grace window that keeps in-flight frames readable.
        assert_eq!(
            r.open_key(0, NonceDirection::InitiatorToResponder, 0),
            Some(before)
        );
    }

    #[test]
    fn test_a_prepared_epoch_can_be_opened_but_not_sealed_on() {
        // The property the transport depends on: the responder can read the
        // initiator's first frame in the new epoch while it is still sealing on
        // the old one, so a lost answer cannot put the two a key apart.
        let mut r = SessionRatchet::new(master());
        let old = r.seal_key(NonceDirection::InitiatorToResponder);
        let (epoch, peer_key) = r.prepare_step(
            &StepSecrets::new([0x01u8; 32], vec![0x02u8; 32]),
            NonceDirection::InitiatorToResponder,
        );
        assert_eq!(epoch, 1);
        assert_eq!(r.sealed_epoch(), 0, "prepare must not advance the ratchet");
        assert_eq!(r.prepared_epoch(), Some(1));
        assert_eq!(r.seal_key(NonceDirection::InitiatorToResponder), old);
        // Openable under the new epoch, and it is the key the peer reports.
        assert_eq!(
            r.open_key(1, NonceDirection::InitiatorToResponder, 0),
            Some(peer_key)
        );
        assert!(r.openable_epochs().contains(&1));

        // Installing it moves the seal key, retires the old epoch, and clears the
        // prepared slot.
        assert!(r.activate(1));
        assert_eq!(r.sealed_epoch(), 1);
        assert_eq!(r.prepared_epoch(), None);
        assert_eq!(r.seal_key(NonceDirection::InitiatorToResponder), peer_key);
        assert_eq!(
            r.open_key(0, NonceDirection::InitiatorToResponder, 0),
            Some(old)
        );
        assert!(
            !r.activate(1),
            "activating twice is refused, not a second step"
        );
        assert_eq!(r.steps(), 1);
    }

    #[test]
    fn test_prepare_step_does_not_match_a_preview_of_other_secrets() {
        // The confirmation must not accept a different step's key.
        let mut r = SessionRatchet::new(master());
        let (_, honest) = r.prepare_step(
            &StepSecrets::new([0x01u8; 32], vec![0x02u8; 32]),
            NonceDirection::InitiatorToResponder,
        );
        let r2 = SessionRatchet::new(master());
        let (_, other) = r2.preview_step_key(
            &StepSecrets::new([0x01u8; 32], vec![0x03u8; 32]),
            NonceDirection::InitiatorToResponder,
        );
        assert_ne!(honest, other);
    }

    #[test]
    fn test_a_later_prepare_replaces_an_unanswered_one() {
        let mut r = SessionRatchet::new(master());
        r.prepare_step(
            &StepSecrets::new([0x01u8; 32], vec![0x02u8; 32]),
            NonceDirection::InitiatorToResponder,
        );
        let (epoch, key) = r.prepare_step(
            &StepSecrets::new([0x03u8; 32], vec![0x04u8; 32]),
            NonceDirection::InitiatorToResponder,
        );
        assert_eq!(
            epoch, 1,
            "a retry is still one step ahead of the sealed epoch"
        );
        assert_eq!(
            r.openable_epochs().len(),
            2,
            "only one prepared epoch is kept"
        );
        assert_eq!(
            r.open_key(1, NonceDirection::InitiatorToResponder, 0),
            Some(key)
        );
    }

    #[test]
    fn test_open_key_refuses_an_epoch_that_is_gone() {
        let mut r = SessionRatchet::new(master());
        for i in 0..8u8 {
            r.step(&StepSecrets::new([i; 32], vec![i; 32]));
        }
        assert_eq!(r.epoch(), 8);
        assert!(r
            .open_key(0, NonceDirection::InitiatorToResponder, 0)
            .is_none());
        assert!(r
            .open_key(99, NonceDirection::InitiatorToResponder, 0)
            .is_none());
        // Only the current epoch plus the retained grace window answer.
        assert_eq!(r.openable_epochs().len(), RATCHET_RETAINED_EPOCHS + 1);
    }

    #[test]
    fn test_both_peers_agree_after_the_same_step() {
        // The load-bearing property: one hybrid exchange, two ratchets, one key.
        let mut a = SessionRatchet::new(master());
        let mut b = SessionRatchet::new(master());

        let initiator = RatchetStep::generate();
        let i_x = initiator.x_public_bytes();
        let i_kem = initiator.kem_public_bytes();

        let responder = RatchetStep::generate();
        let r_x = responder.x_public_bytes();
        let (r_secrets, ct) = responder.respond(&i_x, &i_kem).expect("respond");
        let i_secrets = initiator.finish(&r_x, &ct).expect("finish");

        assert_eq!(a.step(&i_secrets), b.step(&r_secrets));
        assert_eq!(
            a.seal_key(NonceDirection::InitiatorToResponder),
            b.seal_key(NonceDirection::InitiatorToResponder),
        );
        assert_eq!(
            a.seal_key(NonceDirection::ResponderToInitiator),
            b.seal_key(NonceDirection::ResponderToInitiator),
        );
    }

    #[test]
    fn test_second_peer_with_wrong_secrets_diverges() {
        // A third party who watched the exchange but holds neither ephemeral secret
        // cannot produce the epoch key. This is what makes the step authentic
        // without a per-step signature.
        let watcher = RatchetStep::generate();
        let (secrets, _ct) = watcher.respond(&[0x77u8; 32], &[0x88u8; 800]).unwrap();
        let mut a = SessionRatchet::new(master());
        a.step(&secrets);
        let mut honest = SessionRatchet::new(master());
        honest.step(&StepSecrets::new([0x01u8; 32], vec![0x02u8; 32]));
        assert_ne!(
            a.seal_key(NonceDirection::InitiatorToResponder),
            honest.seal_key(NonceDirection::InitiatorToResponder),
        );
    }

    #[test]
    fn test_double_ratchet_forward_secrecy() {
        // The gate this test pins.
        //
        // Three things have to hold, and each is checked against real AEAD output
        // rather than against the shape of the code:
        use crate::ghost::layers::l2_aead::random_xnonce;

        let mut r = SessionRatchet::new(master());
        let mut historical: Vec<([u8; 32], [u8; 12], Vec<u8>)> = Vec::new();

        for epoch in 0..(RATCHET_RETAINED_EPOCHS as u64 + 4) {
            let key = r.seal_key(NonceDirection::InitiatorToResponder);
            let nonce = random_xnonce();
            let ciphertext = xchacha_seal(
                &key,
                &nonce,
                epoch,
                NonceDirection::InitiatorToResponder,
                b"epoch payload",
            )
            .expect("seal");
            historical.push((key, nonce, ciphertext));
            r.step(&StepSecrets::new([epoch as u8; 32], vec![epoch as u8; 32]));
        }

        // (1) The current state holds no key that opens a *retired* epoch: the key
        // is erased and the API says so, instead of trial-decrypting until
        // something works.
        assert!(r
            .open_key(0, NonceDirection::InitiatorToResponder, 0)
            .is_none());
        let (_, nonce0, mut oldest_ct) = historical[0].clone();
        let current = r.seal_key(NonceDirection::InitiatorToResponder);
        assert!(
            xchacha_open(
                &current,
                &nonce0,
                0,
                NonceDirection::InitiatorToResponder,
                &mut oldest_ct,
            )
            .is_err(),
            "today's key must not open yesterday's frame"
        );

        // (2) Epoch keys are all distinct: no epoch reuses another's keystream.
        let keys: std::collections::HashSet<[u8; 32]> =
            historical.iter().map(|(k, _, _)| *k).collect();
        assert_eq!(keys.len(), historical.len());

        // (3) A frame sealed at the *current* epoch is unreadable by a party who
        // took a copy of the state before the step (break-in recovery).
        let mut victim = SessionRatchet::new(master());
        for e in 0..3u8 {
            victim.step(&StepSecrets::new([e; 32], vec![e; 32]));
        }
        let attacker = stepped(3);
        // Attacker must hold the post-compromise state exactly (they read memory).
        assert_eq!(
            attacker.seal_key(NonceDirection::InitiatorToResponder),
            victim.seal_key(NonceDirection::InitiatorToResponder),
        );
        // Now a step happens whose secrets the attacker never saw.
        let stolen_nonce = random_xnonce();
        let attacker_epoch = attacker.epoch();
        victim.step(&StepSecrets::new([0xAAu8; 32], vec![0xBBu8; 32]));
        let new_epoch = victim.epoch();
        let frame = xchacha_seal(
            &victim.seal_key(NonceDirection::InitiatorToResponder),
            &stolen_nonce,
            new_epoch,
            NonceDirection::InitiatorToResponder,
            b"post-compromise secret",
        )
        .expect("seal");
        // The attacker's epoch is the pre-step one, so they cannot even name the
        // epoch the frame came from, let alone hold its key.
        assert_eq!(attacker_epoch, new_epoch - 1);
        assert!(attacker
            .open_key(new_epoch, NonceDirection::InitiatorToResponder, 0)
            .is_none());
        let mut buf = frame.clone();
        let wrong = attacker.seal_key(NonceDirection::InitiatorToResponder);
        assert!(xchacha_open(
            &wrong,
            &stolen_nonce,
            new_epoch,
            NonceDirection::InitiatorToResponder,
            &mut buf,
        )
        .is_err());
    }

    #[test]
    fn test_ratchet_interval_bounds_the_epoch() {
        let mut r = SessionRatchet::new(master());
        assert_eq!(r.epoch_capacity_left(), RATCHET_INTERVAL);
        // Not a million iterations of work: the counter is what the caller bumps.
        r.frames_in_epoch = RATCHET_INTERVAL - 2;
        assert!(!r.count_seal(), "the epoch still has one frame left in it");
        assert!(
            r.count_seal(),
            "the frame that fills the epoch makes a step due"
        );
        assert_eq!(r.epoch_capacity_left(), 0);
    }

    #[test]
    fn test_preview_step_key_matches_the_step_it_previews() {
        // Confirmation depends on this: the initiator computes the key without
        // committing, so the preview must be exactly what `step` would install.
        let previewed = {
            let r = SessionRatchet::new(master());
            let secrets = StepSecrets::new([0x01u8; 32], vec![0x02u8; 32]);
            let (epoch, key) = r.preview_step_key(&secrets, NonceDirection::InitiatorToResponder);
            assert_eq!(epoch, 1);
            assert_eq!(r.epoch(), 0, "previewing must not advance the ratchet");
            (epoch, key)
        };
        let mut r = SessionRatchet::new(master());
        let epoch = r.step(&StepSecrets::new([0x01u8; 32], vec![0x02u8; 32]));
        assert_eq!(epoch, previewed.0);
        assert_eq!(
            r.seal_key(NonceDirection::InitiatorToResponder),
            previewed.1,
            "the preview must equal the committed key"
        );
    }

    #[test]
    fn test_preview_refuses_to_predict_a_wrong_step() {
        let r = SessionRatchet::new(master());
        let honest = r.preview_step_key(
            &StepSecrets::new([0x01u8; 32], vec![0x02u8; 32]),
            NonceDirection::InitiatorToResponder,
        );
        let wrong = r.preview_step_key(
            &StepSecrets::new([0x01u8; 32], vec![0x03u8; 32]),
            NonceDirection::InitiatorToResponder,
        );
        assert_ne!(honest.1, wrong.1);
        assert_ne!(
            honest.1,
            r.preview_step_key(
                &StepSecrets::new([0x09u8; 32], vec![0x02u8; 32]),
                NonceDirection::InitiatorToResponder
            )
            .1,
            "a substituted X25519 half must not preview the same key"
        );
    }

    #[test]
    fn test_step_resets_the_epoch_budget() {
        let mut r = SessionRatchet::new(master());
        r.frames_in_epoch = RATCHET_INTERVAL;
        r.step(&StepSecrets::new([1u8; 32], vec![1u8; 32]));
        assert_eq!(r.frames_in_epoch(), 0);
        assert_eq!(r.epoch_capacity_left(), RATCHET_INTERVAL);
    }

    #[test]
    fn test_secrets_are_actually_used() {
        // A step must depend on BOTH halves, or the ratchet is only as strong as
        // X25519 — which a quantum adversary breaks, making "forward secrecy"
        // meaningless against the adversary it exists for.
        let mut a = SessionRatchet::new(master());
        let mut b = SessionRatchet::new(master());
        let mut c = SessionRatchet::new(master());
        a.step(&StepSecrets::new([0x01u8; 32], vec![0x02u8; 32]));
        b.step(&StepSecrets::new([0x01u8; 32], vec![0x03u8; 32]));
        c.step(&StepSecrets::new([0x09u8; 32], vec![0x02u8; 32]));
        let ka = a.seal_key(NonceDirection::InitiatorToResponder);
        let kb = b.seal_key(NonceDirection::InitiatorToResponder);
        let kc = c.seal_key(NonceDirection::InitiatorToResponder);
        assert_ne!(ka, kb, "the ML-KEM half must affect the key");
        assert_ne!(ka, kc, "the X25519 half must affect the key");
    }

    #[test]
    fn test_ratchet_separates_from_the_handshake_kdf() {
        // A ratchet step must not reproduce the handshake key, or a peer who
        // captured the handshake would hold every epoch.
        let dh = [0x31u8; 32];
        let kem = vec![0x32u8; 8];
        let handshake = derive_hybrid_master_key(&dh, &kem);
        let mut r = SessionRatchet::new(handshake);
        let epoch0 = r.seal_key(NonceDirection::InitiatorToResponder);
        assert_ne!(epoch0, handshake);
        r.step(&StepSecrets::new(dh, kem.clone()));
        assert_ne!(r.seal_key(NonceDirection::InitiatorToResponder), handshake);
    }

    #[test]
    fn test_pq_double_ratchet_post_compromise_recovery() {
        // Post-Compromise Security (PCS) via ephemeral hybrid ratchet exchange.
        // Even if an attacker learns the exact root_key at epoch N, after a fresh
        // ephemeral hybrid exchange (ML-KEM-512 + X25519) between Alice and Bob,
        // the attacker cannot derive the epoch N+1 keys or decrypt traffic.
        let mut alice = SessionRatchet::new(master());
        let mut bob = SessionRatchet::new(master());

        // Epoch 0 compromised: attacker steals root_key
        let compromised_root_epoch0 = alice.root_key();
        assert_eq!(compromised_root_epoch0, master());

        // Alice and Bob generate ephemeral ratchet step
        let alice_step = RatchetStep::generate();
        let bob_step = RatchetStep::generate();
        let bob_x_pub = bob_step.x_public_bytes();

        let (bob_secrets, ct) = bob_step
            .respond(&alice_step.x_public_bytes(), &alice_step.kem_public_bytes())
            .expect("respond");
        let alice_secrets = alice_step.finish(&bob_x_pub, &ct).expect("finish");

        // Step both sides to Epoch 1
        let epoch_alice = alice.step(&alice_secrets);
        let epoch_bob = bob.step(&bob_secrets);
        assert_eq!(epoch_alice, 1);
        assert_eq!(epoch_bob, 1);

        // Verify keys match between Alice and Bob
        let alice_seal_key = alice.seal_key(NonceDirection::InitiatorToResponder);
        let bob_open_key = bob
            .open_key(1, NonceDirection::InitiatorToResponder, 0)
            .expect("bob can open");
        assert_eq!(alice_seal_key, bob_open_key);

        // Attacker attempts to forge/derive epoch 1 without knowing the private ephemeral keys:
        // Attacker has compromised root key and observes on-wire public keys & ciphertext:
        // But attacker cannot decapsulate ML-KEM-512 ct or complete X25519 DH.
        // If attacker guesses/fabricates secrets:
        let fake_secrets = StepSecrets::new([0x00u8; 32], vec![0u8; 32]);
        let mut attacker_ratchet = SessionRatchet::new(compromised_root_epoch0);
        attacker_ratchet.step(&fake_secrets);

        let attacker_key = attacker_ratchet.seal_key(NonceDirection::InitiatorToResponder);
        assert_ne!(
            attacker_key, alice_seal_key,
            "Attacker cannot derive epoch 1 key without breaking KEM"
        );
    }

    #[test]
    fn test_causal_monotonic_counter_replay_resistance() {
        let mut node_a = CausalMonotonicCounter::new();
        let mut node_b = CausalMonotonicCounter::new();

        // Local sequences advance monotonically
        let (epoch_a, seq1, _) = node_a.advance_local();
        assert_eq!((epoch_a, seq1), (0, 1));
        let (_, seq2, _) = node_a.advance_local();
        assert_eq!(seq2, 2);

        // Remote node observes and verifies message 1
        assert!(node_b.verify_and_observe(epoch_a, seq1).is_ok());

        // Replay of message 1 must be rejected regardless of wall clock
        let replay_err = node_b.verify_and_observe(epoch_a, seq1);
        assert_eq!(
            replay_err,
            Err("Causally obsolete sequence: replay detected")
        );

        // In-order delivery of message 2 succeeds
        assert!(node_b.verify_and_observe(epoch_a, seq2).is_ok());

        // Epoch advancement supersedes prior epoch messages
        let new_epoch = node_a.advance_epoch();
        assert_eq!(new_epoch, 1);
        let (epoch1, epoch1_seq1, _) = node_a.advance_local();
        assert_eq!((epoch1, epoch1_seq1), (1, 1));

        // Node B accepts epoch 1 message
        assert!(node_b.verify_and_observe(epoch1, epoch1_seq1).is_ok());

        // Replayed message from old epoch 0 is rejected causally
        let stale_epoch_err = node_b.verify_and_observe(0, 9999);
        assert_eq!(stale_epoch_err, Err("Causally obsolete epoch: rejected"));
    }
}
