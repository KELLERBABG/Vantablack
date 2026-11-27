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
    derive_epoch_key, generate_kyber768_keypair, generate_x25519_keypair, kdf_ck, kdf_rk_hybrid,
    kdf_rk_quantum_mix, kyber768_decapsulate, kyber768_encapsulate, seed_ratchet_chains,
};
use crate::ghost::layers::l2_aead::NonceDirection;
use ml_kem::kem::KeyExport;
use ml_kem::{DecapsulationKey768, EncapsulationKey768};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use zeroize::Zeroize;

pub const RATCHET_INTERVAL: u64 = 1_000_000;

pub const RATCHET_TIME_CEILING: Duration = Duration::from_secs(15 * 60);

pub const RATCHET_RETAINED_EPOCHS: usize = 2;

pub const MAX_SKIP: u64 = 1024;

pub enum OpenPlan {
    Forward {
        key: [u8; 32],
        new_chain: [u8; 32],
        new_pos: u64,
        cache: Vec<(u64, [u8; 32])>,
    },
    Cached { counter: u64, key: [u8; 32] },
    Refused,
}

#[derive(Clone)]
pub struct MsgChain {
    chain: [u8; 32],
    pos: u64,
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
        self.pos = self.pos.wrapping_add(1);
        key
    }

    pub fn plan(&self, counter: u64) -> OpenPlan {
        if counter < self.pos {
            return match self.skipped.get(&counter) {
                Some(key) => OpenPlan::Cached { counter, key: *key },
                None => OpenPlan::Refused,
            };
        }
        let gap = counter - self.pos;
        if gap > MAX_SKIP {
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
            new_pos: counter.saturating_add(1),
            cache,
        }
    }

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
                        self.skipped.entry(counter).or_insert(key);
                    }
                }
                while self.skipped.len() > MAX_SKIP as usize {
                    let oldest = *self.skipped.keys().next().expect("non-empty");
                    if let Some(mut dead) = self.skipped.remove(&oldest) {
                        dead.zeroize();
                    }
                }
            }
            OpenPlan::Cached { counter, .. } => {
                if let Some(mut spent) = self.skipped.remove(&counter) {
                    spent.zeroize();
                }
            }
            OpenPlan::Refused => {}
        }
    }
}

#[derive(Clone)]
struct ChainState {
    chain: [u8; 32],
    msg_chain: MsgChain,
}

impl ChainState {
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

#[derive(Clone)]
pub struct RatchetEpoch {
    pub epoch: u64,
    pub to_resp: MsgChain,
    pub to_init: MsgChain,
}

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

pub struct SessionRatchet {
    root_key: [u8; 32],
    to_resp: ChainState,
    to_init: ChainState,
    epoch: u64,
    steps: u64,
    frames_in_epoch: u64,
    epoch_started_at: Instant,
    retired: VecDeque<RatchetEpoch>,
    pending: Option<PreparedEpoch>,
}

impl SessionRatchet {
    pub fn new(master_key: [u8; 32]) -> Self {
        let (to_resp, to_init) = seed_ratchet_chains(&master_key);
        Self {
            root_key: master_key,
            to_resp: ChainState::seed(to_resp, 0),
            to_init: ChainState::seed(to_init, 0),
            epoch: 0,
            steps: 0,
            frames_in_epoch: 0,
            epoch_started_at: Instant::now(),
            retired: VecDeque::new(),
            pending: None,
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn steps(&self) -> u64 {
        self.steps
    }

    pub fn frames_in_epoch(&self) -> u64 {
        self.frames_in_epoch
    }

    pub fn root_key(&self) -> [u8; 32] {
        self.root_key
    }

    pub fn advance_seal(&mut self, direction: NonceDirection) -> (u64, [u8; 32]) {
        let chain = match direction {
            NonceDirection::InitiatorToResponder => &mut self.to_resp.msg_chain,
            NonceDirection::ResponderToInitiator => &mut self.to_init.msg_chain,
        };
        let counter = chain.pos();
        let key = chain.advance();
        (counter, key)
    }

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

    pub fn prepare_step(
        &mut self,
        secrets: &StepSecrets,
        peer_direction: NonceDirection,
    ) -> (u64, [u8; 32]) {
        let (root_key, chain_to_resp, chain_to_init) =
            kdf_rk_hybrid(&self.root_key, &secrets.dh, &secrets.kem);
        let epoch = self.epoch.saturating_add(1);
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
        self.steps = self.steps.wrapping_add(1);
        self.frames_in_epoch = 0;
        self.epoch_started_at = Instant::now();
        true
    }

    pub fn prepared_epoch(&self) -> Option<u64> {
        self.pending.as_ref().map(|p| p.epoch)
    }

    pub fn sealed_epoch(&self) -> u64 {
        self.epoch
    }

    pub fn is_ratchet_due(&self) -> bool {
        self.frames_in_epoch >= RATCHET_INTERVAL
            || self.epoch_started_at.elapsed() >= RATCHET_TIME_CEILING
    }

    pub fn count_seal(&mut self) -> bool {
        self.frames_in_epoch = self.frames_in_epoch.saturating_add(1);
        self.is_ratchet_due()
    }

    pub fn epoch_capacity_left(&self) -> u64 {
        RATCHET_INTERVAL.saturating_sub(self.frames_in_epoch)
    }

    pub fn preview_step_key(
        &self,
        secrets: &StepSecrets,
        direction: NonceDirection,
    ) -> (u64, [u8; 32]) {
        let (_root, chain_to_resp, chain_to_init) =
            kdf_rk_hybrid(&self.root_key, &secrets.dh, &secrets.kem);
        let epoch = self.epoch.wrapping_add(1);
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

        self.epoch = self.epoch.wrapping_add(1);
        self.steps = self.steps.wrapping_add(1);
        self.frames_in_epoch = 0;
        self.epoch_started_at = Instant::now();
        let next = self.epoch;

        self.to_resp = ChainState::seed(chain_to_resp, next);
        self.to_init = ChainState::seed(chain_to_init, next);

        next
    }

    pub fn mix_quantum_entropy(&mut self, quantum_key: &[u8; 32]) -> u64 {
        self.pending = None;
        let (new_root, chain_to_resp, chain_to_init) =
            kdf_rk_quantum_mix(&self.root_key, quantum_key);

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

        self.epoch = self.epoch.wrapping_add(1);
        self.frames_in_epoch = 0;
        self.epoch_started_at = Instant::now();
        let next = self.epoch;

        self.to_resp = ChainState::seed(chain_to_resp, next);
        self.to_init = ChainState::seed(chain_to_init, next);
        next
    }

    pub fn prepare_quantum_mix(
        &mut self,
        quantum_key: &[u8; 32],
        peer_direction: NonceDirection,
    ) -> (u64, [u8; 32]) {
        let (root_key, chain_to_resp, chain_to_init) =
            kdf_rk_quantum_mix(&self.root_key, quantum_key);
        let epoch = self.epoch.saturating_add(1);
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

    pub fn preview_quantum_mix_key(
        &self,
        quantum_key: &[u8; 32],
        direction: NonceDirection,
    ) -> (u64, [u8; 32]) {
        let (_root, chain_to_resp, chain_to_init) = kdf_rk_quantum_mix(&self.root_key, quantum_key);
        let epoch = self.epoch.saturating_add(1);
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

pub struct RatchetStep {
    x_secret: Option<EphemeralSecret>,
    x_public: X25519PublicKey,
    kem_ek: EncapsulationKey768,
    kem_dk: DecapsulationKey768,
}

impl RatchetStep {
    pub fn generate() -> Self {
        let (x_secret, x_public) = generate_x25519_keypair();
        let (kem_ek, kem_dk) = generate_kyber768_keypair();
        Self {
            x_secret: Some(x_secret),
            x_public,
            kem_ek,
            kem_dk,
        }
    }

    pub fn x_public_bytes(&self) -> [u8; 32] {
        *self.x_public.as_bytes()
    }

    pub fn kem_public_bytes(&self) -> Vec<u8> {
        self.kem_ek.to_bytes().to_vec()
    }

    pub fn respond(
        mut self,
        peer_x_pub: &[u8; 32],
        peer_kem_pub: &[u8],
    ) -> Option<(StepSecrets, [u8; 1088])> {
        let secret = self.x_secret.take()?;
        let dh = secret.diffie_hellman(&X25519PublicKey::from(*peer_x_pub));
        let (ct_vec, kem) = kyber768_encapsulate(peer_kem_pub).ok()?;
        let ct: [u8; 1088] = ct_vec.try_into().ok()?;
        Some((StepSecrets::new(*dh.as_bytes(), kem), ct))
    }

    pub fn finish(mut self, peer_x_pub: &[u8; 32], kem_ct: &[u8; 1088]) -> Option<StepSecrets> {
        let secret = self.x_secret.take()?;
        let dh = secret.diffie_hellman(&X25519PublicKey::from(*peer_x_pub));
        let kem = kyber768_decapsulate(&self.kem_dk, kem_ct).ok()?;
        Some(StepSecrets::new(*dh.as_bytes(), kem))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CausalMonotonicCounter {
    local_seq: u64,
    observed_remote_seq: u64,
    causal_epoch: u64,
}

impl CausalMonotonicCounter {
    pub fn new() -> Self {
        Self {
            local_seq: 0,
            observed_remote_seq: 0,
            causal_epoch: 0,
        }
    }

    pub fn advance_local(&mut self) -> (u64, u64, u64) {
        self.local_seq = self.local_seq.saturating_add(1);
        (self.causal_epoch, self.local_seq, self.observed_remote_seq)
    }

    pub fn advance_epoch(&mut self) -> u64 {
        self.causal_epoch = self.causal_epoch.saturating_add(1);
        self.local_seq = 0;
        self.observed_remote_seq = 0;
        self.causal_epoch
    }

    pub fn verify_and_observe(
        &mut self,
        msg_causal_epoch: u64,
        msg_seq: u64,
    ) -> Result<(), &'static str> {
        if msg_causal_epoch < self.causal_epoch {
            return Err("Causally obsolete epoch: rejected");
        }

        if msg_causal_epoch == self.causal_epoch {
            if msg_seq <= self.observed_remote_seq {
                return Err("Causally obsolete sequence: replay detected");
            }
            self.observed_remote_seq = msg_seq;
            Ok(())
        } else {
            self.causal_epoch = msg_causal_epoch;
            self.observed_remote_seq = msg_seq;
            Ok(())
        }
    }

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
        [0x5Au8; 32]
    }

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
        let mut chain = MsgChain::seed(&master());
        let sent: Vec<[u8; 32]> = (0..8).map(|_| chain.advance()).collect();
        for counter in 0..8u64 {
            assert!(
                matches!(chain.plan(counter), OpenPlan::Refused),
                "counter {counter} was sealed by us and is now unreachable"
            );
        }
        let next = chain.advance();
        assert!(!sent.contains(&next));
    }

    #[test]
    fn msg_chain_opens_out_of_order_and_caches_the_gap_it_jumped() {
        let mut sender = MsgChain::seed(&master());
        let keys: Vec<[u8; 32]> = (0..8).map(|_| sender.advance()).collect();

        let mut receiver = MsgChain::seed(&master());
        let plan = receiver.plan(5);
        let OpenPlan::Forward { key, .. } = plan else {
            panic!("5 is ahead of 0, so it is a forward plan")
        };
        assert_eq!(key, keys[5]);
        receiver.commit(plan);
        assert_eq!(receiver.pos(), 6, "the chain now expects 6");

        for counter in [2u64, 3] {
            let plan = receiver.plan(counter);
            let OpenPlan::Cached { key, .. } = plan else {
                panic!("{counter} should have been cached by the walk to 5")
            };
            assert_eq!(key, keys[counter as usize]);
            receiver.commit(plan);
        }

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

        assert!(matches!(receiver.plan(1), OpenPlan::Refused));
    }

    #[test]
    fn a_gap_beyond_the_cap_is_refused_without_advancing() {
        let receiver = MsgChain::seed(&master());
        assert!(matches!(receiver.plan(MAX_SKIP + 1), OpenPlan::Refused));
        assert_eq!(receiver.pos(), 0, "a refused plan changes nothing");
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
        let receiver = MsgChain::seed(&master());
        let plan = receiver.plan(500);
        assert!(matches!(plan, OpenPlan::Forward { .. }));
        drop(plan);
        assert_eq!(receiver.pos(), 0);
    }

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
        assert_eq!(
            r.open_key(0, NonceDirection::InitiatorToResponder, 0),
            Some(before)
        );
    }

    #[test]
    fn test_a_prepared_epoch_can_be_opened_but_not_sealed_on() {
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
        assert_eq!(
            r.open_key(1, NonceDirection::InitiatorToResponder, 0),
            Some(peer_key)
        );
        assert!(r.openable_epochs().contains(&1));

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
        assert_eq!(r.openable_epochs().len(), RATCHET_RETAINED_EPOCHS + 1);
    }

    #[test]
    fn test_both_peers_agree_after_the_same_step() {
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
        let watcher = RatchetStep::generate();
        let (secrets, _ct) = watcher.respond(&[0x77u8; 32], &[0x88u8; 1184]).unwrap();
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

        let keys: std::collections::HashSet<[u8; 32]> =
            historical.iter().map(|(k, _, _)| *k).collect();
        assert_eq!(keys.len(), historical.len());

        let mut victim = SessionRatchet::new(master());
        for e in 0..3u8 {
            victim.step(&StepSecrets::new([e; 32], vec![e; 32]));
        }
        let attacker = stepped(3);
        assert_eq!(
            attacker.seal_key(NonceDirection::InitiatorToResponder),
            victim.seal_key(NonceDirection::InitiatorToResponder),
        );
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
    fn test_ratchet_time_ceiling_triggers_on_low_volume() {
        let mut r = SessionRatchet::new(master());
        assert!(!r.is_ratchet_due());
        assert!(!r.count_seal());

        r.epoch_started_at = Instant::now() - RATCHET_TIME_CEILING;
        assert!(r.is_ratchet_due());
        assert!(r.count_seal(), "low-volume session must ratchet after 15m");

        r.step(&StepSecrets::new([0x22u8; 32], vec![0x33u8; 32]));
        assert!(!r.is_ratchet_due());
    }

    #[test]
    fn quantum_entropy_mix_is_symmetric_and_opens_the_next_epoch() {
        let quantum_key = [0xA5u8; 32];
        let mut alice = SessionRatchet::new(master());
        let mut bob = SessionRatchet::new(master());

        assert_eq!(
            alice.seal_key(NonceDirection::InitiatorToResponder),
            bob.seal_key(NonceDirection::InitiatorToResponder)
        );

        let ea = alice.mix_quantum_entropy(&quantum_key);
        let eb = bob.mix_quantum_entropy(&quantum_key);
        assert_eq!(ea, 1);
        assert_eq!(eb, 1);
        assert_eq!(
            alice.seal_key(NonceDirection::InitiatorToResponder),
            bob.open_key(1, NonceDirection::InitiatorToResponder, 0)
                .unwrap(),
            "both sides derive identical post-mix epoch keys"
        );

        let e0 = alice
            .open_key(0, NonceDirection::InitiatorToResponder, 0)
            .expect("epoch 0 still openable");
        assert_ne!(e0, alice.seal_key(NonceDirection::InitiatorToResponder));
    }

    #[test]
    fn prepared_quantum_mix_matches_a_direct_mix_and_a_preview() {
        let quantum_key = [0x5Au8; 32];
        let mut prepared = SessionRatchet::new(master());
        let mut direct = SessionRatchet::new(master());

        let (epoch, key) =
            prepared.prepare_quantum_mix(&quantum_key, NonceDirection::InitiatorToResponder);
        assert_eq!(epoch, 1);

        let preview =
            direct.preview_quantum_mix_key(&quantum_key, NonceDirection::InitiatorToResponder);
        assert_eq!(preview.0, epoch, "preview and prepare name the same epoch");
        assert_eq!(preview.1, key, "and derive the same confirmation key");

        assert_eq!(prepared.epoch(), 0);
        assert_eq!(prepared.prepared_epoch(), Some(epoch));
        assert_eq!(
            prepared.seal_key(NonceDirection::InitiatorToResponder),
            direct.seal_key(NonceDirection::InitiatorToResponder),
            "a prepared mix seals nothing new yet"
        );

        assert!(prepared.activate(epoch));
        direct.mix_quantum_entropy(&quantum_key);
        assert_eq!(prepared.epoch(), direct.epoch());
        assert_eq!(
            prepared.seal_key(NonceDirection::InitiatorToResponder),
            direct.seal_key(NonceDirection::InitiatorToResponder),
            "activating a prepared mix equals mixing directly"
        );
    }

    #[test]
    fn a_preview_of_a_different_quantum_key_does_not_match_the_mix() {
        let r = SessionRatchet::new(master());
        let (_, honest) =
            r.preview_quantum_mix_key(&[0x01u8; 32], NonceDirection::InitiatorToResponder);
        let (_, other) =
            r.preview_quantum_mix_key(&[0x02u8; 32], NonceDirection::InitiatorToResponder);
        assert_ne!(honest, other);

        let mut other_side = SessionRatchet::new(master());
        let (_, derived) =
            other_side.prepare_quantum_mix(&[0x02u8; 32], NonceDirection::InitiatorToResponder);
        assert_ne!(derived, honest, "divergent derivations must not confirm");
    }

    #[test]
    fn a_quantum_mix_previews_the_key_for_the_starter_sealing_direction() {
        for starter_dir in [
            NonceDirection::InitiatorToResponder,
            NonceDirection::ResponderToInitiator,
        ] {
            let quantum_key = [0x77u8; 32];
            let mut from_starter = SessionRatchet::new(master());
            let from_answerer = SessionRatchet::new(master());

            let answerer_dir = starter_dir.peer_direction();
            assert_eq!(answerer_dir.peer_direction(), starter_dir);

            let (_, starter_key) = from_starter.prepare_quantum_mix(&quantum_key, starter_dir);
            let (_, answerer_key) =
                from_answerer.preview_quantum_mix_key(&quantum_key, answerer_dir.peer_direction());
            assert_eq!(
                starter_key, answerer_key,
                "the answerer reaches the same chain from the other side"
            );
        }
    }

    #[test]
    fn quantum_mix_changes_the_key_and_is_one_way() {
        let mut r = SessionRatchet::new(master());
        let before = r.seal_key(NonceDirection::InitiatorToResponder);
        r.mix_quantum_entropy(&[0x11u8; 32]);
        let after_a = r.seal_key(NonceDirection::InitiatorToResponder);
        assert_ne!(before, after_a, "the mix must move the key");

        let mut r2 = SessionRatchet::new(master());
        r2.mix_quantum_entropy(&[0x22u8; 32]);
        assert_ne!(
            after_a,
            r2.seal_key(NonceDirection::InitiatorToResponder),
            "different quantum keys must diverge"
        );

        let mut attacker = SessionRatchet::new([0u8; 32]);
        attacker.mix_quantum_entropy(&[0x11u8; 32]);
        assert_ne!(
            attacker.seal_key(NonceDirection::InitiatorToResponder),
            after_a,
            "quantum key without the prior root is useless"
        );
    }

    #[test]
    fn test_secrets_are_actually_used() {
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
        let mut alice = SessionRatchet::new(master());
        let mut bob = SessionRatchet::new(master());

        let compromised_root_epoch0 = alice.root_key();
        assert_eq!(compromised_root_epoch0, master());

        let alice_step = RatchetStep::generate();
        let bob_step = RatchetStep::generate();
        let bob_x_pub = bob_step.x_public_bytes();

        let (bob_secrets, ct) = bob_step
            .respond(&alice_step.x_public_bytes(), &alice_step.kem_public_bytes())
            .expect("respond");
        let alice_secrets = alice_step.finish(&bob_x_pub, &ct).expect("finish");

        let epoch_alice = alice.step(&alice_secrets);
        let epoch_bob = bob.step(&bob_secrets);
        assert_eq!(epoch_alice, 1);
        assert_eq!(epoch_bob, 1);

        let alice_seal_key = alice.seal_key(NonceDirection::InitiatorToResponder);
        let bob_open_key = bob
            .open_key(1, NonceDirection::InitiatorToResponder, 0)
            .expect("bob can open");
        assert_eq!(alice_seal_key, bob_open_key);

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

        let (epoch_a, seq1, _) = node_a.advance_local();
        assert_eq!((epoch_a, seq1), (0, 1));
        let (_, seq2, _) = node_a.advance_local();
        assert_eq!(seq2, 2);

        assert!(node_b.verify_and_observe(epoch_a, seq1).is_ok());

        let replay_err = node_b.verify_and_observe(epoch_a, seq1);
        assert_eq!(
            replay_err,
            Err("Causally obsolete sequence: replay detected")
        );

        assert!(node_b.verify_and_observe(epoch_a, seq2).is_ok());

        let new_epoch = node_a.advance_epoch();
        assert_eq!(new_epoch, 1);
        let (epoch1, epoch1_seq1, _) = node_a.advance_local();
        assert_eq!((epoch1, epoch1_seq1), (1, 1));

        assert!(node_b.verify_and_observe(epoch1, epoch1_seq1).is_ok());

        let stale_epoch_err = node_b.verify_and_observe(0, 9999);
        assert_eq!(stale_epoch_err, Err("Causally obsolete epoch: rejected"));
    }
}
