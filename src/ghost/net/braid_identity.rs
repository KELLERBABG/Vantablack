#![cfg(feature = "research")]
//! Braid-Locked Identity — zero-ledger epidemic clone suicide
//! (`DEV/UNPRECEDENTED_PRIMITIVES.md` §2).
//!
//! Every ratchet step replaces the identity key: the next public key, the
//! previous braid state and the session transcript are hashed together, the
//! hash is signed by the retiring key, and the retiring key is dropped. A node
//! cloned at height `t` therefore eventually emits two different signed
//! transitions from the same parent key. That pair is self-authenticating —
//! both halves verify under the one key the fork is claimed at — so revocation
//! needs no ledger, no directory and no witness vote.
//!
//! What this module does **not** do is write the new key to disk. The
//! primitive's `fsync`-before-send ordering is the caller's obligation;
//! [`BraidLock::secret_state`] returns `(secret, braid, height)` as one value
//! so that ordering is expressible, but this type performs no I/O.

use std::collections::{HashMap, HashSet};
use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

pub const BRAID_MAGIC: &[u8; 8] = b"VB-BRAID";
pub const TRANSITION_BYTES: usize = 200;

const BRAID_GENESIS_DOMAIN: &[u8] = b"VB-BRAID-GENESIS-V1";
const BRAID_STEP_DOMAIN: &[u8] = b"VB-BRAID-STEP-V1";
const TRANSITION_DOMAIN: &[u8] = b"VB-BRAID-TRANSITION-V1";

fn signed_message(height: u64, next_pk: &[u8; 32], braid: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(TRANSITION_DOMAIN.len() + 72);
    message.extend_from_slice(TRANSITION_DOMAIN);
    message.extend_from_slice(&height.to_be_bytes());
    message.extend_from_slice(next_pk);
    message.extend_from_slice(braid);
    message
}

fn braid_step(previous: &[u8; 32], next_pk: &[u8; 32], transcript: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BRAID_STEP_DOMAIN);
    hasher.update(previous);
    hasher.update(next_pk);
    hasher.update(transcript);
    hasher.finalize().into()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub height: u64,
    pub parent_pk: [u8; 32],
    pub next_pk: [u8; 32],
    pub braid: [u8; 32],
    pub signature: [u8; 64],
}

impl Transition {
    pub fn verify(&self) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&self.parent_pk) else {
            return false;
        };
        key.verify_strict(
            &signed_message(self.height, &self.next_pk, &self.braid),
            &Signature::from_bytes(&self.signature),
        )
        .is_ok()
    }

    pub fn to_bytes(&self) -> [u8; TRANSITION_BYTES] {
        let mut out = [0u8; TRANSITION_BYTES];
        out[0..8].copy_from_slice(BRAID_MAGIC);
        out[8..16].copy_from_slice(&self.height.to_be_bytes());
        out[16..48].copy_from_slice(&self.parent_pk);
        out[48..80].copy_from_slice(&self.next_pk);
        out[80..112].copy_from_slice(&self.braid);
        out[112..176].copy_from_slice(&self.signature);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != TRANSITION_BYTES {
            return None;
        }
        if &bytes[0..8] != BRAID_MAGIC {
            return None;
        }
        if bytes[176..].iter().any(|b| *b != 0) {
            return None;
        }
        let mut parent_pk = [0u8; 32];
        let mut next_pk = [0u8; 32];
        let mut braid = [0u8; 32];
        let mut signature = [0u8; 64];
        parent_pk.copy_from_slice(&bytes[16..48]);
        next_pk.copy_from_slice(&bytes[48..80]);
        braid.copy_from_slice(&bytes[80..112]);
        signature.copy_from_slice(&bytes[112..176]);
        Some(Self {
            height: u64::from_be_bytes(bytes[8..16].try_into().ok()?),
            parent_pk,
            next_pk,
            braid,
            signature,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloneProof {
    pub a: Transition,
    pub b: Transition,
}

impl CloneProof {
    pub fn new(a: Transition, b: Transition) -> Option<Self> {
        if a.height != b.height || a.parent_pk != b.parent_pk {
            return None;
        }
        if a.next_pk == b.next_pk && a.braid == b.braid {
            return None;
        }
        if !a.verify() || !b.verify() {
            return None;
        }
        Some(Self { a, b })
    }

    pub fn equivocating_key(&self) -> [u8; 32] {
        self.a.parent_pk
    }

    pub fn to_bytes(&self) -> [u8; 2 * TRANSITION_BYTES] {
        let mut out = [0u8; 2 * TRANSITION_BYTES];
        out[..TRANSITION_BYTES].copy_from_slice(&self.a.to_bytes());
        out[TRANSITION_BYTES..].copy_from_slice(&self.b.to_bytes());
        out
    }
}

pub struct BraidLock {
    key: SigningKey,
    braid: [u8; 32],
    height: u64,
}

impl BraidLock {
    fn fresh_seed() -> [u8; 32] {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        seed
    }

    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed);
        let identity = key.verifying_key().to_bytes();
        seed.zeroize();
        let mut hasher = Sha256::new();
        hasher.update(BRAID_GENESIS_DOMAIN);
        hasher.update(identity);
        Self {
            key,
            braid: hasher.finalize().into(),
            height: 0,
        }
    }

    pub fn generate() -> Self {
        Self::from_seed(Self::fresh_seed())
    }

    pub fn identity(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn braid(&self) -> [u8; 32] {
        self.braid
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    pub fn secret_state(&self) -> ([u8; 32], [u8; 32], u64) {
        (self.key.to_bytes(), self.braid, self.height)
    }

    pub fn restore(mut secret: [u8; 32], braid: [u8; 32], height: u64) -> Self {
        let key = SigningKey::from_bytes(&secret);
        secret.zeroize();
        Self { key, braid, height }
    }

    pub fn advance(&mut self, transcript: &[u8]) -> Transition {
        let mut seed = Self::fresh_seed();
        let next = SigningKey::from_bytes(&seed);
        seed.zeroize();

        let parent_pk = self.key.verifying_key().to_bytes();
        let next_pk = next.verifying_key().to_bytes();
        let height = self.height + 1;
        let braid = braid_step(&self.braid, &next_pk, transcript);
        let signature = self
            .key
            .sign(&signed_message(height, &next_pk, &braid))
            .to_bytes();

        let retired = std::mem::replace(&mut self.key, next);
        self.braid = braid;
        self.height = height;
        drop(retired);

        Transition {
            height,
            parent_pk,
            next_pk,
            braid,
            signature,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BraidVerdict {
    Extended,
    Stale,
    Fork(Box<CloneProof>),
    Revoked([u8; 32]),
    Invalid,
}

#[derive(Debug, Default)]
pub struct BraidChain {
    children: HashMap<[u8; 32], Transition>,
    revoked: HashSet<[u8; 32]>,
}

impl BraidChain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_revoked(&self, identity: &[u8; 32]) -> bool {
        self.revoked.contains(identity)
    }

    pub fn revoked_count(&self) -> usize {
        self.revoked.len()
    }

    pub fn revoke(&mut self, identity: &[u8; 32]) {
        self.revoked.insert(*identity);
    }

    pub fn accept(&mut self, transition: &Transition) -> BraidVerdict {
        if !transition.verify() {
            return BraidVerdict::Invalid;
        }
        if self.revoked.contains(&transition.parent_pk) {
            return BraidVerdict::Revoked(transition.parent_pk);
        }
        match self.children.get(&transition.parent_pk) {
            None => {
                self.children
                    .insert(transition.parent_pk, transition.clone());
                BraidVerdict::Extended
            }
            Some(previous) if previous == transition => BraidVerdict::Stale,
            Some(previous) => match CloneProof::new(previous.clone(), transition.clone()) {
                Some(proof) => {
                    self.revoked.insert(transition.parent_pk);
                    BraidVerdict::Fork(Box::new(proof))
                }
                None => BraidVerdict::Invalid,
            },
        }
    }
}

impl fmt::Display for BraidVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Extended => write!(f, "identity extended"),
            Self::Stale => write!(f, "transition already seen"),
            Self::Fork(_) => write!(f, "clone-suicide proof: identity revoked"),
            Self::Revoked(key) => write!(f, "identity {} is revoked", hex16(key)),
            Self::Invalid => write!(f, "transition does not verify"),
        }
    }
}

fn hex16(bytes: &[u8; 32]) -> String {
    bytes[..8].iter().map(|b| format!("{b:02x}")).collect()
}

pub fn gossip_rounds_to_collision(peers: usize, fanout: usize, delta: f64) -> Option<f64> {
    if peers < 2 || fanout < 2 || !delta.is_finite() || delta <= 0.0 || delta >= 1.0 {
        return None;
    }
    let n = peers as f64;
    let rounds = (n.ln() + (1.0 / delta).ln().ln()) / (2.0 * (fanout as f64).ln());
    Some(rounds.max(0.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock() -> BraidLock {
        BraidLock::from_seed([7u8; 32])
    }

    #[test]
    fn a_linear_braid_extends_without_a_fork() {
        let mut node = lock();
        let root = node.identity();
        let mut chain = BraidChain::new();

        let first = node.advance(b"session with peer A");
        assert_eq!(chain.accept(&first), BraidVerdict::Extended);
        assert_eq!(first.parent_pk, root);
        assert_eq!(first.height, 1);

        let second = node.advance(b"session with peer B");
        assert_eq!(second.parent_pk, first.next_pk);
        assert_eq!(chain.accept(&second), BraidVerdict::Extended);
        assert_eq!(node.height(), 2);
        assert_eq!(node.identity(), second.next_pk);
        assert!(!chain.is_revoked(&root));
        assert_eq!(chain.revoked_count(), 0);
    }

    #[test]
    fn two_transitions_from_one_key_are_a_self_authenticating_proof() {
        let mut real = lock();
        let mut clone = BraidLock::restore(real.secret_state().0, real.braid(), real.height());
        assert_eq!(real.identity(), clone.identity());

        let a = real.advance(b"Wi-Fi transcript");
        let b = clone.advance(b"5G transcript");
        assert_eq!(a.parent_pk, b.parent_pk);
        assert_eq!(a.height, b.height);
        assert_ne!(a.next_pk, b.next_pk);

        let mut chain = BraidChain::new();
        assert_eq!(chain.accept(&a), BraidVerdict::Extended);
        let BraidVerdict::Fork(proof) = chain.accept(&b) else {
            panic!("the second child of one key must be a fork");
        };
        assert_eq!(proof.equivocating_key(), a.parent_pk);
        assert!(proof.a.verify() && proof.b.verify());
        assert!(chain.is_revoked(&a.parent_pk));

        assert_eq!(
            chain.accept(&a),
            BraidVerdict::Revoked(a.parent_pk),
            "revocation must outrank a replay"
        );
    }

    #[test]
    fn a_fork_at_a_later_height_still_proves_the_clone() {
        let mut real = lock();
        let first = real.advance(b"before exfiltration");
        assert_eq!(first.height, 1);

        let saved = real.secret_state();
        let mut clone = BraidLock::restore(saved.0, saved.1, saved.2);
        let a = real.advance(b"after exfiltration A");
        let b = clone.advance(b"after exfiltration B");
        assert_eq!(a.height, 2);
        assert_eq!(b.height, 2);

        let mut chain = BraidChain::new();
        chain.accept(&first);
        assert!(matches!(chain.accept(&a), BraidVerdict::Extended));
        assert!(matches!(chain.accept(&b), BraidVerdict::Fork(_)));
    }

    #[test]
    fn a_tampered_transition_is_refused() {
        let mut node = lock();
        let transition = node.advance(b"transcript");

        let mut forged = transition.clone();
        forged.next_pk[0] ^= 1;
        assert!(!forged.verify());
        assert_eq!(BraidChain::new().accept(&forged), BraidVerdict::Invalid);

        let mut bad_signature = transition.clone();
        bad_signature.signature[63] ^= 0x80;
        assert!(!bad_signature.verify());
        assert_eq!(
            BraidChain::new().accept(&bad_signature),
            BraidVerdict::Invalid
        );
    }

    #[test]
    fn a_restored_revocation_outranks_an_unknown_child() {
        let mut node = lock();
        let transition = node.advance(b"revoked elsewhere");

        let mut restored = BraidChain::new();
        restored.revoke(&transition.parent_pk);
        restored.revoke(&transition.parent_pk); // idempotent
        assert_eq!(restored.revoked_count(), 1);
        assert!(restored.is_revoked(&transition.parent_pk));
        assert_eq!(
            restored.accept(&transition),
            BraidVerdict::Revoked(transition.parent_pk),
            "a revoked key is refused even though no child was ever seen"
        );
    }

    #[test]
    fn a_replayed_transition_is_stale() {
        let mut node = lock();
        let transition = node.advance(b"transcript");
        let mut chain = BraidChain::new();
        assert_eq!(chain.accept(&transition), BraidVerdict::Extended);
        assert_eq!(chain.accept(&transition), BraidVerdict::Stale);
        assert_eq!(chain.revoked_count(), 0);
    }

    #[test]
    fn a_transition_is_two_hundred_bytes_and_round_trips() {
        let mut node = lock();
        let transition = node.advance(b"wire format");
        let bytes = transition.to_bytes();
        assert_eq!(bytes.len(), TRANSITION_BYTES);
        assert_eq!(Transition::from_bytes(&bytes), Some(transition));

        let mut corrupt = bytes;
        corrupt[TRANSITION_BYTES - 1] = 1;
        assert_eq!(
            Transition::from_bytes(&corrupt),
            None,
            "reserved bytes are canonical zero"
        );
    }

    #[test]
    fn the_collision_bound_is_the_theorem_bound() {
        let rounds = gossip_rounds_to_collision(1_000_000, 4, 1e-6).expect("valid bound");
        assert!((rounds - 5.93).abs() < 0.01, "got {rounds}");

        let faster = gossip_rounds_to_collision(1_000_000, 8, 1e-6).unwrap();
        assert!(faster < rounds);
        let larger = gossip_rounds_to_collision(1_000_000_000, 4, 1e-6).unwrap();
        assert!(larger > rounds);

        let tighter = gossip_rounds_to_collision(1_000_000, 4, 1e-12).unwrap();
        assert!(tighter > rounds);
        assert!(tighter - rounds < 3.0);

        assert_eq!(gossip_rounds_to_collision(10, 1, 1e-6), None);
        assert_eq!(gossip_rounds_to_collision(10, 4, 0.0), None);
        assert_eq!(gossip_rounds_to_collision(1, 4, 1e-6), None);
    }
}
