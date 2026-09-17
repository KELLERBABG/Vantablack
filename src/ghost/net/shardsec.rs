//! ShardSec: independent authenticated encryption for Reed-Solomon shards.
//!
//! A message is RS-encoded first, then each shard is sealed with a distinct
//! key derived from the session secret, epoch, message nonce, and shard index.
//! A captured shard therefore does not expose a decryptable fragment of the
//! message and a tampered shard is discarded before reconstruction.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::ghost::layers::l2_aead::{xchacha_open, xchacha_seal_in_place, NonceDirection};
use crate::ghost::layers::l4_rs;

pub const SHARDSEC_LABEL: &[u8] = b"GGN_SHARDSEC_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedShard {
    pub index: u8,
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
}

fn shard_key(master: &[u8; 32], epoch: u64, nonce: &[u8; 12], index: u8) -> [u8; 32] {
    let mut info = Vec::with_capacity(SHARDSEC_LABEL.len() + 8 + 12 + 1);
    info.extend_from_slice(SHARDSEC_LABEL);
    info.extend_from_slice(&epoch.to_be_bytes());
    info.extend_from_slice(nonce);
    info.push(index);
    let hk = Hkdf::<Sha256>::new(Some(master), &[]);
    let mut key = [0u8; 32];
    hk.expand(&info, &mut key).expect("32-byte HKDF output");
    key
}

fn shard_nonce(base: &[u8; 12], index: u8) -> [u8; 12] {
    let mut nonce = *base;
    nonce[11] ^= index;
    nonce
}

/// Seal one already RS-encoded shard with its independent key.
pub fn seal_shard(
    master: &[u8; 32],
    epoch: u64,
    nonce: &[u8; 12],
    direction: NonceDirection,
    index: u8,
    mut shard: Vec<u8>,
) -> SealedShard {
    let key = shard_key(master, epoch, nonce, index);
    let shard_nonce = shard_nonce(nonce, index);
    xchacha_seal_in_place(&key, &shard_nonce, epoch, direction, &mut shard)
        .expect("owned shard seal");
    let tag = shard[shard.len() - 16..].try_into().expect("AEAD tag");
    shard.truncate(shard.len() - 16);
    SealedShard { index, ciphertext: shard, tag }
}

/// Authenticate and open one independently sealed shard.
pub fn open_shard(
    master: &[u8; 32],
    epoch: u64,
    nonce: &[u8; 12],
    direction: NonceDirection,
    sealed: &SealedShard,
) -> Result<Vec<u8>, &'static str> {
    if sealed.index >= 3 {
        return Err("invalid shard index");
    }
    let key = shard_key(master, epoch, nonce, sealed.index);
    let shard_nonce = shard_nonce(nonce, sealed.index);
    let mut ciphertext = sealed.ciphertext.clone();
    ciphertext.extend_from_slice(&sealed.tag);
    xchacha_open(&key, &shard_nonce, epoch, direction, &mut ciphertext)
        .map_err(|_| "shard authentication failed")?;
    Ok(ciphertext)
}

/// RS-encode and independently seal every shard.
pub fn seal_message(
    master: &[u8; 32],
    epoch: u64,
    nonce: &[u8; 12],
    direction: NonceDirection,
    plaintext: &[u8],
) -> Vec<SealedShard> {
    let mut framed = (plaintext.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(plaintext);
    if !framed.len().is_multiple_of(2) {
        framed.push(0);
    }
    let shards = l4_rs::encode(&mut framed);
    shards
        .into_iter()
        .enumerate()
        .map(|(index, shard)| seal_shard(master, epoch, nonce, direction, index as u8, shard))
        .collect()
}

/// Authenticate/decrypt available shards and reconstruct after at least two pass.
pub fn open_message(
    master: &[u8; 32],
    epoch: u64,
    nonce: &[u8; 12],
    direction: NonceDirection,
    sealed: &[Option<SealedShard>],
) -> Result<Vec<u8>, &'static str> {
    if sealed.len() != 3 {
        return Err("ShardSec requires exactly three shard slots");
    }
    let mut shards: Vec<Option<Vec<u8>>> = vec![None, None, None];
    for candidate in sealed.iter().flatten() {
        if candidate.index >= 3 || shards[candidate.index as usize].is_some() {
            continue;
        }
        if let Ok(plaintext) = open_shard(master, epoch, nonce, direction, candidate) {
            shards[candidate.index as usize] = Some(plaintext);
        }
    }
    if shards.iter().filter(|s| s.is_some()).count() < 2 {
        return Err("fewer than two authenticated shards");
    }
    l4_rs::reconstruct(&mut shards).map_err(|_| "Reed-Solomon reconstruction failed")?;
    let first = shards[0].as_ref().ok_or("missing reconstructed shard")?;
    let second = shards[1].as_ref().ok_or("missing reconstructed shard")?;
    let mut framed = Vec::with_capacity(first.len() + second.len());
    framed.extend_from_slice(first);
    framed.extend_from_slice(second);
    if framed.len() < 2 {
        return Err("reconstructed payload is truncated");
    }
    let length = u16::from_be_bytes([framed[0], framed[1]]) as usize;
    if length + 2 > framed.len() {
        return Err("reconstructed payload length is invalid");
    }
    framed.truncate(length + 2);
    Ok(framed[2..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghost::layers::l2_aead::random_xnonce;

    #[test]
    fn two_authenticated_shards_reconstruct() {
        let key = [0x42; 32];
        let nonce = random_xnonce();
        let sealed = seal_message(&key, 3, &nonce, NonceDirection::InitiatorToResponder, b"secret");
        let mut available = vec![Some(sealed[0].clone()), None, Some(sealed[2].clone())];
        assert_eq!(open_message(&key, 3, &nonce, NonceDirection::InitiatorToResponder, &available).unwrap(), b"secret");
        available[0].as_mut().unwrap().ciphertext[0] ^= 1;
        assert!(open_message(&key, 3, &nonce, NonceDirection::InitiatorToResponder, &available).is_err());
    }

    #[test]
    fn one_captured_shard_never_opens() {
        let sealed = seal_message(&[7; 32], 1, &[9; 12], NonceDirection::ResponderToInitiator, b"plaintext");
        let available = vec![Some(sealed[1].clone()), None, None];
        assert!(open_message(&[7; 32], 1, &[9; 12], NonceDirection::ResponderToInitiator, &available).is_err());
    }
}
