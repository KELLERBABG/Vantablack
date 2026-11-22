//! L4 — Reed-Solomon Erasure Coding Layer (High-Performance Zero-Allocation Engine).
//!
//! Implements an optimized (2,1) Reed-Solomon code over GF(2^8):
//! - 2 data shards + 1 parity shard
//! - Any 2 of the 3 shards reconstruct original data with zero packet retransmission
//! - Global static matrix encoder caching to eliminate per-packet heap allocations

use reed_solomon_erasure::galois_8::ReedSolomon;
use std::sync::LazyLock;

/// Statically initialized RS(2,1) encoder instance (thread-safe, zero per-packet setup cost).
static RS_2_1: LazyLock<ReedSolomon> =
    LazyLock::new(|| ReedSolomon::new(2, 1).expect("Failed to initialize static RS(2,1) encoder"));

/// Split data into 3 shards using (2,1) Reed-Solomon encoding.
/// If data length is odd, a padding zero byte is appended.
///
/// Returns vector of 3 shards: [data_low, data_high, parity]
pub fn encode(data: &mut Vec<u8>) -> Vec<Vec<u8>> {
    if data.is_empty() {
        return vec![vec![], vec![], vec![]];
    }

    if !data.len().is_multiple_of(2) {
        data.push(0);
    }

    let mid = data.len() / 2;
    let mut shards = vec![data[0..mid].to_vec(), data[mid..].to_vec(), vec![0u8; mid]];

    RS_2_1
        .encode(&mut shards)
        .expect("RS(2,1) static encoding cannot fail");
    shards
}

/// In-place parity calculation directly into pre-allocated buffer slices.
pub fn encode_parity_slice(d0: &[u8], d1: &[u8], parity_out: &mut [u8]) {
    if d0.len() != d1.len() || d0.len() != parity_out.len() {
        return;
    }
    let _ = RS_2_1.encode_sep(&[d0, d1], &mut [parity_out]);
}

/// Reconstruct missing shards from at least 2 available shards.
/// `shards` is a slice of 3 Option<Vec<u8>>, where None = missing shard.
pub fn reconstruct(shards: &mut [Option<Vec<u8>>]) -> Result<(), reed_solomon_erasure::Error> {
    if shards.len() != 3 {
        return Err(reed_solomon_erasure::Error::TooFewShardsPresent);
    }

    // Fast-path: if both data shards are already present, reconstruct parity if missing and return.
    if shards[0].is_some() && shards[1].is_some() {
        if shards[2].is_none() {
            let d0 = shards[0].as_ref().unwrap();
            let d1 = shards[1].as_ref().unwrap();
            let mut p = vec![0u8; d0.len()];
            encode_parity_slice(d0, d1, &mut p);
            shards[2] = Some(p);
        }
        return Ok(());
    }

    // Otherwise reconstruct missing data shards via cached static matrix instance
    RS_2_1.reconstruct(shards)
}

/// Adaptive erasure coding policy selected from measured path loss and physical diversity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdaptiveCodingMode {
    /// Clean single-NIC link (<1% loss): 0% erasure overhead.
    DirectNoFec,
    /// Lossy WAN / cellular link: low-overhead burst FEC (e.g., 4 data + 1 parity = 25%).
    AdaptiveBurstFec { data: u8, parity: u8 },
    /// Multi-PHY or multi-ASN disjoint paths: AONT + RS(2,1) spatial secrecy.
    ShatterAontRs21,
}

/// Choose the optimal coding mode for the current path loss and physical interface count.
pub fn select_coding_mode(loss_rate: f64, distinct_phys: usize) -> AdaptiveCodingMode {
    if distinct_phys >= 2 {
        AdaptiveCodingMode::ShatterAontRs21
    } else if loss_rate >= 0.01 {
        AdaptiveCodingMode::AdaptiveBurstFec { data: 4, parity: 1 }
    } else {
        AdaptiveCodingMode::DirectNoFec
    }
}

/// Apply an authenticated All-Or-Nothing Transform (AONT) to `data` before erasure coding.
///
/// Generates a fresh 32-byte key `K_e`, seals `data` with XChaCha20-Poly1305 under `K_e`
/// (zero nonce, safe because `K_e` is single-use), and appends `T = K_e XOR SHA256(C)`.
/// Any single systematic shard reveals zero information about `data` without the full block.
pub fn aont_transform(data: &[u8]) -> Vec<u8> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        XChaCha20Poly1305, XNonce,
    };
    use rand::RngCore;
    use sha2::{Digest, Sha256};

    let mut ke = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut ke);
    let cipher = XChaCha20Poly1305::new((&ke).into());
    let nonce = XNonce::from_slice(&[0u8; 24]);
    let mut ciphertext = cipher
        .encrypt(nonce, data)
        .expect("XChaCha20Poly1305 encryption with fresh key cannot fail");
    let digest: [u8; 32] = Sha256::digest(&ciphertext).into();
    let mut tail = [0u8; 32];
    for i in 0..32 {
        tail[i] = ke[i] ^ digest[i];
    }
    ciphertext.extend_from_slice(&tail);
    ciphertext
}

/// Invert an AONT block produced by [`aont_transform`].
pub fn aont_inverse(block: &[u8]) -> Option<Vec<u8>> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        XChaCha20Poly1305, XNonce,
    };
    use sha2::{Digest, Sha256};

    if block.len() < 32 + 16 {
        return None;
    }
    let split = block.len() - 32;
    let (ciphertext, tail) = block.split_at(split);
    let digest: [u8; 32] = Sha256::digest(ciphertext).into();
    let mut ke = [0u8; 32];
    for i in 0..32 {
        ke[i] = tail[i] ^ digest[i];
    }
    let cipher = XChaCha20Poly1305::new((&ke).into());
    let nonce = XNonce::from_slice(&[0u8; 24]);
    cipher.decrypt(nonce, ciphertext).ok()
}

/// Encode `data` with [`aont_transform`] followed by systematic RS(2,1).
///
/// Prefixing a 4-byte little-endian AONT block length handles odd-length padding cleanly.
pub fn encode_aont_rs21(data: &[u8]) -> Vec<Vec<u8>> {
    let aont = aont_transform(data);
    let mut framed = Vec::with_capacity(4 + aont.len());
    framed.extend_from_slice(&(aont.len() as u32).to_le_bytes());
    framed.extend_from_slice(&aont);
    encode(&mut framed)
}

/// Reconstruct RS(2,1) shards and invert the AONT block.
pub fn decode_aont_rs21(shards: &mut [Option<Vec<u8>>]) -> Option<Vec<u8>> {
    reconstruct(shards).ok()?;
    let d0 = shards[0].as_ref()?;
    let d1 = shards[1].as_ref()?;
    let mut framed = Vec::with_capacity(d0.len() + d1.len());
    framed.extend_from_slice(d0);
    framed.extend_from_slice(d1);
    if framed.len() < 4 {
        return None;
    }
    let aont_len = u32::from_le_bytes(framed[..4].try_into().ok()?) as usize;
    if framed.len() < 4 + aont_len {
        return None;
    }
    aont_inverse(&framed[4..4 + aont_len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aont_rs21_hides_plaintext_in_single_shard_and_recovers_with_any_two() {
        let secret = b"TOP_SECRET_HTTP_COOKIE_SESSION_1234567890";
        let shards = encode_aont_rs21(secret);
        assert_eq!(shards.len(), 3);
        // Neither shard[0] nor shard[1] contains the plaintext substring.
        assert!(!shards[0]
            .windows(8)
            .any(|w| secret.windows(8).any(|s| s == w)));
        assert!(!shards[1]
            .windows(8)
            .any(|w| secret.windows(8).any(|s| s == w)));

        // Drop shard 0 -> reconstruct from shard 1 + parity 2.
        let mut partial = vec![None, Some(shards[1].clone()), Some(shards[2].clone())];
        let recovered = decode_aont_rs21(&mut partial).expect("decode with shard 1 + parity");
        assert_eq!(recovered.as_slice(), secret);
    }

    #[test]
    fn adaptive_coding_mode_selection() {
        assert_eq!(
            select_coding_mode(0.001, 1),
            AdaptiveCodingMode::DirectNoFec
        );
        assert_eq!(
            select_coding_mode(0.03, 1),
            AdaptiveCodingMode::AdaptiveBurstFec { data: 4, parity: 1 }
        );
        assert_eq!(
            select_coding_mode(0.0, 2),
            AdaptiveCodingMode::ShatterAontRs21
        );
    }
}
