//! L4 — Reed-Solomon Erasure Coding Layer (High-Performance Zero-Allocation Engine).
//!
//! Implements an optimized (2,1) Reed-Solomon code over GF(2^8):
//! - 2 data shards + 1 parity shard
//! - Any 2 of the 3 shards reconstruct original data with zero packet retransmission
//! - Global static matrix encoder caching to eliminate per-packet heap allocations

use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

static RS_2_1: LazyLock<ReedSolomon> =
    LazyLock::new(|| ReedSolomon::new(2, 1).expect("Failed to initialize static RS(2,1) encoder"));

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

pub fn encode_parity_slice(d0: &[u8], d1: &[u8], parity_out: &mut [u8]) {
    if d0.len() != d1.len() || d0.len() != parity_out.len() {
        return;
    }
    let _ = RS_2_1.encode_sep(&[d0, d1], &mut [parity_out]);
}

pub fn reconstruct(shards: &mut [Option<Vec<u8>>]) -> Result<(), reed_solomon_erasure::Error> {
    if shards.len() != 3 {
        return Err(reed_solomon_erasure::Error::TooFewShardsPresent);
    }

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

    RS_2_1.reconstruct(shards)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdaptiveCodingMode {
    DirectNoFec,
    AdaptiveBurstFec { data: u8, parity: u8 },
    ShatterAontRs21,
}

pub fn select_coding_mode(loss_rate: f64, distinct_phys: usize) -> AdaptiveCodingMode {
    if distinct_phys >= 2 {
        AdaptiveCodingMode::ShatterAontRs21
    } else if loss_rate >= 0.01 {
        AdaptiveCodingMode::AdaptiveBurstFec { data: 4, parity: 1 }
    } else {
        AdaptiveCodingMode::DirectNoFec
    }
}

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

pub fn encode_aont_rs21(data: &[u8]) -> Vec<Vec<u8>> {
    let aont = aont_transform(data);
    let mut framed = Vec::with_capacity(4 + aont.len());
    framed.extend_from_slice(&(aont.len() as u32).to_le_bytes());
    framed.extend_from_slice(&aont);
    encode(&mut framed)
}

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

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            product ^= a;
        }
        let high = a & 0x80 != 0;
        a <<= 1;
        if high {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    product
}

fn gf_pow(base: u8, mut exp: u32) -> u8 {
    let mut acc = 1u8;
    let mut b = base;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = gf_mul(acc, b);
        }
        b = gf_mul(b, b);
        exp >>= 1;
    }
    acc
}

fn gf_inv(a: u8) -> Option<u8> {
    if a == 0 {
        None
    } else {
        Some(gf_pow(a, 254))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RampParams {
    pub data: u8,
    pub masks: u8,
    pub shards: u8,
}

impl RampParams {
    pub fn new(masks: u8, data: u8, failures: u8) -> Result<Self, String> {
        if data == 0 {
            return Err("a ramp code needs at least one data symbol".into());
        }
        let shards = data as u16 + masks as u16 + failures as u16;
        if shards > 255 {
            return Err(format!("GF(2^8) supports at most 255 shards, got {shards}"));
        }
        Ok(Self {
            data,
            masks,
            shards: shards as u8,
        })
    }

    pub fn for_paths(paths: usize) -> Result<Self, String> {
        if paths < 3 {
            return Err(format!(
                "a ramp bond needs at least 3 distinct paths, got {paths}"
            ));
        }
        if paths > 255 {
            return Err(format!("GF(2^8) supports at most 255 shards, got {paths}"));
        }
        Self::new(1, (paths - 2) as u8, 1)
    }

    pub fn failures(&self) -> u8 {
        self.shards
            .saturating_sub(self.data)
            .saturating_sub(self.masks)
    }

    pub fn required(&self) -> usize {
        self.data as usize + self.masks as usize
    }

    pub fn rate(&self) -> f64 {
        self.data as f64 / self.shards as f64
    }

    fn point(&self, index: u8) -> u8 {
        index.wrapping_add(1)
    }
}

pub fn encode_ramp(payload: &[u8], params: &RampParams) -> Result<Vec<Vec<u8>>, String> {
    use rand::RngCore;

    let r = params.data as usize;
    let c = params.masks as usize;
    let m = params.shards as usize;
    let k = r + c;
    if m == 0 || k == 0 {
        return Err("ramp parameters describe no code".into());
    }
    let mut framed = Vec::with_capacity(4 + payload.len() + r);
    framed.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    framed.extend_from_slice(payload);
    while framed.len() % r != 0 {
        framed.push(0);
    }
    let blocks = framed.len() / r;
    let mut out = vec![vec![0u8; blocks]; m];
    let mut rng = rand::thread_rng();
    let mut coefficients = vec![0u8; k];

    for block in 0..blocks {
        coefficients[..r].copy_from_slice(&framed[block * r..block * r + r]);
        rng.fill_bytes(&mut coefficients[r..]);
        for (index, shard) in out.iter_mut().enumerate() {
            let alpha = params.point(index as u8);
            let mut y = 0u8;
            for j in (0..k).rev() {
                y = gf_mul(y, alpha) ^ coefficients[j];
            }
            shard[block] = y;
        }
    }
    Ok(out)
}

fn gf_solve(matrix: &mut [Vec<u8>], rhs: &mut [u8]) -> Option<()> {
    let n = rhs.len();
    for col in 0..n {
        let pivot = (col..n).find(|&row| matrix[row][col] != 0)?;
        if pivot != col {
            matrix.swap(pivot, col);
            rhs.swap(pivot, col);
        }
        let inv = gf_inv(matrix[col][col])?;
        let mut pivot_row: Vec<u8> = matrix[col].clone();
        for value in pivot_row.iter_mut() {
            *value = gf_mul(*value, inv);
        }
        matrix[col].copy_from_slice(&pivot_row);
        rhs[col] = gf_mul(rhs[col], inv);
        for row in 0..n {
            if row != col && matrix[row][col] != 0 {
                let factor = matrix[row][col];
                for j in 0..n {
                    matrix[row][j] ^= gf_mul(factor, pivot_row[j]);
                }
                rhs[row] ^= gf_mul(factor, rhs[col]);
            }
        }
    }
    Some(())
}

pub fn decode_ramp(shards: &[(u8, Vec<u8>)], params: &RampParams) -> Option<Vec<u8>> {
    let r = params.data as usize;
    let c = params.masks as usize;
    let m = params.shards as usize;
    let k = r + c;

    let mut seen = [false; 255];
    let mut chosen: Vec<&(u8, Vec<u8>)> = Vec::with_capacity(k);
    for shard in shards {
        let index = shard.0 as usize;
        if index >= m || seen[index] {
            continue;
        }
        seen[index] = true;
        chosen.push(shard);
        if chosen.len() == k {
            break;
        }
    }
    if chosen.len() < k {
        return None;
    }
    let blocks = chosen[0].1.len();
    if chosen.iter().any(|(_, bytes)| bytes.len() != blocks) {
        return None;
    }
    if blocks == 0 {
        return None;
    }

    let mut framed = Vec::with_capacity(blocks * r);
    let mut matrix = vec![vec![0u8; k]; k];
    let mut rhs = vec![0u8; k];
    for (row, (_, _)) in chosen.iter().enumerate() {
        let alpha = params.point(chosen[row].0);
        let mut power = 1u8;
        for cell in matrix[row].iter_mut() {
            *cell = power;
            power = gf_mul(power, alpha);
        }
    }

    for block in 0..blocks {
        for (row, (_, bytes)) in chosen.iter().enumerate() {
            rhs[row] = bytes[block];
        }
        let mut a = matrix.clone();
        let mut y = rhs.clone();
        gf_solve(&mut a, &mut y)?;
        framed.extend_from_slice(&y[..r]);
    }

    let len = u32::from_le_bytes(framed.get(..4)?.try_into().ok()?) as usize;
    if len > framed.len().saturating_sub(4) {
        return None;
    }
    Some(framed[4..4 + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aont_rs21_hides_plaintext_in_single_shard_and_recovers_with_any_two() {
        let secret = b"TOP_SECRET_HTTP_COOKIE_SESSION_1234567890";
        let shards = encode_aont_rs21(secret);
        assert_eq!(shards.len(), 3);
        assert!(!shards[0]
            .windows(8)
            .any(|w| secret.windows(8).any(|s| s == w)));
        assert!(!shards[1]
            .windows(8)
            .any(|w| secret.windows(8).any(|s| s == w)));

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

#[cfg(test)]
mod ramp_tests {
    use super::*;

    fn params(masks: u8, data: u8, failures: u8) -> RampParams {
        RampParams::new(masks, data, failures).unwrap()
    }

    #[test]
    fn rate_and_thresholds_follow_the_formula() {
        let p = params(1, 1, 1);
        assert_eq!(p.shards, 3);
        assert_eq!(p.failures(), 1);
        assert_eq!(p.required(), 2);
        assert!((p.rate() - 1.0 / 3.0).abs() < 1e-12);

        let p = params(1, 2, 1);
        assert_eq!(p.shards, 4, "m = r + c + f");
        assert!((p.rate() - 0.5).abs() < 1e-12, "R = 1 - (c+f)/m");

        assert!(RampParams::new(1, 0, 1).is_err(), "no data symbol");
    }

    #[test]
    fn any_r_plus_c_shards_reconstruct_and_fewer_do_not() {
        let p = params(1, 2, 1); // m = 4, k = 3
        let payload = b"ramp bonding across four physical paths".to_vec();
        let shards = encode_ramp(&payload, &p).unwrap();
        assert_eq!(shards.len(), 4);

        for missing in 0..4u8 {
            let set: Vec<(u8, Vec<u8>)> = shards
                .iter()
                .enumerate()
                .filter(|(i, _)| *i as u8 != missing)
                .map(|(i, s)| (i as u8, s.clone()))
                .collect();
            assert_eq!(decode_ramp(&set, &p).unwrap(), payload, "missing {missing}");
        }

        let two: Vec<(u8, Vec<u8>)> = vec![(0, shards[0].clone()), (1, shards[1].clone())];
        assert!(
            decode_ramp(&two, &p).is_none(),
            "k - 1 shards must not decode"
        );
    }

    #[test]
    fn duplicate_indices_do_not_count_towards_the_threshold() {
        let p = params(1, 1, 1); // k = 2
        let shards = encode_ramp(b"duplicate index", &p).unwrap();
        let dupes: Vec<(u8, Vec<u8>)> = vec![
            (0, shards[0].clone()),
            (0, shards[0].clone()),
            (0, shards[0].clone()),
        ];
        assert!(decode_ramp(&dupes, &p).is_none());
    }

    #[test]
    fn one_carrier_learns_nothing() {
        let p = params(1, 1, 1);
        let payload = b"TOP_SECRET_MARKER_0123456789abcdef";
        let shards = encode_ramp(payload, &p).unwrap();
        for shard in &shards {
            assert!(
                !shard.windows(8).any(|w| payload.windows(8).any(|p| p == w)),
                "a single ramp shard leaked plaintext"
            );
        }
        assert!(decode_ramp(&[(0, shards[0].clone())], &p).is_none());
    }

    #[test]
    fn a_corrupted_share_does_not_reproduce_the_payload() {
        let p = params(1, 2, 1);
        let payload = b"integrity is the AEAD's job, not the code's".to_vec();
        let mut shards = encode_ramp(&payload, &p).unwrap();
        shards[1][0] ^= 0xFF;
        let set: Vec<(u8, Vec<u8>)> = vec![(0, shards[0].clone()), (1, shards[1].clone())];
        assert!(decode_ramp(&set, &p).is_none());
        let full: Vec<(u8, Vec<u8>)> = shards
            .iter()
            .cloned()
            .enumerate()
            .map(|(i, s)| (i as u8, s))
            .collect();
        assert_ne!(decode_ramp(&full, &p), Some(payload));
    }

    #[test]
    fn every_path_count_from_three_to_eight_reconstructs_from_every_threshold_subset() {
        for m in 3usize..=8 {
            for c in 0u8..m as u8 {
                for f in 0u8..(m as u8 - c) {
                    let r = m as u8 - c - f;
                    if r == 0 {
                        continue;
                    }
                    let p = RampParams::new(c, r, f).unwrap();
                    assert_eq!(p.shards as usize, m);
                    assert!(
                        p.shards as usize > p.masks as usize + p.failures() as usize,
                        "Theorem 1 violated for c={c} r={r} f={f} m={m}"
                    );

                    let payload = vec![0x5Au8 ^ m as u8; 3];
                    let shards = encode_ramp(&payload, &p).unwrap();
                    assert_eq!(shards.len(), m);
                    let k = p.required();

                    for bits in 0u16..(1u16 << m) {
                        let subset: Vec<(u8, Vec<u8>)> = (0..m)
                            .filter(|i| bits & (1u16 << i) != 0)
                            .map(|i| (i as u8, shards[i].clone()))
                            .collect();
                        let decoded = decode_ramp(&subset, &p);
                        if subset.len() >= k {
                            assert_eq!(
                                decoded,
                                Some(payload.clone()),
                                "m={m} c={c} r={r} f={f} subset={bits:#b}"
                            );
                        } else {
                            assert!(
                                decoded.is_none(),
                                "m={m} c={c} r={r} f={f} subset={bits:#b} decoded below threshold"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn degenerate_and_boundary_ramp_parameters_are_refused_or_handled() {
        assert!(RampParams::new(0, 0, 0).is_err(), "no data symbol");
        assert!(
            RampParams::new(255, 1, 0).is_err(),
            "256 shards exceeds GF(2^8)"
        );
        assert!(
            RampParams::new(254, 1, 0).is_ok(),
            "255 shards is the field limit"
        );

        assert!(RampParams::for_paths(2).is_err());
        assert!(RampParams::for_paths(256).is_err());
        for m in 3usize..=8 {
            let p = RampParams::for_paths(m).unwrap();
            assert_eq!(p.masks, 1);
            assert_eq!(p.failures(), 1);
            assert_eq!(p.data as usize, m - 2);
            assert_eq!(p.shards as usize, m);
        }

        let p = RampParams::new(1, 2, 252).unwrap();
        let shards = encode_ramp(b"edge", &p).unwrap();
        assert_eq!(shards.len(), 255);
        let set: Vec<(u8, Vec<u8>)> = vec![
            (0, shards[0].clone()),
            (127, shards[127].clone()),
            (254, shards[254].clone()),
        ];
        assert_eq!(decode_ramp(&set, &p), Some(b"edge".to_vec()));

        let p = RampParams::new(0, 1, 2).unwrap();
        let shards = encode_ramp(b"abc", &p).unwrap();
        assert_eq!(
            decode_ramp(&[(0, shards[0].clone())], &p),
            Some(b"abc".to_vec())
        );

        let p = RampParams::new(1, 1, 1).unwrap();
        let shards = encode_ramp(b"dup", &p).unwrap();
        assert!(decode_ramp(&[(0, shards[0].clone()), (0, shards[0].clone())], &p).is_none());
        assert!(decode_ramp(&[(0, shards[0].clone()), (3, shards[0].clone())], &p).is_none());
        let mut short = shards[1].clone();
        short.pop();
        assert!(decode_ramp(&[(0, shards[0].clone()), (1, short)], &p).is_none());
    }

    #[test]
    fn empty_padded_and_short_payloads_round_trip() {
        let p = params(2, 3, 2); // m = 7, k = 5
        for payload in [
            b"".to_vec(),
            b"x".to_vec(),
            b"12345".to_vec(),
            vec![0xAB; 1000],
        ] {
            let shards = encode_ramp(&payload, &p).unwrap();
            assert_eq!(shards.len(), 7);
            let set: Vec<(u8, Vec<u8>)> = shards
                .iter()
                .take(5)
                .cloned()
                .enumerate()
                .map(|(i, s)| (i as u8, s))
                .collect();
            assert_eq!(decode_ramp(&set, &p), Some(payload));
        }
    }
}
