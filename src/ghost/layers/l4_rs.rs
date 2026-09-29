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

    if data.len() % 2 != 0 {
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
    debug_assert_eq!(d0.len(), d1.len());
    debug_assert_eq!(d0.len(), parity_out.len());
    RS_2_1
        .encode_sep(&[d0, d1], &mut [parity_out])
        .expect("RS(2,1) static encoding cannot fail");
}

/// Reconstruct missing shards from at least 2 available shards.
/// `shards` is a slice of 3 Option<Vec<u8>>, where None = missing shard.
pub fn reconstruct(shards: &mut Vec<Option<Vec<u8>>>) -> Result<(), reed_solomon_erasure::Error> {
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
