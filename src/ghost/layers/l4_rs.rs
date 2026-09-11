/// L4 — Reed-Solomon Erasure Coding Layer
///
/// Implements a (2,1) Reed-Solomon code over GF(2^8):
/// - 2 data shards + 1 parity shard
/// - Any 2 of the 3 shards can reconstruct the original data
/// - Provides resilience against single-packet loss without retransmission
///
/// The input data is split at its midpoint into two shards,
/// then a parity shard is computed from both.

use reed_solomon_erasure::galois_8::ReedSolomon;

/// Split data into 3 shards using (2,1) Reed-Solomon encoding.
/// If data length is odd, a padding zero byte is appended.
///
/// Returns vector of 3 shards: [data_low, data_high, parity]
pub fn encode(data: &mut Vec<u8>) -> Vec<Vec<u8>> {
    // Guard: empty data cannot be encoded
    if data.is_empty() {
        return vec![vec![], vec![], vec![]];
    }

    // Pad to even length
    if !data.len().is_multiple_of(2) {
        data.push(0);
    }

    let mid = data.len() / 2;
    let mut shards = vec![
        data[0..mid].to_vec(),
        data[mid..].to_vec(),
        vec![0u8; mid], // parity placeholder
    ];

    ReedSolomon::new(2, 1).unwrap().encode(&mut shards).unwrap();
    shards
}

/// Reconstruct missing shards from at least 2 available shards.
/// `shards` is a slice of 3 Option<Vec<u8>>, where None = missing shard.
pub fn reconstruct(shards: &mut Vec<Option<Vec<u8>>>) -> Result<(), reed_solomon_erasure::Error> {
    ReedSolomon::new(2, 1).unwrap().reconstruct(shards)
}