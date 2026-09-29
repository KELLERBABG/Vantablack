use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

/// Bit-interleaved coded modulation (BICM) interleaver
///
/// Pseudo-randomly permutes bits to spread burst errors across the code block
pub struct Interleaver {
    pub block_size: usize,
    pub permutation: Vec<usize>,
    inverse_permutation: Vec<usize>,
}

impl Interleaver {
    /// Create a new interleaver with a deterministic permutation from a seed
    pub fn new(block_size: usize, seed: u64) -> Self {
        let mut rng = ChaCha12Rng::seed_from_u64(seed);
        let mut permutation: Vec<usize> = (0..block_size).collect();
        permutation.shuffle(&mut rng);

        let mut inverse_permutation = vec![0usize; block_size];
        for (i, &pos) in permutation.iter().enumerate() {
            inverse_permutation[pos] = i;
        }

        Self {
            block_size,
            permutation,
            inverse_permutation,
        }
    }

    /// Interleave bits: reorder according to the permutation
    pub fn interleave(&self, bits: &[u8]) -> Vec<u8> {
        assert!(
            bits.len() <= self.block_size,
            "Bit vector exceeds block size"
        );
        let mut output = vec![0u8; self.block_size];
        for (i, &bit) in bits.iter().enumerate() {
            output[self.permutation[i]] = bit;
        }
        output
    }

    /// Deinterleave bits: restore original order using the inverse permutation
    pub fn deinterleave(&self, bits: &[u8]) -> Vec<u8> {
        assert!(
            bits.len() <= self.block_size,
            "Bit vector exceeds block size"
        );
        let mut output = vec![0u8; self.block_size];
        for (i, &bit) in bits.iter().enumerate() {
            output[self.inverse_permutation[i]] = bit;
        }
        output
    }
}
