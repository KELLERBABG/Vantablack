use abos_common::error::{Error, Result};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use std::collections::HashSet;

/// Regular LDPC code encoder/decoder.
///
/// The parity-check matrix is constructed in the classic systematic form
/// `H = [A | I]` (A: m×k sparse, I: m×m identity), which makes encoding
/// exact and trivial:
///
/// ```text
/// codeword c = [u | p]   with   p = A·u   ⇒   H·c = A·u + I·p = 0
/// ```
///
/// Every codeword produced by [`LDPCCode::encode`] therefore has a zero
/// syndrome, and the belief-propagation decoder converges immediately on a
/// clean channel.
pub struct LDPCCode {
    /// Parity check matrix H (m × n), in `[A | I]` form.
    pub parity_check: Vec<Vec<u8>>,
    /// Systematic generator matrix G (k × n) such that `c = u · G`.
    pub generator: Vec<Vec<u8>>,
    /// Message length (bits).
    pub k: usize,
    /// Codeword length (bits).
    pub n: usize,
    m: usize,
    col_to_rows: Vec<Vec<usize>>,
}

impl LDPCCode {
    /// Construct a regular (n, k) LDPC code.
    ///
    /// Systematic columns (0..k) get exactly 3 ones each (dv=3 sparsity);
    /// parity columns (k..n) form the identity, one per check equation.
    pub fn new(k: usize, n: usize) -> Self {
        assert!(k > 0 && n > k, "LDPC requires 0 < k < n");
        let m = n - k;
        let mut parity_check = vec![vec![0u8; n]; m];

        // Sparse random part A (m × k), 3 ones per column.
        // Rows are drawn uniformly from a seeded CSPRNG: the previous
        // deterministic `(rng + col) % m` pattern produced correlated
        // duplicate rows (isolated trapping sets) that made belief
        // propagation oscillate instead of correcting a single bit error.
        let mut rng = ChaCha12Rng::seed_from_u64(0xAB0_5EDu64);
        // Column-wise fill of a row-major matrix: iterators would have to
        // walk transposed slices, so the direct index is intentional.
        #[allow(clippy::needless_range_loop)]
        for col in 0..k {
            let mut placed = HashSet::new();
            while placed.len() < 3 {
                let row = rng.gen_range(0..m);
                if placed.insert(row) {
                    parity_check[row][col] = 1;
                }
            }
        }

        // Identity part I: check equation r owns parity column k + r.
        for r in 0..m {
            parity_check[r][k + r] = 1;
        }

        // Belief-propagation adjacency: variable node → check nodes.
        let mut col_to_rows = vec![Vec::new(); n];
        for (row, row_vals) in parity_check.iter().enumerate() {
            for (col, &v) in row_vals.iter().enumerate() {
                if v == 1 {
                    col_to_rows[col].push(row);
                }
            }
        }

        // Systematic generator G = [I | Aᵀ] (row i of G encodes u_i).
        let mut generator = vec![vec![0u8; n]; k];
        for i in 0..k {
            generator[i][i] = 1;
            for r in 0..m {
                generator[i][k + r] = parity_check[r][i];
            }
        }

        Self {
            parity_check,
            generator,
            k,
            n,
            m,
            col_to_rows,
        }
    }

    /// Encode packed data bytes into an n-bit codeword packed into
    /// `(n + 7) / 8` bytes (LSB-first per byte).
    ///
    /// Accepts fewer than `k` bits: missing systematic bits are treated as 0.
    pub fn encode(&self, data: &[u8]) -> Vec<u8> {
        let mut codeword = vec![0u8; self.n];

        // Systematic part (LSB-first within each byte, matching decode).
        let limit = self.k.min(data.len() * 8);
        for (i, bit) in codeword.iter_mut().enumerate().take(limit) {
            *bit = (data[i / 8] >> (i % 8)) & 0x01;
        }

        // Parity part: p = A·u over GF(2). With H = [A | I] this makes the
        // syndrome exactly zero by construction.
        for r in 0..self.m {
            let mut parity = 0u8;
            for (&h, &bit) in self.parity_check[r]
                .iter()
                .zip(codeword.iter())
                .take(self.k)
            {
                if h == 1 {
                    parity ^= bit;
                }
            }
            codeword[self.k + r] = parity;
        }

        // Pack bits back to bytes.
        let byte_len = self.n.div_ceil(8);
        let mut result = vec![0u8; byte_len];
        for (i, &bit) in codeword.iter().enumerate() {
            if bit == 1 {
                result[i / 8] |= 1 << (i % 8);
            }
        }
        result
    }

    /// Decode with belief propagation (sum-product algorithm).
    ///
    /// `llrs` must contain at least `n` soft bits, LSB-first per byte order
    /// matching [`LDPCCode::encode`] (positive LLR → bit 1). Returns the
    /// packed `k`-bit message.
    pub fn decode(&self, llrs: &[f64], max_iter: usize) -> Result<Vec<u8>> {
        if llrs.len() < self.n {
            return Err(Error::FecError("LLR vector too short".into()));
        }

        let mut var_to_check = vec![vec![0.0f64; self.m]; self.n];
        let mut check_to_var = vec![vec![0.0f64; self.n]; self.m];
        // The rest of this decoder is textbook sum-product, which uses the
        // standard convention `L = ln P(b=0)/P(b=1)` (positive → bit 0).
        // The workspace convention (see `qpsk_llr`) is positive → bit 1, so
        // convert on input and flip the hard decision on output.
        let var_llrs: Vec<f64> = llrs[..self.n].iter().map(|&l| -l).collect();

        for _iter in 0..max_iter {
            // Variable node → check node
            for var in 0..self.n {
                for &row in &self.col_to_rows[var] {
                    let mut sum = var_llrs[var];
                    for &other_row in &self.col_to_rows[var] {
                        if other_row != row {
                            sum += check_to_var[other_row][var];
                        }
                    }
                    var_to_check[var][row] = sum;
                }
            }

            // Check node → variable node (tanh rule)
            for row in 0..self.m {
                for &var in &self.check_vars(row) {
                    let mut product = 1.0f64;
                    for &other_var in &self.check_vars(row) {
                        if other_var != var {
                            product *= (var_to_check[other_var][row] / 2.0).tanh();
                        }
                    }
                    // Clamp product to avoid numerical issues
                    product = product.clamp(-0.9999, 0.9999);
                    check_to_var[row][var] = 2.0 * product.atanh();
                }
            }

            // Tentative decoding (standard convention: sum > 0 → bit 0)
            let mut decisions = vec![0u8; self.n];
            for var in 0..self.n {
                let mut sum = var_llrs[var];
                for &row in &self.col_to_rows[var] {
                    sum += check_to_var[row][var];
                }
                decisions[var] = if sum > 0.0 { 0 } else { 1 };
            }

            // Check if valid codeword (zero syndrome)
            let mut valid = true;
            for row in 0..self.m {
                let mut check = 0u8;
                for &var in &self.check_vars(row) {
                    check ^= decisions[var];
                }
                if check != 0 {
                    valid = false;
                    break;
                }
            }

            if valid {
                let byte_len = self.k.div_ceil(8);
                let mut result = vec![0u8; byte_len];
                for (i, &bit) in decisions[..self.k].iter().enumerate() {
                    if bit == 1 {
                        result[i / 8] |= 1 << (i % 8);
                    }
                }
                return Ok(result);
            }
        }

        Err(Error::FecError("LDPC decoding failed to converge".into()))
    }

    /// Variable nodes participating in check equation `row`.
    fn check_vars(&self, row: usize) -> Vec<usize> {
        self.parity_check[row]
            .iter()
            .enumerate()
            .filter(|(_, &v)| v == 1)
            .map(|(c, _)| c)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syndrome(code: &LDPCCode, packed: &[u8]) -> u32 {
        let mut bits = vec![0u8; code.n];
        for i in 0..code.n {
            bits[i] = (packed[i / 8] >> (i % 8)) & 1;
        }
        let mut nonzero = 0;
        for row in &code.parity_check {
            let mut s = 0u8;
            for c in 0..code.n {
                s ^= row[c] & bits[c];
            }
            if s != 0 {
                nonzero += 1;
            }
        }
        nonzero
    }

    #[test]
    fn encode_produces_zero_syndrome_for_many_payloads() {
        let code = LDPCCode::new(256, 512);
        for seed in 0..100u32 {
            let data: Vec<u8> = (0..32u8)
                .map(|i| i.wrapping_mul(7).wrapping_add(seed as u8))
                .collect();
            let cw = code.encode(&data);
            assert_eq!(
                syndrome(&code, &cw),
                0,
                "payload seed {} produced an invalid codeword",
                seed
            );
        }
    }

    #[test]
    fn clean_roundtrip_byte_identical() {
        let code = LDPCCode::new(256, 512);
        let data: Vec<u8> = (0..32u8).collect();
        let cw = code.encode(&data);

        let mut llrs = Vec::with_capacity(512);
        for byte in &cw {
            for i in 0..8 {
                let bit = (byte >> i) & 0x01;
                llrs.push(if bit == 1 { 10.0 } else { -10.0 });
            }
        }
        let decoded = code.decode(&llrs, 50).expect("must converge");
        assert_eq!(decoded, data);
    }

    #[test]
    fn short_input_roundtrips_with_zero_padding() {
        let code = LDPCCode::new(256, 512);
        let data: Vec<u8> = vec![0xAB, 0xCD];
        let cw = code.encode(&data);
        assert_eq!(syndrome(&code, &cw), 0);

        let mut llrs = Vec::with_capacity(512);
        for byte in &cw {
            for i in 0..8 {
                let bit = (byte >> i) & 0x01;
                llrs.push(if bit == 1 { 10.0 } else { -10.0 });
            }
        }
        let decoded = code.decode(&llrs, 50).expect("must converge");
        assert_eq!(&decoded[..2], &data[..]);
    }

    #[test]
    fn decode_rejects_short_llr_vector() {
        let code = LDPCCode::new(16, 32);
        assert!(code.decode(&[1.0; 31], 10).is_err());
    }

    #[test]
    fn decode_corrects_a_single_flipped_bit() {
        let code = LDPCCode::new(256, 512);
        let data: Vec<u8> = vec![0x5A; 32];
        let cw = code.encode(&data);
        let mut llrs = Vec::with_capacity(512);
        for byte in &cw {
            for i in 0..8 {
                let bit = (byte >> i) & 0x01;
                llrs.push(if bit == 1 { 10.0 } else { -10.0 });
            }
        }
        llrs[17] = -llrs[17]; // flip one received bit
        let decoded = code.decode(&llrs, 50).expect("must correct one flip");
        assert_eq!(decoded, data);
    }
}
