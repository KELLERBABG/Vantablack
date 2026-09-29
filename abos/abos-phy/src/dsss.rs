use abos_common::pn_gen::PNGenerator;
use num_complex::Complex64;

/// DSSS Modulator: spreads symbols using a PN sequence
pub struct DSSSModulator {
    pn_gen: PNGenerator,
    pub chips_per_symbol: usize,
}

impl DSSSModulator {
    /// Create a new DSSS modulator with a crypto-deterministic seed
    pub fn new(seed: &[u8; 32], chips_per_symbol: usize) -> Self {
        Self {
            pn_gen: PNGenerator::new(seed),
            chips_per_symbol,
        }
    }

    /// Spread symbols by multiplying each symbol with `chips_per_symbol` chips
    pub fn spread(&mut self, symbols: &[Complex64]) -> Vec<Complex64> {
        let chips = self
            .pn_gen
            .generate_chips(symbols.len() * self.chips_per_symbol);
        let mut output = Vec::with_capacity(symbols.len() * self.chips_per_symbol);
        for (i, &sym) in symbols.iter().enumerate() {
            for j in 0..self.chips_per_symbol {
                let chip = chips[i * self.chips_per_symbol + j];
                output.push(sym * chip);
            }
        }
        output
    }
}

/// DSSS Demodulator: despreads by correlating with the PN sequence
pub struct DSSSDemodulator {
    pn_gen: PNGenerator,
    pub chips_per_symbol: usize,
}

impl DSSSDemodulator {
    /// Create a new DSSS demodulator with a crypto-deterministic seed
    pub fn new(seed: &[u8; 32], chips_per_symbol: usize) -> Self {
        Self {
            pn_gen: PNGenerator::new(seed),
            chips_per_symbol,
        }
    }

    /// Despread samples by correlating each chip position with the matching
    /// chip of the PN sequence — the exact inverse of
    /// [`DSSSModulator::spread`] when both sides share the seed.
    pub fn despread(&mut self, samples: &[Complex64]) -> Vec<Complex64> {
        let mut output = Vec::with_capacity(samples.len() / self.chips_per_symbol);
        for group in samples.chunks(self.chips_per_symbol) {
            // A trailing partial group means the stream was truncated.
            if group.len() != self.chips_per_symbol {
                break;
            }
            let mut acc = Complex64::new(0.0, 0.0);
            for &s in group {
                let chip = self.pn_gen.next_chip();
                acc += s * chip;
            }
            output.push(acc * (1.0 / self.chips_per_symbol as f64));
        }
        output
    }
}

/// Early-Late gate code tracking for DSSS acquisition
pub struct CodeAcquisition {
    early_offset: usize,
    late_offset: usize,
    correlation_threshold: f64,
}

impl CodeAcquisition {
    pub fn new(early_offset: usize, late_offset: usize, threshold: f64) -> Self {
        Self {
            early_offset,
            late_offset,
            correlation_threshold: threshold,
        }
    }

    /// Correlate samples against the PN code at early, on-time, and late positions
    pub fn track(&self, samples: &[Complex64], pn_gen: &mut PNGenerator) -> f64 {
        let code_len = samples.len();
        let early_code = pn_gen.generate_chips(code_len + self.early_offset);
        let late_code = pn_gen.generate_chips(code_len + self.late_offset);

        let early_corr: Complex64 = samples
            .iter()
            .zip(early_code.iter())
            .map(|(&s, &c)| s * c)
            .sum();
        let late_corr: Complex64 = samples
            .iter()
            .zip(late_code.iter().skip(self.late_offset))
            .map(|(&s, &c)| s * c)
            .sum();

        early_corr.norm_sqr() - late_corr.norm_sqr()
    }

    /// Detect whether the code is acquired (correlation above threshold)
    pub fn is_acquired(&self, corr_power: f64) -> bool {
        corr_power > self.correlation_threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spread_despread_roundtrip() {
        let seed = [42u8; 32];
        let symbols = vec![
            Complex64::new(1.0, 1.0),
            Complex64::new(-1.0, 1.0),
            Complex64::new(1.0, -1.0),
            Complex64::new(-1.0, -1.0),
        ];
        let mut modu = DSSSModulator::new(&seed, 8);
        let mut demod = DSSSDemodulator::new(&seed, 8);

        let spread = modu.spread(&symbols);
        assert_eq!(spread.len(), symbols.len() * 8);

        let recovered = demod.despread(&spread);
        assert_eq!(recovered.len(), symbols.len());
        for (orig, got) in symbols.iter().zip(recovered.iter()) {
            assert!(
                (orig.re - got.re).abs() < 1e-9,
                "re mismatch: {} vs {}",
                orig.re,
                got.re
            );
            assert!((orig.im - got.im).abs() < 1e-9);
        }
    }

    #[test]
    fn despread_drops_truncated_tail() {
        let seed = [1u8; 32];
        let symbols = vec![Complex64::new(1.0, 0.0)];
        let mut modu = DSSSModulator::new(&seed, 4);
        let mut demod = DSSSDemodulator::new(&seed, 4);
        let mut spread = modu.spread(&symbols);
        spread.truncate(spread.len() - 2); // truncate mid-group
        assert_eq!(demod.despread(&spread).len(), 0);
    }

    #[test]
    fn different_seed_does_not_recover() {
        let symbols = vec![Complex64::new(1.0, 1.0), Complex64::new(-1.0, -1.0)];
        let mut modu = DSSSModulator::new(&[1u8; 32], 8);
        let mut demod = DSSSDemodulator::new(&[2u8; 32], 8);
        let spread = modu.spread(&symbols);
        let recovered = demod.despread(&spread);
        let same = recovered
            .iter()
            .zip(symbols.iter())
            .all(|(a, b)| (a.re - b.re).abs() < 1e-6 && (a.im - b.im).abs() < 1e-6);
        assert!(!same, "wrong key must not recover the symbols");
    }
}
