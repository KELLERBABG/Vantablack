use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;

/// Pseudo-Noise (PN) sequence generator using ChaCha12 as CSPRNG
///
/// The PN generator is seeded with a krypto-deterministic seed
/// shared between transmitter and receiver. The same seed produces
/// identical spreading sequences.
pub struct PNGenerator {
    rng: ChaCha12Rng,
    state: u64,
}

impl PNGenerator {
    /// Create a new PN generator from a seed
    pub fn new(seed: &[u8; 32]) -> Self {
        let rng = ChaCha12Rng::from_seed(*seed);
        Self { rng, state: 0 }
    }

    /// Generate the next chip in the sequence (-1 or +1)
    pub fn next_chip(&mut self) -> f64 {
        let bit: u8 = self.rng.gen();
        self.state = self.state.wrapping_add(1);
        if bit & 0x01 == 0 {
            -1.0
        } else {
            1.0
        }
    }

    /// Generate a block of chips
    pub fn generate_chips(&mut self, count: usize) -> Vec<f64> {
        (0..count).map(|_| self.next_chip()).collect()
    }

    /// Get current state (for debugging)
    pub fn state(&self) -> u64 {
        self.state
    }

    /// Reset to a new seed
    pub fn reseed(&mut self, seed: &[u8; 32]) {
        self.rng = ChaCha12Rng::from_seed(*seed);
        self.state = 0;
    }
}

/// Gold code generator for CDMA-style multiple access
pub struct GoldCodeGenerator {
    poly1: u32,
    poly2: u32,
    state1: u32,
    state2: u32,
}

impl GoldCodeGenerator {
    /// Create a new Gold code generator with given polynomials
    pub fn new(poly1: u32, poly2: u32, init1: u32, init2: u32) -> Self {
        Self {
            poly1,
            poly2,
            state1: init1,
            state2: init2,
        }
    }

    /// Generate the next Gold code chip (-1 or +1)
    pub fn next_chip(&mut self) -> f64 {
        let feedback1 = (self.state1 & self.poly1).count_ones() & 1;
        let feedback2 = (self.state2 & self.poly2).count_ones() & 1;
        let chip = ((self.state1 & 1) ^ (self.state2 & 1)) as i8;
        self.state1 = (self.state1 >> 1) | (feedback1 << 15);
        self.state2 = (self.state2 >> 1) | (feedback2 << 15);
        if chip == 0 {
            -1.0
        } else {
            1.0
        }
    }
}
