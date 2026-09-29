use abos_common::pn_gen::PNGenerator;

/// Frequency Hopping Spread Spectrum engine
pub struct FHSSEngine {
    pn_gen: PNGenerator,
    pub hop_pattern: Vec<f64>,
    pub current_hop: usize,
    pub hop_duration: f64,  // seconds per hop
    pub min_frequency: f64, // Hz
    pub max_frequency: f64, // Hz
    num_hops: usize,
}

impl FHSSEngine {
    /// Create a new FHSS engine
    pub fn new(
        seed: &[u8; 32],
        hop_duration: f64,
        min_frequency: f64,
        max_frequency: f64,
        num_hops: usize,
    ) -> Self {
        let mut pn_gen = PNGenerator::new(seed);
        let hop_pattern =
            Self::generate_pattern(&mut pn_gen, num_hops, min_frequency, max_frequency);
        Self {
            pn_gen,
            hop_pattern,
            current_hop: 0,
            hop_duration,
            min_frequency,
            max_frequency,
            num_hops,
        }
    }

    fn generate_pattern(
        pn_gen: &mut PNGenerator,
        num_hops: usize,
        min_f: f64,
        max_f: f64,
    ) -> Vec<f64> {
        let bandwidth = max_f - min_f;
        (0..num_hops)
            .map(|_| {
                let chip = pn_gen.next_chip();
                // Map chip [-1, 1] to frequency range
                min_f + ((chip + 1.0) / 2.0) * bandwidth
            })
            .collect()
    }

    /// Get the next hop frequency in Hz
    pub fn next_hop_frequency(&mut self) -> f64 {
        let freq = self.hop_pattern[self.current_hop % self.num_hops];
        self.current_hop += 1;
        freq
    }

    /// Resynchronize with a new seed
    pub fn synchronize(&mut self, seed: &[u8; 32]) {
        self.pn_gen = PNGenerator::new(seed);
        self.hop_pattern = Self::generate_pattern(
            &mut self.pn_gen,
            self.num_hops,
            self.min_frequency,
            self.max_frequency,
        );
        self.current_hop = 0;
    }

    /// Get time until next hop (seconds)
    pub fn time_to_next_hop(&self, elapsed: f64) -> f64 {
        let hop_index = (elapsed / self.hop_duration) as usize;
        (hop_index + 1) as f64 * self.hop_duration - elapsed
    }
}
