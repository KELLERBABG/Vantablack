use num_complex::Complex64;

pub struct DDC {
    pub nco_phase: f64,
    pub phase_increment: f64,
}

impl DDC {
    pub fn new(center_freq: f64, sample_rate: f64) -> Self {
        let phase_increment = 2.0 * std::f64::consts::PI * center_freq / sample_rate;
        Self {
            nco_phase: 0.0,
            phase_increment,
        }
    }

    pub fn process(&mut self, samples: &[Complex64]) -> Vec<Complex64> {
        let mut result = Vec::with_capacity(samples.len());
        for &sample in samples {
            let nco = Complex64::new(self.nco_phase.cos(), -self.nco_phase.sin());
            result.push(sample * nco);
            self.nco_phase += self.phase_increment;
            if self.nco_phase >= 2.0 * std::f64::consts::PI {
                self.nco_phase -= 2.0 * std::f64::consts::PI;
            }
        }
        result
    }
}
