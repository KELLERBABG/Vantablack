use num_complex::Complex64;

pub struct ChirpSounder {
    pub start_freq: f64,
    pub stop_freq: f64,
    pub duration: f64,
}

impl ChirpSounder {
    pub fn new(start_freq: f64, stop_freq: f64, duration: f64) -> Self {
        Self {
            start_freq,
            stop_freq,
            duration,
        }
    }

    pub fn generate_chirp(&self) -> Vec<Complex64> {
        let sample_rate = 1_000_000.0;
        let num_samples = (self.duration * sample_rate) as usize;
        let mut chirp = Vec::with_capacity(num_samples);
        let bandwidth = self.stop_freq - self.start_freq;
        let k = bandwidth / self.duration;
        for i in 0..num_samples {
            let t = i as f64 / sample_rate;
            let phase = 2.0 * std::f64::consts::PI * (self.start_freq * t + 0.5 * k * t * t);
            chirp.push(Complex64::new(phase.cos(), phase.sin()));
        }
        chirp
    }
}
