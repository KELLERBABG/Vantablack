use num_complex::Complex64;

pub struct AGC {
    pub target_power: f64,
    pub gain: f64,
    pub alpha: f64,
}

impl AGC {
    pub fn new(target_power: f64, gain: f64, alpha: f64) -> Self {
        Self {
            target_power,
            gain,
            alpha,
        }
    }

    pub fn process(&mut self, samples: &[Complex64]) -> Vec<Complex64> {
        let mut result = Vec::with_capacity(samples.len());
        for &sample in samples {
            let power = sample.norm_sqr();
            let error = self.target_power - power;
            self.gain += self.alpha * error;
            if self.gain < 0.0 {
                self.gain = 0.0;
            }
            let scale = self.gain.sqrt();
            result.push(Complex64::new(sample.re * scale, sample.im * scale));
        }
        result
    }
}

impl Default for AGC {
    fn default() -> Self {
        Self {
            target_power: 1.0,
            gain: 1.0,
            alpha: 0.01,
        }
    }
}
