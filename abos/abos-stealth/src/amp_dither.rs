use num_complex::Complex64;
use rand::Rng;

pub struct AmpDither {
    pub deviation: f64,
    rng: rand::rngs::ThreadRng,
}

impl AmpDither {
    pub fn new(deviation: f64) -> Self {
        Self {
            deviation,
            rng: rand::thread_rng(),
        }
    }

    pub fn apply_dither(&mut self, samples: &[Complex64]) -> Vec<Complex64> {
        samples
            .iter()
            .map(|&s| {
                let scale = 1.0 + (self.rng.gen::<f64>() - 0.5) * 2.0 * self.deviation;
                Complex64::new(s.re * scale, s.im * scale)
            })
            .collect()
    }
}
