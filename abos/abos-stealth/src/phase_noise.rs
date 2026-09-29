use num_complex::Complex64;
use rand::Rng;

pub struct PhaseNoiseInjector {
    pub std_dev: f64,
    rng: rand::rngs::ThreadRng,
}

impl PhaseNoiseInjector {
    pub fn new(std_dev: f64) -> Self {
        Self {
            std_dev,
            rng: rand::thread_rng(),
        }
    }

    pub fn inject_noise(&mut self, samples: &[Complex64]) -> Vec<Complex64> {
        samples
            .iter()
            .map(|&s| {
                let phase_noise: f64 = self.rng.gen::<f64>() * self.std_dev;
                Complex64::new(
                    s.re * phase_noise.cos() - s.im * phase_noise.sin(),
                    s.re * phase_noise.sin() + s.im * phase_noise.cos(),
                )
            })
            .collect()
    }
}
