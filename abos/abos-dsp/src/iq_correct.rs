use num_complex::Complex64;

pub struct IQCorrect {
    pub phase: f64,
    pub amp: f64,
}

impl IQCorrect {
    pub fn new() -> Self {
        Self {
            phase: 0.0,
            amp: 0.0,
        }
    }

    pub fn process(&mut self, samples: &[Complex64]) -> Vec<Complex64> {
        let mut result = Vec::with_capacity(samples.len());
        for &sample in samples {
            let i = sample.re;
            let q = sample.im;
            let correction_i = i;
            let correction_q = (q - self.phase * i) / (1.0 + self.amp);
            result.push(Complex64::new(correction_i, correction_q));
        }
        result
    }
}

impl Default for IQCorrect {
    fn default() -> Self {
        Self::new()
    }
}
