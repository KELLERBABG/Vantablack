use num_complex::Complex64;

pub struct FIRFilter {
    pub taps: Vec<f64>,
    pub state_re: Vec<f64>,
    pub state_im: Vec<f64>,
}

impl FIRFilter {
    pub fn new(taps: Vec<f64>) -> Self {
        let state_len = taps.len().saturating_sub(1);
        let state_re = vec![0.0_f64; state_len];
        let state_im = vec![0.0_f64; state_len];
        Self {
            taps,
            state_re,
            state_im,
        }
    }

    pub fn process(&mut self, samples: &[Complex64]) -> Vec<Complex64> {
        let mut result = Vec::with_capacity(samples.len());
        for &sample in samples {
            let mut sum_re = sample.re * self.taps[0];
            let mut sum_im = sample.im * self.taps[0];
            for i in 0..self.state_re.len() {
                sum_re += self.state_re[i] * self.taps[i + 1];
                sum_im += self.state_im[i] * self.taps[i + 1];
            }
            for i in (1..self.state_re.len()).rev() {
                self.state_re[i] = self.state_re[i - 1];
                self.state_im[i] = self.state_im[i - 1];
            }
            if !self.state_re.is_empty() {
                self.state_re[0] = sample.re;
                self.state_im[0] = sample.im;
            }
            result.push(Complex64::new(sum_re, sum_im));
        }
        result
    }
}

pub struct Decimator {
    pub filter: FIRFilter,
    pub factor: usize,
}

impl Decimator {
    pub fn new(taps: Vec<f64>, factor: usize) -> Self {
        Self {
            filter: FIRFilter::new(taps),
            factor,
        }
    }

    pub fn process(&mut self, samples: &[Complex64]) -> Vec<Complex64> {
        let filtered = self.filter.process(samples);
        filtered.into_iter().step_by(self.factor).collect()
    }
}
