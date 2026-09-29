use num_complex::Complex64;

pub struct RRCFilter {
    pub taps: Vec<f64>,
    pub state_re: Vec<f64>,
    pub state_im: Vec<f64>,
}

impl RRCFilter {
    pub fn new(samples_per_symbol: usize, alpha: f64, num_taps: usize) -> Self {
        let half_len = num_taps / 2;
        let mut taps = Vec::with_capacity(num_taps);
        for i in 0..num_taps {
            let t = (i as f64) - half_len as f64;
            let tap = rrc_tap(t, samples_per_symbol, alpha);
            taps.push(tap);
        }
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

pub fn rrc_tap(t: f64, samples_per_symbol: usize, alpha: f64) -> f64 {
    if t.abs() < 1e-12 {
        let num = 1.0 - alpha + 4.0 * alpha / std::f64::consts::PI;
        return num / (samples_per_symbol as f64);
    }
    let t_sps = t / (samples_per_symbol as f64);
    let num = (std::f64::consts::PI * t_sps * (1.0 - alpha)).sin()
        + 4.0 * alpha * t_sps * (std::f64::consts::PI * t_sps * (1.0 + alpha)).cos();
    let den = std::f64::consts::PI * t_sps * (1.0 - (4.0 * alpha * t_sps).powi(2));
    if den.abs() < 1e-12 {
        return 0.0;
    }
    num / den
}
