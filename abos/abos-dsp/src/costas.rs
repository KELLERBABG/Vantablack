use num_complex::Complex64;

pub struct CostasLoop {
    pub phase: f64,
    pub frequency: f64,
    pub alpha: f64,
    pub beta: f64,
}

impl CostasLoop {
    pub fn new(loop_bw: f64) -> Self {
        let denom = 1.0 + 2.0 * loop_bw + loop_bw * loop_bw;
        let alpha = (4.0 * loop_bw) / denom;
        let beta = (4.0 * loop_bw * loop_bw) / denom;
        Self {
            phase: 0.0,
            frequency: 0.0,
            alpha,
            beta,
        }
    }

    pub fn process(&mut self, sample: Complex64) -> Complex64 {
        let nco = Complex64::new(self.phase.cos(), -self.phase.sin());
        let mixed = sample * nco;
        let error = phase_detector_qpsk(mixed);
        self.frequency += self.beta * error;
        self.phase += self.frequency + self.alpha * error;
        if self.phase >= 2.0 * std::f64::consts::PI {
            self.phase -= 2.0 * std::f64::consts::PI;
        }
        if self.phase < 0.0 {
            self.phase += 2.0 * std::f64::consts::PI;
        }
        mixed
    }
}

fn phase_detector_qpsk(sample: Complex64) -> f64 {
    let hard_re = if sample.re >= 0.0 { 1.0 } else { -1.0 };
    let hard_im = if sample.im >= 0.0 { 1.0 } else { -1.0 };
    sample.re * hard_im - sample.im * hard_re
}
