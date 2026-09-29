use num_complex::Complex64;
use rustfft::{num_complex::Complex, FftPlanner};

pub struct SpectrumScanner {
    pub fft_size: usize,
    fft: std::sync::Arc<dyn rustfft::Fft<f64>>,
}

impl SpectrumScanner {
    pub fn new(fft_size: usize) -> Self {
        let mut planner = FftPlanner::new();
        let fft = planner.plan_fft_forward(fft_size);
        Self { fft_size, fft }
    }

    pub fn scan(&mut self, samples: &[Complex64]) -> Vec<f64> {
        let n = samples.len().min(self.fft_size);
        let mut buffer: Vec<Complex<f64>> = samples[..n]
            .iter()
            .map(|s| Complex::new(s.re, s.im))
            .collect();
        buffer.resize(self.fft_size, Complex::new(0.0, 0.0));
        self.fft.process(&mut buffer);
        buffer.iter().map(|c| c.norm_sqr()).collect()
    }
}
