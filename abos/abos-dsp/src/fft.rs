use num_complex::Complex64;
use rustfft::FftPlanner;

pub fn fft(samples: &[Complex64]) -> Vec<Complex64> {
    let n = samples.len();
    let mut planner = FftPlanner::<f64>::new();
    let fft_forward = planner.plan_fft_forward(n);
    let mut buffer = samples.to_vec();
    fft_forward.process(&mut buffer);
    buffer
}

pub fn ifft(samples: &[Complex64]) -> Vec<Complex64> {
    let n = samples.len();
    let mut planner = FftPlanner::<f64>::new();
    let fft_inverse = planner.plan_fft_inverse(n);
    let mut buffer = samples.to_vec();
    fft_inverse.process(&mut buffer);
    let inv_n = 1.0 / n as f64;
    for v in buffer.iter_mut() {
        *v *= inv_n;
    }
    buffer
}
