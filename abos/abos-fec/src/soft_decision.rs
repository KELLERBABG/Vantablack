use num_complex::Complex64;

/// Compute Log-Likelihood Ratios for QPSK symbols
///
/// Returns (llr_bit0, llr_bit1) where:
/// - bit0 is the real (in-phase) component decision
/// - bit1 is the imaginary (quadrature) component decision
pub fn qpsk_llr(sample: Complex64, noise_variance: f64) -> (f64, f64) {
    if noise_variance <= 0.0 {
        // Hard decision if no noise estimate
        let bit0 = if sample.re >= 0.0 { 10.0 } else { -10.0 };
        let bit1 = if sample.im >= 0.0 { 10.0 } else { -10.0 };
        return (bit0, bit1);
    }

    let inv_var = 1.0 / noise_variance;
    let llr0 = 2.0 * sample.re * inv_var;
    let llr1 = 2.0 * sample.im * inv_var;
    (llr0, llr1)
}

/// Compute LLR for BPSK symbol
pub fn bpsk_llr(sample: Complex64, noise_variance: f64) -> f64 {
    if noise_variance <= 0.0 {
        if sample.re >= 0.0 {
            10.0
        } else {
            -10.0
        }
    } else {
        2.0 * sample.re / noise_variance
    }
}

/// Compute LLR for 16-QAM symbol (Gray-coded)
/// Returns (llr_bit0, llr_bit1, llr_bit2, llr_bit3)
pub fn qam16_llr(sample: Complex64, noise_variance: f64) -> (f64, f64, f64, f64) {
    if noise_variance <= 0.0 {
        return (0.0, 0.0, 0.0, 0.0);
    }

    let inv_var = 1.0 / noise_variance;

    // Bit 0 (I-axis, sign): same as BPSK on real
    let llr0 = 2.0 * sample.re * inv_var;

    // Bit 1 (I-axis, magnitude): |re| relative to 2/sqrt(10)
    let threshold = 2.0 / (10.0f64).sqrt();
    let llr1 = 2.0 * (sample.re.abs() - threshold) * inv_var;

    // Bit 2 (Q-axis, sign)
    let llr2 = 2.0 * sample.im * inv_var;

    // Bit 3 (Q-axis, magnitude)
    let llr3 = 2.0 * (sample.im.abs() - threshold) * inv_var;

    (llr0, llr1, llr2, llr3)
}
