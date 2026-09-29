use num_complex::Complex64;

pub fn real_to_iq(sample: f64) -> Complex64 {
    Complex64::new(sample, 0.0)
}

pub fn mag_squared(c: Complex64) -> f64 {
    c.norm_sqr()
}

pub fn magnitude(c: Complex64) -> f64 {
    c.norm()
}

pub fn phase(c: Complex64) -> f64 {
    c.arg()
}

pub fn rotate(c: Complex64, phase_rad: f64) -> Complex64 {
    c * Complex64::from_polar(1.0, phase_rad)
}

pub fn mix(a: Complex64, b: Complex64) -> Complex64 {
    a * b
}

/// Convert a byte to QPSK constellation point (gray-coded)
pub fn byte_to_qpsk(b: u8) -> Complex64 {
    match b & 0x03 {
        0 => Complex64::new(1.0, 1.0),   // 00
        1 => Complex64::new(-1.0, 1.0),  // 01
        2 => Complex64::new(-1.0, -1.0), // 11
        3 => Complex64::new(1.0, -1.0),  // 10
        _ => unreachable!(),
    }
}

/// Convert QPSK constellation point to bits
/// Mapping: (1,1)→00, (-1,1)→01, (-1,-1)→11, (1,-1)→10
pub fn qpsk_to_bits(sym: Complex64) -> u8 {
    let re = if sym.re >= 0.0 { 0 } else { 1 };
    let im = if sym.im >= 0.0 { 0 } else { 1 };
    (re << 1) | im
}
