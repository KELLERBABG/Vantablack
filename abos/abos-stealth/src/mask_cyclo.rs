use num_complex::Complex64;

pub fn add_variable_symbol_rate(symbols: &[Complex64], dither: f64) -> Vec<Complex64> {
    let mut output = Vec::with_capacity(symbols.len());
    let mut phase = 0.0_f64;
    for &sym in symbols {
        phase += dither * std::f64::consts::PI * 2.0;
        let rotated = Complex64::new(
            sym.re * phase.cos() - sym.im * phase.sin(),
            sym.re * phase.sin() + sym.im * phase.cos(),
        );
        output.push(rotated);
    }
    output
}
