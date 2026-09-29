pub fn detect_jammer(power_spectrum: &[f64], threshold: f64) -> Vec<usize> {
    power_spectrum
        .iter()
        .enumerate()
        .filter_map(|(i, &p)| if p > threshold { Some(i) } else { None })
        .collect()
}
