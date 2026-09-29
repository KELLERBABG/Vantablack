pub fn select_nvis_frequency(fo_f2: f64, time_of_day: f64) -> f64 {
    let diurnal_factor = if (6.0..=18.0).contains(&time_of_day) {
        0.85
    } else {
        0.70
    };
    fo_f2 * diurnal_factor
}
