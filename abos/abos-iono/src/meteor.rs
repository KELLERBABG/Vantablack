pub fn detect_meteor_burst(snr_history: &[f64]) -> bool {
    if snr_history.len() < 3 {
        return false;
    }
    let window = &snr_history[snr_history.len() - 3..];
    let mean = window.iter().sum::<f64>() / window.len() as f64;
    let burst_threshold = mean + 10.0;
    window.last().copied().unwrap_or(0.0) > burst_threshold
}
