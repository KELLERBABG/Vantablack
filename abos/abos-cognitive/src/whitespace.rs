pub fn find_white_space(power_spectrum: &[f64], noise_floor: f64) -> Vec<(usize, usize)> {
    let mut regions = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &power) in power_spectrum.iter().enumerate() {
        if power <= noise_floor {
            if start.is_none() {
                start = Some(i);
            }
        } else {
            if let Some(s) = start.take() {
                if i - s > 1 {
                    regions.push((s, i - 1));
                }
            }
        }
    }
    if let Some(s) = start {
        regions.push((s, power_spectrum.len() - 1));
    }
    regions
}
