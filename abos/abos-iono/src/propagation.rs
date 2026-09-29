pub fn predict_muf(fo_f2: f64, distance_km: f64) -> f64 {
    let earth_radius = 6371.0;
    let theta = distance_km / earth_radius;
    let muf_factor = 1.0 / (theta * 0.5).cos();
    fo_f2 * muf_factor.max(1.0)
}
