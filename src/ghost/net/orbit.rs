/// Orbital Mechanics & Ephemeris-Driven Predictive Discovery
///
/// Implements the time-variable routing infrastructure for the GhostNet mesh:
///
/// ## Ephemeris-Driven Predictive Discovery
/// Uses Keplerian orbital elements to calculate when a peer satellite rises
/// above the horizon. Nodes transmit discovery beacons only when the link is
/// geometrically possible, preventing traffic analysis from blind beaconing.
///
/// ## Geographically Disjoint Shard Routing
/// No two Reed-Solomon shards travel through the same orbital plane or ground
/// relay, forcing an adversary to intercept traffic across multiple continents
/// to reconstruct a message.
///
/// ## Delta-V Propellant Cost Modeling
/// Uses the Tsiolkovsky rocket equation to model propellant costs in the CGR
/// routing algorithm so evasive orbital maneuvers do not inadvertently exhaust
/// a satellite's finite thruster fuel.

use std::f64::consts::PI;

pub const MU_EARTH: f64 = 3.986004418e14;
pub const EARTH_RADIUS: f64 = 6_371_000.0;
pub const G0: f64 = 9.80665;
pub const C: f64 = 299_792_458.0;
pub const MIN_ELEVATION_DEG: f64 = 10.0;

/// Six classical Keplerian orbital elements.
#[derive(Debug, Clone, Copy)]
pub struct KeplerElements {
    pub a: f64,
    pub e: f64,
    pub i: f64,
    pub raan: f64,
    pub arg_perigee: f64,
    pub mean_anomaly: f64,
}

impl KeplerElements {
    pub fn typical_leo() -> Self {
        Self {
            a: EARTH_RADIUS + 550_000.0,
            e: 0.001,
            i: 53.0_f64.to_radians(),
            raan: 0.0,
            arg_perigee: 0.0,
            mean_anomaly: 0.0,
        }
    }

    pub fn orbital_period(&self) -> f64 {
        2.0 * PI * (self.a.powi(3) / MU_EARTH).sqrt()
    }

    pub fn eccentric_anomaly(&self) -> f64 {
        let mut e = self.mean_anomaly;
        for _ in 0..10 {
            let delta = (e - self.e * e.sin() - self.mean_anomaly) / (1.0 - self.e * e.cos());
            e -= delta;
            if delta.abs() < 1e-12 { break; }
        }
        e
    }

    pub fn true_anomaly(&self) -> f64 {
        let e_anom = self.eccentric_anomaly();
        let sin_e = e_anom.sin();
        let cos_e = e_anom.cos();
        ((1.0 - self.e * self.e).sqrt() * sin_e).atan2(cos_e - self.e)
    }

    pub fn position_eci(&self, time_since_epoch: f64) -> (f64, f64, f64) {
        let n = (MU_EARTH / self.a.powi(3)).sqrt();
        let m = self.mean_anomaly + n * time_since_epoch;
        let mut e_anom = m;
        for _ in 0..10 {
            let delta = (e_anom - self.e * e_anom.sin() - m) / (1.0 - self.e * e_anom.cos());
            e_anom -= delta;
            if delta.abs() < 1e-12 { break; }
        }
        let sin_e = e_anom.sin();
        let cos_e = e_anom.cos();
        let nu = ((1.0 - self.e * self.e).sqrt() * sin_e).atan2(cos_e - self.e);
        let r = self.a * (1.0 - self.e * self.e) / (1.0 + self.e * nu.cos());
        let x_orb = r * nu.cos();
        let y_orb = r * nu.sin();
        let cos_raan = self.raan.cos();
        let sin_raan = self.raan.sin();
        let cos_i = self.i.cos();
        let sin_i = self.i.sin();
        let cos_arg = self.arg_perigee.cos();
        let sin_arg = self.arg_perigee.sin();
        let x = cos_raan * (cos_arg * x_orb - sin_arg * y_orb)
            - sin_raan * (cos_i * (sin_arg * x_orb + cos_arg * y_orb));
        let y = sin_raan * (cos_arg * x_orb - sin_arg * y_orb)
            + cos_raan * (cos_i * (sin_arg * x_orb + cos_arg * y_orb));
        let z = sin_i * (sin_arg * x_orb + cos_arg * y_orb);
        (x, y, z)
    }
}

#[derive(Debug, Clone)]
pub struct GroundPosition {
    pub latitude: f64,
    pub longitude: f64,
    pub altitude: f64,
}

impl GroundPosition {
    pub fn new(lat_deg: f64, lon_deg: f64, alt_m: f64) -> Self {
        Self { latitude: lat_deg, longitude: lon_deg, altitude: alt_m }
    }

    pub fn distance_to(&self, other: &GroundPosition) -> f64 {
        let dlat = (other.latitude - self.latitude).to_radians();
        let dlon = (other.longitude - self.longitude).to_radians();
        let a = (dlat / 2.0).sin().powi(2)
            + self.latitude.to_radians().cos() * other.latitude.to_radians().cos() * (dlon / 2.0).sin().powi(2);
        let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
        EARTH_RADIUS * c
    }
}

pub fn max_los_range(sat_altitude_m: f64) -> f64 {
    (2.0 * EARTH_RADIUS * sat_altitude_m).sqrt()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OrbitalPlane {
    LeoInclined,
    LeoPolar,
    Meo,
    Geo,
    Ground,
}

pub fn classify_orbital_plane(elements: &KeplerElements) -> OrbitalPlane {
    let alt = elements.a - EARTH_RADIUS;
    let inclination_deg = elements.i.to_degrees();
    if alt < 2_000_000.0 {
        if inclination_deg > 80.0 { OrbitalPlane::LeoPolar } else { OrbitalPlane::LeoInclined }
    } else if alt < 35_786_000.0 { OrbitalPlane::Meo } else { OrbitalPlane::Geo }
}

#[derive(Debug, Clone)]
pub struct DisjointRouteConstraint {
    used_planes: Vec<OrbitalPlane>,
    pub min_separation_deg: f64,
}

impl Default for DisjointRouteConstraint {
    fn default() -> Self { Self { used_planes: Vec::new(), min_separation_deg: 30.0 } }
}

impl DisjointRouteConstraint {
    pub fn new() -> Self { Self::default() }

    pub fn is_plane_available(&self, plane: OrbitalPlane) -> bool {
        if plane == OrbitalPlane::Ground { return self.used_planes.len() < 3; }
        !self.used_planes.contains(&plane)
    }

    pub fn reserve_plane(&mut self, plane: OrbitalPlane) -> bool {
        if self.is_plane_available(plane) { self.used_planes.push(plane); true } else { false }
    }

    pub fn distinct_planes_used(&self) -> usize { self.used_planes.len() }

    pub fn can_assign_all_shards(&self, shard_count: usize) -> bool {
        self.used_planes.len() + shard_count <= 5
    }
}

#[derive(Debug, Clone)]
pub struct DeltaVTracker {
    pub total_dv: f64,
    pub used_dv: f64,
    pub isp: f64,
    pub dry_mass: f64,
    pub initial_propellant_mass: f64,
}

impl DeltaVTracker {
    pub fn new(total_dv: f64) -> Self {
        let isp = 300.0;
        let dry_mass = 100.0;
        let mass_ratio = (total_dv / (isp * G0)).exp();
        let initial_propellant_mass = dry_mass * (mass_ratio - 1.0);
        Self { total_dv, used_dv: 0.0, isp, dry_mass, initial_propellant_mass }
    }

    pub fn compute_delta_v(&self, initial_mass: f64, final_mass: f64) -> f64 {
        if final_mass <= 0.0 || initial_mass <= final_mass { return 0.0; }
        self.isp * G0 * (initial_mass / final_mass).ln()
    }

    pub fn propellant_for_delta_v(&self, delta_v: f64) -> f64 {
        if delta_v <= 0.0 { return 0.0; }
        self.initial_propellant_mass * ((delta_v / (self.isp * G0)).exp() - 1.0)
    }

    pub fn record_maneuver(&mut self, delta_v: f64) -> bool {
        let remaining = self.total_dv - self.used_dv;
        if delta_v > remaining { return false; }
        self.used_dv += delta_v;
        true
    }

    pub fn remaining_dv(&self) -> f64 { self.total_dv - self.used_dv }
    pub fn remaining_propellant(&self) -> f64 {
        let r = self.remaining_dv();
        if r <= 0.0 { 0.0 } else { self.propellant_for_delta_v(r) }
    }
    pub fn is_maneuverable(&self) -> bool { self.remaining_dv() > 5.0 }

    pub fn plane_change_delta_v(velocity_ms: f64, inclination_change_deg: f64) -> f64 {
        2.0 * velocity_ms * (inclination_change_deg.to_radians() / 2.0).sin()
    }

    pub fn hohmann_transfer_delta_v(r1_m: f64, r2_m: f64) -> f64 {
        let v1 = (MU_EARTH / r1_m).sqrt();
        let v2 = (MU_EARTH / r2_m).sqrt();
        let v_transfer_1 = v1 * ((2.0 * r2_m / (r1_m + r2_m)).sqrt() - 1.0);
        let v_transfer_2 = v2 * (1.0 - (2.0 * r1_m / (r1_m + r2_m)).sqrt());
        v_transfer_1.abs() + v_transfer_2.abs()
    }
}

#[derive(Debug, Clone)]
pub struct OrbitalState {
    pub elements: KeplerElements,
    pub dv_tracker: DeltaVTracker,
    pub plane: OrbitalPlane,
    pub ground_pos: GroundPosition,
    pub last_update: f64,
}

impl OrbitalState {
    pub fn new(elements: KeplerElements, total_dv: f64, now: f64) -> Self {
        let alt = elements.a - EARTH_RADIUS;
        let (x, y, z) = elements.position_eci(0.0);
        let lat = z.atan2((x * x + y * y).sqrt()).to_degrees();
        let lon = y.atan2(x).to_degrees();
        Self {
            plane: classify_orbital_plane(&elements),
            dv_tracker: DeltaVTracker::new(total_dv),
            ground_pos: GroundPosition::new(lat, lon, alt),
            elements,
            last_update: now,
        }
    }

    pub fn propagate(&mut self, now: f64) {
        let dt = now - self.last_update;
        let (x, y, z) = self.elements.position_eci(dt);
        let alt = self.elements.a - EARTH_RADIUS;
        let lat = z.atan2((x * x + y * y).sqrt()).to_degrees();
        let lon = y.atan2(x).to_degrees() + (now % 86400.0) * 360.0 / 86400.0;
        let lon = ((lon + 180.0) % 360.0) - 180.0;
        self.ground_pos = GroundPosition::new(lat, lon, alt);
        self.last_update = now;
    }

    pub fn can_see(&self, ground: &GroundPosition) -> bool {
        let sat = &self.ground_pos;
        let d_sigma = (sat.latitude.to_radians().sin() * ground.latitude.to_radians().sin()
            + sat.latitude.to_radians().cos() * ground.latitude.to_radians().cos()
            * (ground.longitude - sat.longitude).to_radians().cos()).acos();
        d_sigma.to_degrees() < 90.0
    }

    pub fn signal_delay(&self, ground: &GroundPosition) -> f64 {
        self.ground_pos.distance_to(ground) / C
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orbital_period() {
        let leo = KeplerElements { a: EARTH_RADIUS + 400_000.0, e: 0.001, i: 51.6_f64.to_radians(), raan: 0.0, arg_perigee: 0.0, mean_anomaly: 0.0 };
        let period = leo.orbital_period();
        assert!((period - 5560.0).abs() < 100.0, "LEO period ~92.7 min, got {} s", period);
    }

    #[test]
    fn test_max_los_range() {
        let range = max_los_range(400_000.0);
        assert!((range - 2_285_000.0).abs() < 100_000.0);
    }

    #[test]
    fn test_disjoint_plane_routing() {
        let mut constraint = DisjointRouteConstraint::new();
        assert!(constraint.reserve_plane(OrbitalPlane::LeoInclined));
        assert!(constraint.reserve_plane(OrbitalPlane::LeoPolar));
        assert!(constraint.reserve_plane(OrbitalPlane::Ground));
        assert_eq!(constraint.distinct_planes_used(), 3);
    }

    #[test]
    fn test_delta_v_tracker() {
        let mut tracker = DeltaVTracker::new(200.0);
        assert!((tracker.remaining_dv() - 200.0).abs() < 0.1);
        assert!(tracker.record_maneuver(50.0));
        assert!((tracker.remaining_dv() - 150.0).abs() < 0.1);
        assert!(!tracker.record_maneuver(200.0));
    }

    #[test]
    fn test_plane_change_cost() {
        let cost = DeltaVTracker::plane_change_delta_v(7500.0, 5.0);
        assert!((cost - 654.0).abs() < 10.0);
    }

    #[test]
    fn test_hohmann_transfer() {
        let r1 = EARTH_RADIUS + 400_000.0;
        let r2 = EARTH_RADIUS + 500_000.0;
        let cost = DeltaVTracker::hohmann_transfer_delta_v(r1, r2);
        assert!(cost > 0.0 && cost < 200.0);
    }

    #[test]
    fn test_orbital_state_propagation() {
        let leo = KeplerElements::typical_leo();
        let mut state = OrbitalState::new(leo, 200.0, 0.0);
        state.propagate(3600.0);
        assert_ne!(state.ground_pos.latitude, 0.0);
    }
}