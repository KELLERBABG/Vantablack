#![cfg(feature = "research")]
//! Sovereign Cloud — topology-enforced jurisdiction, proved by light cones.
//!
//! A mesh-native cloud fabric where user devices form the storage and compute
//! layer with zero central provider or cloud accounts.
//!
//! # Why a declared `JurisdictionTag` is not evidence
//!
//! The first version of this module filtered placements on a `jurisdiction`
//! field the device supplied about itself. Every threat the field exists for —
//! a provider in Virginia claiming `Ch`, a BGP hijack, a spoofed GeoIP record —
//! can write that field. This version replaces the declaration with
//! [`LightConeProof`] (Invention 5): ≥3 verifier anchors at known coordinates
//! challenge the node with an unpredictable nonce and measure the round trip.
//! Nothing can answer faster than light, so the node's true position must lie in
//! the intersection of the anchors' light cones. The proof carries only
//! coordinates and RTTs, and [`LightConeProof::verify`] recomputes that
//! intersection, then checks that the whole certified region falls inside the
//! jurisdiction perimeter.
//!
//! Honest boundary: the proof is evidence about **where the signing key is**, not
//! a hardware attestation. An adversary who copies the key into the jurisdiction
//! defeats it unless the key is non-exportable (`hardware-tpm`). The
//! [`CausalHopWitness`] reports `KeyDisjoint` versus `PhysicallyDisjoint` for
//! exactly that reason instead of calling both "separated".

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Mean Earth radius (IUGG), kilometres.
pub const EARTH_RADIUS_KM: f64 = 6371.0088;

/// Light in silica fibre: 204,000 km/s, i.e. 204 km/ms.
pub const FIBRE_KM_PER_MS: f64 = 204.0;

/// Slack added to every cone for scheduling, serialisation and timestamping.
///
/// The physical bound is a floor on RTT; a measurement above it is always
/// possible (queues, interrupts), so the cone radius is the *lower* bound plus a
/// margin. The margin widens the certified region, which is the conservative
/// direction for a jurisdiction check.
pub const LIGHTCONE_SLACK_KM: f64 = 25.0;

/// Anchors whose cones must agree before a proof is evidence.
pub const MIN_ANCHORS: usize = 3;

/// A proof older than this is not evidence of where the node is *now*.
pub const PROOF_MAX_AGE_SECS: u64 = 300;

/// Legal / geographic jurisdiction perimeters for data sovereignty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JurisdictionTag {
    Any,
    Eu,
    Us,
    Ch, // Switzerland
    Apac,
}

/// A latitude/longitude rectangle. Deliberately coarse: a jurisdiction is a
/// legal perimeter, and the proof only has to be contained in it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct JurisdictionRegion {
    pub min_lat: f64,
    pub max_lat: f64,
    pub min_lon: f64,
    pub max_lon: f64,
}

impl JurisdictionRegion {
    /// Conservative containment: the disc's bounding box must fit inside the
    /// region. A disc that crosses the perimeter is refused even if its centre
    /// is inside, because the key could be on the wrong side of the border.
    pub fn contains_disc(&self, center: GeoPoint, radius_km: f64) -> bool {
        let lat_delta = radius_km / 111.32;
        let lon_scale = center.lat_deg.to_radians().cos().abs().max(0.01);
        let lon_delta = lat_delta / lon_scale;
        let (south, north) = (center.lat_deg - lat_delta, center.lat_deg + lat_delta);
        let (west, east) = (center.lon_deg - lon_delta, center.lon_deg + lon_delta);
        // Dateline-crossing regions are not modelled; refuse rather than guess.
        if east > 180.0 || west < -180.0 {
            return false;
        }
        south >= self.min_lat
            && north <= self.max_lat
            && west >= self.min_lon
            && east <= self.max_lon
    }
}

impl JurisdictionTag {
    /// The perimeter this tag stands for. `None` means "no restriction".
    pub fn region(self) -> Option<JurisdictionRegion> {
        match self {
            JurisdictionTag::Any => None,
            JurisdictionTag::Eu => Some(JurisdictionRegion {
                min_lat: 34.0,
                max_lat: 72.0,
                min_lon: -25.0,
                max_lon: 45.0,
            }),
            JurisdictionTag::Us => Some(JurisdictionRegion {
                min_lat: 24.0,
                max_lat: 49.5,
                min_lon: -125.0,
                max_lon: -66.0,
            }),
            JurisdictionTag::Ch => Some(JurisdictionRegion {
                min_lat: 45.8,
                max_lat: 47.9,
                min_lon: 5.9,
                max_lon: 10.5,
            }),
            JurisdictionTag::Apac => Some(JurisdictionRegion {
                min_lat: -50.0,
                max_lat: 50.0,
                min_lon: 95.0,
                max_lon: 180.0,
            }),
        }
    }
}

/// A point on the Earth's surface.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct GeoPoint {
    pub lat_deg: f64,
    pub lon_deg: f64,
}

impl GeoPoint {
    /// Construct a point, refusing coordinates that are not on the globe.
    pub fn new(lat_deg: f64, lon_deg: f64) -> Result<Self, LightConeError> {
        if !lat_deg.is_finite() || !(-90.0..=90.0).contains(&lat_deg) {
            return Err(LightConeError::BadCoordinate(format!("latitude {lat_deg}")));
        }
        if !lon_deg.is_finite() || !(-180.0..=180.0).contains(&lon_deg) {
            return Err(LightConeError::BadCoordinate(format!(
                "longitude {lon_deg}"
            )));
        }
        Ok(Self { lat_deg, lon_deg })
    }

    /// Great-circle distance (haversine), kilometres.
    pub fn distance_km(&self, other: &GeoPoint) -> f64 {
        let rad = std::f64::consts::PI / 180.0;
        let dlat = (other.lat_deg - self.lat_deg) * rad;
        let dlon = (other.lon_deg - self.lon_deg) * rad;
        let a = (dlat / 2.0).sin().powi(2)
            + self.lat_deg.to_radians().cos()
                * other.lat_deg.to_radians().cos()
                * (dlon / 2.0).sin().powi(2);
        2.0 * EARTH_RADIUS_KM * a.sqrt().atan2((1.0 - a).max(0.0).sqrt())
    }
}

/// A verifier anchor at a known surface position.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LightConeAnchor {
    pub anchor_id: String,
    pub at: GeoPoint,
}

/// One anchor's measurement of the candidate's round trip.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnchorMeasurement {
    pub anchor_id: String,
    /// Measured round-trip time in milliseconds. Below `2·d/c` for the claimed
    /// position is physically impossible and refuses the proof.
    pub rtt_ms: f64,
}

/// Physics evidence for where a signing key sits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LightConeProof {
    pub subject: String,
    /// The position the subject claims, in coordinates.
    pub center: GeoPoint,
    pub measurements: Vec<AnchorMeasurement>,
    pub issued_at: u64,
}

/// What a successful verification established.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LightConeVerification {
    /// Radius that certainly contains the signing key, from the cone
    /// intersection (planar approximation around `center`).
    pub certified_radius_km: f64,
    pub anchors: usize,
}

/// Why a proof is not evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LightConeError {
    TooFewAnchors(usize),
    UnknownAnchor(String),
    DuplicateAnchor(String),
    InvalidRtt(String),
    Stale(u64),
    BadCoordinate(String),
    /// The claimed position is farther from an anchor than the measured RTT
    /// permits — the measurement contradicts the claim.
    DistanceExceedsCone {
        anchor: String,
        distance_km: u64,
        allowed_km: u64,
    },
    /// The certified region is not wholly inside the required perimeter.
    RegionLeavesJurisdiction,
    /// Two hops' certified regions intersect, so one machine could be both.
    RegionsOverlap,
    NoAnchorsConfigured,
}

impl std::fmt::Display for LightConeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LightConeError::TooFewAnchors(n) => {
                write!(
                    f,
                    "light-cone proof has {n} anchors, {MIN_ANCHORS} required"
                )
            }
            LightConeError::UnknownAnchor(id) => write!(f, "anchor {id:?} is not configured"),
            LightConeError::DuplicateAnchor(id) => write!(f, "anchor {id:?} measured twice"),
            LightConeError::InvalidRtt(id) => write!(f, "anchor {id:?} reported an invalid RTT"),
            LightConeError::Stale(age) => {
                write!(f, "proof is {age}s old, horizon {PROOF_MAX_AGE_SECS}s")
            }
            LightConeError::BadCoordinate(what) => write!(f, "invalid coordinate: {what}"),
            LightConeError::DistanceExceedsCone {
                anchor,
                distance_km,
                allowed_km,
            } => write!(
                f,
                "claim is {distance_km} km from {anchor} but the RTT allows only {allowed_km} km"
            ),
            LightConeError::RegionLeavesJurisdiction => {
                write!(f, "certified region leaves the required jurisdiction")
            }
            LightConeError::RegionsOverlap => {
                write!(f, "two hops certify overlapping regions")
            }
            LightConeError::NoAnchorsConfigured => write!(f, "no light-cone anchors configured"),
        }
    }
}

impl std::error::Error for LightConeError {}

/// Project a nearby point into kilometres on a plane tangent at `origin`.
fn local_xy(origin: GeoPoint, p: GeoPoint) -> (f64, f64) {
    let rad = std::f64::consts::PI / 180.0;
    let x =
        (p.lon_deg - origin.lon_deg) * rad * origin.lat_deg.to_radians().cos() * EARTH_RADIUS_KM;
    let y = (p.lat_deg - origin.lat_deg) * rad * EARTH_RADIUS_KM;
    (x, y)
}

/// Intersection points of two circles in the tangent plane.
fn circle_intersections(
    (x1, y1, r1): (f64, f64, f64),
    (x2, y2, r2): (f64, f64, f64),
) -> Vec<(f64, f64)> {
    let dx = x2 - x1;
    let dy = y2 - y1;
    let d = dx.hypot(dy);
    if d <= f64::EPSILON || d > r1 + r2 || d < (r1 - r2).abs() {
        return Vec::new();
    }
    let a = (r1 * r1 - r2 * r2 + d * d) / (2.0 * d);
    let h_sq = r1 * r1 - a * a;
    if h_sq < 0.0 {
        return Vec::new();
    }
    let h = h_sq.sqrt();
    let xm = x1 + a * dx / d;
    let ym = y1 + a * dy / d;
    let rx = -dy * h / d;
    let ry = dx * h / d;
    vec![(xm + rx, ym + ry), (xm - rx, ym - ry)]
}

impl LightConeProof {
    /// Area of the cone intersection that certainly contains the key.
    ///
    /// The intersection of the anchors' discs is convex and contains `center`;
    /// its farthest point from `center` is a circle-circle intersection vertex,
    /// or the far side of one disc when the discs are nested. Both are checked.
    fn certified_radius(&self, cones: &[(f64, f64, f64)]) -> f64 {
        let inside_all = |p: (f64, f64)| {
            cones
                .iter()
                .all(|(cx, cy, r)| (p.0 - cx).hypot(p.1 - cy) <= r + 1e-9)
        };
        if !inside_all((0.0, 0.0)) {
            return f64::INFINITY;
        }
        let mut farthest: f64 = 0.0;
        let mut consider = |p: (f64, f64)| {
            if inside_all(p) {
                farthest = farthest.max(p.0.hypot(p.1));
            }
        };
        for (i, a) in cones.iter().enumerate() {
            // Far side of this disc along the ray from the origin.
            let d = a.0.hypot(a.1);
            if d > f64::EPSILON {
                let scale = 1.0 + a.2 / d;
                consider((a.0 * scale, a.1 * scale));
            }
            for b in cones.iter().skip(i + 1) {
                for p in circle_intersections(*a, *b) {
                    consider(p);
                }
            }
        }
        farthest
    }

    /// Recompute the light-cone intersection and check the claims against it.
    pub fn verify(
        &self,
        anchors: &[LightConeAnchor],
        now: u64,
    ) -> Result<LightConeVerification, LightConeError> {
        if anchors.is_empty() {
            return Err(LightConeError::NoAnchorsConfigured);
        }
        let age = now.saturating_sub(self.issued_at);
        if self.issued_at > now + 60 || age > PROOF_MAX_AGE_SECS {
            return Err(LightConeError::Stale(age));
        }
        if self.measurements.len() < MIN_ANCHORS {
            return Err(LightConeError::TooFewAnchors(self.measurements.len()));
        }

        let mut seen = std::collections::HashSet::new();
        let mut cones = Vec::with_capacity(self.measurements.len());
        for measurement in &self.measurements {
            if !seen.insert(measurement.anchor_id.clone()) {
                return Err(LightConeError::DuplicateAnchor(
                    measurement.anchor_id.clone(),
                ));
            }
            let anchor = anchors
                .iter()
                .find(|a| a.anchor_id == measurement.anchor_id)
                .ok_or_else(|| LightConeError::UnknownAnchor(measurement.anchor_id.clone()))?;
            if !measurement.rtt_ms.is_finite() || measurement.rtt_ms <= 0.0 {
                return Err(LightConeError::InvalidRtt(measurement.anchor_id.clone()));
            }
            let distance = self.center.distance_km(&anchor.at);
            let allowed = FIBRE_KM_PER_MS * measurement.rtt_ms / 2.0 + LIGHTCONE_SLACK_KM;
            if distance > allowed {
                return Err(LightConeError::DistanceExceedsCone {
                    anchor: anchor.anchor_id.clone(),
                    distance_km: distance.round() as u64,
                    allowed_km: allowed.round() as u64,
                });
            }
            let (x, y) = local_xy(self.center, anchor.at);
            cones.push((x, y, allowed));
        }

        let certified_radius_km = self.certified_radius(&cones);
        if !certified_radius_km.is_finite() {
            // The claimed centre is not inside every cone: the measurements
            // contradict each other.
            return Err(LightConeError::DistanceExceedsCone {
                anchor: "intersection".to_string(),
                distance_km: 0,
                allowed_km: 0,
            });
        }
        Ok(LightConeVerification {
            certified_radius_km,
            anchors: cones.len(),
        })
    }

    /// Verify and require the whole certified region to be inside `tag`'s
    /// perimeter. This is the only way a device earns a jurisdiction claim.
    pub fn verify_in(
        &self,
        tag: JurisdictionTag,
        anchors: &[LightConeAnchor],
        now: u64,
    ) -> Result<LightConeVerification, LightConeError> {
        let verified = self.verify(anchors, now)?;
        if let Some(region) = tag.region() {
            if !region.contains_disc(self.center, verified.certified_radius_km) {
                return Err(LightConeError::RegionLeavesJurisdiction);
            }
        }
        Ok(verified)
    }
}

/// How strongly a circuit's hops are separated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HopSeparation {
    /// The hops hold distinct keys in provably disjoint regions. One machine
    /// with exportable keys can still hold all three.
    KeyDisjoint,
    /// Each hop's key is non-exportable and the regions are disjoint, so no
    /// single physical machine can be all three.
    PhysicallyDisjoint,
}

/// Three hops' Light-Cone proofs, composed for the causal-hop check (Invention 8).
#[derive(Debug, Clone)]
pub struct CausalHopWitness<'a> {
    pub hops: [&'a LightConeProof; 3],
}

impl CausalHopWitness<'_> {
    /// Verify all three proofs and require their certified regions to be
    /// pairwise disjoint.
    ///
    /// `hardware_bound` says the hop keys live in non-exportable silicon. Only
    /// then, and only in a build that can actually bind keys that way, does the
    /// witness report [`HopSeparation::PhysicallyDisjoint`]; otherwise it reports
    /// [`HopSeparation::KeyDisjoint`], which is what the evidence supports.
    pub fn classify(
        &self,
        anchors: &[LightConeAnchor],
        hardware_bound: bool,
        now: u64,
    ) -> Result<HopSeparation, LightConeError> {
        let mut regions = Vec::with_capacity(3);
        for hop in self.hops {
            let verified = hop.verify(anchors, now)?;
            regions.push((hop.center, verified.certified_radius_km));
        }
        for (i, a) in regions.iter().enumerate() {
            for b in regions.iter().skip(i + 1) {
                let apart = a.0.distance_km(&b.0);
                if apart <= a.1 + b.1 {
                    return Err(LightConeError::RegionsOverlap);
                }
            }
        }
        Ok(if hardware_bound && cfg!(feature = "hardware-tpm") {
            HopSeparation::PhysicallyDisjoint
        } else {
            HopSeparation::KeyDisjoint
        })
    }
}

/// An endpoint device participating in the sovereign cloud mesh.
#[derive(Debug, Clone, PartialEq)]
pub struct SovereignDevice {
    pub device_id: String,
    /// What the operator *declares*. Kept for reporting only; placement never
    /// trusts it — see [`SovereignDevice::attested`].
    pub jurisdiction: JurisdictionTag,
    /// Physics evidence for where this device's key is. `None` means the device
    /// has not proven anything, so it can only hold unrestricted objects.
    pub attested: Option<LightConeProof>,
    pub storage_capacity_bytes: u64,
}

impl SovereignDevice {
    /// Where the device's key provably is, or `None` when it has no proof.
    pub fn proved_jurisdiction(
        &self,
        anchors: &[LightConeAnchor],
        now: u64,
    ) -> Option<JurisdictionTag> {
        let proof = self.attested.as_ref()?;
        [
            JurisdictionTag::Eu,
            JurisdictionTag::Us,
            JurisdictionTag::Ch,
            JurisdictionTag::Apac,
        ]
        .into_iter()
        .find(|tag| proof.verify_in(*tag, anchors, now).is_ok())
    }
}

/// A stored sovereign object metadata record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SovereignObject {
    pub object_id: [u8; 32],
    pub required_jurisdiction: JurisdictionTag,
    pub assigned_devices: Vec<String>,
}

/// Sovereign Cloud Fabric coordinating multi-device storage and topological enforcement.
#[derive(Debug, Default)]
pub struct SovereignCloudFabric {
    devices: HashMap<String, SovereignDevice>,
    objects: HashMap<[u8; 32], SovereignObject>,
    anchors: Vec<LightConeAnchor>,
}

impl SovereignCloudFabric {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install the verifier anchors whose measurements this fabric will trust.
    ///
    /// Without anchors, every jurisdiction-restricted placement is refused: a
    /// declaration alone has never been evidence.
    pub fn set_anchors(&mut self, anchors: Vec<LightConeAnchor>) {
        self.anchors = anchors;
    }

    pub fn anchors(&self) -> &[LightConeAnchor] {
        &self.anchors
    }

    /// Register an owned device into the sovereign cloud fabric.
    pub fn register_device(&mut self, device: SovereignDevice) {
        self.devices.insert(device.device_id.clone(), device);
    }

    /// Devices the fabric may place `required` on right now.
    fn eligible(&self, required: JurisdictionTag, now: u64) -> Vec<&SovereignDevice> {
        self.devices
            .values()
            .filter(|device| {
                if required == JurisdictionTag::Any {
                    return true;
                }
                match &device.attested {
                    Some(proof) => proof.verify_in(required, &self.anchors, now).is_ok(),
                    None => false,
                }
            })
            .collect()
    }

    /// Store an object ensuring strict compliance with the required jurisdiction.
    /// Returns Ok(assigned_device_ids) or Err if no compliant devices are available.
    pub fn place_object(
        &mut self,
        object_id: [u8; 32],
        required_jurisdiction: JurisdictionTag,
        replication_factor: usize,
    ) -> Result<Vec<String>, &'static str> {
        self.place_object_at(
            object_id,
            required_jurisdiction,
            replication_factor,
            crate::ghost::v2::now_secs(),
        )
    }

    /// [`Self::place_object`] with the clock supplied, for tests and replay.
    pub fn place_object_at(
        &mut self,
        object_id: [u8; 32],
        required_jurisdiction: JurisdictionTag,
        replication_factor: usize,
        now: u64,
    ) -> Result<Vec<String>, &'static str> {
        let candidates: Vec<String> = self
            .eligible(required_jurisdiction, now)
            .into_iter()
            .map(|d| d.device_id.clone())
            .collect();

        if candidates.len() < replication_factor {
            return Err("insufficient light-cone-verified endpoints inside the jurisdiction");
        }

        let mut assigned = candidates;
        assigned.truncate(replication_factor);
        self.objects.insert(
            object_id,
            SovereignObject {
                object_id,
                required_jurisdiction,
                assigned_devices: assigned.clone(),
            },
        );

        Ok(assigned)
    }

    /// Verify whether all current holders of an object strictly satisfy its legal
    /// jurisdiction — re-checking their proofs, not their declarations.
    pub fn verify_object_compliance(&self, object_id: &[u8; 32]) -> bool {
        self.verify_object_compliance_at(object_id, crate::ghost::v2::now_secs())
    }

    /// [`Self::verify_object_compliance`] with the clock supplied.
    pub fn verify_object_compliance_at(&self, object_id: &[u8; 32], now: u64) -> bool {
        let Some(obj) = self.objects.get(object_id) else {
            return false;
        };
        if obj.required_jurisdiction == JurisdictionTag::Any {
            return true;
        }
        obj.assigned_devices.iter().all(|dev_id| {
            self.devices.get(dev_id).is_some_and(|device| {
                device.attested.as_ref().is_some_and(|proof| {
                    proof
                        .verify_in(obj.required_jurisdiction, &self.anchors, now)
                        .is_ok()
                })
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn point(lat: f64, lon: f64) -> GeoPoint {
        GeoPoint::new(lat, lon).expect("valid coordinate")
    }

    fn anchor(id: &str, lat: f64, lon: f64) -> LightConeAnchor {
        LightConeAnchor {
            anchor_id: id.to_string(),
            at: point(lat, lon),
        }
    }

    fn anchors() -> Vec<LightConeAnchor> {
        vec![
            anchor("berlin", 52.5200, 13.4050),
            anchor("paris", 48.8566, 2.3522),
            anchor("zurich", 47.3769, 8.5417),
        ]
    }

    /// A proof whose RTTs are exactly the physical floor for `at` plus a tiny
    /// serialisation margin, as a real measurement would be.
    fn proof_at(subject: &str, at: GeoPoint, anchors: &[LightConeAnchor]) -> LightConeProof {
        LightConeProof {
            subject: subject.to_string(),
            center: at,
            measurements: anchors
                .iter()
                .map(|a| AnchorMeasurement {
                    anchor_id: a.anchor_id.clone(),
                    rtt_ms: 2.0 * at.distance_km(&a.at) / FIBRE_KM_PER_MS + 0.2,
                })
                .collect(),
            issued_at: NOW,
        }
    }

    fn device(id: &str, declared: JurisdictionTag, proof: LightConeProof) -> SovereignDevice {
        SovereignDevice {
            device_id: id.to_string(),
            jurisdiction: declared,
            attested: Some(proof),
            storage_capacity_bytes: 1_000_000_000,
        }
    }

    #[test]
    fn a_light_cone_proof_certifies_a_position_inside_every_cone() {
        let anchors = anchors();
        let proof = proof_at("laptop_berlin", point(52.51, 13.40), &anchors);
        let verified = proof.verify(&anchors, NOW).expect("proof verifies");
        assert_eq!(verified.anchors, 3);
        assert!(
            verified.certified_radius_km < 200.0,
            "three tight cones leave a small region, got {} km",
            verified.certified_radius_km
        );
        assert!(proof.verify_in(JurisdictionTag::Eu, &anchors, NOW).is_ok());
        assert!(matches!(
            proof.verify_in(JurisdictionTag::Us, &anchors, NOW),
            Err(LightConeError::RegionLeavesJurisdiction)
        ));
    }

    #[test]
    fn a_claim_faster_than_light_is_refused() {
        let anchors = anchors();
        // Claim New York, but report Berlin-sized RTTs: physically impossible.
        let mut proof = proof_at("spoofed", point(52.51, 13.40), &anchors);
        proof.center = point(40.7128, -74.0060);
        assert!(matches!(
            proof.verify(&anchors, NOW),
            Err(LightConeError::DistanceExceedsCone { .. })
        ));
    }

    #[test]
    fn a_stale_or_thin_proof_is_not_evidence() {
        let anchors = anchors();
        let mut proof = proof_at("laptop_berlin", point(52.51, 13.40), &anchors);
        proof.issued_at = NOW - PROOF_MAX_AGE_SECS - 1;
        assert!(matches!(
            proof.verify(&anchors, NOW),
            Err(LightConeError::Stale(_))
        ));

        let mut proof = proof_at("laptop_berlin", point(52.51, 13.40), &anchors);
        proof.measurements.truncate(2);
        assert!(matches!(
            proof.verify(&anchors, NOW),
            Err(LightConeError::TooFewAnchors(2))
        ));

        // A duplicated anchor must not count as two independent cones.
        let mut proof = proof_at("laptop_berlin", point(52.51, 13.40), &anchors);
        proof.measurements[1].anchor_id = proof.measurements[0].anchor_id.clone();
        assert!(matches!(
            proof.verify(&anchors, NOW),
            Err(LightConeError::DuplicateAnchor(_))
        ));
    }

    #[test]
    fn placement_requires_a_proof_rather_than_a_declaration() {
        let anchors = anchors();
        let mut fabric = SovereignCloudFabric::new();
        fabric.set_anchors(anchors.clone());

        // This device *declares* EU but proves it is in New York. The declaration
        // must not buy it an EU placement.
        let us_anchor_rtts = proof_at("server_us", point(40.7128, -74.0060), &anchors);
        fabric.register_device(device("declared_eu", JurisdictionTag::Eu, us_anchor_rtts));
        assert!(fabric
            .place_object_at([0xAA; 32], JurisdictionTag::Eu, 1, NOW)
            .is_err());

        // An unproven device is likewise refused.
        fabric.register_device(SovereignDevice {
            device_id: "unproven".into(),
            jurisdiction: JurisdictionTag::Eu,
            attested: None,
            storage_capacity_bytes: 1,
        });
        assert!(fabric
            .place_object_at([0xBB; 32], JurisdictionTag::Eu, 1, NOW)
            .is_err());

        // A device that proves EU *and* declares it is accepted.
        fabric.register_device(device(
            "laptop_berlin",
            JurisdictionTag::Eu,
            proof_at("laptop_berlin", point(52.51, 13.40), &anchors),
        ));
        let placed = fabric
            .place_object_at([0xCC; 32], JurisdictionTag::Eu, 1, NOW)
            .expect("verified EU device qualifies");
        assert_eq!(placed, vec!["laptop_berlin".to_string()]);
        assert!(fabric.verify_object_compliance_at(&[0xCC; 32], NOW));
    }

    #[test]
    fn a_swiss_proof_cannot_hold_an_eu_object_without_being_inside_the_perimeter() {
        let anchors = anchors();
        let mut fabric = SovereignCloudFabric::new();
        fabric.set_anchors(anchors.clone());
        // Zurich is inside the EU perimeter's coarse bounding box, so use a
        // device that physically proves a US position while declaring CH.
        fabric.register_device(device(
            "liar",
            JurisdictionTag::Ch,
            proof_at("liar", point(40.7128, -74.0060), &anchors),
        ));
        assert!(fabric
            .place_object_at([0xDD; 32], JurisdictionTag::Ch, 1, NOW)
            .is_err());
        assert!(!fabric.verify_object_compliance_at(&[0xDD; 32], NOW));
    }

    #[test]
    fn a_causal_hop_witness_requires_pairwise_disjoint_cones() {
        let anchors = anchors();
        let berlin = proof_at("guard", point(52.51, 13.40), &anchors);
        let paris = proof_at("middle", point(48.85, 2.35), &anchors);
        let zurich = proof_at("exit", point(47.38, 8.54), &anchors);
        let witness = CausalHopWitness {
            hops: [&berlin, &paris, &zurich],
        };
        assert_eq!(
            witness.classify(&anchors, false, NOW),
            Ok(HopSeparation::KeyDisjoint)
        );
        // This build's test target has no `hardware-tpm`, so even an operator
        // claim of hardware binding may not upgrade the verdict.
        assert_eq!(
            witness.classify(&anchors, true, NOW),
            Ok(HopSeparation::KeyDisjoint)
        );

        // Three threads on one machine share a cone and must be refused.
        let same = proof_at("same", point(52.51, 13.40), &anchors);
        let witness = CausalHopWitness {
            hops: [&berlin, &same, &zurich],
        };
        assert_eq!(
            witness.classify(&anchors, false, NOW),
            Err(LightConeError::RegionsOverlap)
        );
    }

    #[test]
    fn a_proof_needs_configured_anchors() {
        let proof = proof_at("laptop_berlin", point(52.51, 13.40), &anchors());
        assert_eq!(
            proof.verify(&[], NOW),
            Err(LightConeError::NoAnchorsConfigured)
        );
    }
}
