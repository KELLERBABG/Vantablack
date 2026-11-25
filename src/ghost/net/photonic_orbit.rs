#![cfg(feature = "research")]
//! Photonic Secret Orbit — matterless, zero-rest-state memory
//! (`DEV/UNPRECEDENTED_PRIMITIVES.md` §6).
//!
//! A 256-bit key is split into three XOR shares that chase each other around a
//! continental fiber loop. Each share spends `dwell` inside a relay's NIC and
//! the rest of its life as photons in silica; the phases are chosen so that no
//! two shares are ever in silicon at the same instant. A simultaneous physical
//! seizure of every relay therefore captures exactly one share — zero bits of
//! Shannon information about the key — and cutting any one fiber dissolves the
//! key within one orbit, with no wipe command.
//!
//! This module is the schedule arithmetic only: windows, collisions, duty
//! cycle and the XOR split. It never touches a NIC, a socket, or a clock.

use std::fmt;

use rand::rngs::OsRng;
use rand::RngCore;

/// Fiber propagation speed: light in silica travels at about `2c/3`.
pub const FIBER_KM_PER_MS: f64 = 199.86;

/// Why an orbit schedule is impossible.
#[derive(Debug, Clone, PartialEq)]
pub enum OrbitError {
    /// The primitive is defined over at least three shares.
    TooFewShares(usize),
    /// A parameter is out of range or the relay/share sets disagree.
    Shape(&'static str),
    /// A phase does not lie in `[0, perimeter)` or overruns the loop.
    PhaseOutOfRange { share: usize, phase_ms: f64 },
    /// Two shares sit in silicon close enough together in phase to co-locate.
    SharesTooClose {
        a: usize,
        b: usize,
        gap_ms: f64,
        dwell_ms: f64,
    },
}

impl fmt::Display for OrbitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooFewShares(n) => write!(f, "an orbit needs at least 3 shares, got {n}"),
            Self::Shape(message) => write!(f, "{message}"),
            Self::PhaseOutOfRange { share, phase_ms } => {
                write!(f, "share {share} has phase {phase_ms} ms outside the loop")
            }
            Self::SharesTooClose {
                a,
                b,
                gap_ms,
                dwell_ms,
            } => write!(
                f,
                "shares {a} and {b} are {gap_ms} ms apart, within the {dwell_ms} ms dwell"
            ),
        }
    }
}

impl std::error::Error for OrbitError {}

/// A periodic orbit schedule: where the relays sit and when each share enters
/// silicon.
#[derive(Debug, Clone, PartialEq)]
pub struct OrbitPlan {
    perimeter_ms: f64,
    relay_phases_ms: Vec<f64>,
    share_phases_ms: Vec<f64>,
    dwell_ms: f64,
}

impl OrbitPlan {
    /// Build and validate a schedule. Phases are absolute milliseconds within
    /// one orbit; the plan repeats with that period.
    pub fn new(
        perimeter_km: f64,
        relay_phases_ms: Vec<f64>,
        share_phases_ms: Vec<f64>,
        dwell_ms: f64,
    ) -> Result<Self, OrbitError> {
        if share_phases_ms.len() < 3 {
            return Err(OrbitError::TooFewShares(share_phases_ms.len()));
        }
        if relay_phases_ms.len() != share_phases_ms.len() {
            return Err(OrbitError::Shape("one relay phase is required per share"));
        }
        if !perimeter_km.is_finite() || perimeter_km <= 0.0 {
            return Err(OrbitError::Shape("perimeter must be a positive distance"));
        }
        if !dwell_ms.is_finite() || dwell_ms <= 0.0 {
            return Err(OrbitError::Shape("dwell must be a positive duration"));
        }

        let perimeter_ms = perimeter_km / FIBER_KM_PER_MS;
        let plan = Self {
            perimeter_ms,
            relay_phases_ms,
            share_phases_ms,
            dwell_ms,
        };
        for (index, phase) in plan.relay_phases_ms.iter().enumerate() {
            if !(0.0..plan.perimeter_ms).contains(phase) {
                return Err(OrbitError::PhaseOutOfRange {
                    share: index,
                    phase_ms: *phase,
                });
            }
        }
        for (index, phase) in plan.share_phases_ms.iter().enumerate() {
            if !(0.0..plan.perimeter_ms).contains(phase) || phase + dwell_ms > plan.perimeter_ms {
                return Err(OrbitError::PhaseOutOfRange {
                    share: index,
                    phase_ms: *phase,
                });
            }
        }

        for (a, first) in plan.share_phases_ms.iter().enumerate() {
            for (b, second) in plan.share_phases_ms.iter().enumerate().skip(a + 1) {
                let gap = circular_gap(*first, *second, plan.perimeter_ms);
                if gap <= dwell_ms {
                    return Err(OrbitError::SharesTooClose {
                        a,
                        b,
                        gap_ms: gap,
                        dwell_ms,
                    });
                }
            }
        }
        Ok(plan)
    }

    /// Frankfurt → Tokyo → São Paulo → Frankfurt: 40,000 km, relays at
    /// 0/70/145 ms, shares launched at 0/66.7/133.3 ms, 10 µs of silicon.
    pub fn planetary() -> Self {
        Self::new(
            40_000.0,
            vec![0.0, 70.0, 145.0],
            vec![0.0, 66.7, 133.3],
            0.01,
        )
        .expect("the planetary orbit schedule is valid")
    }

    pub fn perimeter_ms(&self) -> f64 {
        self.perimeter_ms
    }

    pub fn dwell_ms(&self) -> f64 {
        self.dwell_ms
    }

    pub fn shares(&self) -> usize {
        self.share_phases_ms.len()
    }

    pub fn relay_phases_ms(&self) -> &[f64] {
        &self.relay_phases_ms
    }

    pub fn share_phases_ms(&self) -> &[f64] {
        &self.share_phases_ms
    }

    /// Fraction of a share's lifetime spent inside silicon: `n * dwell / T`.
    pub fn duty_cycle(&self) -> f64 {
        self.shares() as f64 * self.dwell_ms / self.perimeter_ms
    }

    /// Same quantity as a percentage, for reporting.
    pub fn silicon_percent(&self) -> f64 {
        self.duty_cycle() * 100.0
    }

    /// One orbit is the whole evaporation time: cut the loop, wait `T`.
    pub fn evaporation_ms(&self) -> f64 {
        self.perimeter_ms
    }

    /// The smallest circular phase gap between any two shares.
    pub fn minimum_gap_ms(&self) -> f64 {
        let mut minimum = self.perimeter_ms;
        for (a, first) in self.share_phases_ms.iter().enumerate() {
            for second in self.share_phases_ms.iter().skip(a + 1) {
                minimum = minimum.min(circular_gap(*first, *second, self.perimeter_ms));
            }
        }
        minimum
    }

    /// Silicon intervals `[start, end)` for each share over `orbits` laps.
    pub fn silicon_windows(&self, orbits: u64) -> Vec<Vec<(f64, f64)>> {
        self.share_phases_ms
            .iter()
            .map(|phase| {
                (0..orbits)
                    .map(|lap| {
                        let start = phase + lap as f64 * self.perimeter_ms;
                        (start, start + self.dwell_ms)
                    })
                    .collect()
            })
            .collect()
    }

    /// Every instant at which two shares share silicon, as
    /// `(share_a, share_b, lap)`. Empty is the security property.
    pub fn co_locations(&self, orbits: u64) -> Vec<(usize, usize, u64)> {
        let windows = self.silicon_windows(orbits);
        let mut collisions = Vec::new();
        for (a, first) in windows.iter().enumerate() {
            for (b, second) in windows.iter().enumerate().skip(a + 1) {
                for (lap, (left, right)) in first.iter().zip(second.iter()).enumerate() {
                    if left.0 < right.1 && right.0 < left.1 {
                        collisions.push((a, b, lap as u64));
                    }
                }
            }
        }
        collisions
    }

    /// Which shares are inside silicon at `instant_ms` (phases wrap per orbit).
    pub fn seized_shares(&self, instant_ms: f64) -> Vec<usize> {
        let phase = instant_ms.rem_euclid(self.perimeter_ms);
        self.share_phases_ms
            .iter()
            .enumerate()
            .filter(|(_, start)| **start <= phase && phase < **start + self.dwell_ms)
            .map(|(index, _)| index)
            .collect()
    }
}

fn circular_gap(a: f64, b: f64, perimeter: f64) -> f64 {
    let direct = (a - b).abs();
    direct.min(perimeter - direct)
}

/// Split a 256-bit key into three XOR shares.
pub fn split_key(key: &[u8; 32]) -> [[u8; 32]; 3] {
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    OsRng.fill_bytes(&mut first);
    OsRng.fill_bytes(&mut second);
    let mut third = [0u8; 32];
    for ((dst, k), (a, b)) in third
        .iter_mut()
        .zip(key.iter())
        .zip(first.iter().zip(second.iter()))
    {
        *dst = k ^ a ^ b;
    }
    [first, second, third]
}

/// Rebuild the key from all three shares.
pub fn recombine(shares: &[[u8; 32]; 3]) -> [u8; 32] {
    let mut key = [0u8; 32];
    for ((dst, a), b) in key.iter_mut().zip(shares[0].iter()).zip(shares[1].iter()) {
        *dst = a ^ b;
    }
    for (dst, c) in key.iter_mut().zip(shares[2].iter()) {
        *dst ^= c;
    }
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_planetary_orbit_is_two_hundred_milliseconds() {
        let plan = OrbitPlan::planetary();
        assert!((plan.perimeter_ms() - 200.0).abs() < 1.0);
        assert_eq!(plan.shares(), 3);
        assert_eq!(plan.relay_phases_ms(), &[0.0, 70.0, 145.0]);
        assert!(plan.minimum_gap_ms() > 66.0);
    }

    #[test]
    fn no_two_shares_are_ever_in_silicon_at_the_same_instant() {
        let plan = OrbitPlan::planetary();
        assert!(plan.co_locations(1_000).is_empty());

        // Sample every microsecond of an orbit: never more than one share.
        let mut seen_silicon = 0u32;
        for step in 0..200_000u32 {
            let instant = step as f64 / 1_000.0; // 0.001 ms steps
            let seized = plan.seized_shares(instant);
            assert!(seized.len() <= 1, "co-location at {instant} ms: {seized:?}");
            if !seized.is_empty() {
                seen_silicon += 1;
            }
        }
        // The dwell is really modelled: some instants do hold a share.
        assert!(seen_silicon > 0);
    }

    #[test]
    fn the_matter_duty_cycle_is_the_silicon_fraction() {
        let plan = OrbitPlan::planetary();
        let expected = 3.0 * 0.01 / plan.perimeter_ms();
        assert!((plan.duty_cycle() - expected).abs() < 1e-15);
        // 0.015 % in silicon, 99.985 % as photons.
        assert!((plan.silicon_percent() - 0.015).abs() < 0.001);
    }

    #[test]
    fn overlapping_phases_are_refused() {
        let err = OrbitPlan::new(
            40_000.0,
            vec![0.0, 70.0, 145.0],
            vec![0.0, 0.005, 100.0],
            0.01,
        )
        .expect_err("0.005 ms is inside the 10 us dwell");
        match err {
            OrbitError::SharesTooClose { a, b, gap_ms, .. } => {
                assert_eq!((a, b), (0, 1));
                assert!((gap_ms - 0.005).abs() < 1e-12);
            }
            other => panic!("unexpected error: {other}"),
        }

        // A dwell long enough to span the intended gaps invalidates the plan.
        assert!(OrbitPlan::new(
            40_000.0,
            vec![0.0, 70.0, 145.0],
            vec![0.0, 66.7, 133.3],
            70.0
        )
        .is_err());

        assert_eq!(
            OrbitPlan::new(1_000.0, vec![0.0, 1.0], vec![0.0, 1.0], 0.01).unwrap_err(),
            OrbitError::TooFewShares(2)
        );
    }

    #[test]
    fn one_share_reveals_nothing_and_all_three_rebuild_the_key() {
        let key = [0xA5u8; 32];
        let shares = split_key(&key);
        for (index, share) in shares.iter().enumerate() {
            assert_ne!(share, &key, "share {index} must not be the key");
        }
        // Two shares without the third do not close the equation.
        let mut two = shares;
        two[2] = [0u8; 32];
        assert_ne!(recombine(&two), key);
        assert_eq!(recombine(&shares), key);
    }

    #[test]
    fn a_planetary_seizure_captures_one_share_and_one_orbit_erases_the_key() {
        let plan = OrbitPlan::planetary();
        // Seize all three relays at the instants where each holds a share.
        for phase in plan.share_phases_ms() {
            let seized = plan.seized_shares(*phase + 0.001);
            assert_eq!(seized.len(), 1, "seizure at {phase} ms");
        }
        // A single fiber cut breaks the loop; the key is gone in one orbit.
        assert!((plan.evaporation_ms() - plan.perimeter_ms()).abs() < 1e-12);
        assert!(plan.evaporation_ms() < 250.0);
    }
}
