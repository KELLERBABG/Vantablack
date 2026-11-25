#![cfg(feature = "research")]
//! Metabolic Cryptography — radioactive half-life authority
//! (`DEV/UNPRECEDENTED_PRIMITIVES.md` §3).
//!
//! Authority is nourished by peer pulses in physically distinct administrative
//! domains. Each domain contributes **at most one** unit — the maximum over its
//! pulses of `2^{-(t - t_p) / half_life}` — so a Sybil flood inside one domain
//! is worth exactly one honest pulse. Total metabolic mass is the sum over
//! domains; capability requires `mass >= theta`.
//!
//! A seized or eclipsed node keeps its last pulse timestamps and stops
//! receiving fresh ones. Because every honest domain's weight decays, mass
//! falls through `theta` on a closed-form schedule even if the adversary feeds
//! it unbounded Sybils across `k < theta` colluding domains. No revocation
//! packet is involved: silence is the revocation.

use std::collections::HashMap;
use std::fmt;

/// A physically distinct administrative / light-cone domain.
pub type DomainId = [u8; 16];

/// Why a metabolic clock could not be built.
#[derive(Debug, Clone, PartialEq)]
pub enum MetabolicError {
    /// A half-life must be a positive number of seconds.
    BadHalfLife(f64),
}

impl fmt::Display for MetabolicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadHalfLife(value) => write!(f, "half-life must be positive, got {value}"),
        }
    }
}

impl std::error::Error for MetabolicError {}

/// Per-domain saturated decay state.
#[derive(Debug, Clone)]
pub struct MetabolicClock {
    half_life: f64,
    pulses: HashMap<DomainId, u64>,
}

impl MetabolicClock {
    pub fn new(half_life: f64) -> Result<Self, MetabolicError> {
        if !half_life.is_finite() || half_life <= 0.0 {
            return Err(MetabolicError::BadHalfLife(half_life));
        }
        Ok(Self {
            half_life,
            pulses: HashMap::new(),
        })
    }

    pub fn half_life(&self) -> f64 {
        self.half_life
    }

    pub fn domains(&self) -> usize {
        self.pulses.len()
    }

    /// Record a valid peer pulse. Only the freshest pulse in a domain matters,
    /// which is what caps a Sybil flood at one unit.
    pub fn note_pulse(&mut self, domain: DomainId, at: u64) {
        let entry = self.pulses.entry(domain).or_insert(at);
        if at > *entry {
            *entry = at;
        }
    }

    /// Saturated weight of one domain: at most 1, halving every `half_life`.
    ///
    /// A pulse dated in the future is clamped to saturation rather than
    /// rewarded: otherwise a peer with a fast clock could mint mass.
    pub fn weight(&self, domain: &DomainId, now: u64) -> f64 {
        let Some(&last) = self.pulses.get(domain) else {
            return 0.0;
        };
        if last >= now {
            return 1.0;
        }
        let elapsed = (now - last) as f64;
        2f64.powf(-elapsed / self.half_life)
    }

    /// Total metabolic mass `M_u(t) = sum_a W_a(t)`.
    pub fn mass(&self, now: u64) -> f64 {
        self.pulses
            .keys()
            .map(|domain| self.weight(domain, now))
            .sum()
    }

    pub fn is_authorized(&self, now: u64, theta: f64) -> bool {
        self.mass(now) >= theta
    }

    /// First whole second at which mass drops **below** `theta`.
    ///
    /// `None` only when `theta <= 0` (always authorized) or when the mass has
    /// not fallen below `theta` even after 64 half-lives, which cannot happen
    /// for a finite domain set.
    pub fn projected_death(&self, now: u64, theta: f64) -> Option<u64> {
        if !theta.is_finite() || theta <= 0.0 || self.pulses.is_empty() {
            return None;
        }
        if self.mass(now) < theta {
            return Some(now);
        }
        let horizon = (64.0 * self.half_life).ceil().max(1.0) as u64;
        let end = now.saturating_add(horizon);
        if self.mass(end) >= theta {
            return None;
        }
        let (mut alive, mut dead) = (now, end);
        while dead - alive > 1 {
            let middle = alive + (dead - alive) / 2;
            if self.mass(middle) >= theta {
                alive = middle;
            } else {
                dead = middle;
            }
        }
        Some(dead)
    }
}

/// The starvation deadline from the theorem, in seconds **after** `t0`:
/// `half_life * log2(honest / (theta - adversary))`.
///
/// `None` when the adversary already controls `theta` or more domains — the
/// theorem's hypothesis `k_adv < theta` is exactly the condition under which
/// force-feeding cannot outrun decay.
pub fn starvation_deadline(
    half_life: f64,
    honest_domains: usize,
    adversary_domains: usize,
    theta: f64,
) -> Option<f64> {
    if !half_life.is_finite() || half_life <= 0.0 || !theta.is_finite() || theta <= 0.0 {
        return None;
    }
    let adversary = adversary_domains as f64;
    if adversary >= theta {
        return None;
    }
    if honest_domains == 0 {
        return Some(0.0);
    }
    let ratio = honest_domains as f64 / (theta - adversary);
    Some((half_life * ratio.log2()).max(0.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain(tag: u8) -> DomainId {
        [tag; 16]
    }

    fn nourished(half_life: f64) -> MetabolicClock {
        let mut clock = MetabolicClock::new(half_life).expect("valid half-life");
        clock.note_pulse(domain(1), 1_000);
        clock.note_pulse(domain(2), 1_000);
        clock.note_pulse(domain(3), 1_000);
        clock.note_pulse(domain(4), 1_000);
        clock
    }

    #[test]
    fn a_domain_contributes_at_most_one_however_many_sybils_pulse() {
        let mut clock = MetabolicClock::new(100.0).unwrap();
        for _ in 0..10_001u64 {
            clock.note_pulse(domain(9), 500);
        }
        assert_eq!(clock.domains(), 1);
        assert!((clock.mass(500) - 1.0).abs() < 1e-12);
        assert!((clock.mass(1_000) - 2f64.powi(-5)).abs() < 1e-12);

        // A future-dated pulse cannot mint more than saturation.
        clock.note_pulse(domain(9), 10_000);
        assert_eq!(clock.mass(500), 1.0);

        clock.note_pulse(domain(10), 500);
        assert!((clock.mass(500) - 2.0).abs() < 1e-12);
    }

    #[test]
    fn mass_halves_every_half_life() {
        let mut clock = MetabolicClock::new(100.0).unwrap();
        clock.note_pulse(domain(1), 0);
        assert!((clock.mass(0) - 1.0).abs() < 1e-12);
        assert!((clock.mass(100) - 0.5).abs() < 1e-12);
        assert!((clock.mass(200) - 0.25).abs() < 1e-12);
        assert!((clock.mass(700) - 2f64.powi(-7)).abs() < 1e-12);
    }

    #[test]
    fn an_infinitely_fed_adversary_still_dies_at_the_theorem_deadline() {
        // Four honest domains go silent at t0 = 1000; two adversarial domains
        // force-feed a Sybil every second. theta = 3, half-life = 100 s.
        let t0 = 1_000u64;
        let mut clock = nourished(100.0);
        let theta = 3.0;

        // Griefing bulk: 250 Sybils per second in each of the two domains.
        for t in t0..(t0 + 400) {
            for sybil in 0..250u8 {
                clock.note_pulse(domain(200 + sybil % 2), t);
            }
        }

        let deadline_after_t0 = starvation_deadline(100.0, 4, 2, theta).expect("k < theta");
        assert!((deadline_after_t0 - 200.0).abs() < 1e-9);
        let deadline = t0 + deadline_after_t0 as u64;

        assert!(clock.is_authorized(deadline - 1, theta));
        assert!(
            clock.is_authorized(deadline, theta),
            "equality is still alive"
        );
        assert!(!clock.is_authorized(deadline + 1, theta));
        assert_eq!(clock.projected_death(t0, theta), Some(deadline + 1));

        // The theorem's upper bound really is the death second, within one
        // whole-second tick, and no amount of extra Sybils moved it.
        assert!(clock.projected_death(t0, theta).unwrap() <= deadline + 1);
    }

    #[test]
    fn a_mass_already_below_the_threshold_dies_now() {
        let mut clock = MetabolicClock::new(100.0).unwrap();
        clock.note_pulse(domain(1), 0);
        clock.note_pulse(domain(2), 0);
        // Two units of mass cannot meet a threshold of five.
        assert_eq!(clock.projected_death(0, 5.0), Some(0));
        assert_eq!(clock.projected_death(0, 0.0), None);
        // 2 * 2^(-t/100) < 1.5 first holds at t = 42.
        assert_eq!(clock.projected_death(0, 1.5), Some(42));
    }

    #[test]
    fn collusion_at_the_threshold_has_no_finite_bound() {
        // k_adv >= theta: the adversary alone can hold authority, so decay is
        // not a guarantee. The function refuses to promise a deadline.
        assert_eq!(starvation_deadline(100.0, 4, 3, 3.0), None);
        assert_eq!(starvation_deadline(100.0, 4, 5, 3.0), None);
        // Below the threshold the deadline is finite and tightens as the
        // adversary gains domains.
        let two = starvation_deadline(100.0, 4, 1, 3.0).unwrap();
        let one = starvation_deadline(100.0, 4, 2, 3.0).unwrap();
        assert!(one > two);
    }

    #[test]
    fn a_fresh_pulse_restores_capability() {
        let mut clock = nourished(100.0);
        let theta = 3.0;
        assert!(clock.is_authorized(1_000, theta));
        // Five hundred seconds of silence (five half-lives) leaves 4/32.
        assert!(!clock.is_authorized(1_500, theta));

        clock.note_pulse(domain(5), 1_500);
        clock.note_pulse(domain(6), 1_500);
        clock.note_pulse(domain(7), 1_500);
        assert!(clock.is_authorized(1_500, theta));
        // 3.125 units: below 3 once 2^(-t/100) drops past 0.96, at t = 1506.
        assert_eq!(clock.projected_death(1_500, theta), Some(1_506));
    }

    #[test]
    fn a_clock_needs_a_real_half_life() {
        assert_eq!(
            MetabolicClock::new(0.0).unwrap_err(),
            MetabolicError::BadHalfLife(0.0)
        );
        assert!(MetabolicClock::new(-1.0).is_err());
        assert!(MetabolicClock::new(f64::INFINITY).is_err());
    }
}
