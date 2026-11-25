#![cfg(feature = "research")]
//! Thermodynamic Exhaust of Memoryful Observation — Landauer correlation bound
//! (`DEV/UNPRECEDENTED_PRIMITIVES.md` §7).
//!
//! A passive observer that correlates an incompressible stream across time
//! keeps a state `S_t = g(S_{t-1}, X_t)`. While `g` is injective nothing is
//! forgotten, but a bounded state space forces `g` to merge histories; the
//! merged mass is exactly `H(S_{t-1} | S_t, X_t)`, and Landauer's principle
//! prices every erased bit at `k_B T ln 2`.
//!
//! This module computes that erasure **exactly** from a deterministic update
//! map and a stationary distribution. It is a physical lower bound, not a
//! denial-of-service: at 300 K a bit costs ~2.9e-21 J, far below any practical
//! switching energy.

/// Boltzmann constant in joules per kelvin (CODATA 2018).
pub const BOLTZMANN_J_PER_K: f64 = 1.380_649e-23;

/// Minimum energy dissipated by irreversibly erasing one bit at `kelvin`.
pub fn landauer_joules_per_bit(kelvin: f64) -> f64 {
    BOLTZMANN_J_PER_K * kelvin * std::f64::consts::LN_2
}

/// Minimum dissipation rate for an observer erasing
/// `bits_per_second` irreversible bits.
pub fn landauer_power_watts(kelvin: f64, bits_per_second: f64) -> f64 {
    landauer_joules_per_bit(kelvin) * bits_per_second
}

/// Exact `H(S_{t-1} | S_t, X_t)` for a deterministic update map.
///
/// `stationary[s]` is `P(S = s)` and `input_dist[x]` is `P(X = x)`; `update`
/// is `g(s, x)`. For a fixed input `x`, the mass of histories landing on `s'`
/// is the sum of the stationary weights of its predecessors, and
/// `P(S_t = s', X_t = x) = P(X_t = x) * merged` — **not** `P(S_t = s') * P(X_t = x)`,
/// because `S_t` is produced from `X_t` and the two are not independent. One
/// predecessor means the step is locally invertible and erases nothing; two or
/// more means the entropy of their renormalised weights is gone for good.
pub fn erasure_bits<F>(
    states: usize,
    inputs: usize,
    update: F,
    stationary: &[f64],
    input_dist: &[f64],
) -> f64
where
    F: Fn(usize, usize) -> usize,
{
    assert_eq!(stationary.len(), states, "stationary distribution shape");
    assert_eq!(input_dist.len(), inputs, "input distribution shape");
    let mut erasure = 0.0;
    for (x, p_x) in input_dist.iter().enumerate() {
        if *p_x <= 0.0 {
            continue;
        }
        for (next, _) in stationary.iter().enumerate() {
            let mut merged = 0.0;
            for (previous, p_previous) in stationary.iter().enumerate() {
                if update(previous, x) == next {
                    merged += p_previous;
                }
            }
            if merged <= 0.0 {
                continue;
            }
            let mut entropy = 0.0;
            for (previous, p_previous) in stationary.iter().enumerate() {
                if update(previous, x) != next {
                    continue;
                }
                let conditional = p_previous / merged;
                if conditional > 0.0 {
                    entropy -= conditional * conditional.log2();
                }
            }
            erasure += p_x * merged * entropy;
        }
    }
    erasure
}

/// A bounded saturating counter: `+1` on an up input, `-1` on a down input,
/// clamped to `0..levels-1`. It is the smallest stateful traffic statistic —
/// and at both boundaries two histories merge, so it must erase.
#[derive(Debug, Clone)]
pub struct SaturatingWalk {
    levels: usize,
    state: usize,
}

impl SaturatingWalk {
    pub fn new(levels: usize) -> Self {
        assert!(levels >= 2, "a saturating walk needs at least two levels");
        Self { levels, state: 0 }
    }

    pub fn state(&self) -> usize {
        self.state
    }

    pub fn levels(&self) -> usize {
        self.levels
    }

    /// Bits of history this observer can hold.
    pub fn memory_bits(&self) -> f64 {
        (self.levels as f64).log2()
    }

    pub fn observe(&mut self, up: bool) {
        self.state = if up {
            (self.state + 1).min(self.levels - 1)
        } else {
            self.state.saturating_sub(1)
        };
    }

    /// Stationary distribution of the reflecting random walk.
    ///
    /// Detailed balance across every interior edge gives
    /// `pi_{s+1} = pi_s * p / (1 - p)`, a truncated geometric law.
    pub fn stationary(levels: usize, p_up: f64) -> Vec<f64> {
        assert!(levels >= 2, "a saturating walk needs at least two levels");
        assert!(
            p_up > 0.0 && p_up < 1.0,
            "p_up must be strictly inside (0,1)"
        );
        let log_ratio = (p_up / (1.0 - p_up)).ln();
        let maximum = (levels - 1) as f64 * log_ratio;
        let weights: Vec<f64> = (0..levels)
            .map(|state| (state as f64 * log_ratio - maximum).exp())
            .collect();
        let total: f64 = weights.iter().sum();
        weights.into_iter().map(|weight| weight / total).collect()
    }

    /// `H(S_{t-1} | S_t, X_t)` in bits per observed symbol.
    pub fn erasure_bits_per_step(levels: usize, p_up: f64) -> f64 {
        let stationary = Self::stationary(levels, p_up);
        let input = [1.0 - p_up, p_up];
        erasure_bits(
            levels,
            2,
            |state, x| {
                if x == 1 {
                    (state + 1).min(levels - 1)
                } else {
                    state.saturating_sub(1)
                }
            },
            &stationary,
            &input,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bounded_walk_erases_two_bits_per_level_at_fair_input() {
        // Conditioning on the input resolves every interior step: given S_t
        // and the move, S_{t-1} is unique. Only the two clamped boundaries
        // merge two predecessors, and each is visited with probability
        // 1/levels, so E = 2 / levels bits per symbol.
        for levels in [2usize, 4, 16, 256] {
            let erasure = SaturatingWalk::erasure_bits_per_step(levels, 0.5);
            let expected = 2.0 / levels as f64;
            assert!(
                (erasure - expected).abs() < 1e-12,
                "levels {levels}: {erasure} != {expected}"
            );
        }
    }

    #[test]
    fn more_memory_means_less_irreversible_erasure() {
        let two = SaturatingWalk::erasure_bits_per_step(2, 0.5);
        let four = SaturatingWalk::erasure_bits_per_step(4, 0.5);
        let sixteen = SaturatingWalk::erasure_bits_per_step(16, 0.5);
        assert!((two - 1.0).abs() < 1e-12);
        assert!((four - 0.5).abs() < 1e-12);
        assert!(two > four && four > sixteen);
        // Doubling the state space halves the per-symbol dissipation.
        assert!((two - 2.0 * four).abs() < 1e-12);
        assert!((four - 4.0 * sixteen).abs() < 1e-12);
    }

    #[test]
    fn a_predictable_stream_leaves_less_history_to_erase() {
        // p_up = 0.9 keeps the walk near its upper bound, where the two
        // merging predecessors split 9:1 instead of 1:1. The merge is less
        // uncertain (0.469 bits) and rarer at the lower bound, so the total
        // per-symbol erasure drops below one bit — but never to zero.
        let predictable = SaturatingWalk::erasure_bits_per_step(4, 0.9);
        assert!((predictable - 0.4176).abs() < 0.002, "got {predictable}");
        assert!(predictable < 1.0 && predictable > 0.0);
        assert!(SaturatingWalk::erasure_bits_per_step(4, 0.1) < 1.0);
    }

    #[test]
    fn a_shift_register_erases_exactly_the_bit_that_falls_off() {
        // Three-bit shift register: eight states, two inputs, and for a fixed
        // input two predecessors map to each successor. Uniform stationary
        // law, so each step merges two equally likely histories: 1 bit.
        let states = 8usize;
        let stationary = vec![1.0 / states as f64; states];
        let input = [0.5, 0.5];
        let erased = erasure_bits(
            states,
            2,
            |state, x| ((state << 1) | x) & 0b111,
            &stationary,
            &input,
        );
        assert!(
            (erased - 1.0).abs() < 1e-12,
            "shift register erases {erased}"
        );
    }

    #[test]
    fn an_injective_update_erases_nothing() {
        // A permutation of the state space forgets no history, however long
        // the stream: no non-injectivity, no Landauer cost.
        let states = 8usize;
        let stationary = vec![1.0 / states as f64; states];
        let erased = erasure_bits(
            states,
            2,
            |state, _x| (state + 1) % states,
            &stationary,
            &[0.5, 0.5],
        );
        assert_eq!(erased, 0.0);
    }

    #[test]
    fn the_landauer_power_is_the_erasure_rate_times_kt_ln2() {
        let per_bit = landauer_joules_per_bit(300.0);
        assert!((per_bit - 2.871e-21).abs() < 1e-24, "got {per_bit}");
        assert!((landauer_power_watts(300.0, 1_000_000.0) - per_bit * 1_000_000.0).abs() < 1e-30);
        // Temperature scales the bound exactly.
        assert!((landauer_joules_per_bit(600.0) - 2.0 * per_bit).abs() < 1e-30);
        assert_eq!(landauer_joules_per_bit(0.0), 0.0);
    }

    #[test]
    fn a_room_temperature_wiretap_is_a_physical_bound_not_a_denial_mechanism() {
        // A gigabit stream observed one bit per step at 300 K: about 3 pW.
        let power = landauer_power_watts(300.0, 1e9);
        assert!(power > 1e-12 && power < 1e-11, "got {power} W");
        // The exotic-sounding bound is ten orders below a watt and several
        // orders below CMOS switching energy (~1e-15 J/bit).
        assert!(landauer_joules_per_bit(300.0) < 1e-18);
    }

    #[test]
    fn a_walk_round_trips_its_levels() {
        let mut walk = SaturatingWalk::new(4);
        assert_eq!(walk.memory_bits(), 2.0);
        for _ in 0..10 {
            walk.observe(true);
        }
        assert_eq!(walk.state(), 3);
        for _ in 0..10 {
            walk.observe(false);
        }
        assert_eq!(walk.state(), 0);
        assert_eq!(walk.levels(), 4);
    }
}
