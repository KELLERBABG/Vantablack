//! Deterministic in-memory channel with configurable impairments.

use abos_common::types::Bundle;
use num_complex::Complex64;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// A reproducible link between simulated nodes.
///
/// Impairments are applied independently per item:
/// - **loss** — the item is dropped entirely,
/// - **duplication** — the item is delivered twice (exercises dedup),
/// - **corruption** — one payload byte is flipped (exercises checksums).
///
/// All randomness comes from a seeded RNG, so every test run is identical.
pub struct LoopbackChannel {
    rng: StdRng,
    /// Probability \[0,1\] that an item is dropped.
    pub loss_rate: f64,
    /// Probability \[0,1\] that an item is delivered twice.
    pub duplicate_rate: f64,
    /// Probability \[0,1\] that an item's payload is corrupted.
    pub corruption_rate: f64,
    /// RMS noise added to I/Q samples (0.0 = clean).
    pub noise_rms: f64,
}

impl LoopbackChannel {
    /// A perfect channel: no loss, no corruption, no noise.
    pub fn clean() -> Self {
        Self {
            rng: StdRng::seed_from_u64(0),
            loss_rate: 0.0,
            duplicate_rate: 0.0,
            corruption_rate: 0.0,
            noise_rms: 0.0,
        }
    }

    /// A channel with the given impairments, seeded for reproducibility.
    pub fn seeded(
        seed: u64,
        loss_rate: f64,
        duplicate_rate: f64,
        corruption_rate: f64,
        noise_rms: f64,
    ) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
            loss_rate,
            duplicate_rate,
            corruption_rate,
            noise_rms,
        }
    }

    fn roll(&mut self, p: f64) -> bool {
        p > 0.0 && self.rng.gen::<f64>() < p
    }

    /// Deliver one bundle through the channel, returning every copy that
    /// arrives (0 = lost, 1 = normal, 2 = duplicated).
    pub fn deliver_bundle(&mut self, bundle: &Bundle) -> Vec<Bundle> {
        if self.roll(self.loss_rate) {
            return Vec::new();
        }
        let mut arrived = bundle.clone();
        if self.roll(self.corruption_rate) {
            if let Some(byte) = arrived.payload.last_mut() {
                *byte ^= 0xFF; // flip all bits of the last payload byte
            }
        }
        let mut out = vec![arrived.clone()];
        if self.roll(self.duplicate_rate) {
            out.push(arrived);
        }
        out
    }

    /// Push I/Q samples through the channel, adding AWGN when configured.
    pub fn deliver_samples(&mut self, samples: &[Complex64]) -> Vec<Complex64> {
        if self.noise_rms <= 0.0 {
            return samples.to_vec();
        }
        samples
            .iter()
            .map(|s| {
                let n_re = self.gaussian() * self.noise_rms;
                let n_im = self.gaussian() * self.noise_rms;
                Complex64::new(s.re + n_re, s.im + n_im)
            })
            .collect()
    }

    /// Standard normal sample via Box–Muller.
    fn gaussian(&mut self) -> f64 {
        let u1: f64 = self.rng.gen::<f64>().max(f64::EPSILON);
        let u2: f64 = self.rng.gen();
        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(id: u8) -> Bundle {
        Bundle {
            bundle_id: [id; 32],
            source_node: [1; 32],
            creation_timestamp: 0,
            lifetime_seconds: 3600,
            payload: vec![0x42; 8],
            hop_count: 0,
            ttl: 10,
        }
    }

    #[test]
    fn clean_channel_is_transparent() {
        let mut ch = LoopbackChannel::clean();
        let out = ch.deliver_bundle(&bundle(1));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].payload, bundle(1).payload);
    }

    #[test]
    fn loss_drops_item() {
        let mut ch = LoopbackChannel::seeded(7, 1.0, 0.0, 0.0, 0.0);
        assert!(ch.deliver_bundle(&bundle(1)).is_empty());
    }

    #[test]
    fn duplication_delivers_twice() {
        let mut ch = LoopbackChannel::seeded(7, 0.0, 1.0, 0.0, 0.0);
        assert_eq!(ch.deliver_bundle(&bundle(1)).len(), 2);
    }

    #[test]
    fn corruption_flips_a_byte() {
        let mut ch = LoopbackChannel::seeded(7, 0.0, 0.0, 1.0, 0.0);
        let out = ch.deliver_bundle(&bundle(1));
        assert_ne!(out[0].payload, bundle(1).payload, "payload must differ");
    }

    #[test]
    fn seeded_channel_is_deterministic() {
        let input: Vec<Complex64> = (0..64)
            .map(|i| Complex64::new(i as f64 * 0.1, -(i as f64) * 0.05))
            .collect();
        let a = LoopbackChannel::seeded(42, 0.5, 0.5, 0.5, 0.1).deliver_samples(&input);
        let b = LoopbackChannel::seeded(42, 0.5, 0.5, 0.5, 0.1).deliver_samples(&input);
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.re.to_bits(), y.re.to_bits());
            assert_eq!(x.im.to_bits(), y.im.to_bits());
        }
    }

    #[test]
    fn clean_samples_untouched() {
        let input = vec![Complex64::new(1.0, -1.0); 16];
        let out = LoopbackChannel::clean().deliver_samples(&input);
        assert_eq!(out, input);
    }
}
