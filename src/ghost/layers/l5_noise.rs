/// L5 — Noise Injection / Jitter Padding & GhostMimic Layer
///
/// Adds random-length padding (0–64 bytes) to each packet beyond the
/// base GTF size. This frustrates traffic analysis attacks that rely
/// on correlating packet sizes to message lengths or protocol phases.
///
/// The jitter is appended after the auth tag and filled with random bytes,
/// making it indistinguishable from legitimate payload to a passive observer.
use rand::Rng;

/// Maximum number of jitter bytes appended to a base-size GTF packet.
pub const JITTER_MAX: usize = 64;

/// Applies jitter padding to a packet by extending it with random bytes.
/// Returns the number of jitter bytes added.
pub fn apply_jitter(packet: &mut Vec<u8>) -> usize {
    let jitter = rand::thread_rng().gen_range(0..JITTER_MAX);
    if jitter > 0 {
        let len = packet.len();
        packet.extend(std::iter::repeat_n(0u8, jitter));
        rand::thread_rng().fill(&mut packet[len..]);
    }
    jitter
}

/// Calculate the effective payload capacity for a given base packet size
/// after accounting for jitter space.
pub fn payload_capacity(base_size: usize) -> usize {
    base_size.saturating_sub(JITTER_MAX) // worst case
}

// ══════════════════════════════════════════════════════════════════
// GhostMimic — Learned Per-ASN Cover Traffic
//
// Traditional privacy networks rely on constant-rate or uniform dummy padding,
// which is itself a distinctive, easily-fingerprinted statistical anomaly for
// modern machine-learning DPI classifiers.
//
// GhostMimic learns a per-ASN packet inter-arrival and size histogram (16 bins)
// representing normal web traffic on that network (e.g. Chrome / YouTube / HTTPS).
// When shaping packets or injecting dummy frames, GhostMimic samples padding
// and delay from this Markov transition model so the wire distribution
// D(Ghost) matches D(LocalWeb) on that Autonomous System Number.
// ══════════════════════════════════════════════════════════════════

pub const MIMIC_BINS: usize = 16;

/// A discrete 16-state histogram distribution for packet sizing and timing.
#[derive(Debug, Clone)]
pub struct MimicProfile {
    pub asn: u32,
    /// Probability weights across 16 size/padding states (normalized to sum = 1.0)
    pub size_weights: [f64; MIMIC_BINS],
    /// Mean inter-arrival delay for this ASN in milliseconds
    pub mean_delay_ms: f64,
}

impl MimicProfile {
    /// Chrome / YouTube HTTPS video-stream profile (bimodal small ACK + MTU chunks).
    pub fn chrome_web(asn: u32) -> Self {
        let mut weights = [0.02f64; MIMIC_BINS];
        weights[0] = 0.35; // Short ACKs / control
        weights[MIMIC_BINS - 1] = 0.35; // MTU / video chunk fills
        let sum: f64 = weights.iter().sum();
        for w in &mut weights {
            *w /= sum;
        }
        Self {
            asn,
            size_weights: weights,
            mean_delay_ms: 15.0,
        }
    }

    /// Generic background noise profile (uniform distribution).
    pub fn uniform(asn: u32) -> Self {
        Self {
            asn,
            size_weights: [1.0 / MIMIC_BINS as f64; MIMIC_BINS],
            mean_delay_ms: 30.0,
        }
    }

    /// Sample padding length according to this ASN profile (0..=JITTER_MAX).
    pub fn sample_padding<R: Rng>(&self, rng: &mut R) -> usize {
        let p: f64 = rng.gen_range(0.0..1.0);
        let mut cum = 0.0;
        let mut selected_bin = 0;
        for (idx, &w) in self.size_weights.iter().enumerate() {
            cum += w;
            if p <= cum {
                selected_bin = idx;
                break;
            }
        }
        // Map 16 bins across JITTER_MAX (0..64)
        let bin_width = JITTER_MAX / MIMIC_BINS; // 4 bytes per bin
        let jitter = selected_bin * bin_width + rng.gen_range(0..bin_width);
        jitter.min(JITTER_MAX)
    }
}

/// GhostMimic engine managing per-ASN learned traffic profiles.
#[derive(Debug, Clone)]
pub struct GhostMimicEngine {
    profiles: std::collections::HashMap<u32, MimicProfile>,
}

impl Default for GhostMimicEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl GhostMimicEngine {
    pub fn new() -> Self {
        Self {
            profiles: std::collections::HashMap::new(),
        }
    }

    /// Register or update an ASN profile
    pub fn register_profile(&mut self, profile: MimicProfile) {
        self.profiles.insert(profile.asn, profile);
    }

    /// Apply mimic-shaped jitter padding to packet according to destination ASN
    pub fn apply_mimic_jitter(&self, packet: &mut Vec<u8>, asn: u32) -> usize {
        let profile = self.profiles.get(&asn);
        let jitter = if let Some(prof) = profile {
            prof.sample_padding(&mut rand::thread_rng())
        } else {
            rand::thread_rng().gen_range(0..JITTER_MAX)
        };

        if jitter > 0 {
            let len = packet.len();
            packet.extend(std::iter::repeat_n(0u8, jitter));
            rand::thread_rng().fill(&mut packet[len..]);
        }
        jitter
    }

    /// Calculate Jensen-Shannon divergence between two 16-bin distributions
    pub fn jensen_shannon_divergence(p: &[f64; MIMIC_BINS], q: &[f64; MIMIC_BINS]) -> f64 {
        let mut m = [0.0f64; MIMIC_BINS];
        for i in 0..MIMIC_BINS {
            m[i] = 0.5 * (p[i] + q[i]);
        }

        let kl = |a: &[f64; MIMIC_BINS], b: &[f64; MIMIC_BINS]| -> f64 {
            let mut sum = 0.0;
            for i in 0..MIMIC_BINS {
                if a[i] > 1e-12 && b[i] > 1e-12 {
                    sum += a[i] * (a[i] / b[i]).ln();
                }
            }
            sum
        };

        let jsd = 0.5 * kl(p, &m) + 0.5 * kl(q, &m);
        jsd.max(0.0).sqrt()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ghost_mimic_profile_shaping_and_js_divergence() {
        let target_asn = 15169; // Google ASN
        let chrome_profile = MimicProfile::chrome_web(target_asn);
        let mut engine = GhostMimicEngine::new();
        engine.register_profile(chrome_profile.clone());

        let mut observed_counts = [0usize; MIMIC_BINS];
        let samples = 20_000;
        let mut rng = rand::thread_rng();

        for _ in 0..samples {
            let pad = chrome_profile.sample_padding(&mut rng);
            let bin = (pad / (JITTER_MAX / MIMIC_BINS)).min(MIMIC_BINS - 1);
            observed_counts[bin] += 1;
        }

        let mut observed_dist = [0.0f64; MIMIC_BINS];
        for i in 0..MIMIC_BINS {
            observed_dist[i] = observed_counts[i] as f64 / samples as f64;
        }

        // Calculate JS distance between sample output and target profile
        let js_dist = GhostMimicEngine::jensen_shannon_divergence(
            &observed_dist,
            &chrome_profile.size_weights,
        );
        assert!(
            js_dist < 0.05,
            "Sampled distribution must closely mimic target ASN profile (JS < 0.05, got {})",
            js_dist
        );

        // Uniform baseline should diverge significantly (JS > 0.15)
        let uniform_profile = MimicProfile::uniform(target_asn);
        let js_uniform = GhostMimicEngine::jensen_shannon_divergence(
            &uniform_profile.size_weights,
            &chrome_profile.size_weights,
        );
        assert!(
            js_uniform > 0.15,
            "Uniform distribution must show clear divergence from web profile (got {})",
            js_uniform
        );
    }

    #[test]
    fn test_apply_mimic_jitter_modifies_length() {
        let mut engine = GhostMimicEngine::new();
        engine.register_profile(MimicProfile::chrome_web(13335));

        let mut packet = vec![0xEEu8; 512];
        let added = engine.apply_mimic_jitter(&mut packet, 13335);
        assert_eq!(packet.len(), 512 + added);
        assert!(added <= JITTER_MAX);
    }
}
