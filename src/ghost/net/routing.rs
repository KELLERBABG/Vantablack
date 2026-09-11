/// Contact Graph Routing (CGR) & Time-Variable Graph (TVG)
///
/// Implements the routing abstractions described in the Global Ghost Net architecture:
///
/// ## Poisson-Distributed Error Rate Checking
/// The reputation matrix now uses a Poisson-distributed error model to distinguish
/// between benign cosmic radiation bit-flips (which follow a Poisson process with
/// known rate λ_cosmic) and malicious behavior (which has a significantly higher
/// error rate). This allows the node to issue Byzantine isolation accusations only
/// when the probability of the observed errors being due to cosmic radiation is
/// negligibly small (< 10^-6).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// A node identifier (e.g., satellite ID or ground station).
pub type NodeId = String;

/// Timestamp as seconds since epoch (or relative offset).
pub type Timestamp = f64;

/// A contact window between two nodes.
#[derive(Debug, Clone)]
pub struct Contact {
    pub source: NodeId,
    pub destination: NodeId,
    /// Start of the visibility window (seconds since epoch or offset).
    pub t_start: Timestamp,
    /// End of the visibility window.
    pub t_end: Timestamp,
    /// Maximum data capacity in bits.
    pub x_cap: f64,
}

/// The edge presence function: ρ(e, t) → whether an edge exists at time t.
pub fn edge_presence(contact: &Contact, t: Timestamp) -> bool {
    t >= contact.t_start && t <= contact.t_end
}

/// The latency function: ζ(e, t) — signal propagation delay.
/// For laser inter-satellite links at ~300,000 km/s.
pub fn latency(_contact: &Contact, _t: Timestamp) -> Duration {
    Duration::from_millis(10)
}

/// A journey is a sequence of time-ordered contacts.
#[derive(Debug, Clone)]
pub struct Journey {
    pub contacts: Vec<(Contact, Timestamp)>,
    pub total_latency: Duration,
}

impl Journey {
    /// Create an empty journey.
    pub fn new() -> Self {
        Self {
            contacts: Vec::new(),
            total_latency: Duration::ZERO,
        }
    }

    /// Append a contact with the transmission time to this journey.
    /// Returns false if the contact violates time ordering.
    pub fn append(&mut self, contact: Contact, send_time: Timestamp) -> bool {
        if let Some((_, last_time)) = self.contacts.last() {
            if send_time < *last_time {
                return false;
            }
            if send_time < last_time + latency(&contact, send_time).as_secs_f64() {
                return false;
            }
        }
        self.total_latency += latency(&contact, send_time);
        self.contacts.push((contact, send_time));
        true
    }
}

/// Contact plan: the set of all known contacts in the network.
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct ContactPlan {
    pub contacts: Vec<Contact>,
    pub by_source: HashMap<NodeId, Vec<Contact>>,
}


impl ContactPlan {
    pub fn add_contact(&mut self, contact: Contact) {
        let source = contact.source.clone();
        self.contacts.push(contact.clone());
        self.by_source.entry(source).or_default().push(contact);
    }

    pub fn get_contacts_from(&self, source: &str, t: Timestamp) -> Vec<&Contact> {
        self.by_source
            .get(source)
            .map(|contacts| contacts.iter().filter(|c| edge_presence(c, t)).collect())
            .unwrap_or_default()
    }

    pub fn find_earliest_arrival(
        &self,
        source: &str,
        destination: &str,
        t_now: Timestamp,
    ) -> Option<Journey> {
        if let Some(contacts) = self.by_source.get(source) {
            for contact in contacts {
                if contact.destination == destination && edge_presence(contact, t_now) {
                    let send_time = t_now.max(contact.t_start);
                    let mut journey = Journey::new();
                    journey.append(contact.clone(), send_time);
                    return Some(journey);
                }
            }
        }
        None
    }
}

// ── Poisson-Distributed Error Rate Checking ──────────────────────────

/// Baseline cosmic radiation bit-flip rate per packet (λ_cosmic).
/// In LEO, the typical single-event upset rate is ~10^-7 to 10^-6 errors/bit/day.
/// For a 512-byte (4096-bit) GTF privacy frame, this gives ~4×10^-4 to 4×10^-3
/// errors per packet per day. We use λ = 0.001 as the baseline per-packet error rate
/// due to cosmic radiation.
pub const COSMIC_ERROR_RATE: f64 = 0.001;

/// Threshold for Byzantine isolation: if the probability of observing the
/// actual error count under the Poisson(λ_cosmic) model is below this value,
/// the behavior is classified as malicious.
pub const BYZANTINE_PROB_THRESHOLD: f64 = 1e-6;

/// Maximum number of packets in the sliding observation window.
pub const OBSERVATION_WINDOW_SIZE: usize = 1000;

/// Compute the Poisson probability mass function: P(X = k) = e^{-λ} * λ^k / k!
/// Where λ is the expected number of errors under cosmic radiation.
fn poisson_pmf(k: u64, lambda: f64) -> f64 {
    if lambda <= 0.0 {
        return if k == 0 { 1.0 } else { 0.0 };
    }
    // Use log domain for numerical stability
    let log_p = -lambda + k as f64 * lambda.ln() - log_factorial(k);
    log_p.exp()
}

/// Compute the cumulative Poisson probability: P(X ≥ k) = 1 - Σ_{i=0}^{k-1} P(X = i)
/// This tells us the probability of seeing k or more errors if the true rate is λ.
fn poisson_cdf_tail(k: u64, lambda: f64) -> f64 {
    if k == 0 {
        return 1.0;
    }
    let mut cumulative = 0.0f64;
    for i in 0..k {
        cumulative += poisson_pmf(i, lambda);
        if cumulative > 1.0 {
            cumulative = 1.0;
            break;
        }
    }
    (1.0 - cumulative).max(0.0)
}

/// Natural log of factorial using Stirling's approximation for large k,
/// or direct multiplication for small k.
fn log_factorial(k: u64) -> f64 {
    if k <= 20 {
        // Direct computation for small values
        (1..=k).map(|i| (i as f64).ln()).sum()
    } else {
        // Stirling's approximation: ln(k!) ≈ k*ln(k) - k + 0.5*ln(2πk)
        let kf = k as f64;
        kf * kf.ln() - kf + 0.5 * (2.0 * std::f64::consts::PI * kf).ln()
    }
}

/// A single interaction observation stored per peer pair.
/// Records whether a packet interaction succeeded or failed, and when.
#[derive(Debug, Clone)]
pub struct InteractionObservation {
    /// Whether the interaction was successful (true) or failed (false).
    pub success: bool,
    /// When the interaction occurred.
    pub timestamp: Instant,
}

/// Concurrent reputation matrix using DashMap for lock-free reads.
///
/// Instead of wrapping the whole matrix in a Mutex, we use DashMap for the
/// observation storage so that multiple concurrent packet handlers can
/// record interactions without blocking each other.
pub struct PoissonReputationMatrix {
    /// Internal map: (from, to) → sliding window of observations.
    /// Uses DashMap for concurrent access without a global mutex.
    observations: DashMap<(NodeId, NodeId), Vec<InteractionObservation>>,
    /// The expected Poisson rate λ for cosmic radiation errors per packet.
    cosmic_lambda: f64,
    /// The p-value threshold below which we classify behavior as malicious.
    byzantine_threshold: f64,
    /// Maximum window size for observations.
    window_size: usize,
    /// Whether a peer has been flagged as potentially Byzantine.
    flagged: DashMap<(NodeId, NodeId), bool>,
}

impl Default for PoissonReputationMatrix {
    fn default() -> Self {
        Self {
            observations: DashMap::new(),
            cosmic_lambda: COSMIC_ERROR_RATE,
            byzantine_threshold: BYZANTINE_PROB_THRESHOLD,
            window_size: OBSERVATION_WINDOW_SIZE,
            flagged: DashMap::new(),
        }
    }
}

impl PoissonReputationMatrix {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an interaction outcome between two peers.
    /// `success` is true if the packet was verified as authentic,
    /// false if it failed authentication or was corrupted.
    pub fn record_interaction(&self, from: &str, to: &str, success: bool) {
        let key = (from.to_string(), to.to_string());
        let mut observations = self.observations.entry(key.clone()).or_default();

        // Add observation
        observations.push(InteractionObservation {
            success,
            timestamp: Instant::now(),
        });

        // Prune old observations beyond window size
        while observations.len() > self.window_size {
            observations.remove(0);
        }

        // Re-evaluate Byzantine status (statistical aggregation)
        let error_count = observations.iter().filter(|o| !o.success).count() as u64;
        let total = observations.len() as f64;
        let expected_errors = self.cosmic_lambda * total;
        let p_value = poisson_cdf_tail(error_count, expected_errors);

        // Flag as Byzantine if the observed error rate is statistically
        // unlikely under the cosmic radiation model
        let is_byzantine = p_value < self.byzantine_threshold && error_count > 5;
        self.flagged.insert(key, is_byzantine);
    }

    /// Check if `from` considers `to` to be potentially Byzantine.
    pub fn is_byzantine(&self, from: &str, to: &str) -> bool {
        self.flagged
            .get(&(from.to_string(), to.to_string()))
            .map(|v| *v.value())
            .unwrap_or(false)
    }

    /// Get the observed error rate as a fraction.
    pub fn observed_error_rate(&self, from: &str, to: &str) -> f64 {
        let key = (from.to_string(), to.to_string());
        if let Some(obs) = self.observations.get(&key) {
            let total = obs.len() as f64;
            if total > 0.0 {
                let errors = obs.iter().filter(|o| !o.success).count() as f64;
                errors / total
            } else {
                0.0
            }
        } else {
            0.0
        }
    }

    /// Get the p-value that the observed error rate is consistent with
    /// the cosmic radiation baseline.
    pub fn cosmic_consistency_p_value(&self, from: &str, to: &str) -> f64 {
        let key = (from.to_string(), to.to_string());
        if let Some(obs) = self.observations.get(&key) {
            let total = obs.len() as f64;
            if total > 0.0 {
                let errors = obs.iter().filter(|o| !o.success).count() as u64;
                let expected = self.cosmic_lambda * total;
                poisson_cdf_tail(errors, expected)
            } else {
                1.0
            }
        } else {
            1.0
        }
    }

    /// Clear observations for a peer pair (e.g., after re-establishing a session).
    pub fn reset(&self, from: &str, to: &str) {
        let key = (from.to_string(), to.to_string());
        self.observations.remove(&key);
        self.flagged.remove(&key);
    }

    /// Set a custom cosmic radiation baseline rate.
    pub fn set_cosmic_rate(&mut self, rate: f64) {
        self.cosmic_lambda = rate;
    }
}

/// Legacy reputation matrix (kept for backward compatibility).
pub struct ReputationMatrix {
    scores: HashMap<(NodeId, NodeId), f64>,
    alpha: f64,
    drop_threshold: f64,
}

impl Default for ReputationMatrix {
    fn default() -> Self {
        Self {
            scores: HashMap::new(),
            alpha: 0.9,
            drop_threshold: 0.3,
        }
    }
}

impl ReputationMatrix {
    pub fn record_interaction(&mut self, from: &str, to: &str, success: bool) {
        let key = (from.to_string(), to.to_string());
        let ratio = if success { 1.0 } else { 0.0 };
        let current = self.scores.get(&key).copied().unwrap_or(1.0);
        self.scores.insert(key, self.alpha * current + (1.0 - self.alpha) * ratio);
    }

    pub fn get_reputation(&self, from: &str, to: &str) -> f64 {
        self.scores
            .get(&(from.to_string(), to.to_string()))
            .copied()
            .unwrap_or(1.0)
    }

    pub fn is_trusted(&self, from: &str, to: &str) -> bool {
        self.get_reputation(from, to) >= self.drop_threshold
    }
}

pub fn min_nodes_for_byzantine_tolerance(f: u32) -> u32 {
    f.checked_mul(3)
        .and_then(|x| x.checked_add(1))
        .unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poisson_pmf_small() {
        // For λ=0.001, P(X=0) = e^{-0.001} ≈ 0.999
        let p0 = poisson_pmf(0, 0.001);
        assert!((p0 - 0.9990005).abs() < 0.001);

        // P(X=1) = e^{-0.001} * 0.001 ≈ 0.000999
        let p1 = poisson_pmf(1, 0.001);
        assert!((p1 - 0.000999).abs() < 0.001);
    }

    #[test]
    fn test_cosmic_consistency_normal() {
        // Simulate a peer with errors consistent with cosmic radiation
        let mut rep = PoissonReputationMatrix::new();
        rep.set_cosmic_rate(0.001);

        // 1000 interactions, ~1 error expected (λ * N = 1)
        for _ in 0..1000 {
            rep.record_interaction("alice", "bob", true);
        }
        // A few errors due to cosmic rays
        for _ in 0..2 {
            rep.record_interaction("alice", "bob", false);
        }

        let p_value = rep.cosmic_consistency_p_value("alice", "bob");
        // p-value should be high (errors are consistent with cosmic radiation)
        assert!(p_value > 0.05, "p_value={} should be >0.05 for cosmic-consistent errors", p_value);
        assert!(!rep.is_byzantine("alice", "bob"), "Should not flag as Byzantine for cosmic-consistent errors");
    }

    #[test]
    fn test_byzantine_detection() {
        // Simulate a malicious peer with high error rate
        let mut rep = PoissonReputationMatrix::new();
        rep.set_cosmic_rate(0.001);

        // 100 interactions, 30% error rate — clearly malicious
        for _ in 0..70 {
            rep.record_interaction("alice", "mallory", true);
        }
        for _ in 0..30 {
            rep.record_interaction("alice", "mallory", false);
        }

        let p_value = rep.cosmic_consistency_p_value("alice", "mallory");
        // p-value should be extremely low (errors are NOT consistent with cosmic radiation)
        assert!(p_value < 0.001, "p_value={} should be <0.001 for malicious errors", p_value);
        assert!(rep.is_byzantine("alice", "mallory"), "Should flag malicious peer as Byzantine");
        assert!(rep.observed_error_rate("alice", "mallory") > 0.2);
    }

    #[test]
    fn test_reset_clears_flag() {
        let mut rep = PoissonReputationMatrix::new();
        rep.set_cosmic_rate(0.001);

        // Induce Byzantine flag
        for _ in 0..50 {
            rep.record_interaction("a", "b", false);
        }
        assert!(rep.is_byzantine("a", "b"));

        // Reset should clear the flag
        rep.reset("a", "b");
        assert!(!rep.is_byzantine("a", "b"));
        assert_eq!(rep.observed_error_rate("a", "b"), 0.0);
    }

    #[test]
    fn test_legacy_reputation() {
        let mut rep = ReputationMatrix::default();
        assert!(rep.is_trusted("a", "b"));
        for _ in 0..5 {
            rep.record_interaction("a", "b", false);
        }
        assert!(rep.get_reputation("a", "b") < 1.0);
        for _ in 0..20 {
            rep.record_interaction("a", "b", true);
        }
        assert!(rep.get_reputation("a", "b") > 0.9);
    }
}