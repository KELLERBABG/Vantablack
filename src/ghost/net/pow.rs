//! Proof-of-Work (PoW) Anti-Abuse & Anti-Sybil Engine
//!
//! Provides a cryptographic client puzzle mechanism to mitigate denial-of-service,
//! Sybil connection floods, and unauthenticated handshake storms.
//!
//! ## Design
//! - Challenges are bound to: `[server_salt (32B) || peer_id (32B) || timestamp (8B) || difficulty (1B)]`.
//! - Solver must find a `u64` nonce such that `SHA-256(challenge || nonce)` produces
//!   at least `difficulty` leading zero bits.
//! - Verification is constant-time / $O(1)$ and requires zero heap allocation.
//! - Puzzles automatically expire after `ttl_secs` to prevent pre-computation.

use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;

/// Maximum allowable time skew / validity window for a PoW challenge (5 minutes).

pub const DEFAULT_POW_TTL_SECS: u64 = 300;

/// Default baseline difficulty (12 leading zero bits ~ avg 4,096 hashes, ~1-5ms on CPU).
pub const DEFAULT_POW_DIFFICULTY: u8 = 12;

/// A challenge issued by a node or relay to a connecting peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowChallenge {
    /// Server-generated salt / random seed.
    pub server_salt: [u8; 32],
    /// Peer public identity or ephemeral handshake fingerprint.
    pub peer_id: [u8; 32],
    /// Creation timestamp (Unix epoch seconds).
    pub timestamp: u64,
    /// Time-to-live in seconds.
    pub ttl_secs: u64,
    /// Required leading zero bits in the resulting hash.
    pub difficulty: u8,
}

/// A solution submitted by the peer attempting to establish a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowSolution {
    /// Nonce found by the client satisfying the difficulty requirement.
    pub nonce: u64,
}

impl PowChallenge {
    /// Create a new PoW challenge for a specific peer.
    pub fn new(server_salt: [u8; 32], peer_id: [u8; 32], difficulty: u8, ttl_secs: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            server_salt,
            peer_id,
            timestamp: now,
            ttl_secs,
            difficulty,
        }
    }

    /// Compute the 32-byte digest binding the challenge parameters.
    pub fn challenge_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"GGN_POW_V1_CHALLENGE");
        hasher.update(&self.server_salt);
        hasher.update(&self.peer_id);
        hasher.update(&self.timestamp.to_be_bytes());
        hasher.update(&self.ttl_secs.to_be_bytes());
        hasher.update(&[self.difficulty]);
        hasher.finalize().into()
    }

    /// Count leading zero bits in a 32-byte hash buffer.
    #[inline]
    pub fn count_leading_zeros(hash: &[u8; 32]) -> u8 {
        let mut zeros = 0u8;
        for byte in hash {
            let lz = byte.leading_zeros() as u8;
            zeros += lz;
            if lz < 8 {
                break;
            }
        }
        zeros
    }

    /// Hash a challenge digest together with a nonce candidate.
    #[inline]
    pub fn hash_candidate(digest: &[u8; 32], nonce: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(digest);
        hasher.update(&nonce.to_be_bytes());
        hasher.finalize().into()
    }

    /// Verify a submitted solution against this challenge.
    ///
    /// Checks:
    /// 1. Challenge has not expired (`current_time <= timestamp + ttl_secs`).
    /// 2. Challenge is not from the future (`current_time + 10 >= timestamp`).
    /// 3. SHA-256(challenge_digest || nonce) has at least `difficulty` leading zeros.
    pub fn verify(&self, solution: &PowSolution, current_time: u64) -> bool {
        // Expiry check
        if current_time > self.timestamp.saturating_add(self.ttl_secs) {
            return false;
        }
        // Clock skew check (allow up to 10s future drift)
        if self.timestamp > current_time.saturating_add(10) {
            return false;
        }

        let digest = self.challenge_digest();
        let hash = Self::hash_candidate(&digest, solution.nonce);
        Self::count_leading_zeros(&hash) >= self.difficulty
    }

    /// Solve the challenge synchronously by iterating nonces.
    /// Returns `PowSolution` when the difficulty condition is satisfied.
    pub fn solve(&self) -> PowSolution {
        let digest = self.challenge_digest();
        let target_zeros = self.difficulty;
        let mut nonce = 0u64;

        loop {
            let hash = Self::hash_candidate(&digest, nonce);
            if Self::count_leading_zeros(&hash) >= target_zeros {
                return PowSolution { nonce };
            }
            nonce = nonce.wrapping_add(1);
        }
    }

    /// Solve with a maximum iteration cap (useful for non-blocking worker loops).
    pub fn solve_bounded(&self, start_nonce: u64, max_steps: u64) -> Option<PowSolution> {
        let digest = self.challenge_digest();
        let target_zeros = self.difficulty;
        let mut nonce = start_nonce;

        for _ in 0..max_steps {
            let hash = Self::hash_candidate(&digest, nonce);
            if Self::count_leading_zeros(&hash) >= target_zeros {
                return Some(PowSolution { nonce });
            }
            nonce = nonce.wrapping_add(1);
        }
        None
    }
}

/// Dynamic difficulty rate-limiter: adjusts required difficulty based on
/// request rate or concurrent connection attempts from a subnet or peer.
#[derive(Debug, Clone)]
pub struct DynamicPowGovernor {
    base_difficulty: u8,
    max_difficulty: u8,
}

impl DynamicPowGovernor {
    pub fn new(base_difficulty: u8, max_difficulty: u8) -> Self {
        Self {
            base_difficulty,
            max_difficulty,
        }
    }

    /// Computes target difficulty given current unauthenticated load:
    /// - `current_pending`: number of pending handshakes or unauthenticated packets
    /// - `load_threshold`: threshold before increasing difficulty
    pub fn compute_difficulty(&self, current_pending: usize, load_threshold: usize) -> u8 {
        if current_pending <= load_threshold {
            return self.base_difficulty;
        }
        let excess = current_pending - load_threshold;
        // Each step above threshold adds 1 bit of difficulty (doubling required work)
        let added_bits = (excess as u32).ilog2() as u8 + 1;
        self.base_difficulty
            .saturating_add(added_bits)
            .min(self.max_difficulty)
    }
}

// ══════════════════════════════════════════════════════════════════
// Invention §50: Anti-Fragile Tarpit — Attacker Compute Penalty
// ══════════════════════════════════════════════════════════════════

/// Record tracking violation history and active penalty difficulty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TarpitPenalty {
    pub violations: u32,
    pub last_violation_ts: u64,
    pub active_penalty_bits: u8,
}

/// Anti-Fragile Tarpit: forces attackers into escalating Hashcash compute traps.
///
/// Ties failed handshakes, authentication anomalies, and tampered honey shards
/// directly into escalating PoW difficulty for the offending peer:
/// - Baseline: `base_difficulty` bits (e.g. 10 bits).
/// - Failed handshake: +2 difficulty bits per failure (4x compute penalty).
/// - Honey-shard tamper (§15): +4 difficulty bits immediately (16x compute penalty).
/// - Maximum cap: `max_difficulty` bits (e.g. 24 bits ~ 16M hashes).
/// - Successful authentication decays or clears penalties.
#[derive(Debug, Clone)]
pub struct AntiFragileTarpit {
    pub base_difficulty: u8,
    pub max_difficulty: u8,
    pub penalty_ttl_secs: u64,
    penalties: Arc<DashMap<[u8; 32], TarpitPenalty>>,
}

impl AntiFragileTarpit {
    pub fn new(base_difficulty: u8, max_difficulty: u8, penalty_ttl_secs: u64) -> Self {
        Self {
            base_difficulty,
            max_difficulty,
            penalty_ttl_secs,
            penalties: Arc::new(DashMap::new()),
        }
    }

    /// Record a failed handshake or unauthenticated probe from a peer.
    pub fn record_failed_handshake(&self, peer_id: &[u8; 32], now: u64) -> u8 {
        self.escalate_penalty(peer_id, 2, now)
    }

    /// Record a honey-shard canary tag tampering event (§15) from a peer.
    /// Honey-shard tampering is a proven Byzantine violation and escalates immediately by +4 bits.
    pub fn record_honey_shard_tamper(&self, peer_id: &[u8; 32], now: u64) -> u8 {
        self.escalate_penalty(peer_id, 4, now)
    }

    fn escalate_penalty(&self, peer_id: &[u8; 32], added_bits: u8, now: u64) -> u8 {
        let mut entry = self.penalties.entry(*peer_id).or_insert(TarpitPenalty {
            violations: 0,
            last_violation_ts: now,
            active_penalty_bits: 0,
        });

        // If previous penalty expired, reset
        if now
            > entry
                .last_violation_ts
                .saturating_add(self.penalty_ttl_secs)
        {
            entry.violations = 0;
            entry.active_penalty_bits = 0;
        }

        entry.violations = entry.violations.saturating_add(1);
        entry.last_violation_ts = now;
        entry.active_penalty_bits = entry.active_penalty_bits.saturating_add(added_bits);

        self.base_difficulty
            .saturating_add(entry.active_penalty_bits)
            .min(self.max_difficulty)
    }

    /// Get current required difficulty for this peer.
    pub fn difficulty_for_peer(&self, peer_id: &[u8; 32], now: u64) -> u8 {
        if let Some(entry) = self.penalties.get(peer_id) {
            if now
                <= entry
                    .last_violation_ts
                    .saturating_add(self.penalty_ttl_secs)
            {
                return self
                    .base_difficulty
                    .saturating_add(entry.active_penalty_bits)
                    .min(self.max_difficulty);
            }
        }
        self.base_difficulty
    }

    /// Creates a personalized PoW challenge reflecting the peer's tarpit difficulty.
    pub fn create_challenge(
        &self,
        peer_id: &[u8; 32],
        server_salt: [u8; 32],
        now: u64,
        ttl_secs: u64,
    ) -> PowChallenge {
        let difficulty = self.difficulty_for_peer(peer_id, now);
        let mut ch = PowChallenge::new(server_salt, *peer_id, difficulty, ttl_secs);
        ch.timestamp = now;
        ch
    }

    /// Record a successful authenticated exchange, resetting the peer's tarpit penalty.
    pub fn record_success(&self, peer_id: &[u8; 32]) {
        self.penalties.remove(peer_id);
    }
}

#[cfg(test)]

mod tests {
    use super::*;

    #[test]
    fn test_pow_solve_and_verify_success() {
        let salt = [0x42u8; 32];
        let peer = [0x99u8; 32];
        let difficulty = 10; // 10 bits is fast in test suite (~1ms)
        let ttl = 60;

        let challenge = PowChallenge::new(salt, peer, difficulty, ttl);
        let solution = challenge.solve();

        assert!(challenge.verify(&solution, challenge.timestamp));
    }

    #[test]
    fn test_pow_tampered_nonce_fails() {
        let salt = [0x11u8; 32];
        let peer = [0x22u8; 32];
        let difficulty = 12;
        let ttl = 60;

        let challenge = PowChallenge::new(salt, peer, difficulty, ttl);
        let solution = challenge.solve();

        // Tamper with the nonce
        let tampered = PowSolution {
            nonce: solution.nonce.wrapping_add(1),
        };
        // It should either fail or only succeed with probability 2^(-12)
        assert!(!challenge.verify(&tampered, challenge.timestamp) || difficulty == 0);
    }

    #[test]
    fn test_pow_expired_challenge_fails() {
        let salt = [0xaau8; 32];
        let peer = [0xbbu8; 32];
        let difficulty = 8;
        let ttl = 30;

        let challenge = PowChallenge::new(salt, peer, difficulty, ttl);
        let solution = challenge.solve();

        // Check at timestamp + ttl + 1 -> must fail
        let expired_time = challenge.timestamp + ttl + 1;
        assert!(!challenge.verify(&solution, expired_time));
    }

    #[test]
    fn test_pow_difficulty_scaling() {
        let gov = DynamicPowGovernor::new(10, 24);
        assert_eq!(gov.compute_difficulty(5, 10), 10);
        assert_eq!(gov.compute_difficulty(10, 10), 10);
        // Excess 1 -> ilog2(1) + 1 = 1 -> difficulty 11
        assert_eq!(gov.compute_difficulty(11, 10), 11);
        // Excess 4 -> ilog2(4) + 1 = 3 -> difficulty 13
        assert_eq!(gov.compute_difficulty(14, 10), 13);
        // Huge flood -> capped at max_difficulty
        assert_eq!(gov.compute_difficulty(100_000, 10), 24);
    }

    #[test]
    fn test_antifragile_tarpit_penalty_escalation_and_recovery() {
        let tarpit = AntiFragileTarpit::new(8, 20, 300);
        let attacker_id = [0xEEu8; 32];
        let now = 1_000_000u64;

        // Baseline difficulty is 8 bits
        assert_eq!(tarpit.difficulty_for_peer(&attacker_id, now), 8);

        // Failed handshake increases difficulty by +2 bits (8 -> 10)
        let diff1 = tarpit.record_failed_handshake(&attacker_id, now);
        assert_eq!(diff1, 10);
        assert_eq!(tarpit.difficulty_for_peer(&attacker_id, now), 10);

        // Another failed handshake increases by +2 bits (10 -> 12)
        let diff2 = tarpit.record_failed_handshake(&attacker_id, now + 1);
        assert_eq!(diff2, 12);

        // Tampering with a §15 honey shard increases by +4 bits immediately (12 -> 16)
        let diff3 = tarpit.record_honey_shard_tamper(&attacker_id, now + 2);
        assert_eq!(diff3, 16);

        // Challenge reflects the escalated 16-bit difficulty
        let challenge = tarpit.create_challenge(&attacker_id, [0xAAu8; 32], now + 2, 60);
        assert_eq!(challenge.difficulty, 16);

        // Successful authentication clears penalties back to base difficulty
        tarpit.record_success(&attacker_id);
        assert_eq!(tarpit.difficulty_for_peer(&attacker_id, now + 3), 8);
    }
}
