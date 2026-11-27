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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

static ENABLED: AtomicBool = AtomicBool::new(false);

pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::Relaxed);
}

use dashmap::DashMap;

pub const DEFAULT_POW_TTL_SECS: u64 = 300;

pub const DEFAULT_POW_DIFFICULTY: u8 = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowChallenge {
    pub server_salt: [u8; 32],
    pub peer_id: [u8; 32],
    pub timestamp: u64,
    pub ttl_secs: u64,
    pub difficulty: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowSolution {
    pub nonce: u64,
}

impl PowChallenge {
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

    pub fn challenge_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"GGN_POW_V1_CHALLENGE");
        hasher.update(self.server_salt);
        hasher.update(self.peer_id);
        hasher.update(self.timestamp.to_be_bytes());
        hasher.update(self.ttl_secs.to_be_bytes());
        hasher.update([self.difficulty]);
        hasher.finalize().into()
    }

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

    #[inline]
    pub fn hash_candidate(digest: &[u8; 32], nonce: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(digest);
        hasher.update(nonce.to_be_bytes());
        hasher.finalize().into()
    }

    pub fn verify(&self, solution: &PowSolution, current_time: u64) -> bool {
        if current_time > self.timestamp.saturating_add(self.ttl_secs) {
            return false;
        }
        if self.timestamp > current_time.saturating_add(10) {
            return false;
        }

        let digest = self.challenge_digest();
        let hash = Self::hash_candidate(&digest, solution.nonce);
        Self::count_leading_zeros(&hash) >= self.difficulty
    }

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

    pub fn compute_difficulty(&self, current_pending: usize, load_threshold: usize) -> u8 {
        if current_pending <= load_threshold {
            return self.base_difficulty;
        }
        let excess = current_pending - load_threshold;
        let added_bits = (excess as u32).ilog2() as u8 + 1;
        self.base_difficulty
            .saturating_add(added_bits)
            .min(self.max_difficulty)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TarpitPenalty {
    pub violations: u32,
    pub last_violation_ts: u64,
    pub active_penalty_bits: u8,
}

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

    pub fn record_failed_handshake(&self, peer_id: &[u8; 32], now: u64) -> u8 {
        self.escalate_penalty(peer_id, 2, now)
    }

    pub fn record_honey_shard_tamper(&self, peer_id: &[u8; 32], now: u64) -> u8 {
        self.escalate_penalty(peer_id, 4, now)
    }

    fn escalate_penalty(&self, peer_id: &[u8; 32], added_bits: u8, now: u64) -> u8 {
        let mut entry = self.penalties.entry(*peer_id).or_insert(TarpitPenalty {
            violations: 0,
            last_violation_ts: now,
            active_penalty_bits: 0,
        });

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

        let tampered = PowSolution {
            nonce: solution.nonce.wrapping_add(1),
        };
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

        let expired_time = challenge.timestamp + ttl + 1;
        assert!(!challenge.verify(&solution, expired_time));
    }

    #[test]
    fn test_pow_difficulty_scaling() {
        let gov = DynamicPowGovernor::new(10, 24);
        assert_eq!(gov.compute_difficulty(5, 10), 10);
        assert_eq!(gov.compute_difficulty(10, 10), 10);
        assert_eq!(gov.compute_difficulty(11, 10), 11);
        assert_eq!(gov.compute_difficulty(14, 10), 13);
        assert_eq!(gov.compute_difficulty(100_000, 10), 24);
    }

    #[test]
    fn test_antifragile_tarpit_penalty_escalation_and_recovery() {
        let tarpit = AntiFragileTarpit::new(8, 20, 300);
        let attacker_id = [0xEEu8; 32];
        let now = 1_000_000u64;

        assert_eq!(tarpit.difficulty_for_peer(&attacker_id, now), 8);

        let diff1 = tarpit.record_failed_handshake(&attacker_id, now);
        assert_eq!(diff1, 10);
        assert_eq!(tarpit.difficulty_for_peer(&attacker_id, now), 10);

        let diff2 = tarpit.record_failed_handshake(&attacker_id, now + 1);
        assert_eq!(diff2, 12);

        let diff3 = tarpit.record_honey_shard_tamper(&attacker_id, now + 2);
        assert_eq!(diff3, 16);

        let challenge = tarpit.create_challenge(&attacker_id, [0xAAu8; 32], now + 2, 60);
        assert_eq!(challenge.difficulty, 16);

        tarpit.record_success(&attacker_id);
        assert_eq!(tarpit.difficulty_for_peer(&attacker_id, now + 3), 8);
    }
}
