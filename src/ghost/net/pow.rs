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
use std::time::{SystemTime, UNIX_EPOCH};

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
        self.base_difficulty.saturating_add(added_bits).min(self.max_difficulty)
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
}
