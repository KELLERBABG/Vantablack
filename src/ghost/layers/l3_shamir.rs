//! L3 — Shamir's Secret Sharing Layer (GF(256))
//!
//! Implements an information-theoretic (2,3) threshold scheme over GF(256):
//! - 3 shares are generated from a 32-byte secret (e.g., PSK or recovery key)
//! - Any 2 shares are sufficient to reconstruct the secret
//! - Any single share reveals mathematically ZERO information about the secret
//!   (Shannon information-theoretic security)
//!
//! ### Architectural Role & Distinction from L4 Reed-Solomon:
//! - **L3 Shamir SSS:** Designed for threshold key distribution, multi-party key escrow,
//!   and split recovery of root secrets (such as `GHOST_PSK` or identity backups).
//! - **L4 Reed-Solomon RS(2,1):** Systematic erasure coding for datagram transport
//!   availability and multipath packet loss recovery. Systematic RS shards contain
//!   direct message fragments and parity. Datagram confidentiality on the wire rests
//!   on L2 AEAD authenticated encryption (and ShardSec per-shard AEAD keys),
//!   not on erasure coding.
use gf256::shamir::shamir;

/// Split a 32-byte secret into 3 shares using (2,3) Shamir SSS.
/// Returns 3 shares, each approximately sizeof(secret) + overhead.
pub fn split_secret(secret: &mut [u8; 32]) -> Vec<Vec<u8>> {
    shamir::generate(secret, 3, 2)
}

/// Split an immutable 32-byte secret slice into 3 shares using (2,3) Shamir SSS.
pub fn split_secret_bytes(secret: &[u8; 32]) -> Vec<Vec<u8>> {
    let mut copy = *secret;
    let shares = shamir::generate(&mut copy, 3, 2);
    // Zeroize copy
    copy.fill(0);
    shares
}

/// Reconstruct the original secret from any 2 valid shares.
/// Returns the reconstructed bytes.
pub fn join_shares(share0: &[u8], share1: &[u8]) -> Vec<u8> {
    shamir::reconstruct(&[share0.to_vec(), share1.to_vec()])
}

/// Reconstruct the secret from a slice of any number of shares (minimum 2 required).
pub fn join_share_slice(shares: &[&[u8]]) -> Vec<u8> {
    let owned: Vec<Vec<u8>> = shares.iter().map(|s| s.to_vec()).collect();
    shamir::reconstruct(&owned)
}

// ═════════════════════════════════════════════════════════════════════════════
// Invention §41: Group-as-Shards (Threshold Governance)
// ═════════════════════════════════════════════════════════════════════════════

/// Threshold group key and authority management.
///
/// Models group authority and authorization as a 3-of-5 threshold erasure-coded object:
/// - 5 total shares are generated from a 32-byte group master secret
/// - Any 3 of 5 members can cooperate to reconstruct the group authorization key
/// - Any 2 members (or an adversary compromising up to 2 devices) learn mathematically
///   ZERO information about the group secret
#[derive(Debug, Clone)]
pub struct ThresholdGroupKey {
    pub group_id: [u8; 16],
    pub threshold: usize,
    pub total_shares: usize,
    pub shares: Vec<Vec<u8>>,
}

impl ThresholdGroupKey {
    /// Generate a 3-of-5 threshold group key set from a 32-byte group master secret.
    pub fn new_3_of_5(group_id: [u8; 16], secret: &[u8; 32]) -> Self {
        let mut copy = *secret;
        let shares = shamir::generate(&mut copy, 5, 3);
        copy.fill(0);
        Self {
            group_id,
            threshold: 3,
            total_shares: 5,
            shares,
        }
    }

    /// Reconstruct the group master secret from at least `threshold` (3) shares.
    /// Returns Err if fewer than 3 shares are supplied.
    pub fn reconstruct(candidate_shares: &[&[u8]]) -> Result<[u8; 32], &'static str> {
        if candidate_shares.len() < 3 {
            return Err("insufficient shares: threshold requires at least 3 of 5 shares");
        }
        let owned: Vec<Vec<u8>> = candidate_shares.iter().map(|s| s.to_vec()).collect();
        let rec = shamir::reconstruct(&owned);
        if rec.len() < 32 {
            return Err("reconstructed secret is malformed");
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&rec[..32]);
        Ok(out)
    }

    /// Derives a deterministic epoch capability token for the group using the reconstructed secret.
    pub fn derive_group_capability(
        reconstructed_secret: &[u8; 32],
        epoch: u64,
        scope: &[u8],
    ) -> [u8; 32] {
        use hkdf::Hkdf;
        use sha2::Sha256;
        let mut info = Vec::with_capacity(32 + 8 + scope.len());
        info.extend_from_slice(b"GGN_GROUP_SHARD_GOVERNANCE_V1");
        info.extend_from_slice(&epoch.to_be_bytes());
        info.extend_from_slice(scope);
        let hk = Hkdf::<Sha256>::new(Some(reconstructed_secret), &[]);
        let mut cap = [0u8; 32];
        hk.expand(&info, &mut cap).expect("32-byte capability");
        cap
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamir_2_of_3_reconstructs_all_combinations() {
        let secret = [0x42u8; 32];
        let shares = split_secret_bytes(&secret);
        assert_eq!(shares.len(), 3, "Must generate exactly 3 shares");

        // Any 2-of-3 must reconstruct the secret:
        // Combination (0, 1)
        let rec01 = join_shares(&shares[0], &shares[1]);
        assert_eq!(
            rec01,
            secret.to_vec(),
            "Shares (0,1) must reconstruct secret"
        );

        // Combination (0, 2)
        let rec02 = join_shares(&shares[0], &shares[2]);
        assert_eq!(
            rec02,
            secret.to_vec(),
            "Shares (0,2) must reconstruct secret"
        );

        // Combination (1, 2)
        let rec12 = join_shares(&shares[1], &shares[2]);
        assert_eq!(
            rec12,
            secret.to_vec(),
            "Shares (1,2) must reconstruct secret"
        );

        // All 3 shares together must also reconstruct secret
        let rec_all = join_share_slice(&[&shares[0], &shares[1], &shares[2]]);
        assert_eq!(
            rec_all,
            secret.to_vec(),
            "All 3 shares must reconstruct secret"
        );
    }

    #[test]
    fn test_shamir_split_secret_mut_compatibility() {
        let mut secret = [0x99u8; 32];
        let shares = split_secret(&mut secret);
        assert_eq!(shares.len(), 3);
        let rec = join_shares(&shares[0], &shares[1]);
        assert_eq!(rec, [0x99u8; 32].to_vec());
    }

    #[test]
    fn test_shamir_distinct_shares() {
        let secret = [0x17u8; 32];
        let shares = split_secret_bytes(&secret);
        assert_ne!(shares[0], shares[1], "Share 0 and 1 must differ");
        assert_ne!(shares[0], shares[2], "Share 0 and 2 must differ");
        assert_ne!(shares[1], shares[2], "Share 1 and 2 must differ");
    }

    #[test]
    fn test_shamir_corrupted_share_fails_or_mismatches() {
        let secret = [0xAAu8; 32];
        let shares = split_secret_bytes(&secret);
        let mut corrupted_share1 = shares[1].clone();
        if let Some(b) = corrupted_share1.last_mut() {
            *b ^= 0xFF;
        }
        let rec = join_shares(&shares[0], &corrupted_share1);
        assert_ne!(
            rec,
            secret.to_vec(),
            "Corrupted share must not reconstruct secret"
        );
    }

    #[test]
    fn test_threshold_group_key_3_of_5_governance() {
        let group_id = [0x77u8; 16];
        let master_secret = [0x35u8; 32];
        let group = ThresholdGroupKey::new_3_of_5(group_id, &master_secret);
        assert_eq!(group.shares.len(), 5, "Must generate exactly 5 shares");

        // Any 3 shares out of 5 must successfully reconstruct:
        // Combination (0, 1, 2)
        let rec012 =
            ThresholdGroupKey::reconstruct(&[&group.shares[0], &group.shares[1], &group.shares[2]])
                .expect("3 shares must reconstruct");
        assert_eq!(rec012, master_secret);

        // Combination (1, 3, 4)
        let rec134 =
            ThresholdGroupKey::reconstruct(&[&group.shares[1], &group.shares[3], &group.shares[4]])
                .expect("3 shares must reconstruct");
        assert_eq!(rec134, master_secret);

        // Capability token derivation matches
        let cap1 = ThresholdGroupKey::derive_group_capability(&rec012, 42, b"admin_scope");
        let cap2 = ThresholdGroupKey::derive_group_capability(&rec134, 42, b"admin_scope");
        assert_eq!(
            cap1, cap2,
            "Capability tokens derived from same secret must match"
        );

        // Different epoch or scope produces different capability
        let cap_diff = ThresholdGroupKey::derive_group_capability(&rec012, 43, b"admin_scope");
        assert_ne!(cap1, cap_diff);
    }

    #[test]
    fn test_threshold_group_insufficient_shares_rejected() {
        let group_id = [0x88u8; 16];
        let master_secret = [0x55u8; 32];
        let group = ThresholdGroupKey::new_3_of_5(group_id, &master_secret);

        // 2 shares must be rejected
        let res = ThresholdGroupKey::reconstruct(&[&group.shares[0], &group.shares[1]]);
        assert!(res.is_err(), "2 shares must not meet 3-of-5 threshold");
    }
}
