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
//!
//! **These shares are not transport shards.** A `(c, r, f)` multipath bond must
//! satisfy `m ≥ c + f + 1`; two carriers cannot give one-carrier secrecy *and*
//! one-outage recovery at once. That bound is enforced in [`crate::ghost::v2::hpeb`]
//! and [`crate::ghost::layers::l4_rs`].
//!
//! **One construction, two uses.** Generalized threshold sharing here is the
//! same GF(2^8) ramp engine as L4 with `r = 1`: a `(c, r = 1, f)` ramp code is
//! Shamir's scheme with threshold `c + 1` and `m = c + 1 + f` shares — any
//! `c + 1` reconstruct, any `c` learn nothing. The legacy 2-of-3 functions below
//! keep the historical `gf256` share encoding because OMR envelopes outlive an
//! upgrade; new threshold work goes through [`split_secret_ramp`] /
//! [`join_secret_ramp`], and [`ThresholdGroupKey`] is built on it.
use crate::ghost::layers::l4_rs;
use gf256::shamir::shamir;

/// Split a 32-byte secret into 3 shares using (2,3) Shamir SSS.
/// Returns 3 shares, each approximately sizeof(secret) + overhead.
pub fn split_secret(secret: &mut [u8; 32]) -> Vec<Vec<u8>> {
    shamir::generate(secret, 3, 2)
}

/// Split an immutable 32-byte secret slice into 3 shares using (2,3) Shamir SSS.
pub fn split_secret_bytes(secret: &[u8; 32]) -> Vec<Vec<u8>> {
    let mut copy = *secret;
    let shares = shamir::generate(&copy, 3, 2);
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
// Unified (c, r = 1, f) threshold sharing — the L4 ramp engine
// ═════════════════════════════════════════════════════════════════════════════

fn validate_threshold_params(params: &l4_rs::RampParams) -> Result<(), String> {
    if params.data != 1 {
        return Err("threshold secret sharing needs exactly one data symbol per block".into());
    }
    if params.masks == 0 {
        return Err("threshold secret sharing needs at least one mask symbol".into());
    }
    if params.shards < 3 {
        return Err(format!(
            "threshold secret sharing needs m >= 3, got {}",
            params.shards
        ));
    }
    if (params.shards as u16) <= params.masks as u16 + params.failures() as u16 {
        return Err("threshold parameters violate m >= c + f + 1".into());
    }
    Ok(())
}

/// Split a 32-byte secret with the same GF(2^8) ramp engine as L4.
///
/// With `r = 1`, `c = threshold − 1` and `f = m − threshold`, this is Shamir's
/// scheme expressed as a ramp code: any `c + 1` shares reconstruct, any `c`
/// shares are independent of the secret, and `m ≥ c + f + 1` holds because
/// `r ≥ 1`. Parameters with `r != 1`, `c = 0` (one share would reveal the
/// secret) or `m < 3` are refused rather than silently downgraded.
///
/// Each share is self-describing: `[index, 4-byte frame + 32 shard bytes]`, so
/// 37 bytes for a 32-byte secret (the frame is part of the coded message).
pub fn split_secret_ramp(
    secret: &[u8; 32],
    params: &l4_rs::RampParams,
) -> Result<Vec<Vec<u8>>, String> {
    validate_threshold_params(params)?;
    let shards = l4_rs::encode_ramp(secret, params)?;
    Ok(shards
        .into_iter()
        .enumerate()
        .map(|(index, bytes)| {
            let mut share = Vec::with_capacity(1 + bytes.len());
            share.push(index as u8);
            share.extend_from_slice(&bytes);
            share
        })
        .collect())
}

/// Reconstruct a 32-byte secret from `c + 1` or more self-describing shares.
///
/// Duplicate indices, indices outside `m`, wrong share lengths and fewer than
/// `c + 1` shares are all typed errors. A corrupted share past the threshold
/// decodes to different bytes; the caller's AEAD is what authenticates it (the
/// same division of labour as L4).
pub fn join_secret_ramp(shares: &[&[u8]], params: &l4_rs::RampParams) -> Result<[u8; 32], String> {
    validate_threshold_params(params)?;
    // The ramp block carries a 4-byte little-endian length frame before the
    // 32 secret bytes, so every share body is 36 bytes for a 32-byte secret.
    const EXPECTED_BODY: usize = 4 + 32;
    let mut parsed = Vec::with_capacity(shares.len());
    let mut seen = [false; 255];
    for share in shares {
        let (index, body) = share
            .split_first()
            .ok_or_else(|| "empty secret share".to_string())?;
        let index = *index;
        if index as usize >= params.shards as usize {
            return Err(format!(
                "share index {index} is outside m={}",
                params.shards
            ));
        }
        if seen[index as usize] {
            return Err(format!("share index {index} appears more than once"));
        }
        if body.len() != EXPECTED_BODY {
            return Err(format!(
                "a 32-byte secret share must carry {EXPECTED_BODY} shard bytes, got {}",
                body.len()
            ));
        }
        seen[index as usize] = true;
        parsed.push((index, body.to_vec()));
    }
    if parsed.len() < params.required() {
        return Err(format!(
            "insufficient shares: need {} of {}, got {}",
            params.required(),
            params.shards,
            parsed.len()
        ));
    }
    let decoded = l4_rs::decode_ramp(&parsed, params)
        .ok_or_else(|| "shares do not decode under these parameters".to_string())?;
    if decoded.len() != 32 {
        return Err("reconstructed secret is malformed".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}

// ═════════════════════════════════════════════════════════════════════════════
// Group-as-Shards (Threshold Governance)
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
    /// The `(c, r = 1, f)` ramp parameters this group was split under.
    pub params: l4_rs::RampParams,
}

impl ThresholdGroupKey {
    /// The fixed 3-of-5 policy: `c = 2`, `r = 1`, `f = 2`.
    fn three_of_five_params() -> l4_rs::RampParams {
        l4_rs::RampParams::new(2, 1, 2).expect("3-of-5 ramp parameters are valid")
    }

    /// Generate a 3-of-5 threshold group key set from a 32-byte group master secret.
    pub fn new_3_of_5(group_id: [u8; 16], secret: &[u8; 32]) -> Self {
        Self::with_params(group_id, secret, Self::three_of_five_params())
            .expect("3-of-5 ramp parameters are valid")
    }

    /// Generalized threshold group split: `threshold = c + 1` and
    /// `total_shares = m = c + 1 + f`. Built on the same ramp engine as L4.
    pub fn with_params(
        group_id: [u8; 16],
        secret: &[u8; 32],
        params: l4_rs::RampParams,
    ) -> Result<Self, String> {
        let shares = split_secret_ramp(secret, &params)?;
        Ok(Self {
            group_id,
            threshold: params.masks as usize + 1,
            total_shares: params.shards as usize,
            shares,
            params,
        })
    }

    /// Reconstruct the 3-of-5 group master secret from at least 3 shares.
    ///
    /// Kept as an associated function for the fixed governance policy; for a
    /// group created with [`Self::with_params`], use [`Self::reconstruct_with`].
    pub fn reconstruct(candidate_shares: &[&[u8]]) -> Result<[u8; 32], &'static str> {
        let params = Self::three_of_five_params();
        if candidate_shares.len() < params.required() {
            return Err("insufficient shares: threshold requires at least 3 of 5 shares");
        }
        join_secret_ramp(candidate_shares, &params)
            .map_err(|_| "shares do not reconstruct this group")
    }

    /// Reconstruct this group's secret with the parameters it was created under.
    pub fn reconstruct_with(&self, candidate_shares: &[&[u8]]) -> Result<[u8; 32], String> {
        join_secret_ramp(candidate_shares, &self.params)
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

    /// L3 is the same construction as L4 with `r = 1`: every threshold subset
    /// reconstructs and every smaller subset is refused, exhaustively.
    #[test]
    fn ramp_threshold_is_the_same_construction_as_l4() {
        let secret: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
        for (c, f) in [(1u8, 1u8), (2, 1), (2, 2), (3, 2)] {
            let m = c as usize + 1 + f as usize;
            let params = l4_rs::RampParams::new(c, 1, f).unwrap();
            let shares = split_secret_ramp(&secret, &params).unwrap();
            assert_eq!(shares.len(), m);
            assert!(
                shares.iter().all(|s| s.len() == 37),
                "index + 4-byte frame + 32 secret bytes"
            );

            for share in &shares {
                assert!(
                    !share.windows(8).any(|w| secret.windows(8).any(|s| s == w)),
                    "a single share leaked the secret"
                );
            }

            for bits in 0u16..(1u16 << m) {
                let subset: Vec<&[u8]> = (0..m)
                    .filter(|i| bits & (1u16 << i) != 0)
                    .map(|i| shares[i].as_slice())
                    .collect();
                let rec = join_secret_ramp(&subset, &params);
                if subset.len() > c as usize {
                    assert_eq!(rec.unwrap(), secret, "c={c} f={f} subset={bits:#b}");
                } else {
                    assert!(
                        rec.is_err(),
                        "c={c} f={f} subset={bits:#b} reconstructed below threshold"
                    );
                }
            }
        }
    }

    #[test]
    fn ramp_threshold_refuses_degenerate_parameters_and_bad_shares() {
        let secret = [0x11u8; 32];
        assert!(
            split_secret_ramp(&secret, &l4_rs::RampParams::new(0, 1, 1).unwrap()).is_err(),
            "c = 0 reveals the secret to one holder"
        );
        assert!(
            split_secret_ramp(&secret, &l4_rs::RampParams::new(1, 2, 1).unwrap()).is_err(),
            "threshold sharing is r = 1"
        );
        assert!(
            split_secret_ramp(&secret, &l4_rs::RampParams::new(1, 1, 0).unwrap()).is_err(),
            "m < 3 is not a threshold"
        );

        let params = l4_rs::RampParams::new(1, 1, 1).unwrap();
        let shares = split_secret_ramp(&secret, &params).unwrap();
        assert!(join_secret_ramp(&[&shares[0], &shares[0]], &params).is_err());

        let mut out_of_range = shares[0].clone();
        out_of_range[0] = 9;
        assert!(join_secret_ramp(&[&shares[1], &out_of_range], &params).is_err());

        let mut short = shares[1].clone();
        short.pop();
        assert!(join_secret_ramp(&[&shares[0], &short], &params).is_err());
    }

    #[test]
    fn threshold_group_key_uses_the_ramp_engine_for_all_three_of_five_subsets() {
        let secret = [0x6Cu8; 32];
        let group = ThresholdGroupKey::new_3_of_5([0x01u8; 16], &secret);
        assert_eq!(group.params.masks, 2);
        assert_eq!(group.params.data, 1);
        assert_eq!(group.params.failures(), 2);
        assert_eq!(group.threshold, 3);
        assert_eq!(group.total_shares, 5);

        for a in 0..5 {
            for b in (a + 1)..5 {
                for c in (b + 1)..5 {
                    let rec = group
                        .reconstruct_with(&[&group.shares[a], &group.shares[b], &group.shares[c]])
                        .unwrap();
                    assert_eq!(rec, secret, "subset ({a},{b},{c})");
                }
            }
        }

        let two: Vec<&[u8]> = group.shares.iter().take(2).map(|s| s.as_slice()).collect();
        assert!(group.reconstruct_with(&two).is_err());
    }
}
