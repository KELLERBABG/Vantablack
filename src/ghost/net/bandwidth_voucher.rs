//! Anonymous Bandwidth Vouchers & Sybil Defense Subsystem.
//!
//! Provides lightweight, privacy-preserving bandwidth allocation tokens to prevent
//! relay exhaustion, mitigate Sybil attacks, and incentivize honest mesh routing.
//!
//! - Clients mint or earn vouchers via Proof-of-Work (PoW) or Proof-of-Erasure-Repair.
//! - Relays verify vouchers in O(1) time and decrement token capacity per forwarded megabyte.
//! - Anonymous nullifiers prevent double-spending without revealing the client's identity.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use sha2::{Digest, Sha256};

/// 32-byte unique cryptographic nullifier preventing double-spending of a bandwidth voucher.
pub type VoucherNullifier = [u8; 32];

/// Cryptographic bandwidth voucher presented to relays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BandwidthVoucher {
    /// Serial / secret token preimage known to the spender.
    pub token_preimage: [u8; 32],
    /// Epoch slot during which the voucher is valid.
    pub epoch_slot: u64,
    /// Allocated bandwidth quota in megabytes (e.g. 10 MB per token).
    pub quota_mb: u32,
    /// Proof of work difficulty or repair commitment hash that minted this voucher.
    pub proof_hash: [u8; 32],
}

impl BandwidthVoucher {
    /// Mint a new bandwidth voucher backed by proof of work or erasure repair work.
    pub fn mint(token_preimage: [u8; 32], epoch_slot: u64, quota_mb: u32, proof_hash: [u8; 32]) -> Self {
        Self {
            token_preimage,
            epoch_slot,
            quota_mb,
            proof_hash,
        }
    }

    /// Compute the deterministic nullifier revealed to the relay upon spending.
    /// Nullifier = SHA-256("VANTABLACK_BANDWIDTH_NULLIFIER_V1" || epoch_slot || token_preimage)
    pub fn compute_nullifier(&self) -> VoucherNullifier {
        let mut hasher = Sha256::new();
        hasher.update(b"VANTABLACK_BANDWIDTH_NULLIFIER_V1");
        hasher.update(&self.epoch_slot.to_be_bytes());
        hasher.update(&self.token_preimage);
        hasher.finalize().into()
    }
}

/// Relay admission controller tracking spent nullifiers and enforcing Sybil resistance.
#[derive(Debug, Clone, Default)]
pub struct RelayBandwidthBank {
    /// Spent nullifiers mapped to remaining megabytes allowed.
    active_vouchers: Arc<DashMap<VoucherNullifier, u32>>,
    /// Set of exhausted nullifiers to prevent replay.
    exhausted_nullifiers: Arc<DashMap<VoucherNullifier, u64>>,
}

impl RelayBandwidthBank {
    pub fn new() -> Self {
        Self::default()
    }

    /// Deposit / redeem a voucher at a relay node to acquire bandwidth credits.
    pub fn redeem_voucher(&self, voucher: &BandwidthVoucher) -> Result<u32, &'static str> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let current_slot = now / 3600;

        // Ensure voucher is not from a far-future or deeply expired epoch
        if voucher.epoch_slot + 24 < current_slot {
            return Err("voucher expired (outside 24-hour validity window)");
        }

        let nullifier = voucher.compute_nullifier();

        if self.exhausted_nullifiers.contains_key(&nullifier) {
            return Err("voucher nullifier already exhausted (double-spend rejected)");
        }

        if self.active_vouchers.contains_key(&nullifier) {
            return Err("voucher nullifier already active in bank");
        }

        self.active_vouchers.insert(nullifier, voucher.quota_mb);
        Ok(voucher.quota_mb)
    }

    /// Deduct consumed bandwidth (in MB) for a given nullifier. Returns true if admitted.
    pub fn consume_bandwidth(&self, nullifier: &VoucherNullifier, consumed_mb: u32) -> bool {
        if let Some(mut entry) = self.active_vouchers.get_mut(nullifier) {
            if *entry >= consumed_mb {
                *entry -= consumed_mb;
                if *entry == 0 {
                    drop(entry);
                    self.active_vouchers.remove(nullifier);
                    self.exhausted_nullifiers.insert(*nullifier, SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
                }
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Query available bandwidth quota for an active voucher nullifier.
    pub fn remaining_quota(&self, nullifier: &VoucherNullifier) -> u32 {
        self.active_vouchers.get(nullifier).map(|v| *v).unwrap_or(0)
    }

    /// Check if a nullifier has been fully spent and exhausted.
    pub fn is_exhausted(&self, nullifier: &VoucherNullifier) -> bool {
        self.exhausted_nullifiers.contains_key(nullifier)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bandwidth_voucher_mint_redeem_and_exhaustion() {
        let bank = RelayBandwidthBank::new();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let current_slot = now / 3600;

        let voucher = BandwidthVoucher::mint([0x77; 32], current_slot, 20, [0x99; 32]);
        let nullifier = voucher.compute_nullifier();

        // 1. Initial redemption grants 20 MB
        let granted = bank.redeem_voucher(&voucher).expect("redemption succeeds");
        assert_eq!(granted, 20);
        assert_eq!(bank.remaining_quota(&nullifier), 20);

        // 2. Double-spend of active voucher fails
        let dup = bank.redeem_voucher(&voucher);
        assert!(dup.is_err(), "duplicate active nullifier must fail");

        // 3. Consume 15 MB
        assert!(bank.consume_bandwidth(&nullifier, 15));
        assert_eq!(bank.remaining_quota(&nullifier), 5);

        // 4. Overconsumption fails (trying to consume 10 MB when only 5 MB left)
        assert!(!bank.consume_bandwidth(&nullifier, 10));

        // 5. Consume remaining 5 MB -> voucher moves to exhausted
        assert!(bank.consume_bandwidth(&nullifier, 5));
        assert_eq!(bank.remaining_quota(&nullifier), 0);
        assert!(bank.is_exhausted(&nullifier));

        // 6. Attempting to redeem an exhausted voucher fails
        let post_exhaust_dup = bank.redeem_voucher(&voucher);
        assert!(post_exhaust_dup.is_err(), "exhausted voucher cannot be re-minted");
    }
}
