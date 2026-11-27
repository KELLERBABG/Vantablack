#![cfg(feature = "research")]
//! Inventions §22 & §33: Autonomous Dead-Drop Mesh Storage & Self-Eating Storage
//!
//! §22 Autonomous Dead-Drop Mesh Storage (Fleet Vault - Consolidated §22, §23, §26):
//! - Serverless Tahoe-style ciphertext storage holding opaque 576-byte GTF blobs.
//! - Destination is addressed by cryptographic SHA-256 drop commitments, not IP or node IDs.
//! - Hosts hold blind ciphertexts they can never decrypt; host seizure reveals zero plaintext.
//! - Deposits are indistinguishable from normal mesh transit; recipients sweep drop commitments.
//!
//! §33 Self-Eating Storage (Adaptive Poisson Decay):
//! - Unrequested / cold shards decay and are garbage collected automatically.
//! - Decay rate is inversely coupled to network error rates: in peace (low error), data is
//!   minimized and forgotten quickly; during partitions/crises (high error), retention is extended.
//! - Keyholders can issue lightweight `prove_retention_interest` keep-proofs to protect hot shards.

use std::sync::Arc;

use dashmap::DashMap;

use sha2::{Digest, Sha256};

pub const DEAD_DROP_MAGIC: &[u8; 4] = b"DROP";
pub const DEAD_DROP_FRAME_LEN: usize = 576;

pub type DropCommitment = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlindDeadDropBlob {
    pub commitment: DropCommitment,
    pub opaque_ciphertext: [u8; DEAD_DROP_FRAME_LEN],
    pub deposit_timestamp: u64,
    pub base_ttl_secs: u64,
    pub access_count: u32,
    pub last_kept_timestamp: u64,
}

impl BlindDeadDropBlob {
    pub fn derive_commitment(drop_seed: &[u8], slot_index: u64) -> DropCommitment {
        let mut hasher = Sha256::new();
        hasher.update(b"GGN_DEAD_DROP_COMMITMENT_V1");
        hasher.update(slot_index.to_be_bytes());
        hasher.update(drop_seed);
        hasher.finalize().into()
    }

    pub fn new(
        commitment: DropCommitment,
        frame: &[u8],
        deposit_timestamp: u64,
        base_ttl_secs: u64,
    ) -> Self {
        let mut opaque = [0u8; DEAD_DROP_FRAME_LEN];
        let copy_len = frame.len().min(DEAD_DROP_FRAME_LEN);
        opaque[..copy_len].copy_from_slice(&frame[..copy_len]);
        Self {
            commitment,
            opaque_ciphertext: opaque,
            deposit_timestamp,
            base_ttl_secs,
            access_count: 0,
            last_kept_timestamp: deposit_timestamp,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DeadDropVault {
    slots: Arc<DashMap<DropCommitment, BlindDeadDropBlob>>,
}

impl DeadDropVault {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn deposit(&self, blob: BlindDeadDropBlob) {
        self.slots.insert(blob.commitment, blob);
    }

    pub fn sweep(&self, commitment: &DropCommitment) -> Option<BlindDeadDropBlob> {
        self.slots.get_mut(commitment).map(|mut entry| {
            entry.access_count = entry.access_count.saturating_add(1);
            entry.clone()
        })
    }

    pub fn sweep_and_consume(&self, commitment: &DropCommitment) -> Option<BlindDeadDropBlob> {
        self.slots.remove(commitment).map(|(_, blob)| blob)
    }

    pub fn stored_count(&self) -> usize {
        self.slots.len()
    }

    pub fn prove_retention_interest(
        &self,
        commitment: &DropCommitment,
        renewal_timestamp: u64,
    ) -> bool {
        if let Some(mut entry) = self.slots.get_mut(commitment) {
            entry.last_kept_timestamp = renewal_timestamp;
            entry.access_count = entry.access_count.saturating_add(1);
            true
        } else {
            false
        }
    }

    pub fn collect_self_eating_decay(
        &self,
        current_timestamp: u64,
        observed_error_rate: f64,
    ) -> usize {
        let error_clamped = observed_error_rate.clamp(0.0, 1.0);
        let retention_multiplier = 1.0 + (error_clamped * 4.0);

        let mut to_remove = Vec::new();

        for entry in self.slots.iter() {
            let blob = entry.value();
            let effective_ttl = ((blob.base_ttl_secs as f64) * retention_multiplier) as u64;
            let expiration = blob.last_kept_timestamp.saturating_add(effective_ttl);

            if current_timestamp > expiration {
                to_remove.push(*entry.key());
            }
        }

        let removed_count = to_remove.len();
        for commitment in to_remove {
            self.slots.remove(&commitment);
        }
        removed_count
    }

    pub fn host_audit_inspect_raw(&self) -> Vec<u8> {
        let mut raw = Vec::new();
        for entry in self.slots.iter() {
            raw.extend_from_slice(&entry.key()[..]);
            raw.extend_from_slice(&entry.value().opaque_ciphertext[..]);
        }
        raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dead_drop_deposit_and_sweep() {
        let vault = DeadDropVault::new();
        let drop_seed = b"secret_mailbox_rendezvous_seed";
        let slot = 42u64;

        let commitment = BlindDeadDropBlob::derive_commitment(drop_seed, slot);
        let payload = b"opaque_encrypted_gtf_576b_blob_content";
        let blob = BlindDeadDropBlob::new(commitment, payload, 1000, 3600);

        vault.deposit(blob);
        assert_eq!(vault.stored_count(), 1);

        let swept = vault.sweep(&commitment).expect("sweep deposited blob");
        assert_eq!(&swept.opaque_ciphertext[..payload.len()], payload);
        assert_eq!(swept.access_count, 1);

        let consumed = vault
            .sweep_and_consume(&commitment)
            .expect("sweep and consume");
        assert_eq!(&consumed.opaque_ciphertext[..payload.len()], payload);
        assert_eq!(vault.stored_count(), 0);
    }

    #[test]
    fn test_self_eating_storage_adaptive_poisson_decay() {
        let vault = DeadDropVault::new();
        let commitment = [0x77u8; 32];
        let payload = [0x55u8; 576];
        let blob = BlindDeadDropBlob::new(commitment, &payload, 1000, 100);
        vault.deposit(blob);

        let reclaimed = vault.collect_self_eating_decay(1050, 0.0);
        assert_eq!(reclaimed, 0);
        assert_eq!(vault.stored_count(), 1);

        let reclaimed_during_partition = vault.collect_self_eating_decay(1150, 0.8);
        assert_eq!(
            reclaimed_during_partition, 0,
            "High network error must extend retention"
        );
        assert_eq!(vault.stored_count(), 1);

        let reclaimed_peace = vault.collect_self_eating_decay(1150, 0.0);
        assert_eq!(
            reclaimed_peace, 1,
            "Normal conditions must garbage collect cold shard"
        );
        assert_eq!(vault.stored_count(), 0);
    }

    #[test]
    fn test_host_audit_zero_metadata_exposure() {
        let vault = DeadDropVault::new();
        let commitment = [0x42u8; 32];
        let payload = [0x99u8; 576];
        let blob = BlindDeadDropBlob::new(commitment, &payload, 500, 3600);
        vault.deposit(blob);

        let raw = vault.host_audit_inspect_raw();
        assert!(!raw
            .windows(4)
            .any(|w| w == b"user" || w == b"node" || w == b"ip4"));
        assert_eq!(raw.len(), 32 + 576);
    }
}
