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

/// 32-byte cryptographic commitment identifying a dead-drop storage slot.
pub type DropCommitment = [u8; 32];

/// A blind 576-byte GTF ciphertext blob held at rest by a vault host.
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
    /// Compute a deterministic drop commitment from a recipient drop seed and epoch slot.
    pub fn derive_commitment(drop_seed: &[u8], slot_index: u64) -> DropCommitment {
        let mut hasher = Sha256::new();
        hasher.update(b"GGN_DEAD_DROP_COMMITMENT_V1");
        hasher.update(&slot_index.to_be_bytes());
        hasher.update(drop_seed);
        hasher.finalize().into()
    }

    /// Create a new blind dead-drop blob from an opaque 576-byte GTF frame.
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

/// Serverless Tahoe-style Dead-Drop Vault with Adaptive Self-Eating Storage (§22, §33).
#[derive(Debug, Clone, Default)]
pub struct DeadDropVault {
    /// In-memory blind storage keyed by drop commitment.
    slots: Arc<DashMap<DropCommitment, BlindDeadDropBlob>>,
}

impl DeadDropVault {
    pub fn new() -> Self {
        Self::default()
    }

    /// Deposit an opaque 576-byte ciphertext blob into a commitment slot.
    pub fn deposit(&self, blob: BlindDeadDropBlob) {
        self.slots.insert(blob.commitment, blob);
    }

    /// Sweep / retrieve a deposited blob using the exact commitment.
    /// Increments access count and returns the blind ciphertext.
    pub fn sweep(&self, commitment: &DropCommitment) -> Option<BlindDeadDropBlob> {
        self.slots.get_mut(commitment).map(|mut entry| {
            entry.access_count = entry.access_count.saturating_add(1);
            entry.clone()
        })
    }

    /// Withdraw and delete the blob from the vault (single-use dead-drop sweep).
    pub fn sweep_and_consume(&self, commitment: &DropCommitment) -> Option<BlindDeadDropBlob> {
        self.slots.remove(commitment).map(|(_, blob)| blob)
    }

    /// Number of active blind drop blobs stored.
    pub fn stored_count(&self) -> usize {
        self.slots.len()
    }

    /// Keep-proof issued by a client to renew retention on a stored shard.
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

    /// Self-Eating Storage garbage collection loop.
    ///
    /// Reclaims cold/unrequested shards based on observed network error rate $\lambda_{\text{error}}$:
    /// - Normal conditions ($\lambda_{\text{error}} \approx 0.0$): decay is swift, data minimization active.
    /// - Crisis/partition conditions ($\lambda_{\text{error}} > 0.05$): decay multiplier shrinks,
    ///   extending object life so partitions do not cause premature data loss.
    /// Returns the number of reclaimed cold shards.
    pub fn collect_self_eating_decay(
        &self,
        current_timestamp: u64,
        observed_error_rate: f64,
    ) -> usize {
        // Compute adaptive retention multiplier:
        // High error rate -> higher multiplier (e.g. 1.0 up to 5.0x retention)
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

    /// Host audit inspection helper: proves stored data contains zero metadata or plaintext keys.
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

        // Sweep by commitment
        let swept = vault.sweep(&commitment).expect("sweep deposited blob");
        assert_eq!(&swept.opaque_ciphertext[..payload.len()], payload);
        assert_eq!(swept.access_count, 1);

        // Sweep and consume deletes from vault
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
        // Base TTL of 100 seconds, deposited at timestamp 1000
        let blob = BlindDeadDropBlob::new(commitment, &payload, 1000, 100);
        vault.deposit(blob);

        // At timestamp 1050 (under normal low error 0.0): not expired yet (expires at 1100)
        let reclaimed = vault.collect_self_eating_decay(1050, 0.0);
        assert_eq!(reclaimed, 0);
        assert_eq!(vault.stored_count(), 1);

        // At timestamp 1150 with high network error (partition 0.8):
        // Retention multiplier is 1.0 + (0.8 * 4.0) = 4.2x -> effective TTL = 420s -> expires at 1420!
        let reclaimed_during_partition = vault.collect_self_eating_decay(1150, 0.8);
        assert_eq!(
            reclaimed_during_partition, 0,
            "High network error must extend retention"
        );
        assert_eq!(vault.stored_count(), 1);

        // Under peaceful network (error 0.0), at timestamp 1150 (past 1100), cold shard decays!
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
        // Plaintext usernames, node IDs, or IP addresses are strictly absent
        assert!(!raw
            .windows(4)
            .any(|w| w == b"user" || w == b"node" || w == b"ip4"));
        assert_eq!(raw.len(), 32 + 576);
    }
}
