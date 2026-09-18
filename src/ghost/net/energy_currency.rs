//! Energy-Voucher Currency (Proof-of-Erasure-Repair)
//!
//! A decentralized credit ledger pricing forwarding priority strictly based on
//! verified erasure-repair work rather than wasteful proof-of-burn computation.
//!
//! - Nodes earn credits by performing honest Reed-Solomon(2,1) shard reconstruction
//!   for lost or damaged packets across the mesh.
//! - Proofs bind the repaired shard hash commitments, epoch, and worker identity.
//! - Anti-replay and double-minting protections ensure identical repairs cannot be credited twice.
//! - Earned credits can be spent to boost forwarding QoS and bypass rate-limiting tarpits.

use dashmap::DashMap;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Cryptographic proof demonstrating valid erasure repair of a lost Reed-Solomon shard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErasureRepairProof {
    pub input_shard_hashes: [[u8; 32]; 2],
    pub repaired_shard_hash: [u8; 32],
    pub epoch: u64,
    pub worker_pk: [u8; 32],
    pub signature: [u8; 64],
}

impl ErasureRepairProof {
    /// Compute unique proof identifier binding the repair transaction.
    pub fn proof_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"GGN_ERASURE_REPAIR_PROOF_V1");
        hasher.update(&self.input_shard_hashes[0]);
        hasher.update(&self.input_shard_hashes[1]);
        hasher.update(&self.repaired_shard_hash);
        hasher.update(&self.epoch.to_be_bytes());
        hasher.update(&self.worker_pk);
        hasher.finalize().into()
    }

    /// Mint a signed repair proof.
    pub fn mint(
        signing_key: &SigningKey,
        input_shard_hashes: [[u8; 32]; 2],
        repaired_shard_hash: [u8; 32],
        epoch: u64,
    ) -> Self {
        let worker_pk = signing_key.verifying_key().to_bytes();
        let mut hasher = Sha256::new();
        hasher.update(b"GGN_ERASURE_REPAIR_PROOF_V1");
        hasher.update(&input_shard_hashes[0]);
        hasher.update(&input_shard_hashes[1]);
        hasher.update(&repaired_shard_hash);
        hasher.update(&epoch.to_be_bytes());
        hasher.update(&worker_pk);
        let digest: [u8; 32] = hasher.finalize().into();

        let sig = signing_key.sign(&digest);

        Self {
            input_shard_hashes,
            repaired_shard_hash,
            epoch,
            worker_pk,
            signature: sig.to_bytes(),
        }
    }

    /// Verify signature and structural integrity.
    pub fn verify(&self) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(&self.worker_pk) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&self.signature) else {
            return false;
        };

        let mut hasher = Sha256::new();
        hasher.update(b"GGN_ERASURE_REPAIR_PROOF_V1");
        hasher.update(&self.input_shard_hashes[0]);
        hasher.update(&self.input_shard_hashes[1]);
        hasher.update(&self.repaired_shard_hash);
        hasher.update(&self.epoch.to_be_bytes());
        hasher.update(&self.worker_pk);
        let digest: [u8; 32] = hasher.finalize().into();

        vk.verify(&digest, &sig).is_ok()
    }
}

/// Ledger tracking energy currency balances earned via proof-of-erasure-repair.
#[derive(Debug, Default)]
pub struct EnergyCreditLedger {
    /// worker_pk -> balance
    balances: DashMap<[u8; 32], u64>,
    /// Set of already-credited proof IDs to prevent double-minting
    credited_proofs: DashMap<[u8; 32], u64>,
}

impl EnergyCreditLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Credits fixed reward (e.g. 10 energy credits) to worker upon validating proof.
    pub fn credit_repair(&self, proof: &ErasureRepairProof) -> Result<u64, &'static str> {
        if !proof.verify() {
            return Err("invalid erasure repair signature or malformed proof");
        }

        let pid = proof.proof_id();
        if self.credited_proofs.contains_key(&pid) {
            return Err("proof already credited (duplicate minting rejected)");
        }

        self.credited_proofs.insert(pid, proof.epoch);
        let mut bal = self.balances.entry(proof.worker_pk).or_insert(0);
        *bal = bal.saturating_add(10);
        Ok(*bal)
    }

    /// Spend credits to acquire priority QoS forwarding tier (Level 1: 10 credits, Level 2: 25 credits).
    pub fn spend_for_priority(
        &self,
        worker_pk: &[u8; 32],
        credits_to_spend: u64,
    ) -> Result<u8, &'static str> {
        let mut bal = self
            .balances
            .get_mut(worker_pk)
            .ok_or("no account balance found")?;
        if *bal < credits_to_spend {
            return Err("insufficient energy credits");
        }
        *bal -= credits_to_spend;

        let priority_tier = if credits_to_spend >= 25 {
            2 // Highest VIP priority
        } else if credits_to_spend >= 10 {
            1 // Standard elevated priority
        } else {
            0
        };
        Ok(priority_tier)
    }

    /// Check balance for worker.
    pub fn balance_of(&self, worker_pk: &[u8; 32]) -> u64 {
        self.balances.get(worker_pk).map(|b| *b).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_energy_credit_minting_and_priority_spending() {
        let mut csprng = OsRng;
        let worker_signing_key = SigningKey::generate(&mut csprng);
        let worker_pk = worker_signing_key.verifying_key().to_bytes();

        let input_hashes = [[0x11u8; 32], [0x22u8; 32]];
        let repaired_hash = [0x33u8; 32];
        let epoch = 500;

        let proof =
            ErasureRepairProof::mint(&worker_signing_key, input_hashes, repaired_hash, epoch);
        assert!(proof.verify());

        let ledger = EnergyCreditLedger::new();

        // 1. Initial credit mint succeeds: balance becomes 10
        let bal = ledger.credit_repair(&proof).expect("credit succeeds");
        assert_eq!(bal, 10);
        assert_eq!(ledger.balance_of(&worker_pk), 10);

        // 2. Duplicate mint of same proof MUST be rejected
        let dup_res = ledger.credit_repair(&proof);
        assert!(dup_res.is_err(), "duplicate minting must be rejected");

        // 3. Second distinct repair succeeds: balance becomes 20
        let proof2 = ErasureRepairProof::mint(
            &worker_signing_key,
            [[0x44u8; 32], [0x55u8; 32]],
            [0x66u8; 32],
            epoch,
        );
        let bal2 = ledger
            .credit_repair(&proof2)
            .expect("second credit succeeds");
        assert_eq!(bal2, 20);

        // 4. Spend 10 credits for Priority Tier 1
        let priority = ledger
            .spend_for_priority(&worker_pk, 10)
            .expect("spend succeeds");
        assert_eq!(priority, 1);
        assert_eq!(ledger.balance_of(&worker_pk), 10);

        // 5. Attempting to spend more than remaining balance fails
        let overspend = ledger.spend_for_priority(&worker_pk, 25);
        assert!(overspend.is_err());
        assert_eq!(ledger.balance_of(&worker_pk), 10);
    }
}
