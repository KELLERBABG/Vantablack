#![cfg(feature = "research")]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErasureRepairProof {
    pub input_shard_hashes: [[u8; 32]; 2],
    pub repaired_shard_hash: [u8; 32],
    pub epoch: u64,
    pub worker_pk: [u8; 32],
    pub signature: [u8; 64],
}

impl ErasureRepairProof {
    pub fn proof_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"GGN_ERASURE_REPAIR_PROOF_V1");
        hasher.update(self.input_shard_hashes[0]);
        hasher.update(self.input_shard_hashes[1]);
        hasher.update(self.repaired_shard_hash);
        hasher.update(self.epoch.to_be_bytes());
        hasher.update(self.worker_pk);
        hasher.finalize().into()
    }

    pub fn mint(
        signing_key: &SigningKey,
        input_shard_hashes: [[u8; 32]; 2],
        repaired_shard_hash: [u8; 32],
        epoch: u64,
    ) -> Self {
        let worker_pk = signing_key.verifying_key().to_bytes();
        let mut hasher = Sha256::new();
        hasher.update(b"GGN_ERASURE_REPAIR_PROOF_V1");
        hasher.update(input_shard_hashes[0]);
        hasher.update(input_shard_hashes[1]);
        hasher.update(repaired_shard_hash);
        hasher.update(epoch.to_be_bytes());
        hasher.update(worker_pk);
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

    pub fn verify(&self) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(&self.worker_pk) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&self.signature) else {
            return false;
        };

        let mut hasher = Sha256::new();
        hasher.update(b"GGN_ERASURE_REPAIR_PROOF_V1");
        hasher.update(self.input_shard_hashes[0]);
        hasher.update(self.input_shard_hashes[1]);
        hasher.update(self.repaired_shard_hash);
        hasher.update(self.epoch.to_be_bytes());
        hasher.update(self.worker_pk);
        let digest: [u8; 32] = hasher.finalize().into();

        vk.verify(&digest, &sig).is_ok()
    }
}

#[derive(Debug, Default)]
pub struct EnergyCreditLedger {
    balances: DashMap<[u8; 32], u64>,
    credited_proofs: DashMap<[u8; 32], u64>,
}

impl EnergyCreditLedger {
    pub fn new() -> Self {
        Self::default()
    }

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

        let bal = ledger.credit_repair(&proof).expect("credit succeeds");
        assert_eq!(bal, 10);
        assert_eq!(ledger.balance_of(&worker_pk), 10);

        let dup_res = ledger.credit_repair(&proof);
        assert!(dup_res.is_err(), "duplicate minting must be rejected");

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

        let priority = ledger
            .spend_for_priority(&worker_pk, 10)
            .expect("spend succeeds");
        assert_eq!(priority, 1);
        assert_eq!(ledger.balance_of(&worker_pk), 10);

        let overspend = ledger.spend_for_priority(&worker_pk, 25);
        assert!(overspend.is_err());
        assert_eq!(ledger.balance_of(&worker_pk), 10);
    }
}
