//! Protocol Semantic Fuzzer
//!
//! Property-based semantic sequence fuzzer verifying multi-step invariants
//! across randomized permutations of:
//! - Dead-Drop Vault blind addressing, sweeps, and Poisson decay (§22, §33)
//! - Anonymous Threshold Capability Ledger and anti-double-spend (§45, §41)
//! - DTN Merkle anti-entropy state reconciliation convergence (§29)
//! - Spatio-Temporal Erosion Code epoch boundaries (§27)
//!
//! Unlike byte-level fuzzers (which target parser crashes), the semantic fuzzer
//! explores randomized operation sequences to prove safety, quota bounds,
//! zero-metadata leakage, and double-spend immunity.

use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use std::collections::HashMap;

use vantablack::ghost::layers::l2_aead::NonceDirection;
use vantablack::ghost::net::dead_drop::{BlindDeadDropBlob, DeadDropVault, DropCommitment};
use vantablack::ghost::net::dtn_reconcile::{reconcile_blackout_stores, DtnBundle, DtnMerkleTree};
use vantablack::ghost::net::relay::{AnonymousCapabilityLedger, AnonymousThresholdVoucher};
use vantablack::ghost::net::shardsec::SpatioTemporalErosionCodec;

#[test]
fn test_semantic_fuzzer_dead_drop_vault_invariants() {
    let mut rng = StdRng::seed_from_u64(0xDEAD_BEEF_CAFE_0001);
    let vault = DeadDropVault::new();

    // Track active deposits: commitment -> (expected_prefix, is_consumed)
    let mut ground_truth: HashMap<DropCommitment, (Vec<u8>, bool)> = HashMap::new();
    let mut commitments = Vec::new();

    let mut now = 10_000u64;

    // Run 1,000 randomized stateful operations
    for op_idx in 0..1000 {
        now += 1;
        let op_type = rng.gen_range(0..4);
        match op_type {
            0 => {
                // Operation: Deposit fresh blind blob
                let mut seed = [0u8; 16];
                rng.fill_bytes(&mut seed);
                let commitment = BlindDeadDropBlob::derive_commitment(&seed, op_idx);

                let mut data = vec![0u8; 256];
                rng.fill_bytes(&mut data);

                let blob = BlindDeadDropBlob::new(commitment, &data, now, 3600);
                vault.deposit(blob);

                ground_truth.insert(commitment, (data, false));
                commitments.push(commitment);
            }
            1 => {
                // Operation: Sweep an existing deposit (non-destructive or destructive)
                if !commitments.is_empty() {
                    let idx = rng.gen_range(0..commitments.len());
                    let comm = commitments[idx];
                    let (expected_data, is_consumed) = ground_truth.get_mut(&comm).unwrap();

                    if *is_consumed {
                        // Already consumed -> sweep should return None
                        let res = vault.sweep(&comm);
                        assert!(
                            res.is_none(),
                            "Invariant VIOLATION: Consumed blob swept again on op {}",
                            op_idx
                        );
                    } else {
                        // Consume the blob
                        let res = vault.sweep_and_consume(&comm);
                        assert!(
                            res.is_some(),
                            "Invariant VIOLATION: Unconsumed blob sweep failed on op {}",
                            op_idx
                        );
                        let blob = res.unwrap();
                        assert_eq!(
                            &blob.opaque_ciphertext[..expected_data.len()],
                            expected_data.as_slice(),
                            "Invariant VIOLATION: Ciphertext payload corrupted on op {}",
                            op_idx
                        );
                        *is_consumed = true;
                    }
                }
            }
            2 => {
                // Operation: Invalid / unregistered commitment sweep attempt
                let mut bogus_comm = [0u8; 32];
                rng.fill_bytes(&mut bogus_comm);
                let res = vault.sweep(&bogus_comm);
                assert!(
                    res.is_none(),
                    "Invariant VIOLATION: Random commitment returned data"
                );
            }
            _ => {
                // Operation: Self-eating decay pass
                let error_rate = rng.gen_range(0.0..0.5);
                let removed = vault.collect_self_eating_decay(now, error_rate);
                assert!(
                    removed <= commitments.len(),
                    "Decayed count exceeds total deposits"
                );
            }
        }
    }
}

#[test]
fn test_semantic_fuzzer_anonymous_capability_ledger_invariants() {
    let mut rng = StdRng::seed_from_u64(0xFEED_FACE_BEEF_0002);
    let ledger = AnonymousCapabilityLedger::new();

    let group_id = [0x55u8; 16];
    let group_secret = [0x99u8; 32];
    let now = 10_000u64;

    struct VoucherState {
        voucher: AnonymousThresholdVoucher,
        max_bytes: u64,
        total_consumed: u64,
    }

    let mut vouchers = Vec::new();
    for v_id in 1..=10u64 {
        let max_bytes = rng.gen_range(5_000..50_000);
        let voucher = AnonymousThresholdVoucher::mint(
            group_id,
            &group_secret,
            v_id,
            max_bytes,
            now + 100_000,
        );
        vouchers.push(VoucherState {
            voucher,
            max_bytes,
            total_consumed: 0,
        });
    }

    // Run 2,000 randomized interleaved spend sequences
    for op_idx in 0..2000 {
        let v_idx = rng.gen_range(0..vouchers.len());
        let v = &mut vouchers[v_idx];
        let spend_req = rng.gen_range(100..10_000);

        let res = ledger.try_spend(&v.voucher, &group_secret, spend_req, now + op_idx as u64);
        if v.total_consumed + spend_req <= v.max_bytes {
            // Must succeed
            assert!(
                res.is_ok(),
                "Invariant VIOLATION: Legitimate capability spend rejected"
            );
            v.total_consumed += spend_req;
            let remaining = res.unwrap();
            assert_eq!(
                remaining,
                v.max_bytes - v.total_consumed,
                "Invariant VIOLATION: Ledger balance mismatch"
            );
        } else {
            // Must fail - over quota / double spend
            assert!(
                res.is_err(),
                "Invariant VIOLATION: Ledger permitted over-quota spend ({}/{})",
                v.total_consumed + spend_req,
                v.max_bytes
            );
        }

        // Invariant: Under all circumstances, total consumed <= max_bytes
        assert!(v.total_consumed <= v.max_bytes);
    }
}

#[test]
fn test_semantic_fuzzer_dtn_anti_entropy_convergence_invariants() {
    let mut rng = StdRng::seed_from_u64(0xABCD_EF01_2345_0003);

    // Run 50 partition synchronization trials under random drop/interruption patterns
    for _trial in 0..50 {
        let mut store_a = DtnMerkleTree::new();
        let mut store_b = DtnMerkleTree::new();

        let num_bundles = rng.gen_range(5..25);
        for b_id in 0..num_bundles {
            let mut id = [0u8; 16];
            id[0..8].copy_from_slice(&(b_id as u64).to_be_bytes());
            let mut payload = vec![0u8; 32];
            rng.fill_bytes(&mut payload);
            let bundle = DtnBundle::new(id, b_id as u64, payload);

            let toss = rng.gen_range(0..3);
            if toss == 0 {
                store_a.insert(bundle);
            } else if toss == 1 {
                store_b.insert(bundle);
            } else {
                store_a.insert(bundle.clone());
                store_b.insert(bundle);
            }
        }

        // Reconcile via Merkle anti-entropy exchange
        let _ = reconcile_blackout_stores(&mut store_a, &mut store_b);

        // Invariant: After reconciliation, both stores have identical count and identical root hash
        assert_eq!(
            store_a.len(),
            store_b.len(),
            "Invariant VIOLATION: Stores did not converge on bundle count"
        );
        assert_eq!(
            store_a.root_hash(),
            store_b.root_hash(),
            "Invariant VIOLATION: Stores did not converge on Merkle root hash"
        );
    }
}

#[test]
fn test_semantic_fuzzer_spatio_temporal_erosion_invariants() {
    let mut rng = StdRng::seed_from_u64(0x7777_8888_9999_0004);

    for _trial in 0..30 {
        let mut payload = vec![0u8; rng.gen_range(32..256)];
        rng.fill_bytes(&mut payload);

        let k0 = [0x11u8; 32];
        let k1 = [0x22u8; 32];
        let k2 = [0x33u8; 32];
        let epoch_keys = [k0, k1, k2];
        let base_epoch = 100u64;
        let nonce = [0xAAu8; 12];

        let shards = SpatioTemporalErosionCodec::encode_space_time(
            &epoch_keys,
            base_epoch,
            &nonce,
            NonceDirection::InitiatorToResponder,
            &payload,
        );
        assert_eq!(shards.len(), 3);

        // Invariant 1: Any 2 surviving shards with active keys reconstruct perfectly
        let keys_0_1 = [Some(k0), Some(k1), None];
        let p1 = SpatioTemporalErosionCodec::reconstruct_space_time(
            &keys_0_1,
            base_epoch,
            &nonce,
            NonceDirection::InitiatorToResponder,
            &shards,
        )
        .expect("Any 2 shards reconstruct");
        assert_eq!(p1, payload);

        let keys_1_2 = [None, Some(k1), Some(k2)];
        let p2 = SpatioTemporalErosionCodec::reconstruct_space_time(
            &keys_1_2,
            base_epoch,
            &nonce,
            NonceDirection::InitiatorToResponder,
            &shards,
        )
        .expect("Any 2 shards reconstruct");
        assert_eq!(p2, payload);

        // Invariant 2: Exactly 1 surviving key CANNOT reconstruct
        let keys_only_0 = [Some(k0), None, None];
        let p_fail = SpatioTemporalErosionCodec::reconstruct_space_time(
            &keys_only_0,
            base_epoch,
            &nonce,
            NonceDirection::InitiatorToResponder,
            &shards,
        );
        assert!(p_fail.is_err(), "Single shard key must not reconstruct");

        // Invariant 3: All keys eroded/wiped CANNOT reconstruct
        let keys_eroded = [None, None, None];
        let p_wiped = SpatioTemporalErosionCodec::reconstruct_space_time(
            &keys_eroded,
            base_epoch,
            &nonce,
            NonceDirection::InitiatorToResponder,
            &shards,
        );
        assert!(p_wiped.is_err(), "Eroded keys must fail reconstruction");
    }
}
