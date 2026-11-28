//! Dedicated integration tests for the seven Tier 1 modules wired by
//! `docs/DORMANT_MODULES.md` (`cargo test --features research --test research_tier1`).
//!
//! Each test pins the property the daemon relies on. The daemon-side composition
//! itself (vault sealing, braid gossip, voucher admission, path probes) is covered
//! by the unit tests in `src/daemon/research_hooks.rs`, which live in the binary.
#![cfg(feature = "research")]

use std::collections::BTreeSet;

use curve25519_dalek::scalar::Scalar;
use vantablack::ghost::net::{
    bandwidth_voucher::{BandwidthVoucher, RelayBandwidthBank},
    braid_identity::{gossip_rounds_to_collision, BraidChain, BraidLock, BraidVerdict, Transition},
    dead_drop::{BlindDeadDropBlob, DeadDropVault},
    entropy_beacon::{EntropyBeaconCommons, EntropyShare},
    mesh_archive::ArchivalRecord,
    polysemy::PolysemicCode,
};
use vantablack::ghost::v2::erosion::{
    bundle_point, combine_partials, open_bundle, seal_bundle, EphemerizerCommittee,
    PartialEvaluation,
};

const NOW: u64 = 1_800_000_000;

// ── 1. braid_identity ───────────────────────────────────────────────────────

#[test]
fn braid_identity_a_clone_forks_and_the_pair_is_a_self_authenticating_revocation() {
    let mut real = BraidLock::from_seed([0x21; 32]);
    let mut clone = BraidLock::restore(real.secret_state().0, real.braid(), real.height());

    let a = real.advance(b"Wi-Fi transcript");
    let b = clone.advance(b"5G transcript");
    assert_eq!(a.parent_pk, b.parent_pk);
    assert_ne!(a.next_pk, b.next_pk);

    let mut chain = BraidChain::new();
    assert_eq!(chain.accept(&a), BraidVerdict::Extended);
    let BraidVerdict::Fork(proof) = chain.accept(&b) else {
        panic!("two children of one key are a fork");
    };
    assert_eq!(proof.equivocating_key(), a.parent_pk);
    assert!(proof.a.verify() && proof.b.verify());
    assert_eq!(proof.to_bytes().len(), 400, "two 200-byte transitions");
    assert!(chain.is_revoked(&a.parent_pk));
    // Monotone: the honest half is dead too.
    assert_eq!(chain.accept(&a), BraidVerdict::Revoked(a.parent_pk));

    // A skipped height cannot dodge detection: one child per parent, forever.
    assert_eq!(chain.revoked_count(), 1);
    assert_eq!(Transition::from_bytes(&a.to_bytes()), Some(a));
}

#[test]
fn braid_identity_the_collision_bound_is_the_documented_theorem() {
    let rounds = gossip_rounds_to_collision(1_000_000, 4, 1e-6).expect("valid bound");
    assert!((rounds - 5.93).abs() < 0.01, "got {rounds}");
    assert!(gossip_rounds_to_collision(1_000_000, 8, 1e-6).unwrap() < rounds);
    assert_eq!(gossip_rounds_to_collision(10, 1, 1e-6), None);
}

// ── 2. erosion ──────────────────────────────────────────────────────────────

#[test]
fn erosion_a_bundle_is_readable_only_while_two_of_three_shares_exist() {
    let (mut committee, _public) =
        EphemerizerCommittee::from_secret(2, 3, NOW + 10_000, Scalar::from(7u64))
            .expect("2-of-3 committee");
    let bundle_id = [0x31; 32];
    let key = [0x44; 32];
    let sealed = seal_bundle(&committee, &bundle_id, NOW + 600, &key, NOW).expect("seals");

    assert_eq!(open_bundle(&committee, &sealed, NOW + 1).unwrap(), key);
    // At the deadline the key is mathematically gone.
    assert!(open_bundle(&committee, &sealed, NOW + 600).is_err());

    // Retiring one share still leaves threshold; retiring a second is oblivion.
    committee.retire(2);
    assert_eq!(open_bundle(&committee, &sealed, NOW + 1).unwrap(), key);
    committee.retire(0);
    assert_eq!(committee.retained_shares(), 1);
    assert!(open_bundle(&committee, &sealed, NOW + 1).is_err());
    assert_eq!(committee.evaluate(0, &bundle_point(&bundle_id)), None);
}

#[test]
fn erosion_a_dishonest_partial_evaluation_is_refused_by_its_dleq() {
    let (committee, _public) =
        EphemerizerCommittee::from_secret(2, 3, NOW + 10_000, Scalar::from(11u64))
            .expect("committee");
    let bundle_id = [0x32; 32];
    let blinded = Scalar::from(5u64) * bundle_point(&bundle_id);
    let p0 = committee.evaluate(0, &blinded).expect("member 0");
    let p1 = committee.evaluate(1, &blinded).expect("member 1");
    let impostor = PartialEvaluation {
        index: 0,
        evaluation: p1.evaluation,
        proof: p1.proof.clone(),
    };
    assert!(combine_partials(
        committee.commitments(),
        2,
        &blinded,
        &[impostor, p0.clone()]
    )
    .is_err());
    assert!(combine_partials(committee.commitments(), 2, &blinded, &[p0]).is_err());
}

// ── 3. dead_drop ────────────────────────────────────────────────────────────

#[test]
fn dead_drop_blind_chunks_sweep_only_by_commitment_and_decay_adaptively() {
    let vault = DeadDropVault::new();
    let commitment = BlindDeadDropBlob::derive_commitment(b"drop seed", 17);
    let payload = [0x5A; 576];
    vault.deposit(BlindDeadDropBlob::new(commitment, &payload, 1_000, 100));
    assert_eq!(vault.stored_count(), 1);

    // A wrong commitment reveals nothing and consumes nothing.
    let wrong = BlindDeadDropBlob::derive_commitment(b"other seed", 17);
    assert!(vault.sweep(&wrong).is_none());
    assert_eq!(vault.stored_count(), 1);

    // Peace-time retention is the base TTL; a partition stretches it.
    assert_eq!(vault.collect_self_eating_decay(1_150, 0.8), 0);
    assert_eq!(vault.stored_count(), 1);
    assert_eq!(vault.collect_self_eating_decay(1_150, 0.0), 1);
    assert_eq!(vault.stored_count(), 0);

    // A fresh deposit is swept exactly once.
    vault.deposit(BlindDeadDropBlob::new(commitment, &payload, 2_000, 100));
    assert_eq!(
        vault.sweep_and_consume(&commitment).unwrap().access_count,
        0
    );
    assert!(vault.sweep_and_consume(&commitment).is_none());
}

// ── 4. entropy_beacon ───────────────────────────────────────────────────────

#[test]
fn entropy_beacon_output_is_threshold_and_contributor_order_independent() {
    let round = 4_242u64;
    let a = EntropyShare::new(round, [0x0A; 32], [0xA1; 32]);
    let b = EntropyShare::new(round, [0x0B; 32], [0xB2; 32]);
    let c = EntropyShare::new(round, [0x0C; 32], [0xC3; 32]);

    let mut first = EntropyBeaconCommons::new(3);
    first.submit_share(a.clone());
    first.submit_share(b.clone());
    assert!(first.try_finalize_round(round).is_none(), "below threshold");

    first.submit_share(c.clone());
    let output = first.try_finalize_round(round).expect("threshold reached");
    assert_eq!(output.participant_count, 3);

    let mut second = EntropyBeaconCommons::new(3);
    second.submit_share(c);
    second.submit_share(a);
    second.submit_share(b);
    assert_eq!(
        second.try_finalize_round(round).unwrap().beacon_digest,
        output.beacon_digest,
        "aggregation sorts contributors, so arrival order cannot steer it"
    );

    // Round retention is bounded by the caller's policy, and pruning is exact.
    second.submit_share(EntropyShare::new(round - 5, [0x0D; 32], [0xD4; 32]));
    second.retain_rounds(|r| r + 2 >= round);
    assert_eq!(second.round_count(), 1);
}

// ── 5. polysemy ─────────────────────────────────────────────────────────────

#[test]
fn polysemy_every_surviving_subset_collapses_its_own_world_and_hides_the_rest() {
    let code = PolysemicCode::new(3, 2, 2).expect("3-path link");
    assert_eq!(code.world_count(), 3);
    assert_eq!(code.shard_len(), 4, "C(n-1,k-1)*r");
    let worlds = vec![vec![0x11, 0x12], vec![0x21, 0x22], vec![0x31, 0x32]];
    let shards = code.encode(&worlds).expect("encodes");
    for (index, subset) in code.world_subsets().iter().enumerate() {
        assert_eq!(&code.collapse(&shards, subset).unwrap(), &worlds[index]);
        assert_eq!(code.world_index(subset), Some(index));
    }

    // 0-bit counterfactual leakage: hold paths 1 and 2, and every one of the
    // 256 candidate values for the hidden world {0,1} is consistent with those
    // exact shards once the mask is chosen to match.
    let unit = PolysemicCode::new(3, 2, 1).unwrap();
    let unit_worlds = vec![vec![0xAAu8], vec![0xBB], vec![0xCC]];
    let masks = vec![vec![vec![0x11u8]], vec![vec![0x22]], vec![vec![0x33]]];
    let unit_shards = unit
        .encode_with_masks(&unit_worlds, &masks)
        .expect("pinned masks");
    let mut reachable = BTreeSet::new();
    for candidate in 0u16..=255 {
        let mut alt_masks = masks.clone();
        alt_masks[0][0][0] = unit_shards[1][0] ^ candidate as u8;
        let mut alt_worlds = unit_worlds.clone();
        alt_worlds[0] = vec![candidate as u8];
        let rebuilt = unit.encode_with_masks(&alt_worlds, &alt_masks).unwrap();
        assert_eq!(rebuilt[1], unit_shards[1], "path 1 does not move");
        assert_eq!(rebuilt[2], unit_shards[2], "path 2 does not move");
        reachable.insert(candidate);
    }
    assert_eq!(reachable.len(), 256, "the hidden world is uniform");
    assert!(code.collapse(&shards, &[0]).is_err());
    assert!(code.collapse(&shards, &[0, 1, 2]).is_err());
}

// ── 6. mesh_archive ─────────────────────────────────────────────────────────

#[test]
fn mesh_archive_any_two_shards_reconstruct_and_tampering_fails_the_hash() {
    let document = b"RFC 9591 FROST threshold signatures, archived across the mesh";
    let archive = ArchivalRecord::create("urn:standard:ietf:rfc9591".into(), document);
    assert_eq!(archive.shards.len(), 3);

    for (left, right) in [(0, 1), (0, 2), (1, 2)] {
        let mut slots = vec![None; 3];
        slots[left] = Some(archive.shards[left].clone());
        slots[right] = Some(archive.shards[right].clone());
        assert_eq!(archive.reconstruct(&slots).unwrap(), document);
    }

    // One shard is not enough; a corrupted pair is refused by the content hash.
    assert!(archive
        .reconstruct(&[Some(archive.shards[0].clone()), None, None])
        .is_err());
    let mut corrupted = archive.clone();
    corrupted.shards[0][0] ^= 0xFF;
    corrupted.shards[1][0] ^= 0xFF;
    let slots = vec![
        Some(corrupted.shards[0].clone()),
        Some(corrupted.shards[1].clone()),
        None,
    ];
    assert!(archive.reconstruct(&slots).is_err());
}

// ── 7. bandwidth_voucher ────────────────────────────────────────────────────

#[test]
fn bandwidth_voucher_a_nullifier_is_single_use_and_credit_is_finite() {
    let bank = RelayBandwidthBank::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let slot = now / 3_600;
    let voucher = BandwidthVoucher::mint([0x77; 32], slot, 10, [0x99; 32]);
    let nullifier = voucher.compute_nullifier();

    assert_eq!(bank.redeem_voucher(&voucher), Ok(10));
    assert!(
        bank.redeem_voucher(&voucher).is_err(),
        "double-spend refused"
    );
    assert!(bank.consume_bandwidth(&nullifier, 4));
    assert_eq!(bank.remaining_quota(&nullifier), 6);
    assert!(!bank.consume_bandwidth(&nullifier, 7), "overdraw refused");
    assert!(bank.consume_bandwidth(&nullifier, 6));
    assert!(bank.is_exhausted(&nullifier));
    assert!(
        bank.redeem_voucher(&voucher).is_err(),
        "exhausted stays spent"
    );

    // Epoch slots are part of the nullifier, and stale vouchers expire.
    let other_epoch = BandwidthVoucher::mint([0x77; 32], slot + 1, 10, [0x99; 32]);
    assert_ne!(other_epoch.compute_nullifier(), nullifier);
    let stale = BandwidthVoucher::mint([0x88; 32], slot.saturating_sub(25), 10, [0x99; 32]);
    assert!(bank.redeem_voucher(&stale).is_err());
}
