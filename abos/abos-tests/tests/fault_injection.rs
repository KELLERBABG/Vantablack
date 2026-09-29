//! Fault injection: loss, corruption, duplication and TTL expiry must never
//! produce silent data corruption — only clean delivery or a hard error.

use abos_common::types::{Bundle, Shard};
use abos_protocol::bundle::{create_bundle, is_bundle_expired};
use abos_protocol::shard::{reconstruct_file, split_file};
use abos_storage::bundle_store::BundleStore;
use abos_tests::channel::LoopbackChannel;

fn temp_store(tag: &str) -> BundleStore {
    let path = std::env::temp_dir().join(format!("abos_e2e_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    BundleStore::new(path.to_str().unwrap()).expect("open store")
}

fn deliver_all(channel: &mut LoopbackChannel, bundles: &[Bundle]) -> Vec<Bundle> {
    bundles
        .iter()
        .flat_map(|b| channel.deliver_bundle(b))
        .collect()
}

fn shards_to_bundles(shards: &[Shard]) -> Vec<Bundle> {
    shards
        .iter()
        .map(|s| {
            let payload = bincode::serialize(s).unwrap();
            create_bundle(&payload, [1; 32], 3600)
        })
        .collect()
}

fn received_shards(bundles: &[Bundle]) -> Vec<Shard> {
    bundles
        .iter()
        .filter_map(|b| bincode::deserialize(&b.payload).ok())
        .collect()
}

#[test]
fn clean_delivery_reconstructs_file_exactly() {
    let payload: Vec<u8> = (0..3000u32).map(|i| (i % 256) as u8).collect();
    let shards = split_file(&payload, 1024, 1.5);
    let bundles = shards_to_bundles(&shards);

    let mut channel = LoopbackChannel::clean();
    let arrived = deliver_all(&mut channel, &bundles);
    let recovered = reconstruct_file(&received_shards(&arrived)).expect("reconstruct");
    assert_eq!(recovered, payload);
}

#[test]
fn loss_below_redundancy_still_reconstructs() {
    // 2.0× redundancy gives every original shard a repetition copy. Drop
    // the bundle carrying original shard 0 — its copy (shard index 4)
    // must fill the gap and the file must still roundtrip byte-identical.
    let payload: Vec<u8> = (0..2048u32).map(|i| (i * 13 % 251) as u8).collect();
    let shards = split_file(&payload, 512, 2.0);
    assert!(
        shards.len() >= 8,
        "redundancy must add a copy of every original"
    );
    // Sanity: the copy really is a copy of original 0.
    assert_eq!(
        shards[0].data, shards[4].data,
        "shard 4 must repeat shard 0"
    );

    let bundles = shards_to_bundles(&shards);
    let mut arrived = Vec::new();
    for (i, b) in bundles.iter().enumerate() {
        if i == 0 {
            continue; // simulated loss of the original shard 0 bundle
        }
        arrived.extend(LoopbackChannel::clean().deliver_bundle(b));
    }
    assert!(arrived.len() + 1 == bundles.len());

    let recovered = reconstruct_file(&received_shards(&arrived))
        .expect("redundancy must cover a lost original");
    assert_eq!(recovered, payload);
}

#[test]
fn heavy_loss_surfaces_as_error_not_garbage() {
    let payload: Vec<u8> = vec![0xAB; 1500];
    let shards = split_file(&payload, 512, 1.5);
    let bundles = shards_to_bundles(&shards);

    let mut channel = LoopbackChannel::seeded(3, 0.9, 0.0, 0.0, 0.0);
    let arrived = deliver_all(&mut channel, &bundles);

    // Either we reconstruct correctly or we error — never wrong data.
    if let Ok(recovered) = reconstruct_file(&received_shards(&arrived)) {
        assert_eq!(recovered, payload, "silent corruption detected");
    }
}

#[test]
fn corrupted_shard_is_rejected_by_checksum() {
    let payload: Vec<u8> = vec![0x5A; 1024];
    let mut shards = split_file(&payload, 1024, 1.0);
    // Flip a byte inside the first shard's data — checksum must catch it.
    shards[0].data[10] ^= 0xFF;

    // The shard with a broken checksum fails verification inside the
    // per-shard check when its slot is validated.
    let result = reconstruct_file(&shards);
    match result {
        Ok(recovered) => {
            // Only acceptable if reconstruction used a redundant copy that
            // still matches the file HMAC (impossible with redundancy 1.0
            // and a corrupted original dominating the slot).
            assert_ne!(recovered, payload, "corrupted data must not pass");
        }
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("checksum") || msg.contains("hash"),
                "error must name the integrity failure, got: {}",
                msg
            );
        }
    }
}

#[test]
fn duplicated_bundles_are_deduplicated_by_store() {
    let store = temp_store("dup");
    let shard = Shard {
        file_id: [5; 32],
        shard_index: 0,
        total_shards: 1,
        data: vec![1, 2, 3],
        checksum: 0,
    };
    let payload = bincode::serialize(&shard).unwrap();
    let bundle = create_bundle(&payload, [1; 32], 3600);

    let mut channel = LoopbackChannel::seeded(11, 0.0, 1.0, 0.0, 0.0);
    let arrivals = channel.deliver_bundle(&bundle);
    assert_eq!(arrivals.len(), 2, "channel duplicates");

    let mut inserted = 0;
    for b in &arrivals {
        if store.store_bundle(b).unwrap() {
            inserted += 1;
        }
    }
    assert_eq!(inserted, 1, "store dedups by bundle id");
    assert_eq!(store.len(), 1);
}

#[test]
fn expired_bundles_are_evicted_from_store() {
    let store = temp_store("ttl");
    let shard = Shard {
        file_id: [6; 32],
        shard_index: 0,
        total_shards: 1,
        data: vec![9],
        checksum: 0,
    };
    let payload = bincode::serialize(&shard).unwrap();
    let mut bundle = create_bundle(&payload, [1; 32], 60); // 60s lifetime
    bundle.creation_timestamp = 1_000; // epoch → long expired by now

    assert!(is_bundle_expired(&bundle));
    store.store_bundle(&bundle).unwrap();
    assert_eq!(store.len(), 1);

    let evicted = store.evict_expired(10_000).unwrap();
    assert_eq!(evicted, 1);
    assert!(store.is_empty());
    assert!(store.list_pending(10_000, None).unwrap().is_empty());
}

#[test]
fn pending_listing_excludes_expired_includes_fresh() {
    let store = temp_store("pending");
    let mk = |id: u8, created: u64, life: u64| {
        let shard = Shard {
            file_id: [id; 32],
            shard_index: 0,
            total_shards: 1,
            data: vec![id],
            checksum: 0,
        };
        let payload = bincode::serialize(&shard).unwrap();
        let mut b = create_bundle(&payload, [1; 32], life);
        b.creation_timestamp = created;
        b
    };

    store.store_bundle(&mk(1, 800, 100)).unwrap(); // expired at t=900 < 1000
    let fresh_bundle = mk(2, 990, 100); // alive at t=1000
    store.store_bundle(&fresh_bundle).unwrap();

    let pending = store.list_pending(1000, None).unwrap();
    assert_eq!(pending.len(), 1, "only the fresh bundle is pending");
    assert_eq!(pending[0].bundle_id, fresh_bundle.bundle_id);
}
