//! Three-node mesh simulation: discovery, forwarding, ACK aggregation and
//! shard-availability tracking — the T4 acceptance test for Ghost-node
//! coordination, with no hardware and no timers (all time is injected).

use abos_common::types::{Bundle, Shard};
use abos_protocol::mesh::{Beacon, MeshNode};
use abos_protocol::routing::{increment_hop, DedupCache};

fn nid(tag: u8) -> [u8; 32] {
    [tag; 32]
}

fn make_shard(file_id: u8, index: u32, total: u32) -> Shard {
    Shard {
        file_id: [file_id; 32],
        shard_index: index,
        total_shards: total,
        data: vec![file_id, index as u8],
        checksum: 0, // not exercised at this layer
    }
}

fn bundle_from_shard(shard: &Shard, source: [u8; 32]) -> Bundle {
    let payload = bincode::serialize(shard).unwrap();
    Bundle {
        bundle_id: abos_common::crypto::hmac_sha256(b"b", &payload),
        source_node: source,
        creation_timestamp: 0,
        lifetime_seconds: 3600,
        payload,
        hop_count: 0,
        ttl: 8,
    }
}

#[test]
fn three_nodes_discover_each_other_via_beacon_flooding() {
    let (a, b, c) = (nid(1), nid(2), nid(3));
    let mut na = MeshNode::new(a);
    let mut nb = MeshNode::new(b);
    let mut nc = MeshNode::new(c);

    // A beacons; B hears and re-floods; C hears the forwarded copy.
    let beacon_a = na.emit_beacon("alpha");
    assert!(nb.on_beacon(&beacon_a), "B must forward a fresh beacon");
    let relayed = Beacon {
        hop_count: beacon_a.hop_count + 1,
        ..beacon_a.clone()
    };
    assert!(nc.on_beacon(&relayed), "C must forward too (hop < ttl)");

    // B beacons back; A hears.
    let beacon_b = nb.emit_beacon("bravo");
    assert!(na.on_beacon(&beacon_b));

    // C beacons; A and B both hear it (flooding from C).
    let beacon_c = nc.emit_beacon("charlie");
    assert!(na.on_beacon(&beacon_c));
    assert!(nb.on_beacon(&beacon_c));

    assert_eq!(na.peer_count(), 2, "A sees B and C");
    assert_eq!(nb.peer_count(), 2, "B sees A and C");
    assert_eq!(
        nc.peer_count(),
        1,
        "C saw A via relay and B? — B never beaconed to C directly here"
    );

    assert_eq!(na.peer(&b).unwrap().alias, "bravo");
    assert_eq!(na.peer(&c).unwrap().alias, "charlie");
}

#[test]
fn forwarding_floods_then_terminates_via_dedup() {
    let (a, b, c) = (nid(1), nid(2), nid(3));
    let mut na = MeshNode::new(a);
    let mut nb = MeshNode::new(b);
    let mut nc = MeshNode::new(c);

    let shard = make_shard(7, 0, 4);
    let original = bundle_from_shard(&shard, a);

    // A originated it: never re-forwarded by A.
    assert!(!na.should_forward_bundle(&original));

    // B sees it first time → forward with hop increment.
    assert!(nb.should_forward_bundle(&original));
    let mut forwarded = original.clone();
    increment_hop(&mut forwarded);
    assert_eq!(forwarded.hop_count, 1);

    // B sees the flooded copy again → dedup stops re-flooding.
    assert!(!nb.should_forward_bundle(&forwarded));

    // C receives B's forwarded copy → forwards once.
    assert!(nc.should_forward_bundle(&forwarded));

    // TTL exhaustion stops the flood regardless of dedup.
    let mut expired = original.clone();
    expired.hop_count = expired.ttl;
    assert!(!nc.should_forward_bundle(&expired));
}

#[test]
fn ack_aggregation_and_backoff_across_nodes() {
    let (a, b, c) = (nid(1), nid(2), nid(3));
    let mut na = MeshNode::with_timings(a, 120, 30, 5);

    let shard = make_shard(1, 0, 2);
    let bundle = bundle_from_shard(&shard, a);
    na.track_bundle_at(&bundle, 1000);

    // Retransmit gating with injected time.
    assert!(na.due_for_retransmit_at(1004).is_empty(), "inside backoff");
    assert_eq!(na.due_for_retransmit_at(1005).len(), 1, "base delay hit");

    // ACKs from both peers retire the pending bundle.
    assert!(na.is_unacked(&bundle.bundle_id));
    assert!(na.record_ack(bundle.bundle_id, b));
    assert!(na.record_ack(bundle.bundle_id, c));
    assert!(!na.is_unacked(&bundle.bundle_id));
    assert_eq!(na.acks_for(&bundle.bundle_id).len(), 2);
}

#[test]
fn shard_availability_tracked_per_peer() {
    let (a, b, c) = (nid(1), nid(2), nid(3));
    let mut na = MeshNode::new(a);

    // B holds shards 0,2 of file 9; C holds shard 1.
    na.record_availability_from_shard(&make_shard(9, 0, 4), b);
    na.record_availability_from_shard(&make_shard(9, 2, 4), b);
    na.record_availability_from_shard(&make_shard(9, 1, 4), c);

    let holders = na.holders_of(&[9; 32]);
    assert_eq!(holders.len(), 2);
    assert_eq!(na.peer_holds(&[9; 32], &b), vec![0, 2]);
    assert_eq!(na.available_indices(&[9; 32]), vec![0, 1, 2]);

    // Another file is invisible.
    assert!(na.holders_of(&[100; 32]).is_empty());
}

#[test]
fn dedup_cache_stops_rebroadcast_but_not_new_bundles() {
    let mut dedup = DedupCache::new(4);
    let id = [9u8; 32];
    assert!(!dedup.check_and_insert(id), "first sight passes");
    assert!(dedup.check_and_insert(id), "second sight is a duplicate");

    // FIFO eviction: after capacity+1 inserts the oldest is forgotten.
    for i in 0..5u8 {
        dedup.check_and_insert([i; 32]);
    }
    // [0;32] was evicted (6 distinct inserts into capacity 4)…
    assert!(!dedup.check_and_insert([0; 32]), "evicted entry re-learned");
}
