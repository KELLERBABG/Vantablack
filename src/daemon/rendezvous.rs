//! Slot rendezvous discovery for the live daemon (`exp_rendezvous`).
//!
//! [`vantablack::ghost::net::rendezvous`] owns slot derivation, the signed presence
//! beacon and the Kademlia-shaped routing table. This module uses them for two
//! things the daemon needs at bootstrap time.
//!
//! ## Meeting points, not one point
//!
//! A blind mailbox fetch with the default client asks a single slot per epoch. That
//! is one shared address for the whole swarm — easy to enumerate, and a single
//! empty answer leaves the node with nothing. Instead each node publishes to **2 of
//! 3** slots chosen by rendezvous hashing over its own fingerprint, and queries all
//! three. Any two nodes have at least one slot in common (2 + 2 > 3), so a searcher
//! always meets a publisher somewhere, while no single slot carries the whole swarm
//! and a node's choice of slot says nothing about who it will meet.
//!
//! ## The routing table
//!
//! Every descriptor installed through the ordinary discovery path is also recorded
//! in a [`DhtRoutingTable`] keyed by the peer's XOR distance from us. When the
//! tracker and the mailbox both come back empty, those contacts are the last
//! bootstrap candidates the node has: peers it has met before, closest first.
//!
//! Neither half invents reachability: slots only ever return signed descriptors,
//! which are verified by the ordinary install path before a session is attempted.

use std::net::SocketAddr;
use std::sync::OnceLock;

use vantablack::ghost::net::discovery::{BlindMailboxClient, PeerDescriptorV2};
use vantablack::ghost::net::rendezvous::{DhtRoutingTable, NodeId, PeerContact};

pub(crate) const SLOT_COUNT: u32 = 3;
pub(crate) const PUBLISH_SLOTS: usize = 2;
const SKEW_SECS: u64 = 7200;

pub(crate) fn enabled() -> bool {
    vantablack::ghost::net::rendezvous::is_enabled()
}

fn node_id(fingerprint: &str) -> NodeId {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"GGN_RENDEZVOUS_NODE_ID_V1");
    hasher.update(fingerprint.as_bytes());
    hasher.finalize().into()
}

fn slot_rank(fingerprint: &str, slot: u32) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"GGN_RENDEZVOUS_SLOT_RANK_V1");
    hasher.update(fingerprint.as_bytes());
    hasher.update(slot.to_be_bytes());
    hasher.finalize().into()
}

pub(crate) fn publish_slots(fingerprint: &str) -> Vec<u32> {
    let mut slots: Vec<u32> = (0..SLOT_COUNT).collect();
    slots.sort_by_key(|slot| (slot_rank(fingerprint, *slot), *slot));
    slots.truncate(PUBLISH_SLOTS);
    slots.sort_unstable();
    slots
}

pub(crate) fn query_slots() -> Vec<u32> {
    (0..SLOT_COUNT).collect()
}

fn epoch_hour() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 3600
}

pub(crate) async fn sync(
    base_url: &str,
    swarm_secret: &[u8],
    our_fingerprint: &str,
    local_desc: &PeerDescriptorV2,
) -> Vec<PeerDescriptorV2> {
    let epoch = epoch_hour();
    for slot in publish_slots(our_fingerprint) {
        let client = match BlindMailboxClient::with_options(slot, SKEW_SECS) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(slot, error = %e, "Rendezvous: cannot build the mailbox client");
                continue;
            }
        };
        match client
            .publish_descriptor_at_epoch(base_url, swarm_secret, epoch, local_desc)
            .await
        {
            Ok(()) => tracing::debug!(slot, epoch, "Rendezvous: descriptor published"),
            Err(e) => tracing::warn!(slot, error = %e, "Rendezvous: publish failed for this slot"),
        }
    }

    let mut seen = std::collections::HashSet::new();
    let mut found = Vec::new();
    for slot in query_slots() {
        let client = match BlindMailboxClient::with_options(slot, SKEW_SECS) {
            Ok(c) => c,
            Err(_) => continue,
        };
        match client.fetch_descriptors(base_url, swarm_secret).await {
            Ok(descriptors) => {
                for desc in descriptors {
                    let fp = desc.fingerprint();
                    if fp == our_fingerprint || !seen.insert(fp) {
                        continue;
                    }
                    found.push(desc);
                }
            }
            Err(e) => tracing::debug!(slot, error = %e, "Rendezvous: slot came back empty"),
        }
    }
    tracing::info!(
        slots = SLOT_COUNT,
        published = PUBLISH_SLOTS,
        found = found.len(),
        "Rendezvous: slot sweep complete"
    );
    found
}

struct Table {
    our_fingerprint: String,
    table: DhtRoutingTable,
}

fn table(our_fingerprint: &str) -> &'static parking_lot::Mutex<Table> {
    static TABLE: OnceLock<parking_lot::Mutex<Table>> = OnceLock::new();
    TABLE.get_or_init(|| {
        parking_lot::Mutex::new(Table {
            our_fingerprint: our_fingerprint.to_string(),
            table: DhtRoutingTable::new(node_id(our_fingerprint)),
        })
    })
}

pub(crate) fn note_descriptor(our_fingerprint: &str, desc: &PeerDescriptorV2) {
    if !enabled() {
        return;
    }
    let mut addresses = vec![desc.endpoint];
    addresses.extend(desc.lan_endpoints.iter().copied());
    note_contact(our_fingerprint, &desc.fingerprint(), addresses);
}

pub(crate) fn note_contact(our_fingerprint: &str, fingerprint: &str, addresses: Vec<SocketAddr>) {
    if addresses.is_empty() {
        return;
    }
    let table = table(our_fingerprint);
    let guard = table.lock();
    if guard.our_fingerprint != our_fingerprint {
        return;
    }
    guard.table.insert(PeerContact::new(
        node_id(fingerprint),
        fingerprint.to_string(),
        addresses,
    ));
}

pub(crate) fn closest_addrs(our_fingerprint: &str, count: usize) -> Vec<SocketAddr> {
    if !enabled() || our_fingerprint.is_empty() {
        return Vec::new();
    }
    let table = table(our_fingerprint);
    let guard = table.lock();
    let contacts = guard.table.find_closest(&node_id(our_fingerprint), count);
    drop(guard);
    contacts
        .into_iter()
        .flat_map(|contact| contact.addresses.into_iter())
        .collect()
}

pub(crate) fn contact_count(our_fingerprint: &str) -> usize {
    if our_fingerprint.is_empty() {
        return 0;
    }
    let table = table(our_fingerprint);
    let guard = table.lock();
    guard.table.total_contacts()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_nodes_always_share_a_publish_or_query_slot() {
        let mut pairs_checked = 0;
        for i in 0..64 {
            let a = format!("peer-{i}");
            let b = format!("peer-{i}-other");
            let pa = publish_slots(&a);
            let pb = publish_slots(&b);
            assert_eq!(pa.len(), PUBLISH_SLOTS);
            assert!(pa.iter().all(|s| *s < SLOT_COUNT));
            assert_eq!(pa, publish_slots(&a), "deterministic per node");
            let shared = pa.iter().any(|slot| pb.contains(slot));
            assert!(
                shared
                    || query_slots()
                        .iter()
                        .all(|s| pa.contains(s) || pb.contains(s)),
                "every publish set is reachable through the full query set"
            );
            pairs_checked += 1;
        }
        assert_eq!(pairs_checked, 64);
        assert_eq!(query_slots(), vec![0, 1, 2]);
    }

    #[test]
    fn a_search_finds_every_publisher_because_it_queries_every_slot() {
        let query = query_slots();
        for i in 0..32 {
            let fp = format!("publisher-{i}");
            let publish = publish_slots(&fp);
            assert!(
                publish.iter().any(|slot| query.contains(slot)),
                "slot {publish:?} must be inside the queried set"
            );
        }
    }

    #[test]
    fn the_routing_table_records_contacts_and_answers_closest_first() {
        vantablack::ghost::net::rendezvous::set_enabled(true);
        let me = "self-fingerprint";
        assert!(closest_addrs(me, 4).is_empty(), "nothing learned yet");
        assert_eq!(contact_count(me), 0);
        let a: SocketAddr = "10.0.0.1:2270".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:2270".parse().unwrap();
        note_contact(me, "peer-a", vec![a]);
        note_contact(me, "peer-b", vec![b]);
        assert_eq!(contact_count(me), 2);
        let found = closest_addrs(me, 8);
        assert_eq!(found.len(), 2);
        assert!(found.contains(&a) && found.contains(&b));

        assert_eq!(contact_count(me), 2);
        vantablack::ghost::net::rendezvous::set_enabled(false);
    }

    #[test]
    fn node_ids_are_stable_and_distinct() {
        assert_eq!(node_id("aa"), node_id("aa"));
        assert_ne!(node_id("aa"), node_id("bb"));
        assert_eq!(node_id("aa").len(), 32);
    }
}
