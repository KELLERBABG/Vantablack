//! Decentralized Bootstrap & Rendezvous Subsystem.
//!
//! Eliminates dependency on centralized DNS servers, hardcoded VPS seeds, or domain names.
//!
//! Provides:
//! 1. **Kademlia DHT Routing Table**: 256-bit XOR metric k-buckets for decentralized node discovery.
//! 2. **Dead-Drop Rendezvous Points**: Deterministic slot derivation for peer and swarm discovery.
//! 3. **Decentralized Relay & Nostr Event Transport**: Censorship-resistant presence beacons
//!    over public decentralized relays without single points of failure.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

static ENABLED: AtomicBool = AtomicBool::new(false);

pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::Relaxed);
}

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type NodeId = [u8; 32];

pub fn xor_distance(a: &NodeId, b: &NodeId) -> NodeId {
    let mut dist = [0u8; 32];
    for i in 0..32 {
        dist[i] = a[i] ^ b[i];
    }
    dist
}

pub fn leading_zeros(dist: &NodeId) -> usize {
    let mut zeros = 0;
    for &byte in dist {
        if byte == 0 {
            zeros += 8;
        } else {
            zeros += byte.leading_zeros() as usize;
            break;
        }
    }
    zeros.min(255)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerContact {
    pub node_id: NodeId,
    pub fingerprint: String,
    pub addresses: Vec<SocketAddr>,
    pub last_seen_secs: u64,
}

impl PeerContact {
    pub fn new(node_id: NodeId, fingerprint: String, addresses: Vec<SocketAddr>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            node_id,
            fingerprint,
            addresses,
            last_seen_secs: now,
        }
    }
}

pub const K_BUCKET_SIZE: usize = 20;

pub const NUM_BUCKETS: usize = 256;

#[derive(Debug, Clone)]
pub struct DhtRoutingTable {
    pub local_id: NodeId,
    buckets: Arc<[DashMap<NodeId, PeerContact>; NUM_BUCKETS]>,
}

impl DhtRoutingTable {
    pub fn new(local_id: NodeId) -> Self {
        let buckets = std::array::from_fn(|_| DashMap::new());
        Self {
            local_id,
            buckets: Arc::new(buckets),
        }
    }

    pub fn bucket_index_for(&self, target: &NodeId) -> usize {
        let dist = xor_distance(&self.local_id, target);
        leading_zeros(&dist)
    }

    pub fn insert(&self, contact: PeerContact) -> bool {
        if contact.node_id == self.local_id {
            return false;
        }
        let idx = self.bucket_index_for(&contact.node_id);
        let bucket = &self.buckets[idx];

        if bucket.contains_key(&contact.node_id) || bucket.len() < K_BUCKET_SIZE {
            bucket.insert(contact.node_id, contact);
            true
        } else {
            false
        }
    }

    pub fn find_closest(&self, target: &NodeId, count: usize) -> Vec<PeerContact> {
        let mut candidates: Vec<(NodeId, PeerContact)> = Vec::new();

        for bucket in self.buckets.iter() {
            for entry in bucket.iter() {
                let dist = xor_distance(target, &entry.node_id);
                candidates.push((dist, entry.value().clone()));
            }
        }

        candidates.sort_by_key(|a| a.0);
        candidates.into_iter().take(count).map(|(_, c)| c).collect()
    }

    pub fn total_contacts(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }
}

pub struct RendezvousPoint;

impl RendezvousPoint {
    pub fn global_swarm_slot(epoch_secs: u64, epoch_duration: u64) -> [u8; 32] {
        let epoch = epoch_secs / epoch_duration.max(1);
        let mut hasher = Sha256::new();
        hasher.update(b"VANTABLACK_GLOBAL_SWARM_BOOTSTRAP_V1");
        hasher.update(epoch.to_be_bytes());
        hasher.finalize().into()
    }

    pub fn pairwise_peer_slot(peer_a_pk: &[u8], peer_b_pk: &[u8], day_epoch: u64) -> [u8; 32] {
        let mut sorted = [peer_a_pk, peer_b_pk];
        sorted.sort();
        let mut hasher = Sha256::new();
        hasher.update(b"VANTABLACK_PAIRWISE_RENDEZVOUS_V1");
        hasher.update(sorted[0]);
        hasher.update(sorted[1]);
        hasher.update(day_epoch.to_be_bytes());
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceBeacon {
    pub fingerprint: String,
    pub endpoints: Vec<SocketAddr>,
    pub timestamp: u64,
    pub nonce: u64,
    pub signature_hex: String,
}

impl PresenceBeacon {
    pub fn signing_bytes(
        fingerprint: &str,
        endpoints: &[SocketAddr],
        timestamp: u64,
        nonce: u64,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"VANTABLACK_PRESENCE_BEACON_V1");
        out.extend_from_slice(fingerprint.as_bytes());
        for ep in endpoints {
            out.extend_from_slice(ep.to_string().as_bytes());
        }
        out.extend_from_slice(&timestamp.to_be_bytes());
        out.extend_from_slice(&nonce.to_be_bytes());
        out
    }

    pub fn create<F>(fingerprint: String, endpoints: Vec<SocketAddr>, nonce: u64, signer: F) -> Self
    where
        F: FnOnce(&[u8]) -> [u8; 64],
    {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let msg = Self::signing_bytes(&fingerprint, &endpoints, now, nonce);
        let sig = signer(&msg);
        Self {
            fingerprint,
            endpoints,
            timestamp: now,
            nonce,
            signature_hex: hex::encode(sig),
        }
    }

    pub fn verify<V>(&self, verifier: V) -> bool
    where
        V: FnOnce(&[u8], &[u8; 64]) -> bool,
    {
        let Ok(sig_bytes) = hex::decode(&self.signature_hex) else {
            return false;
        };
        if sig_bytes.len() != 64 {
            return false;
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let msg = Self::signing_bytes(
            &self.fingerprint,
            &self.endpoints,
            self.timestamp,
            self.nonce,
        );
        verifier(&msg, &sig_arr)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrRendezvousEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

impl NostrRendezvousEvent {
    pub fn from_beacon(
        beacon: &PresenceBeacon,
        nostr_pubkey: String,
    ) -> Result<Self, serde_json::Error> {
        let content = serde_json::to_string(beacon)?;
        let slot_hex = hex::encode(RendezvousPoint::global_swarm_slot(beacon.timestamp, 3600));
        let mut hasher = Sha256::new();
        hasher.update(beacon.timestamp.to_be_bytes());
        hasher.update(content.as_bytes());
        let event_id = hex::encode(hasher.finalize());

        Ok(Self {
            id: event_id,
            pubkey: nostr_pubkey,
            created_at: beacon.timestamp,
            kind: 20000,
            tags: vec![vec!["d".into(), slot_hex]],
            content,
            sig: beacon.signature_hex.clone(),
        })
    }

    pub fn from_opaque_share(
        slot_hex: &str,
        share_bytes: &[u8],
        nostr_pubkey: String,
        created_at: u64,
        sig: String,
    ) -> Self {
        let content = hex::encode(share_bytes);
        let mut hasher = Sha256::new();
        hasher.update(created_at.to_be_bytes());
        hasher.update(slot_hex.as_bytes());
        hasher.update(content.as_bytes());
        let event_id = hex::encode(hasher.finalize());

        Self {
            id: event_id,
            pubkey: nostr_pubkey,
            created_at,
            kind: 20000,
            tags: vec![vec!["d".into(), slot_hex.to_string()]],
            content,
            sig,
        }
    }

    pub fn slot_hex(&self) -> Option<&str> {
        self.tags
            .iter()
            .find(|t| t.len() >= 2 && t[0] == "d")
            .map(|t| t[1].as_str())
    }

    pub fn extract_opaque_share(&self) -> Option<Vec<u8>> {
        hex::decode(&self.content).ok()
    }

    pub fn parse_beacon(&self) -> Result<PresenceBeacon, serde_json::Error> {
        serde_json::from_str(&self.content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dht_xor_distance_and_routing_table() {
        let local_id = [0xAA; 32];
        let table = DhtRoutingTable::new(local_id);

        let mut peer1_id = [0xAA; 32];
        peer1_id[31] = 0xAB; // very close

        let peer2_id = [0x55; 32]; // very far

        let addr: SocketAddr = "192.168.1.100:2270".parse().unwrap();
        let c1 = PeerContact::new(peer1_id, "peer1_fp".into(), vec![addr]);
        let c2 = PeerContact::new(peer2_id, "peer2_fp".into(), vec![addr]);

        assert!(table.insert(c1.clone()));
        assert!(table.insert(c2.clone()));
        assert_eq!(table.total_contacts(), 2);

        let closest = table.find_closest(&peer1_id, 1);
        assert_eq!(closest.len(), 1);
        assert_eq!(closest[0].fingerprint, "peer1_fp");
    }

    #[test]
    fn test_rendezvous_slot_deterministic_agreement() {
        let slot1 = RendezvousPoint::global_swarm_slot(3600, 3600);
        let slot2 = RendezvousPoint::global_swarm_slot(3650, 3600);
        assert_eq!(slot1, slot2, "Same epoch should yield identical slot");

        let slot3 = RendezvousPoint::global_swarm_slot(7200, 3600);
        assert_ne!(slot1, slot3, "Different epoch must yield different slot");

        let pk_a = b"alice_public_key_32_bytes_long!!";
        let pk_b = b"bob_public_key_32_bytes_long!!!!";
        let p_slot1 = RendezvousPoint::pairwise_peer_slot(pk_a, pk_b, 100);
        let p_slot2 = RendezvousPoint::pairwise_peer_slot(pk_b, pk_a, 100);
        assert_eq!(p_slot1, p_slot2, "Pairwise slot must be commutative");
    }

    #[test]
    fn test_presence_beacon_and_nostr_bridge() {
        let addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let mock_signer = |_msg: &[u8]| [0x42; 64];

        let beacon = PresenceBeacon::create("node_test_fp".into(), vec![addr], 12345, mock_signer);
        assert_eq!(beacon.fingerprint, "node_test_fp");
        assert_eq!(beacon.endpoints, vec![addr]);

        let verified = beacon.verify(|_msg, sig| sig == &[0x42; 64]);
        assert!(verified);

        let rejected = beacon.verify(|_msg, sig| sig == &[0x00; 64]);
        assert!(!rejected);

        let event = NostrRendezvousEvent::from_beacon(&beacon, "nostr_hex_pubkey".into()).unwrap();
        assert_eq!(event.kind, 20000);
        assert!(event.slot_hex().is_some());
        assert!(!event
            .tags
            .iter()
            .any(|t| t.iter().any(|v| v == "fp" || v == "vantablack_mesh")));

        let parsed = event.parse_beacon().unwrap();
        assert_eq!(parsed, beacon);

        let opaque = NostrRendezvousEvent::from_opaque_share(
            "deadbeef01",
            b"opaque-share-bytes",
            "nostr_hex_pubkey".into(),
            1700000000,
            "sig".into(),
        );
        assert_eq!(opaque.kind, 20000);
        assert_eq!(opaque.slot_hex(), Some("deadbeef01"));
        assert_eq!(
            opaque.extract_opaque_share().as_deref(),
            Some(b"opaque-share-bytes".as_slice())
        );
        assert!(!opaque
            .tags
            .iter()
            .any(|t| t.iter().any(|v| v == "fp" || v == "vantablack_mesh")));
    }
}
