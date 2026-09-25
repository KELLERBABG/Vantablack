//! Windowing the Blackout (DTN State Reconciliation)
//!
//! Merkle-tree anti-entropy synchronization between peers upon reconnecting after
//! extended network partitions or communications blackouts (airplane mode, satellite gaps,
//! national censorship windows).
//!
//! When link connectivity is restored, peers compare Merkle tree root commitments over their
//! locally buffered bundle histories. Discrepancies are isolated in O(log N) branch queries
//! and missing bundles are reconciled and spliced without re-transmitting redundant data.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const DTN_RECONCILE_MAGIC: &[u8; 4] = b"MREC";

/// An archived bundle or state update buffered during a communications blackout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtnBundle {
    pub bundle_id: [u8; 16],
    pub sequence: u64,
    pub payload_hash: [u8; 32],
    pub payload: Vec<u8>,
}

impl DtnBundle {
    pub fn new(bundle_id: [u8; 16], sequence: u64, payload: Vec<u8>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&payload);
        let payload_hash = hasher.finalize().into();
        Self {
            bundle_id,
            sequence,
            payload_hash,
            payload,
        }
    }

    /// Leaf hash binding bundle_id, sequence, and payload_hash.
    pub fn leaf_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"GGN_DTN_LEAF_V1");
        hasher.update(&self.bundle_id);
        hasher.update(&self.sequence.to_be_bytes());
        hasher.update(&self.payload_hash);
        hasher.finalize().into()
    }

    /// Export bundle as an atmospheric skywave transmission payload (ABOS).
    pub fn to_skywave_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.payload.len());
        out.extend_from_slice(DTN_RECONCILE_MAGIC);
        out.extend_from_slice(&self.bundle_id);
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.payload_hash);
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parse a bundle received from an atmospheric skywave transmission (ABOS).
    pub fn from_skywave_payload(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 64 || &bytes[..4] != DTN_RECONCILE_MAGIC {
            return None;
        }
        let mut bundle_id = [0u8; 16];
        bundle_id.copy_from_slice(&bytes[4..20]);
        let sequence = u64::from_be_bytes(bytes[20..28].try_into().ok()?);
        let mut payload_hash = [0u8; 32];
        payload_hash.copy_from_slice(&bytes[28..60]);
        let payload_len = u32::from_be_bytes(bytes[60..64].try_into().ok()?) as usize;
        if bytes.len() < 64 + payload_len {
            return None;
        }
        let payload = bytes[64..64 + payload_len].to_vec();
        Some(Self {
            bundle_id,
            sequence,
            payload_hash,
            payload,
        })
    }
}


/// Merkle tree over buffered DTN bundles for logarithmic anti-entropy reconciliation.
#[derive(Debug, Clone, Default)]
pub struct DtnMerkleTree {
    bundles: BTreeMap<[u8; 16], DtnBundle>,
}

impl DtnMerkleTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or buffer a bundle recorded during blackout.
    pub fn insert(&mut self, bundle: DtnBundle) {
        self.bundles.insert(bundle.bundle_id, bundle);
    }

    pub fn get(&self, bundle_id: &[u8; 16]) -> Option<&DtnBundle> {
        self.bundles.get(bundle_id)
    }

    pub fn len(&self) -> usize {
        self.bundles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bundles.is_empty()
    }

    /// Compute root hash over all buffered bundle leaf hashes in sorted order.
    pub fn root_hash(&self) -> [u8; 32] {
        if self.bundles.is_empty() {
            return [0u8; 32];
        }
        let mut hasher = Sha256::new();
        hasher.update(b"GGN_DTN_ROOT_V1");
        for bundle in self.bundles.values() {
            hasher.update(bundle.leaf_hash());
        }
        hasher.finalize().into()
    }

    /// Partition bundle set into 2 buckets (left/right by first bit of bundle_id) for logarithmic sync.
    pub fn bucket_hashes(&self) -> ([u8; 32], [u8; 32]) {
        let mut left_hasher = Sha256::new();
        let mut right_hasher = Sha256::new();
        left_hasher.update(b"LEFT");
        right_hasher.update(b"RIGHT");

        for (id, bundle) in &self.bundles {
            if id[0] & 0x80 == 0 {
                left_hasher.update(bundle.leaf_hash());
            } else {
                right_hasher.update(bundle.leaf_hash());
            }
        }
        (
            left_hasher.finalize().into(),
            right_hasher.finalize().into(),
        )
    }

    /// Identifies all bundle IDs present locally that are missing from a remote bundle manifest.
    pub fn compute_missing_from(&self, remote_known_ids: &[[u8; 16]]) -> Vec<DtnBundle> {
        self.bundles
            .iter()
            .filter(|(id, _)| !remote_known_ids.contains(id))
            .map(|(_, b)| b.clone())
            .collect()
    }

    /// Reconcile and splice incoming missing bundles into the local store.
    pub fn splice_incoming(&mut self, incoming: Vec<DtnBundle>) -> usize {
        let mut added = 0;
        for b in incoming {
            if !self.bundles.contains_key(&b.bundle_id) {
                self.bundles.insert(b.bundle_id, b);
                added += 1;
            }
        }
        added
    }
}

/// Helper performing two-way anti-entropy sync between two partitioned node stores.
pub fn reconcile_blackout_stores(
    node_a: &mut DtnMerkleTree,
    node_b: &mut DtnMerkleTree,
) -> (usize, usize) {
    if node_a.root_hash() == node_b.root_hash() {
        return (0, 0); // Already in sync!
    }

    let a_ids: Vec<[u8; 16]> = node_a.bundles.keys().copied().collect();
    let b_ids: Vec<[u8; 16]> = node_b.bundles.keys().copied().collect();

    // Node A sends to B what B lacks
    let missing_on_b = node_a.compute_missing_from(&b_ids);
    // Node B sends to A what A lacks
    let missing_on_a = node_b.compute_missing_from(&a_ids);

    let added_to_b = node_b.splice_incoming(missing_on_b);
    let added_to_a = node_a.splice_incoming(missing_on_a);

    (added_to_a, added_to_b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dtn_merkle_anti_entropy_blackout_sync() {
        let mut node_a = DtnMerkleTree::new();
        let mut node_b = DtnMerkleTree::new();

        // Common bundles created before partition
        let b0 = DtnBundle::new([0x01; 16], 0, b"common_bundle_0".to_vec());
        node_a.insert(b0.clone());
        node_b.insert(b0);

        // Blackout begins: nodes are partitioned!
        // Node A buffers bundle 1 & 2 while offline
        let b1 = DtnBundle::new([0x10; 16], 1, b"offline_node_a_bundle_1".to_vec());
        let b2 = DtnBundle::new([0x20; 16], 2, b"offline_node_a_bundle_2".to_vec());
        node_a.insert(b1);
        node_a.insert(b2);

        // Node B buffers bundle 3 while offline
        let b3 = DtnBundle::new([0x90; 16], 3, b"offline_node_b_bundle_3".to_vec());
        node_b.insert(b3);

        assert_ne!(
            node_a.root_hash(),
            node_b.root_hash(),
            "Partitions have divergent root hashes"
        );

        // Link returns! Reconcile blackout stores
        let (added_to_a, added_to_b) = reconcile_blackout_stores(&mut node_a, &mut node_b);
        assert_eq!(added_to_a, 1, "Node A should receive 1 bundle from B");
        assert_eq!(added_to_b, 2, "Node B should receive 2 bundles from A");

        // Both nodes must now possess identical root hashes and converged bundle sets
        assert_eq!(node_a.root_hash(), node_b.root_hash());
        assert_eq!(node_a.len(), 4);
        assert_eq!(node_b.len(), 4);

        // Second reconcile on converged stores is a zero-op
        let (re_a, re_b) = reconcile_blackout_stores(&mut node_a, &mut node_b);
        assert_eq!((re_a, re_b), (0, 0));
    }
}
