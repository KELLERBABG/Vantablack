//! Implicit routing / flooding logic — no routing tables required.
//!
//! Every node that receives a bundle decides independently whether to
//! forward it further, based on hop count and TTL. This creates a
//! decentralized, unstructured flooding mesh network.

use abos_common::types::Bundle;

/// Determine if a bundle should be forwarded based on hop count and TTL
pub fn should_forward(hop_count: u32, ttl: u32) -> bool {
    hop_count < ttl
}

/// Increment the hop count of a bundle (called when relaying)
pub fn increment_hop(bundle: &mut Bundle) {
    bundle.hop_count += 1;
}

/// Check if a bundle has exceeded its maximum hop count
pub fn is_hop_limit_exceeded(bundle: &Bundle) -> bool {
    bundle.hop_count >= bundle.ttl
}

/// Deduplication: check if this bundle has been seen before
/// (using bundle_id as the deduplication key)
pub struct DedupCache {
    seen: std::collections::HashSet<[u8; 32]>,
    max_size: usize,
    order: std::collections::VecDeque<[u8; 32]>,
}

impl DedupCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            seen: std::collections::HashSet::new(),
            max_size,
            order: std::collections::VecDeque::new(),
        }
    }

    /// Check if a bundle_id has been seen, and mark it as seen
    /// Returns true if this is a duplicate (already seen)
    pub fn check_and_insert(&mut self, bundle_id: [u8; 32]) -> bool {
        if self.seen.contains(&bundle_id) {
            return true;
        }

        self.seen.insert(bundle_id);
        self.order.push_back(bundle_id);

        // Evict oldest entries if over capacity (FIFO eviction)
        while self.order.len() > self.max_size {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }

        false
    }
}
