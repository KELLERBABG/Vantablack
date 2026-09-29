use abos_common::types::*;
use std::collections::HashMap;

/// Buffer-Bounce engine implementing asynchronous store-and-forward relay
///
/// The atmosphere acts as a distributed relay: shards are transmitted upward
/// without a specific destination. Other Ghost Nodes capture, store, and
/// re-emit shards. The engine waits for ACKs or complementary shards
/// appearing in the spectrum before stopping its own transmit cycle.
pub struct BufferBounceEngine {
    /// Shards we have submitted for transmission (pending ACK)
    pending_shards: HashMap<[u8; 32], (Shard, u64)>,
    /// ACKs we've received from other nodes
    received_acks: Vec<[u8; 32]>,
    /// Complementary shards we've detected in the spectrum
    complementary_shards: Vec<Shard>,
    /// Maximum number of retransmissions per shard
    max_retransmissions: u32,
    /// Current retransmission count per shard
    retransmit_count: HashMap<[u8; 32], u32>,
}

impl BufferBounceEngine {
    pub fn new(max_retransmissions: u32) -> Self {
        Self {
            pending_shards: HashMap::new(),
            received_acks: Vec::new(),
            complementary_shards: Vec::new(),
            max_retransmissions,
            retransmit_count: HashMap::new(),
        }
    }

    /// Submit a shard for buffer-bounce transmission
    pub fn submit_shard(&mut self, shard: Shard, timestamp: u64) {
        let mut shard_id = [0u8; 32];
        shard_id[..4].copy_from_slice(&shard.shard_index.to_le_bytes());
        shard_id[4..8].copy_from_slice(&shard.file_id[..4]);
        self.pending_shards.insert(shard_id, (shard, timestamp));
        self.retransmit_count.entry(shard_id).or_insert(0);
    }

    /// Process an ACK for a specific shard
    /// Returns true if all complementary shards for this file have been received
    pub fn process_ack(&mut self, shard_id: [u8; 32]) -> bool {
        self.received_acks.push(shard_id);
        self.pending_shards.remove(&shard_id);

        // Check if we have enough complementary shards to reconstruct
        // (simplified: just check if we have received ACKs for all our shards)

        self.pending_shards.is_empty()
    }

    /// Record a complementary shard detected in the spectrum
    pub fn record_complementary_shard(&mut self, shard: Shard) {
        let index = shard.shard_index;
        // Avoid duplicates
        if !self
            .complementary_shards
            .iter()
            .any(|s| s.shard_index == index)
        {
            self.complementary_shards.push(shard);
        }
    }

    /// Check if we should retransmit a shard
    pub fn should_retransmit(&mut self, shard_id: &[u8; 32]) -> bool {
        if let Some(count) = self.retransmit_count.get_mut(shard_id) {
            if *count < self.max_retransmissions {
                *count += 1;
                return true;
            }
        }
        false
    }

    /// Get pending shards that need transmission
    pub fn get_pending_shards(&self) -> Vec<&Shard> {
        self.pending_shards.values().map(|(s, _)| s).collect()
    }

    /// Get the number of complementary shards collected
    pub fn complementary_shard_count(&self) -> usize {
        self.complementary_shards.len()
    }

    /// Clear completed transfers
    pub fn cleanup(&mut self) {
        self.pending_shards.clear();
        self.received_acks.clear();
        self.complementary_shards.clear();
        self.retransmit_count.clear();
    }
}
