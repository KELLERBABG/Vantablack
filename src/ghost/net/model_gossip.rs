//! Invention §43: Sharded Model Gossip
//!
//! Decentralized behavioral model learning over mesh metadata without a central coordinator.
//!
//! The mesh peers locally observe link dynamics (jitter distributions, packet loss, burstiness)
//! and gossip lightweight model gradient/parameter shards. Local models (e.g. §6 GhostMimic cover traffic
//! shaping parameters) converge adaptively toward true network conditions without any central parameter
//! server or raw trace exposure.

use std::sync::RwLock;

/// Local behavioral parameters governing cover traffic and routing timing.
#[derive(Debug, Clone, PartialEq)]
pub struct BehavioralMeshModel {
    /// Expected mean jitter (ms)
    pub mean_jitter_ms: f32,
    /// Learned packet loss rate (0.0 .. 1.0)
    pub loss_rate: f32,
    /// Cover traffic Poisson lambda rate (packets/sec)
    pub cover_lambda: f32,
    /// Model version / iteration epoch
    pub version: u64,
}

impl Default for BehavioralMeshModel {
    fn default() -> Self {
        Self {
            mean_jitter_ms: 20.0,
            loss_rate: 0.01,
            cover_lambda: 4.0,
            version: 0,
        }
    }
}

/// A gossiped model gradient update shard.
#[derive(Debug, Clone, PartialEq)]
pub struct ModelGossipDelta {
    pub version: u64,
    pub observed_jitter_delta: f32,
    pub observed_loss_delta: f32,
    pub sample_count: u32,
}

/// Sharded Model Gossip Engine coordinating decentralized parameter aggregation.
pub struct ShardedModelGossipEngine {
    local_model: RwLock<BehavioralMeshModel>,
    learning_rate: f32,
}

impl Default for ShardedModelGossipEngine {
    fn default() -> Self {
        Self {
            local_model: RwLock::new(BehavioralMeshModel::default()),
            learning_rate: 0.1,
        }
    }
}

impl ShardedModelGossipEngine {
    pub fn new(learning_rate: f32) -> Self {
        Self {
            local_model: RwLock::new(BehavioralMeshModel::default()),
            learning_rate,
        }
    }

    /// Read current local model parameters.
    pub fn current_model(&self) -> BehavioralMeshModel {
        self.local_model.read().unwrap().clone()
    }

    /// Create a delta shard from a batch of local link observations.
    pub fn produce_delta_shard(
        &self,
        local_jitter_samples: &[f32],
        local_loss_samples: &[f32],
    ) -> Option<ModelGossipDelta> {
        if local_jitter_samples.is_empty() || local_loss_samples.is_empty() {
            return None;
        }

        let model = self.local_model.read().unwrap();
        let avg_jitter: f32 =
            local_jitter_samples.iter().sum::<f32>() / (local_jitter_samples.len() as f32);
        let avg_loss: f32 =
            local_loss_samples.iter().sum::<f32>() / (local_loss_samples.len() as f32);

        Some(ModelGossipDelta {
            version: model.version,
            observed_jitter_delta: avg_jitter - model.mean_jitter_ms,
            observed_loss_delta: avg_loss - model.loss_rate,
            sample_count: local_jitter_samples.len() as u32,
        })
    }

    /// Ingest a gossiped delta from a peer and apply federated update step.
    pub fn apply_gossip_delta(&self, delta: &ModelGossipDelta) {
        let mut model = self.local_model.write().unwrap();

        // Weight update proportional to sample count and learning rate
        let weight = (self.learning_rate * (delta.sample_count as f32 / 100.0).clamp(0.1, 1.0))
            .clamp(0.01, 0.5);

        model.mean_jitter_ms =
            (model.mean_jitter_ms + weight * delta.observed_jitter_delta).max(1.0);
        model.loss_rate = (model.loss_rate + weight * delta.observed_loss_delta).clamp(0.0, 1.0);

        // Adapt cover traffic lambda: when loss is high, reduce cover burstiness to conserve bandwidth
        model.cover_lambda = (4.0 * (1.0 - model.loss_rate)).clamp(0.5, 10.0);
        model.version = model.version.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_gossip_decentralized_convergence() {
        let engine_a = ShardedModelGossipEngine::new(0.2);
        let engine_b = ShardedModelGossipEngine::new(0.2);
        let engine_c = ShardedModelGossipEngine::new(0.2);

        // Ground truth reality shifts: network enters high-latency 60ms jitter environment
        let real_jitter_samples = vec![58.0, 62.0, 59.0, 61.0, 60.0];
        let real_loss_samples = vec![0.05, 0.06, 0.04, 0.05];

        // Node A produces observation delta
        let delta_a = engine_a
            .produce_delta_shard(&real_jitter_samples, &real_loss_samples)
            .expect("produce delta");

        // Gossiped to B and C
        engine_b.apply_gossip_delta(&delta_a);
        engine_c.apply_gossip_delta(&delta_a);

        let model_b = engine_b.current_model();
        let model_c = engine_c.current_model();

        // Parameters converge upward toward true jitter
        assert!(model_b.mean_jitter_ms > 20.0);
        assert!(model_c.mean_jitter_ms > 20.0);
        assert_eq!(model_b.version, 1);
        assert_eq!(model_c.version, 1);
    }
}
