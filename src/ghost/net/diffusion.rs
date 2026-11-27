//! Diffusion Routing (Opt-in Emergency Mode)
//!
//! Epidemic gossip shard dispersal behind `GHOST_DIFFUSION=1` for disaster recovery,
//! hostile link-pruning events, or severe network partitions where global routing tables
//! have collapsed.
//!
//! Bounded copies of erasure-coded shards diffuse like heat across local peers:
//! - Inactive during standard low-latency operation (zero ambient traffic overhead).
//! - Active when `GHOST_DIFFUSION=1` or during emergency partition failover.
//! - Bounded hop counts (`max_hops`) and duplicate suppression caches eliminate broadcast storms.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

static ENABLED: AtomicBool = AtomicBool::new(false);

pub fn is_enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
        || std::env::var("GHOST_DIFFUSION")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
}

pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::Relaxed);
}

use dashmap::DashMap;

pub const DIFFUSION_MAGIC: &[u8; 4] = b"DIFF";
pub const DEFAULT_MAX_DIFFUSION_HOPS: u8 = 4;
pub const DEFAULT_DIFFUSION_FANOUT: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffusionPacket {
    pub diffusion_id: [u8; 16],
    pub hop_count: u8,
    pub max_hops: u8,
    pub payload: Vec<u8>,
}

impl DiffusionPacket {
    pub fn new(diffusion_id: [u8; 16], max_hops: u8, payload: Vec<u8>) -> Self {
        Self {
            diffusion_id,
            hop_count: 0,
            max_hops,
            payload,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 16 + 1 + 1 + 2 + self.payload.len());
        out.extend_from_slice(DIFFUSION_MAGIC);
        out.extend_from_slice(&self.diffusion_id);
        out.push(self.hop_count);
        out.push(self.max_hops);
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn from_bytes(slice: &[u8]) -> Option<Self> {
        if slice.len() < 24 || &slice[0..4] != DIFFUSION_MAGIC {
            return None;
        }
        let mut diffusion_id = [0u8; 16];
        diffusion_id.copy_from_slice(&slice[4..20]);
        let hop_count = slice[20];
        let max_hops = slice[21];
        let payload_len = u16::from_be_bytes(slice[22..24].try_into().ok()?) as usize;
        if slice.len() < 24 + payload_len {
            return None;
        }
        let payload = slice[24..24 + payload_len].to_vec();
        Some(Self {
            diffusion_id,
            hop_count,
            max_hops,
            payload,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DiffusionAction {
    ForwardTo(Vec<SocketAddr>),
    DropAlreadySeen,
    DropHopsExceeded,
    Disabled,
}

#[derive(Debug, Clone)]
pub struct DiffusionRouter {
    pub enabled: bool,
    pub max_hops: u8,
    pub fanout: usize,
    seen_cache: Arc<DashMap<[u8; 16], Instant>>,
}

impl Default for DiffusionRouter {
    fn default() -> Self {
        let enabled = std::env::var("GHOST_DIFFUSION")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Self {
            enabled,
            max_hops: DEFAULT_MAX_DIFFUSION_HOPS,
            fanout: DEFAULT_DIFFUSION_FANOUT,
            seen_cache: Arc::new(DashMap::new()),
        }
    }
}

impl DiffusionRouter {
    pub fn new(enabled: bool, max_hops: u8, fanout: usize) -> Self {
        Self {
            enabled,
            max_hops,
            fanout,
            seen_cache: Arc::new(DashMap::new()),
        }
    }

    pub fn process_inbound(
        &self,
        packet: &mut DiffusionPacket,
        from_peer: Option<SocketAddr>,
        available_neighbors: &[SocketAddr],
    ) -> DiffusionAction {
        if !self.enabled {
            return DiffusionAction::Disabled;
        }

        if packet.hop_count >= packet.max_hops.min(self.max_hops) {
            return DiffusionAction::DropHopsExceeded;
        }

        if self.seen_cache.contains_key(&packet.diffusion_id) {
            return DiffusionAction::DropAlreadySeen;
        }

        self.seen_cache.insert(packet.diffusion_id, Instant::now());
        packet.hop_count += 1;

        let mut candidates = Vec::new();
        for &neighbor in available_neighbors {
            if Some(neighbor) != from_peer {
                candidates.push(neighbor);
                if candidates.len() >= self.fanout {
                    break;
                }
            }
        }

        DiffusionAction::ForwardTo(candidates)
    }

    pub fn prune_seen_cache(&self, ttl: Duration) {
        let now = Instant::now();
        self.seen_cache
            .retain(|_, &mut seen_at| now.duration_since(seen_at) < ttl);
    }

    pub fn seen_count(&self) -> usize {
        self.seen_cache.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diffusion_packet_serialization() {
        let id = [0x42u8; 16];
        let payload = b"shard_erasure_packet_payload".to_vec();
        let pkt = DiffusionPacket::new(id, 4, payload.clone());
        let bytes = pkt.to_bytes();
        let parsed = DiffusionPacket::from_bytes(&bytes).expect("parse diffusion packet");
        assert_eq!(parsed, pkt);
    }

    #[test]
    fn test_diffusion_router_bounded_fanout_and_loop_suppression() {
        let router = DiffusionRouter::new(true, 3, 2);
        let mut pkt = DiffusionPacket::new([0x99u8; 16], 3, b"data".to_vec());

        let peer1: SocketAddr = "10.0.0.1:2270".parse().unwrap();
        let peer2: SocketAddr = "10.0.0.2:2270".parse().unwrap();
        let peer3: SocketAddr = "10.0.0.3:2270".parse().unwrap();
        let neighbors = vec![peer1, peer2, peer3];

        let action1 = router.process_inbound(&mut pkt, Some(peer1), &neighbors);
        match action1 {
            DiffusionAction::ForwardTo(targets) => {
                assert_eq!(targets.len(), 2);
                assert!(!targets.contains(&peer1)); // Sender excluded
            }
            other => panic!("Expected ForwardTo, got {:?}", other),
        }
        assert_eq!(pkt.hop_count, 1);

        let action_dup = router.process_inbound(&mut pkt, Some(peer2), &neighbors);
        assert_eq!(action_dup, DiffusionAction::DropAlreadySeen);

        let mut expired_pkt = DiffusionPacket::new([0x55u8; 16], 3, b"data".to_vec());
        expired_pkt.hop_count = 3; // at max_hops
        let action_exp = router.process_inbound(&mut expired_pkt, None, &neighbors);
        assert_eq!(action_exp, DiffusionAction::DropHopsExceeded);
    }
}
