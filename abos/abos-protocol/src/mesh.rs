//! Mesh / Ghost-node coordination.
//!
//! Decentralized operation with no central authority:
//! - **Discovery**: nodes announce themselves with periodic beacons; every node
//!   keeps a peer table with last-seen expiry.
//! - **ACK aggregation**: shards awaiting confirmation are tracked per peer with
//!   exponential backoff between retransmission attempts.
//! - **Shard availability**: each node records which peers hold which file's
//!   shards so reconstruction requests can be directed (or flooded).
//!
//! Every node that receives a bundle independently decides whether to forward
//! it (see [`crate::routing`]), which creates a decentralized flooding mesh.

use abos_common::types::{Bundle, NodeId, Shard};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default beacon interval in seconds.
pub const DEFAULT_BEACON_INTERVAL_SECS: u64 = 30;
/// Default peer expiry: a peer not heard from within this window is dropped.
pub const DEFAULT_PEER_EXPIRY_SECS: u64 = 120;
/// Base delay (seconds) for retransmission backoff.
pub const DEFAULT_BACKOFF_BASE_SECS: u64 = 5;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A discovery beacon announcing a node's presence and capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Beacon {
    /// Node that originated the beacon.
    pub origin: NodeId,
    /// Number of hops this beacon has travelled (beacons are flooded).
    pub hop_count: u32,
    /// Beacon TTL — same flooding rule as bundles.
    pub ttl: u32,
    /// Unix timestamp of emission.
    pub timestamp: u64,
    /// Human-readable node alias (not authenticated; debug aid only).
    pub alias: String,
}

impl Beacon {
    /// Create a fresh beacon for local emission.
    pub fn new(origin: NodeId, alias: &str) -> Self {
        Self {
            origin,
            hop_count: 0,
            ttl: 3,
            timestamp: now_secs(),
            alias: alias.to_string(),
        }
    }

    /// Whether this beacon should be re-flooded (and hop count incremented).
    pub fn should_forward(&self) -> bool {
        self.hop_count < self.ttl
    }
}

/// A peer discovered via beacons.
#[derive(Debug, Clone)]
pub struct Peer {
    /// Peer node id.
    pub node_id: NodeId,
    /// Alias from the most recent beacon.
    pub alias: String,
    /// Unix time of the most recent beacon heard from this peer.
    pub last_seen: u64,
    /// Number of beacons heard (liveness signal).
    pub beacon_count: u64,
    /// Timestamp of the newest beacon seen from this peer (dedup key).
    last_beacon_ts: u64,
}

/// Pending transmission awaiting ACK, with exponential backoff state.
#[derive(Debug, Clone)]
pub struct PendingTransmission {
    /// Bundle id being tracked.
    pub bundle_id: [u8; 32],
    /// Unix time of first submission.
    pub submitted_at: u64,
    /// Unix time after which the next retransmission is allowed.
    pub next_attempt_at: u64,
    /// How many retransmissions have been scheduled so far.
    pub attempts: u32,
    /// Give up after this many attempts.
    pub max_attempts: u32,
    /// Backoff base in seconds: delay = base * 2^attempts.
    pub backoff_base_secs: u64,
}

impl PendingTransmission {
    /// Delay before attempt `attempts` (saturating exponential backoff).
    fn backoff_secs(&self) -> u64 {
        let shift = self.attempts.min(16);
        self.backoff_base_secs.saturating_mul(1u64 << shift)
    }
}

/// Mesh coordination state for one Ghost Node.
///
/// All methods are pure/synchronous so they can be unit-tested and driven by
/// any scheduler (tokio task, CLI loop, or test harness).
pub struct MeshNode {
    /// This node's id.
    local_id: NodeId,
    /// Discovered peers, keyed by node id.
    peers: HashMap<NodeId, Peer>,
    /// Seconds without a beacon before a peer is considered gone.
    peer_expiry_secs: u64,
    /// Beacon interval used by [`MeshNode::beacon_due`].
    beacon_interval_secs: u64,
    /// Unix time the last local beacon was emitted.
    last_beacon_at: u64,
    /// Bundles awaiting ACK, keyed by bundle id.
    pending: HashMap<[u8; 32], PendingTransmission>,
    /// Maximum retransmission attempts per bundle.
    max_attempts: u32,
    /// Backoff base seconds.
    backoff_base_secs: u64,
    /// Aggregated ACKs: bundle id -> peers that acknowledged it.
    acks: HashMap<[u8; 32], Vec<NodeId>>,
    /// file_id -> (peer -> set of shard indices held).
    availability: HashMap<[u8; 32], HashMap<NodeId, std::collections::BTreeSet<u32>>>,
    /// Bundles we originated and still track.
    origin_bundles: HashMap<[u8; 32], u64>,
    /// Bundle ids we already forwarded (flooding dedup).
    forwarded: std::collections::HashSet<[u8; 32]>,
}

impl MeshNode {
    /// Create a mesh node with default timing parameters.
    pub fn new(local_id: NodeId) -> Self {
        Self::with_timings(
            local_id,
            DEFAULT_PEER_EXPIRY_SECS,
            DEFAULT_BEACON_INTERVAL_SECS,
            DEFAULT_BACKOFF_BASE_SECS,
        )
    }

    /// Create a mesh node with explicit timing parameters (used by tests).
    pub fn with_timings(
        local_id: NodeId,
        peer_expiry_secs: u64,
        beacon_interval_secs: u64,
        backoff_base_secs: u64,
    ) -> Self {
        Self {
            local_id,
            peers: HashMap::new(),
            peer_expiry_secs,
            beacon_interval_secs,
            last_beacon_at: 0,
            pending: HashMap::new(),
            max_attempts: 8,
            backoff_base_secs,
            acks: HashMap::new(),
            availability: HashMap::new(),
            origin_bundles: HashMap::new(),
            forwarded: std::collections::HashSet::new(),
        }
    }

    /// This node's id.
    pub fn local_id(&self) -> NodeId {
        self.local_id
    }

    // --- Discovery -----------------------------------------------------

    /// Handle an incoming beacon. Returns `true` if the beacon is new/stale
    /// enough that it should be re-flooded to other peers.
    pub fn on_beacon(&mut self, beacon: &Beacon) -> bool {
        if beacon.origin == self.local_id {
            return false; // never reflect our own beacons
        }
        let now = now_secs();
        let entry = self.peers.entry(beacon.origin).or_insert_with(|| Peer {
            node_id: beacon.origin,
            alias: beacon.alias.clone(),
            last_seen: beacon.timestamp,
            beacon_count: 0,
            last_beacon_ts: 0,
        });
        // Refresh liveness on every copy, but only count strictly newer
        // beacons — flooded duplicates carry the same timestamp.
        entry.last_seen = now;
        if beacon.timestamp > entry.last_beacon_ts {
            entry.last_beacon_ts = beacon.timestamp;
            entry.alias = beacon.alias.clone();
            entry.beacon_count += 1;
        }
        beacon.should_forward()
    }

    /// Emit a local beacon and record it (called on the beacon interval).
    pub fn emit_beacon(&mut self, alias: &str) -> Beacon {
        self.last_beacon_at = now_secs();
        Beacon::new(self.local_id, alias)
    }

    /// Whether enough time has passed to emit another beacon.
    pub fn beacon_due(&self) -> bool {
        now_secs().saturating_sub(self.last_beacon_at) >= self.beacon_interval_secs
    }

    /// Drop peers not heard from within the expiry window.
    /// Returns the number of peers removed.
    pub fn expire_peers(&mut self) -> usize {
        self.expire_peers_at(now_secs())
    }

    /// [`expire_peers`] with an injected timestamp (test/simulation hook).
    pub fn expire_peers_at(&mut self, now: u64) -> usize {
        let expiry = self.peer_expiry_secs;
        let before = self.peers.len();
        self.peers
            .retain(|_, p| now.saturating_sub(p.last_seen) <= expiry);
        before - self.peers.len()
    }

    /// All currently-live peers.
    pub fn peers(&self) -> impl Iterator<Item = &Peer> {
        self.peers.values()
    }

    /// Number of live peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Look up a peer by id.
    pub fn peer(&self, id: &NodeId) -> Option<&Peer> {
        self.peers.get(id)
    }

    // --- Outbound tracking / backoff -----------------------------------

    /// Track a bundle we just transmitted and expect an ACK for.
    /// If already tracked, this is a no-op (idempotent submit).
    pub fn track_bundle(&mut self, bundle: &Bundle) {
        self.track_bundle_at(bundle, now_secs());
    }

    /// [`Track_bundle`] with an injected timestamp (test/simulation hook).
    ///
    /// [`Track_bundle`]: MeshNode::track_bundle
    pub fn track_bundle_at(&mut self, bundle: &Bundle, now: u64) {
        let id = bundle.bundle_id;
        self.origin_bundles.entry(id).or_insert_with(|| now);
        self.pending
            .entry(id)
            .or_insert_with(|| PendingTransmission {
                bundle_id: id,
                submitted_at: now,
                next_attempt_at: now.saturating_add(self.backoff_base_secs),
                attempts: 0,
                max_attempts: self.max_attempts,
                backoff_base_secs: self.backoff_base_secs,
            });
    }

    /// Bundles whose backoff window has elapsed and that still have retry
    /// budget. Consumed by the transmit loop; each returned id is marked with
    /// an increased attempt count and a doubled next-attempt time.
    pub fn due_for_retransmit(&mut self) -> Vec<[u8; 32]> {
        self.due_for_retransmit_at(now_secs())
    }

    /// [`due_for_retransmit`] with an injected timestamp (test/simulation hook).
    pub fn due_for_retransmit_at(&mut self, now: u64) -> Vec<[u8; 32]> {
        let mut due = Vec::new();
        for p in self.pending.values_mut() {
            if now >= p.next_attempt_at && p.attempts < p.max_attempts {
                p.attempts += 1;
                p.next_attempt_at = now.saturating_add(p.backoff_secs());
                due.push(p.bundle_id);
            }
        }
        // Attempts exhausted: stop tracking so the queue drains.
        let exhausted: Vec<[u8; 32]> = self
            .pending
            .values()
            .filter(|p| p.attempts >= p.max_attempts)
            .map(|p| p.bundle_id)
            .collect();
        for id in exhausted {
            self.pending.remove(&id);
        }
        due
    }

    /// Bundles that exhausted their retry budget and were dropped.
    /// (Called by sweeping: returns ids whose attempts hit the cap.)
    pub fn failed_bundles(&self) -> Vec<[u8; 32]> {
        self.pending
            .values()
            .filter(|p| p.attempts >= p.max_attempts)
            .map(|p| p.bundle_id)
            .collect()
    }

    /// Number of bundles still awaiting ACK.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Record an ACK received for a bundle from `peer`.
    /// Returns `true` if this is the first ACK from that peer.
    pub fn record_ack(&mut self, bundle_id: [u8; 32], peer: NodeId) -> bool {
        let list = self.acks.entry(bundle_id).or_default();
        let first = !list.contains(&peer);
        if first {
            list.push(peer);
        }
        // An ACK retires the pending retransmission entry.
        self.pending.remove(&bundle_id);
        first
    }

    /// All peers that ACKed a given bundle.
    pub fn acks_for(&self, bundle_id: &[u8; 32]) -> &[NodeId] {
        self.acks
            .get(bundle_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Whether we originated a bundle and it has not been ACKed by anyone yet.
    pub fn is_unacked(&self, bundle_id: &[u8; 32]) -> bool {
        self.pending.contains_key(bundle_id)
    }

    // --- Shard availability --------------------------------------------

    /// Record that `peer` holds shard `index` of `file_id`.
    pub fn record_availability(&mut self, file_id: [u8; 32], peer: NodeId, index: u32) {
        self.availability
            .entry(file_id)
            .or_default()
            .entry(peer)
            .or_default()
            .insert(index);
    }

    /// Record availability from a bundle payload (a serialized shard).
    pub fn record_availability_from_shard(&mut self, shard: &Shard, peer: NodeId) {
        self.record_availability(shard.file_id, peer, shard.shard_index);
    }

    /// Peers holding at least one shard of `file_id`.
    pub fn holders_of(&self, file_id: &[u8; 32]) -> Vec<NodeId> {
        self.availability
            .get(file_id)
            .map(|m| m.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Union of shard indices of `file_id` known to be held anywhere in the
    /// mesh (including our own contributions).
    pub fn available_indices(&self, file_id: &[u8; 32]) -> Vec<u32> {
        let mut set = std::collections::BTreeSet::new();
        if let Some(m) = self.availability.get(file_id) {
            for indices in m.values() {
                set.extend(indices.iter().copied());
            }
        }
        set.into_iter().collect()
    }

    /// Which specific shards of `file_id` are held by `peer`.
    pub fn peer_holds(&self, file_id: &[u8; 32], peer: &NodeId) -> Vec<u32> {
        self.availability
            .get(file_id)
            .and_then(|m| m.get(peer))
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    // --- Forwarding ------------------------------------------------------

    /// Decide whether an inbound bundle should be forwarded, applying the
    /// flooding rule plus local dedup (bundles we originated or already
    /// forwarded are not re-flooded).
    pub fn should_forward_bundle(&mut self, bundle: &Bundle) -> bool {
        if bundle.source_node == self.local_id {
            return false;
        }
        if self.origin_bundles.contains_key(&bundle.bundle_id) {
            return false;
        }
        if !crate::routing::should_forward(bundle.hop_count, bundle.ttl) {
            return false;
        }
        // Flooding dedup: first sight forwards, later sightings are dropped.
        self.forwarded.insert(bundle.bundle_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn bundle(id: u8, hops: u32, ttl: u32) -> Bundle {
        Bundle {
            bundle_id: [id; 32],
            source_node: nid(id),
            creation_timestamp: 0,
            lifetime_seconds: 3600,
            payload: vec![1, 2, 3],
            hop_count: hops,
            ttl,
        }
    }

    #[test]
    fn beacon_discovery_registers_peer() {
        let mut node = MeshNode::new(nid(1));
        let beacon = Beacon::new(nid(2), "ghost-2");
        assert!(node.on_beacon(&beacon), "fresh beacon should be flooded");
        assert_eq!(node.peer_count(), 1);
        assert_eq!(node.peer(&nid(2)).unwrap().alias, "ghost-2");
    }

    #[test]
    fn own_beacons_ignored() {
        let mut node = MeshNode::new(nid(1));
        let beacon = Beacon::new(nid(1), "me");
        assert!(!node.on_beacon(&beacon));
        assert_eq!(node.peer_count(), 0);
    }

    #[test]
    fn beacon_ttl_stops_flooding() {
        let mut b = Beacon::new(nid(2), "x");
        b.hop_count = 3; // == ttl
        assert!(!b.should_forward());
    }

    #[test]
    fn duplicate_beacon_does_not_double_count() {
        let mut node = MeshNode::new(nid(1));
        let beacon = Beacon::new(nid(2), "ghost-2");
        node.on_beacon(&beacon);
        node.on_beacon(&beacon); // flooded duplicate with same timestamp
        assert_eq!(node.peer(&nid(2)).unwrap().beacon_count, 1);
    }

    #[test]
    fn backoff_grows_exponentially() {
        let mut node = MeshNode::with_timings(nid(1), 120, 30, 5);
        node.track_bundle_at(&bundle(9, 0, 10), 1000);

        // Inside the base backoff window: nothing due.
        assert!(node.due_for_retransmit_at(1000).is_empty());
        assert!(node.due_for_retransmit_at(1004).is_empty());

        // Base delay (5s) elapsed: first retry fires, window doubles to 10s.
        assert_eq!(node.due_for_retransmit_at(1005).len(), 1);
        assert!(node.due_for_retransmit_at(1006).is_empty());

        // Second retry at 1005 + 5*2^1 = 1015; window doubles again to 20s.
        assert_eq!(node.due_for_retransmit_at(1015).len(), 1);
        assert!(node.due_for_retransmit_at(1016).is_empty());
        assert_eq!(node.due_for_retransmit_at(1035).len(), 1);
    }

    #[test]
    fn retries_exhaust_and_drain() {
        let mut node = MeshNode::with_timings(nid(1), 120, 30, 5);
        node.track_bundle_at(&bundle(9, 0, 10), 0);
        // max_attempts = 8; sweep far into the future until the queue drains.
        let mut now = 0u64;
        let mut fired = 0;
        for _ in 0..64 {
            now = now.saturating_add(1_000_000);
            fired += node.due_for_retransmit_at(now).len();
        }
        assert_eq!(fired, 8, "exactly max_attempts retries fire");
        assert_eq!(node.pending_count(), 0, "queue drains after exhaustion");
    }

    #[test]
    fn ack_retires_pending_and_aggregates() {
        let mut node = MeshNode::new(nid(1));
        node.track_bundle(&bundle(9, 0, 10));
        assert!(node.is_unacked(&[9; 32]));
        assert!(node.record_ack([9; 32], nid(2)));
        assert!(!node.record_ack([9; 32], nid(2)), "duplicate ack");
        assert!(node.record_ack([9; 32], nid(3)), "second peer acks");
        assert!(!node.is_unacked(&[9; 32]));
        assert_eq!(node.acks_for(&[9; 32]).len(), 2);
        assert!(node.pending_count() == 0);
    }

    #[test]
    fn availability_tracking_and_union() {
        let mut node = MeshNode::new(nid(1));
        node.record_availability([7; 32], nid(2), 0);
        node.record_availability([7; 32], nid(2), 2);
        node.record_availability([7; 32], nid(3), 1);
        assert_eq!(node.holders_of(&[7; 32]).len(), 2);
        assert_eq!(node.available_indices(&[7; 32]), vec![0, 1, 2]);
        assert_eq!(node.peer_holds(&[7; 32], &nid(2)), vec![0, 2]);
    }

    #[test]
    fn forwarding_rules() {
        let mut node = MeshNode::new(nid(1));
        // Own bundle: never forward.
        let mut mine = bundle(1, 0, 10);
        mine.source_node = nid(1);
        assert!(!node.should_forward_bundle(&mine));
        // Foreign bundle within TTL: forward.
        let foreign = bundle(2, 0, 10);
        assert!(node.should_forward_bundle(&foreign));
        // At hop limit: do not forward.
        let expired = bundle(3, 10, 10);
        assert!(!node.should_forward_bundle(&expired));
        // Already seen: do not forward again.
        assert!(!node.should_forward_bundle(&foreign));
    }

    #[test]
    fn peer_expiry_prunes_stale_entries() {
        let mut node = MeshNode::with_timings(nid(1), 60, 30, 5);
        node.on_beacon(&Beacon::new(nid(2), "x"));
        assert_eq!(node.peer_count(), 1);

        // Age the peer beyond the expiry window (test reaches into the
        // private table directly, as a child module can).
        node.peers.get_mut(&nid(2)).unwrap().last_seen = 1;
        assert_eq!(node.expire_peers(), 1);
        assert_eq!(node.peer_count(), 0);
    }
}
