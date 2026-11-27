//! Store-and-forward for peers that are between sessions (`exp_dtn_reconcile`).
//!
//! [`vantablack::ghost::net::dtn_reconcile`] owns the bundle and the Merkle
//! anti-entropy primitives. This module is the store: a per-peer set of
//! **self-contained, idempotent** payloads that were produced while the peer had no
//! session, kept until a session appears, then flushed.
//!
//! ## What may be buffered
//!
//! Only a payload that means the same thing whether it arrives once or ten times:
//! today that is the signed PEX descriptor batch, which is additive and carries its
//! own signatures. A control message with an effect — a tunnel `OPEN`, a handshake —
//! is never buffered; replaying it later would be a different instruction.
//!
//! ## The store
//!
//! Each peer gets a [`DtnMerkleTree`] keyed by `SHA256(peer_fp ‖ payload)[..16]`, so
//! the same batch offered twice stays one bundle. A `delivered` set records what has
//! already reached the peer, and pending work is
//! `tree.compute_missing_from(delivered)` — the same "what do they not have yet"
//! question the Merkle reconciliation answers, so a reconnect does not resend a
//! batch that already arrived. When the tree grows past twice the pending cap it is
//! rebuilt from the pending set alone, which is the only compaction this needs.

use crate::*;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;

use vantablack::ghost::net::dtn_reconcile::{DtnBundle, DtnMerkleTree};

const MAX_PENDING: usize = 64;

pub(crate) fn enabled() -> bool {
    vantablack::ghost::net::dtn_reconcile::is_enabled()
}

struct PeerStore {
    tree: DtnMerkleTree,
    delivered: HashSet<[u8; 16]>,
    next_sequence: u64,
}

impl PeerStore {
    fn new() -> Self {
        Self {
            tree: DtnMerkleTree::new(),
            delivered: HashSet::new(),
            next_sequence: 1,
        }
    }

    fn delivered_ids(&self) -> Vec<[u8; 16]> {
        self.delivered.iter().copied().collect()
    }

    fn pending(&self) -> Vec<DtnBundle> {
        self.tree.compute_missing_from(&self.delivered_ids())
    }

    fn compact(&mut self) {
        if self.tree.len() <= MAX_PENDING * 2 {
            return;
        }
        let pending = self.pending();
        self.tree = DtnMerkleTree::new();
        for bundle in pending {
            self.tree.insert(bundle);
        }
        self.delivered.clear();
    }
}

fn stores() -> &'static DashMap<String, parking_lot::Mutex<PeerStore>> {
    static STORES: OnceLock<DashMap<String, parking_lot::Mutex<PeerStore>>> = OnceLock::new();
    STORES.get_or_init(DashMap::new)
}

fn bundle_id(peer_fp: &str, payload: &[u8]) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"GGN_DTN_BUNDLE_V1");
    hasher.update(peer_fp.as_bytes());
    hasher.update(payload);
    let digest = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

fn queue(store: &mut PeerStore, peer_fp: &str, payload: &[u8]) -> bool {
    if payload.is_empty() {
        return false;
    }
    let id = bundle_id(peer_fp, payload);
    if store.tree.get(&id).is_some() {
        return false;
    }
    if store.pending().len() >= MAX_PENDING {
        tracing::warn!(
            peer = %peer_fp,
            "DTN: queue is full — this bundle is dropped, not deferred forever"
        );
        return false;
    }
    let sequence = store.next_sequence;
    store.next_sequence = store.next_sequence.saturating_add(1);

    #[cfg(feature = "research")]
    if super::research_hooks::vault::enabled() {
        let Some(descriptor) = super::research_hooks::vault::deposit(peer_fp, payload) else {
            return false;
        };
        store
            .tree
            .insert(DtnBundle::new(id, sequence, descriptor));
        return true;
    }

    store
        .tree
        .insert(DtnBundle::new(id, sequence, payload.to_vec()));
    true
}

pub(crate) fn store(peer_fp: &str, payload: &[u8]) -> bool {
    if !enabled() || payload.is_empty() {
        return false;
    }
    let entry = stores()
        .entry(peer_fp.to_string())
        .or_insert_with(|| parking_lot::Mutex::new(PeerStore::new()));
    let mut store = entry.lock();
    let stored = queue(&mut store, peer_fp, payload);
    if stored {
        tracing::info!(
            peer = %peer_fp,
            queued = store.pending().len(),
            len = payload.len(),
            "DTN: peer unreachable — payload buffered until it returns"
        );
    }
    stored
}

pub(crate) fn pending_for(peer_fp: &str) -> usize {
    stores()
        .get(peer_fp)
        .map(|entry| entry.lock().pending().len())
        .unwrap_or(0)
}

pub(crate) async fn flush_all(nc: &Arc<GhostNode>, peers: &DashMap<String, SocketAddr>) {
    #[cfg(feature = "research")]
    super::research_hooks::vault::flush_outbox(nc, peers).await;
    if !enabled() {
        return;
    }
    let reachable: Vec<String> = peers
        .iter()
        .filter(|entry| nc.sessions.contains_key(entry.key()))
        .map(|entry| entry.key().clone())
        .collect();
    for peer_fp in reachable {
        let pending = {
            let Some(entry) = stores().get(&peer_fp) else {
                continue;
            };
            let mut store = entry.lock();
            store.compact();
            store.pending()
        };
        if pending.is_empty() {
            continue;
        }
        let mut sent = Vec::new();
        for bundle in &pending {
            #[cfg(feature = "research")]
            let body =
                match super::research_hooks::vault::open_mesh(nc, peers, &bundle.payload).await {
                Ok(plain) => plain,
                Err(reason) => {
                    tracing::warn!(
                        peer = %peer_fp,
                        bundle = %hex::encode(&bundle.bundle_id[..4]),
                        ?reason,
                        "vault: undeliverable bundle dropped from the queue"
                    );
                    sent.push(bundle.bundle_id);
                    continue;
                }
            };
            #[cfg(not(feature = "research"))]
            let body = bundle.payload.clone();

            if super::tunnel::send_payload(nc, peers, &peer_fp, &body).await {
                sent.push(bundle.bundle_id);
                #[cfg(feature = "research")]
                super::research_hooks::vault::forget(&bundle.payload);
            } else {
                break;
            }
        }
        if sent.is_empty() {
            continue;
        }
        let count = sent.len();
        if let Some(entry) = stores().get(&peer_fp) {
            let mut store = entry.lock();
            for id in sent {
                store.delivered.insert(id);
            }
        }
        tracing::info!(
            peer = %peer_fp,
            bundles = count,
            remaining = pending_for(&peer_fp),
            "DTN: buffered payloads delivered after reconnect"
        );
    }
}

pub(crate) fn spawn_flush_loop(
    nc: Arc<GhostNode>,
    peers: Arc<DashMap<String, SocketAddr>>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            flush_all(&nc, &peers).await;
            #[cfg(feature = "research")]
            super::research_hooks::vault::collect_decay();
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_payload_is_one_bundle_and_a_second_peer_gets_its_own() {
        let mut store_a = PeerStore::new();
        assert!(queue(
            &mut store_a,
            "peer-a",
            b"GHOST_PEX2____\x00\x01batch"
        ));
        assert!(
            !queue(&mut store_a, "peer-a", b"GHOST_PEX2____\x00\x01batch"),
            "the same batch is one bundle"
        );
        assert_eq!(store_a.pending().len(), 1);
        let mut store_b = PeerStore::new();
        assert!(queue(
            &mut store_b,
            "peer-b",
            b"GHOST_PEX2____\x00\x01batch"
        ));
        assert!(queue(
            &mut store_a,
            "peer-a",
            b"GHOST_PEX2____\x00\x02other"
        ));
        assert_eq!(store_a.pending().len(), 2, "a new batch is new work");
        assert!(!queue(&mut store_a, "peer-a", b""), "empty is not a bundle");
    }

    #[test]
    fn delivered_bundles_are_never_pending_again() {
        let mut store = PeerStore::new();
        assert!(queue(&mut store, "peer-a", b"one"));
        assert!(queue(&mut store, "peer-a", b"two"));
        assert_eq!(store.pending().len(), 2);
        store.delivered.insert(bundle_id("peer-a", b"one"));
        assert_eq!(store.pending().len(), 1, "delivered work does not repeat");
        assert_eq!(store.delivered_ids(), vec![bundle_id("peer-a", b"one")]);
    }

    #[test]
    fn a_full_queue_drops_new_work_instead_of_growing() {
        let mut store = PeerStore::new();
        for i in 0..MAX_PENDING {
            assert!(queue(&mut store, "peer-a", format!("batch-{i}").as_bytes()));
        }
        assert!(
            !queue(&mut store, "peer-a", b"one-too-many"),
            "the queue is bounded"
        );
        assert_eq!(store.pending().len(), MAX_PENDING);
    }

    #[test]
    fn compaction_keeps_exactly_the_pending_work() {
        let mut store = PeerStore::new();
        for i in 0..(MAX_PENDING * 2 + 5) {
            store.tree.insert(DtnBundle::new(
                bundle_id("peer-a", format!("b{i}").as_bytes()),
                i as u64,
                format!("b{i}").into_bytes(),
            ));
        }
        for i in 0..(MAX_PENDING * 2) {
            store
                .delivered
                .insert(bundle_id("peer-a", format!("b{i}").as_bytes()));
        }
        let pending = store.pending().len();
        assert_eq!(pending, 5);
        store.compact();
        assert!(store.tree.len() <= MAX_PENDING * 2, "the tree shrinks");
        assert_eq!(store.pending().len(), pending, "pending work is preserved");
        assert!(store.delivered.is_empty(), "delivered ids need no keeping");
    }

    #[tokio::test]
    async fn a_reconnected_peer_receives_the_queued_payload_exactly_once() {
        let node = Arc::new(GhostNode::new("127.0.0.1:0").await.expect("a node"));
        let me = l0_identity::GhostIdentity::generate_fresh();
        let peer = l0_identity::GhostIdentity::generate_fresh();
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("a receiver");
        let addr = sock.local_addr().expect("a bound receiver");

        let master = [0x31u8; 32];
        let ours = Session::new_with_role(master, peer.fingerprint(), SessionRole::Initiator);
        ours.pin_peer_identity(peer.public_key_bytes());
        let theirs = Session::new_with_role(master, me.fingerprint(), SessionRole::Responder);
        theirs.pin_peer_identity(me.public_key_bytes());

        let peers: Arc<DashMap<String, SocketAddr>> = Arc::new(DashMap::new());

        vantablack::ghost::net::dtn_reconcile::set_enabled(true);
        let payload = b"GHOST_PEX2____\x00\x01descriptor-batch".to_vec();
        assert!(store(&peer.fingerprint(), &payload), "buffered while away");

        let flush = spawn_flush_loop(
            Arc::clone(&node),
            Arc::clone(&peers),
            Duration::from_millis(40),
        );
        let mut buf = vec![0u8; 65_535];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), sock.recv_from(&mut buf))
                .await
                .is_err(),
            "an absent peer receives nothing and keeps its queue"
        );
        assert_eq!(pending_for(&peer.fingerprint()), 1);

        node.sessions.insert(peer.fingerprint(), ours);
        peers.insert(peer.fingerprint(), addr);
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
            .await
            .expect("the flush loop delivers the bundle")
            .expect("a datagram");
        flush.abort();
        assert_eq!(pending_for(&peer.fingerprint()), 0, "delivered once");
        let frame = &buf[..n];
        let header = net::parse_gtf_v2_header(frame).expect("a GTFv2 frame");
        let plan = theirs.plan_open(
            header.epoch,
            NonceDirection::InitiatorToResponder,
            header.counter,
        );
        let key = match &plan {
            vantablack::ghost::session::ratchet::OpenPlan::Forward { key, .. } => *key,
            vantablack::ghost::session::ratchet::OpenPlan::Cached { key, .. } => *key,
            vantablack::ghost::session::ratchet::OpenPlan::Refused => panic!("refused"),
        };
        let mut carried = unframe(net::extract_payload(frame)).expect("a framed shard");
        let opened = vantablack::ghost::layers::l2_aead::xchacha_open(
            &key,
            &header.nonce,
            header.epoch,
            NonceDirection::InitiatorToResponder,
            &mut carried,
        )
        .expect("the peer's session opens it");
        theirs.commit_open(header.epoch, NonceDirection::InitiatorToResponder, plan);
        assert_eq!(
            frame_payload(opened).expect("a framed payload"),
            payload,
            "the queued bytes arrive unchanged"
        );

        assert!(
            tokio::time::timeout(Duration::from_millis(250), sock.recv_from(&mut buf))
                .await
                .is_err(),
            "a delivered bundle is not resent"
        );
        stores().remove(&peer.fingerprint());
        vantablack::ghost::net::dtn_reconcile::set_enabled(false);
    }
}
