//! Emergency epidemic routing for the live daemon (`exp_diffusion`, Phase 2 wiring).
//!
//! [`vantablack::ghost::net::diffusion`] owns the envelope, the duplicate
//! suppression cache and the bounded fanout decision. This module is the daemon
//! half: it floods a datagram that no route could carry, and forwards one it
//! receives.
//!
//! ## What travels
//!
//! A `DIFF` packet carries **the original sealed GTFv2 datagram unchanged**. Hops
//! between the sender and the target hold no key for it, so forwarding is blind —
//! exactly the property that makes epidemic routing safe to use with strangers.
//! The packet itself is sealed under the *hop's* session, because that is the only
//! key a neighbour can open.
//!
//! ## Bounds
//!
//! * hop count: `DiffusionPacket::max_hops`, capped by the router's own maximum
//!   (`DEFAULT_MAX_DIFFUSION_HOPS`, 4);
//! * fanout: `DEFAULT_DIFFUSION_FANOUT` (3) neighbours per hop, sender excluded;
//! * duplicate suppression: a 16-byte diffusion id in a seen cache pruned after
//!   5 minutes — a broadcast storm is what this exists to prevent, so the cache is
//!   checked before anything is forwarded;
//! * nesting: a `DIFF` payload that itself starts with `DIFF` is dropped. One
//!   envelope is enough, and nesting would let a peer multiply the amplification
//!   the hop limit is supposed to bound.
//!
//! ## When it is used
//!
//! Only when the toggle is on (`exp_diffusion` or `GHOST_DIFFUSION=1`) and only
//! for a frame the ordinary path reported `Unroutable`. The cost is real — this is
//! the one feature here that spends bandwidth to beat a partition — so it is never
//! a silent retry of every send.

use crate::*;
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::Duration;

use vantablack::ghost::net::diffusion::{DiffusionAction, DiffusionPacket, DiffusionRouter};

const SEEN_TTL: Duration = Duration::from_secs(300);

pub(crate) fn enabled() -> bool {
    vantablack::ghost::net::diffusion::is_enabled()
}

fn router() -> &'static parking_lot::Mutex<DiffusionRouter> {
    static ROUTER: OnceLock<parking_lot::Mutex<DiffusionRouter>> = OnceLock::new();
    ROUTER.get_or_init(|| {
        parking_lot::Mutex::new(DiffusionRouter::new(
            true,
            vantablack::ghost::net::diffusion::DEFAULT_MAX_DIFFUSION_HOPS,
            vantablack::ghost::net::diffusion::DEFAULT_DIFFUSION_FANOUT,
        ))
    })
}

pub(crate) fn looks_like(payload: &[u8]) -> bool {
    payload.len() >= 24 && &payload[..4] == vantablack::ghost::net::diffusion::DIFFUSION_MAGIC
}

pub(crate) fn diffusion_id(our_fp: &str, datagram: &[u8]) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"GGN_DIFFUSION_ID_V1");
    hasher.update(our_fp.as_bytes());
    hasher.update(datagram);
    let digest = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

pub(crate) async fn flood(
    nc: &Arc<GhostNode>,
    peers: &DashMap<String, SocketAddr>,
    datagram: &[u8],
) -> usize {
    if !enabled() {
        return 0;
    }
    let mut packet = DiffusionPacket::new(
        diffusion_id(&nc.fingerprint(), datagram),
        vantablack::ghost::net::diffusion::DEFAULT_MAX_DIFFUSION_HOPS,
        datagram.to_vec(),
    );
    {
        let router = router().lock();
        router.prune_seen_cache(SEEN_TTL);
        let _ = router.process_inbound(&mut packet, None, &[]);
    }
    let neighbours = neighbours_with_sessions(nc, peers);
    forward_to(nc, &packet, &neighbours).await
}

pub(crate) async fn handle(rx: &RxContext, payload: &[u8], from: SocketAddr) -> bool {
    if !looks_like(payload) {
        return false;
    }
    if !enabled() {
        tracing::debug!(peer = %from, "Diffusion: packet ignored — the toggle is off");
        return true;
    }
    let Some(mut packet) = DiffusionPacket::from_bytes(payload) else {
        tracing::debug!(peer = %from, "Diffusion: malformed envelope dropped");
        return true;
    };
    if looks_like(&packet.payload) {
        tracing::debug!(peer = %from, "Diffusion: nested envelope dropped");
        return true;
    }

    let neighbours = neighbours_with_sessions(&rx.node, &rx.peers);
    let addrs: Vec<SocketAddr> = neighbours.iter().map(|(_, addr)| *addr).collect();
    let action = {
        let router = router().lock();
        router.prune_seen_cache(SEEN_TTL);
        router.process_inbound(&mut packet, Some(from), &addrs)
    };
    match action {
        DiffusionAction::ForwardTo(targets) => {
            let chosen: Vec<(String, SocketAddr)> = neighbours
                .iter()
                .filter(|(_, addr)| targets.contains(addr))
                .cloned()
                .collect();
            let forwarded = forward_to(&rx.node, &packet, &chosen).await;
            tracing::debug!(
                peer = %from,
                hop = packet.hop_count,
                forwarded,
                "Diffusion: forwarded"
            );
        }
        DiffusionAction::DropAlreadySeen => {
            tracing::trace!(peer = %from, "Diffusion: duplicate suppressed");
            return true;
        }
        DiffusionAction::DropHopsExceeded => {
            tracing::debug!(peer = %from, hop = packet.hop_count, "Diffusion: hop limit reached");
            return true;
        }
        DiffusionAction::Disabled => return true,
    }

    let inner = &packet.payload;
    if net::parse_gtf_v2_header(inner).is_some() {
        let session = net::parse_session_hash(inner);
        if session != [0, 0, 0, 0] {
            if let Some(addr) = session_peer_addr(&rx.node, &rx.peers, session) {
                tracing::info!(
                    peer = %addr,
                    len = inner.len(),
                    "Diffusion: datagram for a local session — delivering"
                );
                let inner = inner.clone();
                Box::pin(rx.ingest(&inner, addr)).await;
            }
        }
    }
    true
}

fn neighbours_with_sessions(
    nc: &Arc<GhostNode>,
    peers: &DashMap<String, SocketAddr>,
) -> Vec<(String, SocketAddr)> {
    let mut out: Vec<(String, SocketAddr)> = peers
        .iter()
        .filter(|e| nc.sessions.contains_key(e.key()))
        .map(|e| (e.key().clone(), *e.value()))
        .collect();
    out.sort();
    out
}

async fn forward_to(
    nc: &Arc<GhostNode>,
    packet: &DiffusionPacket,
    targets: &[(String, SocketAddr)],
) -> usize {
    let payload = packet.to_bytes();
    let mut reached = 0;
    for (fp, target) in targets {
        let Some(sess) = nc.sessions.get(fp) else {
            continue;
        };
        let ctx = SealCtx::from_session(&sess);
        drop(sess);
        if payload.len() + 2 <= net::V2_MAX_BULK_PAYLOAD_LEN {
            let frame = seal_single(&ctx, &payload);
            if super::srtp::send_raw(&nc.socket, target, &frame)
                .await
                .is_ok()
            {
                reached += 1;
            }
            continue;
        }
        let (carriers, tag) = enc_split(&ctx, &payload);
        let mut carried = true;
        for (i, carrier) in carriers.iter().take(3).enumerate() {
            if let Err(e) = super::srtp::send_v2(
                &nc.socket,
                target,
                &ctx.data_header(i as u8, true, 0),
                carrier,
                &tag,
            )
            .await
            {
                tracing::debug!(peer = %target, error = %e, "Diffusion: hop send failed");
                carried = false;
            }
        }
        if carried {
            reached += 1;
        }
    }
    reached
}

fn session_peer_addr(
    nc: &Arc<GhostNode>,
    peers: &DashMap<String, SocketAddr>,
    session: [u8; 4],
) -> Option<SocketAddr> {
    let fp = nc
        .sessions
        .iter()
        .find(|entry| entry.value().session_hash == session)
        .map(|entry| entry.key().clone())?;
    peers.get(&fp).map(|entry| *entry.value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn session_pair() -> (l0_identity::GhostIdentity, l0_identity::GhostIdentity) {
        (
            l0_identity::GhostIdentity::generate_fresh(),
            l0_identity::GhostIdentity::generate_fresh(),
        )
    }

    #[test]
    fn only_a_diffusion_envelope_looks_like_one() {
        let mut packet = DiffusionPacket::new([7u8; 16], 4, b"inner".to_vec());
        packet.hop_count = 0;
        let bytes = packet.to_bytes();
        assert!(looks_like(&bytes));
        assert!(!looks_like(b"GHOST_HANDSHAKE_"), "a handshake is not one");
        assert!(!looks_like(&bytes[..20]), "a truncated envelope is not one");
        let nested = DiffusionPacket::new([8u8; 16], 4, bytes.clone()).to_bytes();
        assert!(looks_like(&nested));
    }

    #[test]
    fn the_id_is_stable_per_node_and_datagram() {
        let d = b"one sealed datagram";
        assert_eq!(diffusion_id("aa", d), diffusion_id("aa", d));
        assert_ne!(diffusion_id("aa", d), diffusion_id("bb", d));
        assert_ne!(diffusion_id("aa", d), diffusion_id("aa", b"another"));
    }

    #[tokio::test]
    async fn flood_seals_one_envelope_per_neighbour_that_has_a_session() {
        let node = Arc::new(GhostNode::new("127.0.0.1:0").await.expect("a node"));
        let (me, peer) = session_pair();
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("a receiver");
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let addr = sock.local_addr().unwrap();

        let master = [0x42u8; 32];
        let ours = Session::new_with_role(master, peer.fingerprint(), SessionRole::Initiator);
        ours.pin_peer_identity(peer.public_key_bytes());
        let theirs = Session::new_with_role(master, me.fingerprint(), SessionRole::Responder);
        theirs.pin_peer_identity(me.public_key_bytes());
        node.sessions.insert(peer.fingerprint(), ours);

        let peers: DashMap<String, SocketAddr> = DashMap::new();
        peers.insert(peer.fingerprint(), addr);

        let inner = {
            let mut frame = vec![0u8; 64];
            frame[..4].copy_from_slice(&[1, 2, 3, 4]);
            frame
        };
        vantablack::ghost::net::diffusion::set_enabled(true);
        let reached = flood(&node, &peers, &inner).await;
        vantablack::ghost::net::diffusion::set_enabled(false);
        assert_eq!(reached, 1, "one neighbour holds a session");

        let mut buf = vec![0u8; 65_535];
        let (n, _) = sock.recv_from(&mut buf).expect("a hop envelope arrives");
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
        .expect("the neighbour's session opens it");
        theirs.commit_open(header.epoch, NonceDirection::InitiatorToResponder, plan);
        let payload = frame_payload(opened).expect("a framed payload");
        let packet = DiffusionPacket::from_bytes(payload).expect("a diffusion envelope");
        assert_eq!(packet.payload, inner);
        assert_eq!(packet.hop_count, 1, "the seeder's packet was counted once");
    }

    #[test]
    fn a_suppressed_duplicate_is_never_forwarded_twice() {
        let router = DiffusionRouter::new(true, 4, 3);
        let peer: SocketAddr = "10.0.0.1:2270".parse().unwrap();
        let neighbours = [peer, "10.0.0.2:2270".parse().unwrap()];
        let mut packet = DiffusionPacket::new([3u8; 16], 4, b"x".to_vec());
        assert!(matches!(
            router.process_inbound(&mut packet, Some(peer), &neighbours),
            DiffusionAction::ForwardTo(_)
        ));
        assert_eq!(
            router.process_inbound(&mut packet, Some(peer), &neighbours),
            DiffusionAction::DropAlreadySeen
        );
    }
}
