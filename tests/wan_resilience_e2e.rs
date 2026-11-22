//! WAN Resilience E2E Tests (A3 Phase 2, A6, C4).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use vantablack::ghost::net::fallback::{blind_envelope, relay_hop, Fallback, FallbackPath};
use vantablack::ghost::net::relay::{wrap_blind_frame, DerpRelay, WanRateLimiter, BLIND_MAGIC};
use vantablack::ghost::net::FlowController;

#[test]
fn blnd_divergent_shard_forwarding_to_primary_fp() {
    let primary_fp = "primary-peer-fp-01";
    let carrier_fp = "carrier-peer-fp-02";
    let sender_fp = "sender-peer-fp-03";
    let shard_gtf_payload = b"GTF_V2_OPAQUE_SHARD_1".to_vec();

    // Wrap shard in BLND! envelope addressed to primary_fp.
    let wrapped = wrap_blind_frame(primary_fp, &shard_gtf_payload);
    assert!(wrapped.starts_with(BLIND_MAGIC));
    assert_eq!(blind_envelope(primary_fp, &shard_gtf_payload), wrapped);

    // Carrier's DerpRelay processes the BLND! envelope and forwards opaque shard to primary_fp.
    let relay = DerpRelay::new(Arc::new(FlowController::new(100)));
    let primary_addr: SocketAddr = "10.0.0.10:2270".parse().unwrap();
    let carrier_addr: SocketAddr = "10.0.0.20:2270".parse().unwrap();
    relay.authorize(primary_fp, primary_addr);
    relay.authorize(carrier_fp, carrier_addr);
    relay.authorize(sender_fp, "10.0.0.30:2270".parse().unwrap());

    let hop = relay_hop(&relay, sender_fp, &wrapped).expect("relay_hop must succeed");
    assert_eq!(hop.dest, primary_addr);
    assert_eq!(hop.bytes, shard_gtf_payload);
}

#[test]
fn dead_peer_eviction_and_route_failover() {
    let fb = Arc::new(Fallback::new(None));
    let dead_relay = "dead-relay-fp";
    let dead_addr: SocketAddr = "198.51.100.10:2270".parse().unwrap();
    let healthy_relay = "healthy-relay-fp";
    let healthy_addr: SocketAddr = "198.51.100.20:2270".parse().unwrap();

    fb.record_relay(dead_relay, dead_addr);
    fb.record_relay(healthy_relay, healthy_addr);

    // Peer A is relaying through dead_relay; Peer B is relaying through healthy_relay.
    fb.set(
        "peer-a",
        FallbackPath::MeshRelay {
            relay_fp: dead_relay.to_string(),
            relay_addr: dead_addr,
        },
    );
    fb.set(
        "peer-b",
        FallbackPath::MeshRelay {
            relay_fp: healthy_relay.to_string(),
            relay_addr: healthy_addr,
        },
    );
    fb.set(
        dead_relay,
        FallbackPath::MeshRelay {
            relay_fp: healthy_relay.to_string(),
            relay_addr: healthy_addr,
        },
    );

    // Evict dead_relay: its relay candidate, its own route, and peer-a's route are cleared.
    let affected = fb.evict_dead_peer(dead_relay);
    assert_eq!(affected, vec!["peer-a".to_string()]);
    assert!(fb.path("peer-a").is_none());
    assert!(fb.path(dead_relay).is_none());
    // Healthy peer-b route and healthy_relay candidate remain intact.
    assert!(fb.path("peer-b").is_some());
    assert_eq!(fb.relay_count(), 1);
}

#[test]
fn per_ip_handshake_rate_limiter_under_flood() {
    let limiter = WanRateLimiter::new(4.0, 1.0);
    let attacker_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99));
    let legit_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42));
    let max_pending = 512;

    // Below 50% capacity (pending_hs < 256), requests are not throttled.
    for _ in 0..10 {
        assert!(limiter.allow(attacker_ip, 100, max_pending));
    }

    // At >= 50% capacity (pending_hs >= 256), per-IP token bucket (capacity 4) is enforced.
    for _ in 0..4 {
        assert!(limiter.allow(attacker_ip, 256, max_pending));
    }
    assert!(
        !limiter.allow(attacker_ip, 256, max_pending),
        "attacker IP must be rate-limited once bucket is exhausted"
    );
    // Legitimate separate IP still has its own full bucket.
    assert!(limiter.allow(legit_ip, 256, max_pending));

    // Stateless handshake cookie roundtrip.
    let secret = [0x42u8; 32];
    let now = 1_700_000_000;
    let cookie = WanRateLimiter::issue_cookie(&secret, legit_ip, now);
    assert!(WanRateLimiter::verify_cookie(
        &secret, legit_ip, &cookie, now
    ));
    assert!(!WanRateLimiter::verify_cookie(
        &secret,
        attacker_ip,
        &cookie,
        now
    ));
}
