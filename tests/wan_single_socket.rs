//! Integration tests for single-socket UDP multiplexing, ICE nomination routing,
//! client relay discovery without `GHOST_RELAY=1`, and primary-targeted RS(2,1)
//! shard delivery (`A1`–`A4` from M1).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc};

use vantablack::ghost::net::fallback::{choose_fallback_with_skywave, Fallback, FallbackPath};
use vantablack::ghost::net::ice::{
    Candidate, CandidateType, IceAgent, IceOffer, IceRole, DEFAULT_COMPONENT,
};
use vantablack::ghost::net::mesh::{
    classify_nat_type, resolve_stun_pool, update_wan_telemetry, wan_telemetry_snapshot,
    AdaptiveShardRouter, NatHolePuncher, NatType,
};
use vantablack::ghost::net::{
    build_gtf_v2_frame, send_gtf_v2, stun, GtfV2Header, JITTER_MAX, OFFSET_SHARD_INDEX,
};

#[tokio::test]
async fn single_socket_demuxes_stun_and_gtf_without_cross_leak() {
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let local_addr = sock.local_addr().unwrap();

    let stun_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let stun_addr = stun_server.local_addr().unwrap();

    let (stun_tx, _) = broadcast::channel::<(Vec<u8>, SocketAddr)>(32);
    let (gtf_tx, mut gtf_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(32);

    // Subscribe before sending so no STUN reply is missed.
    let mut stun_rx = stun_tx.subscribe();

    // Spawn single-socket receive loop mirroring `nc.socket` in `src/main.rs`.
    let rx_sock = Arc::clone(&sock);
    let stun_tx_loop = stun_tx.clone();
    let recv_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        for _ in 0..2 {
            let (amt, src) = rx_sock.recv_from(&mut buf).await.unwrap();
            if stun::is_stun_packet(&buf[..amt]) {
                let _ = stun_tx_loop.send((buf[..amt].to_vec(), src));
            } else {
                let _ = gtf_tx.send((buf[..amt].to_vec(), src)).await;
            }
        }
    });

    // Mock STUN server responding on `stun_addr` with XOR-MAPPED-ADDRESS.
    let mapped_pub: SocketAddr = "198.51.100.77:55225".parse().unwrap();
    let srv_task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (amt, from) = stun_server.recv_from(&mut buf).await.unwrap();
        let req = stun::Message::parse(&buf[..amt]).unwrap();
        let resp = stun::Message::binding_success(req.txid, mapped_pub).encode();
        stun_server.send_to(&resp, from).await.unwrap();
    });

    // Gather STUN reflexive candidate via the muxed channel on the shared socket.
    let mut agent = IceAgent::new(IceRole::Controlling);
    let cand = agent
        .gather_reflexive_mux(&sock, stun_addr, Duration::from_secs(2), &mut stun_rx)
        .await
        .expect("STUN reflexive response must be demuxed via stun_tx");
    assert_eq!(cand.addr, mapped_pub);

    // Send a GTF v2 datagram to the same shared socket and ensure it goes to the GTF path.
    let peer_sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let header = GtfV2Header {
        session_hash: [0x11, 0x22, 0x33, 0x44],
        counter: 7,
        epoch: 1,
        nonce: [0x55; 12],
        shard_index: 1,
        flags: 0,
        bulk: false,
        tail: [0u8; JITTER_MAX],
    };
    let gtf_frame = build_gtf_v2_frame(&header, b"muxed-gtf-payload", &[0x99; 16]);
    assert!(
        !stun::is_stun_packet(&gtf_frame),
        "GTF frame must never match RFC 8489 STUN header"
    );
    peer_sender.send_to(&gtf_frame, local_addr).await.unwrap();

    let (got_gtf, _) = tokio::time::timeout(Duration::from_secs(2), gtf_rx.recv())
        .await
        .expect("GTF frame must arrive on GTF channel")
        .unwrap();
    assert_eq!(got_gtf, gtf_frame);

    // Ensure no GTF frame leaked onto `stun_rx`.
    assert!(
        tokio::time::timeout(Duration::from_millis(50), stun_rx.recv())
            .await
            .is_err()
    );

    srv_task.await.unwrap();
    recv_task.await.unwrap();
}

#[tokio::test]
async fn ice_nomination_updates_peer_routing_via_nominated_addr() {
    let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr_a = sock_a.local_addr().unwrap();
    let addr_b = sock_b.local_addr().unwrap();

    let (tx_a, _) = broadcast::channel::<(Vec<u8>, SocketAddr)>(64);
    let (tx_b, _) = broadcast::channel::<(Vec<u8>, SocketAddr)>(64);

    // Demux loops for both sockets.
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let spawn_demux = |sock: Arc<UdpSocket>,
                       tx: broadcast::Sender<(Vec<u8>, SocketAddr)>,
                       run: Arc<std::sync::atomic::AtomicBool>| {
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while run.load(std::sync::atomic::Ordering::Relaxed) {
                match tokio::time::timeout(Duration::from_millis(50), sock.recv_from(&mut buf))
                    .await
                {
                    Ok(Ok((amt, src))) if stun::is_stun_packet(&buf[..amt]) => {
                        let _ = tx.send((buf[..amt].to_vec(), src));
                    }
                    _ => {}
                }
            }
        })
    };
    let h_a = spawn_demux(Arc::clone(&sock_a), tx_a.clone(), Arc::clone(&running));
    let h_b = spawn_demux(Arc::clone(&sock_b), tx_b.clone(), Arc::clone(&running));

    let mut puncher_a = NatHolePuncher::new().with_stun_mux(tx_a);
    puncher_a.set_local_fingerprint("fp_alice_00000002");
    let mut puncher_b = NatHolePuncher::new().with_stun_mux(tx_b);
    puncher_b.set_local_fingerprint("fp_bob_0000000001");

    let offer_a = IceOffer::new(
        puncher_a.local_credentials().clone(),
        vec![Candidate::new(
            CandidateType::Host,
            addr_a,
            addr_a,
            DEFAULT_COMPONENT,
            None,
        )],
        true,
    );
    let offer_b = IceOffer::new(
        puncher_b.local_credentials().clone(),
        vec![Candidate::new(
            CandidateType::Host,
            addr_b,
            addr_b,
            DEFAULT_COMPONENT,
            None,
        )],
        false,
    );

    // Register initial stale port on peer map, then run ICE checks on muxed sockets.
    let stale_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let addrs_a: DashMap<String, SocketAddr> = DashMap::new();
    addrs_a.insert("fp_bob_0000000001".to_string(), stale_addr);

    puncher_a.register_peer("fp_bob_0000000001", addr_b, addr_a);
    puncher_a.set_ice_offer("fp_bob_0000000001", offer_b);
    puncher_b.register_peer("fp_alice_00000002", addr_a, addr_b);
    puncher_b.set_ice_offer("fp_alice_00000002", offer_a);

    let (ok_a, ok_b) = tokio::join!(
        puncher_a.punch_hole(&sock_a, "fp_bob_0000000001"),
        puncher_b.punch_hole(&sock_b, "fp_alice_00000002")
    );
    assert!(ok_a && ok_b, "both ICE agents must establish a path");

    let nominated_b = puncher_a
        .nominated_addr("fp_bob_0000000001")
        .expect("nominated_addr must return Bob's nominated socket");
    assert_eq!(nominated_b, addr_b);
    addrs_a.insert("fp_bob_0000000001".to_string(), nominated_b);
    assert_eq!(
        addrs_a.get("fp_bob_0000000001").map(|e| *e.value()),
        Some(addr_b)
    );

    running.store(false, std::sync::atomic::Ordering::Relaxed);
    let _ = tokio::join!(h_a, h_b);
}

#[test]
fn client_without_ghost_relay_discovers_and_selects_relay_candidate() {
    // Client node has NO DerpRelay (simulating GHOST_RELAY unset).
    let fallback = Fallback::new(None);
    let relay_addr: SocketAddr = "203.0.113.40:55225".parse().unwrap();
    fallback.record_relay("relay_node_fp", relay_addr);

    assert_eq!(fallback.relay_count(), 1);
    let chosen = choose_fallback_with_skywave(
        "client_a_fp",
        "client_b_fp",
        &fallback.relay_candidates(),
        None,
        None,
    );
    assert_eq!(
        chosen,
        Some(FallbackPath::MeshRelay {
            relay_fp: "relay_node_fp".to_string(),
            relay_addr,
        })
    );
}

#[tokio::test]
async fn primary_shard_routing_delivers_all_3_shards_to_primary_when_3_peers_exist() {
    let send_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let primary_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer2_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer3_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let primary_addr = primary_sock.local_addr().unwrap();
    let peers: DashMap<String, SocketAddr> = DashMap::new();
    peers.insert("primary_fp".to_string(), primary_addr);
    peers.insert("peer2_fp".to_string(), peer2_sock.local_addr().unwrap());
    peers.insert("peer3_fp".to_string(), peer3_sock.local_addr().unwrap());

    let router = AdaptiveShardRouter::new();
    let routes = router.assign_shards_to_primary("primary_fp", 3);
    assert_eq!(routes.len(), 3);

    let shards = [
        b"shard-0".to_vec(),
        b"shard-1".to_vec(),
        b"shard-2".to_vec(),
    ];
    let tag = [0x42u8; 16];
    for route in routes {
        let dst = peers
            .get(&route.peer_fingerprint)
            .map(|e| *e.value())
            .unwrap();
        let hdr = GtfV2Header {
            session_hash: [0xDE, 0xAD, 0xBE, 0xEF],
            counter: 10,
            epoch: 0,
            nonce: [0x11; 12],
            shard_index: route.shard_index,
            flags: 0,
            bulk: false,
            tail: [0u8; JITTER_MAX],
        };
        send_gtf_v2(
            &send_sock,
            &dst,
            &hdr,
            &shards[route.shard_index as usize],
            &tag,
        )
        .await
        .unwrap();
    }

    let mut received = Vec::new();
    let mut buf = [0u8; 2048];
    for _ in 0..3 {
        let (amt, _) =
            tokio::time::timeout(Duration::from_secs(1), primary_sock.recv_from(&mut buf))
                .await
                .expect("primary_fp must receive all 3 shards")
                .unwrap();
        assert!(amt > OFFSET_SHARD_INDEX);
        received.push(buf[OFFSET_SHARD_INDEX]);
    }
    received.sort();
    assert_eq!(received, vec![0, 1, 2]);

    assert!(
        tokio::time::timeout(Duration::from_millis(60), peer2_sock.recv_from(&mut buf))
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(60), peer3_sock.recv_from(&mut buf))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn stun_pool_and_nat_classification_are_offline_safe() {
    // Explicit override with unreachable/unresolvable host must never panic or error.
    let local: SocketAddr = "192.168.1.50:55225".parse().unwrap();
    assert_eq!(classify_nat_type(Some(local), &[]), NatType::Unknown);
    assert_eq!(
        classify_nat_type(
            Some(local),
            &[
                "198.51.100.1:44000".parse().unwrap(),
                "198.51.100.1:44000".parse().unwrap(),
            ]
        ),
        NatType::Cone
    );
    assert_eq!(
        classify_nat_type(
            Some(local),
            &[
                "198.51.100.1:44000".parse().unwrap(),
                "198.51.100.1:44001".parse().unwrap(),
            ]
        ),
        NatType::Symmetric
    );

    // Offline / timeout check: short timeout resolves cleanly without panicking.
    let _ = resolve_stun_pool(Duration::from_millis(50), true).await;

    update_wan_telemetry(|s| {
        s.nat_type = NatType::Cone;
    });
    assert_eq!(wan_telemetry_snapshot().nat_type, NatType::Cone);
}
