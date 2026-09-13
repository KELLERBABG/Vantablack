#![cfg(feature = "vpn")]

//! Transport-level e2e gate: a REAL GTF bulk frame through REAL session
//! crypto (ChaCha20Poly1305, direction-bound nonce) and the REAL tunnel
//! magic dispatch — exactly the wire path `main.rs` uses for VPN payloads.
//!
//! Caught a real integration bug when written: the main.rs receive loop fed
//! every frame through the 2-of-3 RS shard pool (`assemble`), so single-frame
//! tunnel datagrams never assembled and were silently dropped. This gate
//! pins the bypass (flags bit 1 → direct dispatch).

mod common;
use common::tunnel::{receiver_open, tunnel_frame};
use vantablack::ghost::layers::l2_aead::NonceDirection;
use vantablack::ghost::net::vpn::client::{open_to_tun, seal_from_tun, ClientState};
use vantablack::ghost::net::vpn::hub::VpnHub;
use vantablack::ghost::net::vpn::tun::{FakeTun, TunDevice};
use vantablack::ghost::net::vpn::{VpnConfig, VpnRole};
use vantablack::ghost::net::GTF_BULK_SIZE;

#[test]
fn transport_phone_to_hub_via_real_gtf_frames() {
    let key = [0xA5u8; 32];
    let sh = [0x11, 0x22, 0x33, 0x44];
    let fp = "a1b2c3d4e5f6a7b8";

    let phone = ClientState::new(fp, key);
    let cfg = VpnConfig {
        role: VpnRole::Hub,
        allowed_fingerprints: vec![fp.to_string()],
        ..VpnConfig::default()
    };
    let hub = VpnHub::start(cfg);
    let phone_addr: std::net::SocketAddr = "198.51.100.7:45000".parse().unwrap();
    // Production order (main.rs:394): the handshake creates the lease and
    // rotates the epoch BEFORE any tunnel traffic.
    hub.on_handshake(fp, phone_addr);

    // 10 sealed IP packets from the phone TUN — real ClientState counters.
    let mut tun = FakeTun::new();
    for i in 0..10u32 {
        let mut pkt = vec![0x45u8; 120];
        pkt[4..8].copy_from_slice(&i.to_be_bytes());
        tun.push_inbound(pkt);
    }
    let mut rbuf = [0u8; 1400];
    let mut ctr = 2u32; // session counters live above the handshake range
    let mut sent = 0usize;
    loop {
        match TunDevice::read_packet(&mut tun, &mut rbuf) {
            Ok(n) => {
                let wire = seal_from_tun(&phone, &rbuf[..n]).unwrap();
                let frame =
                    tunnel_frame(&key, sh, ctr, NonceDirection::InitiatorToResponder, &wire);
                assert!(frame.len() <= GTF_BULK_SIZE);
                // ── receiver side: the real wire pipeline ──
                let body = receiver_open(&frame, frame.len(), &key, sh, ctr)
                    .expect("tunnel frame must survive the real GTF path");
                assert_eq!(body, wire, "tunnel datagram intact");
                hub.handle_tunnel_payload(fp, &key, sh, &body, phone_addr);
                ctr += 1;
                sent += 1;
            }
            Err(_) => break,
        }
    }
    assert_eq!(sent, 10);

    // The hub accepted and routed them: stats_in counts every accepted frame,
    // none dropped on a clean link.
    let (stats_in, _out, dropped, _tcp, _udp) = hub.stats();
    assert_eq!(stats_in, 10, "all frames accepted");
    assert_eq!(dropped, 0, "no frame may be dropped on a clean link");

    // The lease is anchored at the phone's endpoint (monotonic re-anchor).
    let lease = hub.leases.lease_for(fp).unwrap();
    assert_eq!(hub.leases.endpoint_for_ip(lease).unwrap(), phone_addr);
}

#[test]
fn transport_hub_to_phone_reply_lands_in_tun() {
    let key = [0x5Au8; 32];
    let sh = [0x55, 0x66, 0x77, 0x88];
    let fp = "b1b2c3d4e5f6a7b8";

    let phone = ClientState::new(fp, key);
    let cfg = VpnConfig {
        role: VpnRole::Hub,
        allowed_fingerprints: vec![fp.to_string()],
        ..VpnConfig::default()
    };
    let hub = VpnHub::start(cfg);
    let phone_addr: std::net::SocketAddr = "198.51.100.9:46000".parse().unwrap();
    hub.on_handshake(fp, phone_addr); // production order: handshake first

    // 1. Phone → hub ICMP echo for the hub's own overlay IP (in scope).
    let mut tun = FakeTun::new();
    let mut echo = vec![0u8; 84];
    echo[0] = 0x45;
    echo[9] = 1; // ICMP
    echo[12..16].copy_from_slice(&[10, 66, 0, 10]); // phone overlay src
    echo[16..20].copy_from_slice(&[10, 66, 0, 1]); // hub overlay dst
    echo[20] = 8; // echo request
    tun.push_inbound(echo);
    let mut rbuf = [0u8; 1400];
    let n = TunDevice::read_packet(&mut tun, &mut rbuf).unwrap();
    let wire = seal_from_tun(&phone, &rbuf[..n]).unwrap();
    let frame = tunnel_frame(&key, sh, 2, NonceDirection::InitiatorToResponder, &wire);
    let body = receiver_open(&frame, frame.len(), &key, sh, 2).expect("frame intact");
    hub.handle_tunnel_payload(fp, &key, sh, &body, phone_addr);

    // 2. Hub egress: poll the reply and send it back as a real tunnel frame
    //    (hub = session responder → ResponderToInitiator direction).
    let u = hub.poll_egress().expect("ICMP reply must be queued");
    assert_eq!(u.fingerprint, fp);
    assert_eq!(u.endpoint, phone_addr);
    let reply_frame = tunnel_frame(
        &key,
        sh,
        1002,
        NonceDirection::ResponderToInitiator,
        &u.wire,
    );

    // 3. Phone opens the reply through the exact receive path.
    let reply_wire =
        receiver_open(&reply_frame, reply_frame.len(), &key, sh, 1002).expect("reply frame intact");
    let tun2 = FakeTun::new();
    let (accepted, _adv) = open_to_tun(&phone, &reply_wire, &tun2);
    assert!(accepted, "phone must accept the hub's reply");
    let out = tun2.drain_outbound();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0][9], 1, "still ICMP");
    assert_eq!(
        out[0][20], 0,
        "echo REPLY type (byte 20, after the IP header)"
    );
    assert_eq!(&out[0][12..16], &[10, 66, 0, 1], "from the hub overlay IP");
    assert_eq!(&out[0][16..20], &[10, 66, 0, 10], "to the phone overlay IP");
}
