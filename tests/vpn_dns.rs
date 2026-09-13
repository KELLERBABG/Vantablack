#![cfg(feature = "vpn")]

//! DNS round-trip gate — the #1 real user flow (audit gap: flood caps were
//! gated, the functional path never was).
//!
//! Proves, end-to-end through the production pieces only:
//!   phone TUN → ClientState seal → real GTF tunnel frame → hub
//!   `handle_tunnel_payload` → `route_inner` UDP arm → `UdpFlowTable`
//!   (`get_or_create`, nonblocking OS socket bound per flow) → a real
//!   loopback UDP listener standing in for the home DNS server → crafted
//!   A-record reply → `spawn_flow_reader` → `build_udp_packet`
//!   (src = the real DNS server, dst = phone overlay) → `poll_egress` →
//!   real tunnel frame back → phone `open_to_tun` writes it into the TUN.
//!
//! Also asserts the NAT'd source tuple the server actually sees, valid
//! checksums on the reply, and that a second query on the same flow reuses
//! the flow/reader (no reader-per-query) while staying far below the caps.

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use vantablack::ghost::layers::l2_aead::NonceDirection;
use vantablack::ghost::net::vpn::client::{open_to_tun, seal_from_tun, ClientState};
use vantablack::ghost::net::vpn::hub::build_udp_packet;
use vantablack::ghost::net::vpn::hub::VpnHub;
use vantablack::ghost::net::vpn::tun::{FakeTun, TunDevice};
use vantablack::ghost::net::vpn::{VpnConfig, VpnRole};
use vantablack::ghost::net::GTF_BULK_SIZE;

mod common;
use common::tunnel::{receiver_open, tunnel_frame};
use common::wire::{dns_query, dns_response, internet_checksum, parse_udp};

const FP: &str = "c1b2c3d4e5f6a7b8";
const KEY: [u8; 32] = [0x77u8; 32];
const SH: [u8; 4] = [0x99, 0x88, 0x77, 0x66];
const PHONE: ([u8; 4], u16) = ([10, 66, 0, 10], 51555);
const NAS_IP: [u8; 4] = [192, 168, 1, 50];

/// Stand-in for the home DNS server. 127.0.0.1:<ephemeral> — port 53 is
/// taken on this machine (netstat) and the tuple logic is port-agnostic.
fn dns_server() -> (UdpSocket, std::net::SocketAddr) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind stand-in DNS server");
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let addr = sock.local_addr().unwrap();
    (sock, addr)
}

fn server_ip_of(addr: std::net::SocketAddr) -> [u8; 4] {
    match addr.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        _ => panic!("v4 listener"),
    }
}

/// The phone sends one DNS query through the REAL wire path:
/// TUN → seal → GTF tunnel frame → hub tunnel payload.
fn phone_sends_query(
    tun: &mut FakeTun,
    phone: &ClientState,
    hub: &std::sync::Arc<VpnHub>,
    phone_addr: std::net::SocketAddr,
    server: std::net::SocketAddr,
    server_ip: [u8; 4],
    id: u16,
    ctr: u32,
) {
    let q = build_udp_packet(
        std::net::IpAddr::V4(PHONE.0.into()),
        PHONE.1,
        std::net::IpAddr::V4(server_ip.into()),
        server.port(),
        &dns_query(id, "nas.home"),
    )
    .expect("query packet");
    tun.push_inbound(q);
    let mut rbuf = [0u8; 1500];
    let n = TunDevice::read_packet(tun, &mut rbuf).expect("TUN read");
    let wire = seal_from_tun(phone, &rbuf[..n]).expect("seal");
    let frame = tunnel_frame(&KEY, SH, ctr, NonceDirection::InitiatorToResponder, &wire);
    assert!(frame.len() <= GTF_BULK_SIZE);
    let body = receiver_open(&frame, frame.len(), &KEY, SH, ctr).expect("frame intact");
    hub.handle_tunnel_payload(FP, &KEY, SH, &body, phone_addr);
}

/// Poll egress for up to `secs`, collecting up to `want` tunnel units.
fn poll_units(
    hub: &VpnHub,
    want: usize,
    secs: u64,
) -> Vec<vantablack::ghost::net::vpn::hub::EgressUnit> {
    let mut out = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(secs);
    while out.len() < want && Instant::now() < deadline {
        if let Some(u) = hub.poll_egress() {
            out.push(u);
        } else {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    out
}

#[test]
fn dns_query_reaches_home_server_and_reply_lands_in_tun() {
    let (server, server_addr) = dns_server();
    let server_ip = server_ip_of(server_addr);

    let hub = VpnHub::start(VpnConfig {
        role: VpnRole::Hub,
        allowed_fingerprints: vec![FP.to_string()],
        ..VpnConfig::default()
    });
    let phone_addr: std::net::SocketAddr = "198.51.100.11:47000".parse().unwrap();
    // Production order (main.rs): the handshake creates the lease and
    // rotates the epoch BEFORE any tunnel traffic.
    hub.on_handshake(FP, phone_addr);

    let mut tun = FakeTun::new();
    let phone = ClientState::new(FP, KEY);
    phone_sends_query(
        &mut tun,
        &phone,
        &hub,
        phone_addr,
        server_addr,
        server_ip,
        0x1234,
        2,
    );

    // ── The home DNS server receives the query, NAT'd off the overlay. ──
    let mut buf = [0u8; 1500];
    let (amt, src) = server
        .recv_from(&mut buf)
        .expect("query must reach the server");
    let got = &buf[..amt];
    assert_eq!(&got[..2], &[0x12, 0x34], "DNS transaction id intact");
    let src_ip: [u8; 4] = match src.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        _ => panic!("v4 source"),
    };
    assert_ne!(src_ip, PHONE.0, "source must be NAT'd, not the overlay IP");

    // ── Crafted valid A-record reply, back to the query's source. ──
    let resp = dns_response(0x1234, "nas.home", NAS_IP);
    server.send_to(&resp, src).expect("send reply");

    // ── The flow reader relays it into egress as a tunnel unit. ──
    let mut units = poll_units(&hub, 1, 5);
    let u = units.pop().expect("flow reader never relayed the reply");
    assert_eq!(u.fingerprint, FP);
    assert_eq!(u.endpoint, phone_addr);

    // ── The phone opens the reply frame → sealed datagram → TUN. ──
    let reply_frame = tunnel_frame(
        &KEY,
        SH,
        1003,
        NonceDirection::ResponderToInitiator,
        &u.wire,
    );
    let reply =
        receiver_open(&reply_frame, reply_frame.len(), &KEY, SH, 1003).expect("reply frame intact");
    let tun2 = FakeTun::new();
    let (accepted, _adv) = open_to_tun(&phone, &reply, &tun2);
    assert!(accepted, "phone must accept the hub's relayed reply");
    let out = tun2.drain_outbound();
    assert_eq!(out.len(), 1);
    // ── Reply packet byte-correct: real server ip:port → phone overlay. ──
    let ip = &out[0];
    let (rsrc, rdst, rpayload) = parse_udp(ip).expect("reply is UDP/IP");
    assert_eq!(rsrc.0, server_ip, "reply src = the real DNS server");
    assert_eq!(rsrc.1, server_addr.port());
    assert_eq!(rdst.0, PHONE.0, "reply dst = phone overlay");
    assert_eq!(rdst.1, PHONE.1, "reply dst port = the phone's source port");
    assert_eq!(rpayload, &resp[..], "payload byte-correct");
    assert_eq!(internet_checksum(&ip[..20]), 0, "reply IP checksum valid");

    // ── Stats account for the round trip; nothing dropped. ──
    let (stats_in, _out, dropped, _tcp, _udp) = hub.stats();
    assert!(stats_in >= 1, "tunnel frames accepted");
    assert_eq!(dropped, 0, "clean-path round trip must drop nothing");
}

#[test]
fn dns_second_query_reuses_flow_and_reader() {
    let (server, server_addr) = dns_server();
    let server_ip = server_ip_of(server_addr);

    let hub = VpnHub::start(VpnConfig {
        role: VpnRole::Hub,
        allowed_fingerprints: vec![FP.to_string()],
        ..VpnConfig::default()
    });
    let phone_addr: std::net::SocketAddr = "198.51.100.12:48000".parse().unwrap();
    hub.on_handshake(FP, phone_addr);

    let mut tun = FakeTun::new();
    let phone = ClientState::new(FP, KEY);

    // Two queries from the SAME client port to the SAME server = one flow
    // key → one flow socket, one reader thread.
    phone_sends_query(
        &mut tun,
        &phone,
        &hub,
        phone_addr,
        server_addr,
        server_ip,
        0x0001,
        2,
    );
    phone_sends_query(
        &mut tun,
        &phone,
        &hub,
        phone_addr,
        server_addr,
        server_ip,
        0x0002,
        3,
    );

    // Both queries reach the server, in order.
    let mut got = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while got.len() < 2 && Instant::now() < deadline {
        let mut buf = [0u8; 1500];
        if let Ok((amt, src)) = server.recv_from(&mut buf) {
            got.push((u16::from_be_bytes([buf[0], buf[1]]), src));
        }
    }
    assert_eq!(
        got.iter().map(|g| g.0).collect::<Vec<_>>(),
        vec![1, 2],
        "both queries arrived, in order"
    );
    // Same flow: both queries must carry the same NAT'd source port.
    assert_eq!(
        got[0].1, got[1].1,
        "same client port → same flow socket port"
    );

    // Answer both, to the exact source of each query.
    for (id, src) in &got {
        let resp = dns_response(*id, "nas.home", NAS_IP);
        server.send_to(&resp, *src).expect("send reply");
    }

    // Both replies relayed through the one flow reader.
    let units = poll_units(&hub, 2, 5);
    assert_eq!(units.len(), 2, "both replies relayed");
    assert!(units.iter().all(|u| u.fingerprint == FP));

    // Open both on the phone side; both land in the TUN byte-correct.
    let tun2 = FakeTun::new();
    for (i, u) in units.iter().enumerate() {
        let f = tunnel_frame(
            &KEY,
            SH,
            2000 + i as u32,
            NonceDirection::ResponderToInitiator,
            &u.wire,
        );
        let reply = receiver_open(&f, f.len(), &KEY, SH, 2000 + i as u32).expect("reply intact");
        let (accepted, _) = open_to_tun(&phone, &reply, &tun2);
        assert!(accepted, "reply {i} accepted");
    }
    let out = tun2.drain_outbound();
    assert_eq!(out.len(), 2, "both replies delivered into the TUN");

    // Two small queries must not trip any cap.
    let (_in, _out, dropped, _tcp, _udp) = hub.stats();
    assert_eq!(dropped, 0, "two queries must not trip any cap");
}
