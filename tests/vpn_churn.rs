#![cfg(feature = "vpn")]

//! Churn gate — reader/flow lifecycle agreement across the idle boundary.
//!
//! Before the fix: reader exits after ~10 s of silence but its dedup key
//! stayed in `readers_spawned` forever, so a post-idle query on the same
//! tuple opened a fresh flow socket nobody read — silent DNS blackhole
//! until the client re-handshook.
//!
//! Production clocks are 10 s DNS TTL / 10 s reader idle. The gate injects
//! 300 ms on both (test constructors only — no runtime knobs) and proves:
//!   1. query → reply round trip works;
//!   2. after idle expiry + sweep, a NEW query on the SAME tuple gets a
//!      served flow (fresh socket) and its reply returns to the client;
//!   3. the racy window (reader exited, flow not yet swept) re-serves on
//!      the SAME socket with the SAME NAT'd port.

use std::net::UdpSocket;
use std::sync::Arc;
use std::time::{Duration, Instant};

use vantablack::ghost::layers::l2_aead::NonceDirection;
use vantablack::ghost::net::vpn::client::{open_to_tun, seal_from_tun, ClientState};
use vantablack::ghost::net::vpn::hub::{build_udp_packet, VpnHub};
use vantablack::ghost::net::vpn::tun::{FakeTun, TunDevice};
use vantablack::ghost::net::vpn::{UdpFlowTable, VpnConfig, VpnRole};

mod common;
use common::tunnel::{receiver_open, tunnel_frame};
use common::wire::{dns_query, dns_response, parse_udp};

const FP: &str = "f1b2c3d4e5f6a7b8";
const KEY: [u8; 32] = [0xCcu8; 32];
const SH: [u8; 4] = [0xAB, 0xCD, 0xEF, 0x01];
const PHONE: ([u8; 4], u16) = ([10, 66, 0, 10], 51777);
const NAS_IP: [u8; 4] = [192, 168, 1, 53];

fn dns_server() -> (UdpSocket, std::net::SocketAddr) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind stand-in DNS server");
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let addr = sock.local_addr().unwrap();
    (sock, addr)
}

fn server_ip_of(addr: std::net::SocketAddr) -> [u8; 4] {
    match addr.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        _ => panic!("v4 listener"),
    }
}

/// Hub with short injected clocks (the stand-in server is NOT on port 53,
/// so flows classify as general — both TTLs are injected anyway).
fn churn_hub(dns_ttl: Duration, general_ttl: Duration, reader_idle: Duration) -> Arc<VpnHub> {
    let table = Arc::new(UdpFlowTable::with_timing(
        "0.0.0.0".parse().unwrap(),
        dns_ttl,
        general_ttl,
    ));
    VpnHub::start_with_flows(
        VpnConfig {
            role: VpnRole::Hub,
            allowed_fingerprints: vec![FP.to_string()],
            ..Default::default()
        },
        table,
        reader_idle,
    )
}

/// One query through the real wire path; asserts it reaches the server.
fn phone_sends_query(
    tun: &mut FakeTun,
    phone: &ClientState,
    hub: &Arc<VpnHub>,
    phone_ep: std::net::SocketAddr,
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
    assert!(frame.len() <= vantablack::ghost::net::GTF_BULK_SIZE);
    let body = receiver_open(&frame, frame.len(), &KEY, SH, ctr).expect("frame intact");
    hub.handle_tunnel_payload(FP, &KEY, SH, &body, phone_ep);
}

/// Poll exactly one egress unit, open it on the phone, and return the TUN
/// packet (asserting the DNS transaction id survived the round trip).
fn relay_and_open(
    hub: &Arc<VpnHub>,
    phone: &ClientState,
    ctr: u32,
    want_id: u16,
) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let u = loop {
        if let Some(u) = hub.poll_egress() {
            break u;
        }
        assert!(Instant::now() < deadline, "no relayed reply for id {want_id}");
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(u.fingerprint, FP);
    let f = tunnel_frame(&KEY, SH, ctr, NonceDirection::ResponderToInitiator, &u.wire);
    let reply = receiver_open(&f, f.len(), &KEY, SH, ctr).expect("reply frame intact");
    let tun = FakeTun::new();
    let (ok, _) = open_to_tun(phone, &reply, &tun);
    assert!(ok, "phone must accept the reply to id {want_id}");
    let out = tun.drain_outbound();
    assert_eq!(out.len(), 1, "exactly one TUN packet for id {want_id}");
    let (_, _, payload) = parse_udp(&out[0]).expect("TUN packet is UDP/IP");
    assert_eq!(u16::from_be_bytes([payload[0], payload[1]]), want_id);
    out[0].clone()
}

#[test]
fn churn_after_full_idle_expiry_new_query_gets_served() {
    let (server, server_addr) = dns_server();
    let server_ip = server_ip_of(server_addr);
    let hub = churn_hub(
        Duration::from_millis(300),
        Duration::from_millis(300),
        Duration::from_millis(300),
    );
    let ep: std::net::SocketAddr = "198.51.100.31:42001".parse().unwrap();
    hub.on_handshake(FP, ep);
    let mut tun = FakeTun::new();
    let phone = ClientState::new(FP, KEY);

    // ── (1) First round trip on the fresh flow. ──
    phone_sends_query(&mut tun, &phone, &hub, ep, server_addr, server_ip, 0x21, 2);
    let mut buf = [0u8; 1500];
    let (amt, src1) = server.recv_from(&mut buf).expect("query 1 at server");
    assert_ne!(
        &buf[..amt].len() + 1,
        0,
        "payload sanity"
    );
    let resp1 = dns_response(0x21, "nas.home", NAS_IP);
    server.send_to(&resp1, src1).expect("reply 1");
    relay_and_open(&hub, &phone, 1001, 0x21);

    // ── (2) Cross BOTH clocks: reader exits, sweep evicts the flow. ──
    std::thread::sleep(Duration::from_millis(1000));
    assert_eq!(hub.sweep(), 1, "idle DNS-classified flow evicted");
    assert_eq!(hub.flows.len(), 0);

    // ── (3) SAME tuple again (same client port → same FlowKey). ──
    phone_sends_query(&mut tun, &phone, &hub, ep, server_addr, server_ip, 0x22, 4);
    let (amt2, src2) = server.recv_from(&mut buf).expect("query 2 at server AFTER idle expiry");
    let src2_ip: [u8; 4] = match src2.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        _ => panic!("v4"),
    };
    assert_ne!(src2_ip, PHONE.0, "still NAT'd off the overlay");
    let resp2 = dns_response(0x22, "nas.home", NAS_IP);
    server.send_to(&resp2, src2).expect("reply 2");
    relay_and_open(&hub, &phone, 1002, 0x22);

    let (_in, _out, dropped, _tcp, _udp) = hub.stats();
    assert_eq!(dropped, 0, "no drops across the churn boundary");
}

#[test]
fn churn_racy_window_reader_gone_flow_alive_serves_same_socket() {
    let (server, server_addr) = dns_server();
    let server_ip = server_ip_of(server_addr);
    // Flow TTL 2 s (alive), reader idle 300 ms (reader exits first).
    let hub = churn_hub(
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_millis(300),
    );
    let ep: std::net::SocketAddr = "198.51.100.32:42002".parse().unwrap();
    hub.on_handshake(FP, ep);
    let mut tun = FakeTun::new();
    let phone = ClientState::new(FP, KEY);

    // Round trip 1.
    phone_sends_query(&mut tun, &phone, &hub, ep, server_addr, server_ip, 0x31, 2);
    let mut buf = [0u8; 1500];
    let (amt, src1) = server.recv_from(&mut buf).expect("query 1 at server");
    server.send_to(&dns_response(0x31, "nas.home", NAS_IP), src1).expect("reply 1");
    relay_and_open(&hub, &phone, 1001, 0x31);

    // Cross the READER clock only: reader exits, flow stays live.
    std::thread::sleep(Duration::from_millis(700));
    assert_eq!(hub.flows.len(), 1, "flow still inside its TTL");

    // Same tuple: get_or_create returns the SAME live socket (same NAT'd
    // port); the absent dedup key lets a reader re-attach to it.
    phone_sends_query(&mut tun, &phone, &hub, ep, server_addr, server_ip, 0x32, 4);
    let (amt2, src2) = server.recv_from(&mut buf).expect("query 2 at server (racy window)");
    assert_eq!(src2, src1, "same live flow socket → same NAT'd port");
    let _ = amt;
    let _ = amt2;
    server.send_to(&dns_response(0x32, "nas.home", NAS_IP), src2).expect("reply 2");
    relay_and_open(&hub, &phone, 1002, 0x32);

    let (_in, _out, dropped, _tcp, _udp) = hub.stats();
    assert_eq!(dropped, 0);
}
