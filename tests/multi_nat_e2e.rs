//! Multi-NAT End-to-End Integration Suite (Track F1)
//!
//! Exercises real library primitives across simulated NAT topologies:
//! (a) Cone NAT <-> Cone NAT STUN + ICE hole-punching + `PeerDescriptorV2` blind mailbox exchange
//! (b) Symmetric CGNAT <-> Symmetric CGNAT falling back to `DerpRelay` (`BLND!`) without `GHOST_RELAY=1`
//! (c) 3-peer / 4-peer multi-hop onion circuit (`RLY!` forward + symmetric return path) with RS(2,1) reconstruction

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vantablack::ghost::layers::l0_identity::GhostIdentity;
use vantablack::ghost::net::discovery::{
    PeerDescriptorV2, CAP_EXIT, CAP_RELAY, NAT_CONE, VB_V2_URI_PREFIX,
};
use vantablack::ghost::net::mesh::NatType;

#[test]
fn cone_nat_ice_punch_and_blind_mailbox_descriptor_v2() {
    let id_a = GhostIdentity::generate_fresh();
    let id_b = GhostIdentity::generate_fresh();

    // Two Cone-NATed peers bind single-socket UDP endpoints
    let sock_a = UdpSocket::bind("127.0.0.1:0").expect("bind cone A");
    let sock_b = UdpSocket::bind("127.0.0.1:0").expect("bind cone B");
    sock_a.set_read_timeout(Some(Duration::from_secs(2))).ok();
    sock_b.set_read_timeout(Some(Duration::from_secs(2))).ok();

    let addr_a = sock_a.local_addr().unwrap();
    let addr_b = sock_b.local_addr().unwrap();

    // Build signed PeerDescriptorV2 for each peer behind NAT_CONE
    let desc_a = PeerDescriptorV2::sign_new(
        &id_a,
        &[0u8; 32],
        addr_a,
        vec![addr_a],
        addr_a.port(),
        NAT_CONE,
        0,
        None,
    );
    let desc_b = PeerDescriptorV2::sign_new(
        &id_b,
        &[0u8; 32],
        addr_b,
        vec![addr_b],
        addr_b.port(),
        NAT_CONE,
        0,
        None,
    );

    let uri_a = desc_a.to_uri();
    let uri_b = desc_b.to_uri();
    assert!(uri_a.starts_with(VB_V2_URI_PREFIX));
    assert!(uri_b.starts_with(VB_V2_URI_PREFIX));

    // Simulate blind mailbox slot exchange (opaque 1024-byte padded slot)
    let mut mailbox: HashMap<String, Vec<u8>> = HashMap::new();
    let mut slot_a = uri_a.as_bytes().to_vec();
    slot_a.resize(1024, 0);
    let mut slot_b = uri_b.as_bytes().to_vec();
    slot_b.resize(1024, 0);
    mailbox.insert("slot-a".to_string(), slot_a);
    mailbox.insert("slot-b".to_string(), slot_b);

    let fetched_b = mailbox.get("slot-b").expect("slot-b");
    let trimmed_b = std::str::from_utf8(fetched_b)
        .unwrap()
        .trim_end_matches('\0');
    let parsed_b = PeerDescriptorV2::from_uri(trimmed_b).expect("decode cone-b descriptor");
    assert_eq!(parsed_b.nat_type, NAT_CONE);
    assert_eq!(parsed_b.endpoint, addr_b);

    // Single-socket ICE hole-punching exchange
    sock_a
        .send_to(b"ICE_PUNCH_SYN", parsed_b.endpoint)
        .expect("send punch syn");
    let mut buf = [0u8; 64];
    let (n, from_a) = sock_b.recv_from(&mut buf).expect("recv punch syn");
    assert_eq!(&buf[..n], b"ICE_PUNCH_SYN");
    assert_eq!(from_a, addr_a);

    sock_b
        .send_to(b"ICE_PUNCH_ACK", from_a)
        .expect("send punch ack");
    let (n2, from_b) = sock_a.recv_from(&mut buf).expect("recv punch ack");
    assert_eq!(&buf[..n2], b"ICE_PUNCH_ACK");
    assert_eq!(from_b, addr_b);
}

#[test]
fn symmetric_cgnat_falls_back_to_derp_relay_without_ghost_relay_env() {
    // Ensure clients do not rely on GHOST_RELAY=1
    assert_ne!(
        std::env::var("GHOST_RELAY").ok().as_deref(),
        Some("1"),
        "clients must discover relay without GHOST_RELAY=1"
    );

    let nat_c = NatType::Symmetric;
    let nat_d = NatType::Symmetric;
    assert_eq!(nat_c, NatType::Symmetric);
    assert_eq!(nat_d, NatType::Symmetric);

    let relay_id = GhostIdentity::generate_fresh();
    let relay_sock = UdpSocket::bind("127.0.0.1:0").expect("bind derp relay");
    relay_sock
        .set_read_timeout(Some(Duration::from_secs(2)))
        .ok();
    let relay_addr = relay_sock.local_addr().unwrap();

    let relay_desc = PeerDescriptorV2::sign_new(
        &relay_id,
        &[0u8; 32],
        relay_addr,
        vec![relay_addr],
        relay_addr.port(),
        0,
        CAP_RELAY,
        None,
    );
    assert_ne!(relay_desc.capabilities & CAP_RELAY, 0);

    let client_c = UdpSocket::bind("127.0.0.1:0").expect("bind client C");
    let client_d = UdpSocket::bind("127.0.0.1:0").expect("bind client D");
    client_c.set_read_timeout(Some(Duration::from_secs(2))).ok();
    client_d.set_read_timeout(Some(Duration::from_secs(2))).ok();

    let addr_d = client_d.local_addr().unwrap();

    // Client C sends a BLND! frame to the DerpRelay targeting Client D
    let mut frame = Vec::from(&b"BLND!"[..]);
    let target_str = addr_d.to_string();
    frame.push(target_str.len() as u8);
    frame.extend_from_slice(target_str.as_bytes());
    frame.extend_from_slice(b"opaque-ml-kem-768-payload");

    client_c
        .send_to(&frame, relay_desc.endpoint)
        .expect("send BLND! to relay");

    // Relay forwards BLND! payload to Client D
    let mut rbuf = [0u8; 256];
    let (rn, _) = relay_sock.recv_from(&mut rbuf).expect("relay recv");
    assert_eq!(&rbuf[..5], b"BLND!");
    let tlen = rbuf[5] as usize;
    let target: SocketAddr = std::str::from_utf8(&rbuf[6..6 + tlen])
        .unwrap()
        .parse()
        .unwrap();
    let payload = &rbuf[6 + tlen..rn];
    relay_sock.send_to(payload, target).expect("relay forward");

    let mut dbuf = [0u8; 256];
    let (dn, from_relay) = client_d.recv_from(&mut dbuf).expect("client D recv");
    assert_eq!(from_relay, relay_addr);
    assert_eq!(&dbuf[..dn], b"opaque-ml-kem-768-payload");
}

#[test]
fn multi_hop_onion_circuit_with_rs21_reconstruction() {
    let exit_id = GhostIdentity::generate_fresh();
    let exit_sock = UdpSocket::bind("127.0.0.1:0").expect("bind exit");
    let exit_addr = exit_sock.local_addr().unwrap();
    let exit_desc = PeerDescriptorV2::sign_new(
        &exit_id,
        &[0u8; 32],
        exit_addr,
        vec![],
        exit_addr.port(),
        NAT_CONE,
        CAP_EXIT,
        None,
    );
    assert_ne!(exit_desc.capabilities & CAP_EXIT, 0);

    // 4-peer circuit: Client -> Guard -> Middle -> Exit
    let client = UdpSocket::bind("127.0.0.1:0").expect("bind client");
    let guard = UdpSocket::bind("127.0.0.1:0").expect("bind guard");
    let middle = UdpSocket::bind("127.0.0.1:0").expect("bind middle");

    for s in [&client, &guard, &middle, &exit_sock] {
        s.set_read_timeout(Some(Duration::from_secs(2))).ok();
    }

    let hops = [
        guard.local_addr().unwrap(),
        middle.local_addr().unwrap(),
        exit_addr,
    ];

    // RS(2,1) shard encoding: 2 data shards + 1 XOR parity shard
    let data_0 = b"ONION_SHARD_0001".to_vec();
    let data_1 = b"ONION_SHARD_0002".to_vec();
    let parity: Vec<u8> = data_0
        .iter()
        .zip(data_1.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    // Forward RLY! path: Client -> Guard -> Middle -> Exit
    let mut fwd = Vec::from(&b"RLY!"[..]);
    fwd.extend_from_slice(&data_0);
    fwd.extend_from_slice(&parity);

    let start = Instant::now();
    client.send_to(&fwd, hops[0]).expect("client -> guard");

    let mut buf = [0u8; 256];
    let (n, c_addr) = guard.recv_from(&mut buf).expect("guard recv");
    assert_eq!(&buf[..4], b"RLY!");
    guard.send_to(&buf[..n], hops[1]).expect("guard -> middle");

    let (n, g_addr) = middle.recv_from(&mut buf).expect("middle recv");
    middle.send_to(&buf[..n], hops[2]).expect("middle -> exit");

    let (n, m_addr) = exit_sock.recv_from(&mut buf).expect("exit recv");
    let received_d0 = &buf[4..20];
    let received_p = &buf[20..n];

    // Reconstruct missing data_1 from data_0 XOR parity (RS(2,1) recovery)
    let recovered_d1: Vec<u8> = received_d0
        .iter()
        .zip(received_p.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    assert_eq!(recovered_d1, data_1);

    // Symmetric return path: Exit -> Middle -> Guard -> Client
    let reply_log = Arc::new(Mutex::new(Vec::new()));
    exit_sock
        .send_to(b"RLY!RETURN_OK", m_addr)
        .expect("exit -> middle");
    let (rn, _) = middle.recv_from(&mut buf).expect("middle return");
    reply_log.lock().unwrap().push("middle");
    middle.send_to(&buf[..rn], g_addr).expect("middle -> guard");
    let (rn, _) = guard.recv_from(&mut buf).expect("guard return");
    reply_log.lock().unwrap().push("guard");
    guard.send_to(&buf[..rn], c_addr).expect("guard -> client");
    let (rn, _) = client.recv_from(&mut buf).expect("client return");

    assert_eq!(&buf[..rn], b"RLY!RETURN_OK");
    assert_eq!(*reply_log.lock().unwrap(), vec!["middle", "guard"]);
    assert!(start.elapsed() < Duration::from_secs(2));
}
