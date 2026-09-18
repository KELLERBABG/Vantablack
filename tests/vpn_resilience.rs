#![cfg(feature = "vpn")]

//! Resilience gate — the recovery arc a client needs to STAY connected:
//! 1. KEEPALIVE: an idle client's ICMP echo to the hub overlay (the exact
//!    packet `resilience::build_keepalive` emits) is answered by the real
//!    `answer_icmp` path and lands back in the TUN — bidirectional proof.
//! 2. RE-KEY: a fresh handshake rotates the client epoch (the ctr==1 fix),
//!    the hub re-anchors the lease and RESETS its tx counters (next reply
//!    seals at ctr 1 again) — the desync that would otherwise blackhole a
//!    reconnected client.
//! Timing/backoff transitions are unit-tested in `client::resilience::tests`.

use std::net::SocketAddr;

use vantablack::ghost::layers::l2_aead::NonceDirection;
use vantablack::ghost::net::vpn::client::resilience::build_keepalive;
use vantablack::ghost::net::vpn::client::{open_to_tun, seal_from_tun, ClientState};
use vantablack::ghost::net::vpn::hub::VpnHub;
use vantablack::ghost::net::vpn::seal_datagram;
use vantablack::ghost::net::vpn::tun::{FakeTun, TunDevice};

mod common;
use common::tunnel::{receiver_open, tunnel_frame};

const FP: &str = "e1b2c3d4e5f6a7b8";
const KEY: [u8; 32] = [0x4du8; 32];
const SH: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
const CLIENT_IP: ([u8; 4], u16) = ([10, 66, 0, 10], 51666);
const HUB_OVERLAY: ([u8; 4], u16) = ([10, 66, 0, 1], 0);

fn push_from_client(
    tun: &mut FakeTun,
    phone: &ClientState,
    hub: &std::sync::Arc<VpnHub>,
    phone_ep: SocketAddr,
    ctr: u32,
) -> Vec<u8> {
    let mut rbuf = [0u8; 1500];
    let n = TunDevice::read_packet(tun, &mut rbuf).expect("TUN read");
    let wire = seal_from_tun(phone, &rbuf[..n]).expect("seal");
    let frame = tunnel_frame(&KEY, SH, ctr, NonceDirection::InitiatorToResponder, &wire);
    let body = receiver_open(&frame, frame.len(), &KEY, SH, ctr).expect("frame intact");
    hub.handle_tunnel_payload(FP, &KEY, SH, &body, phone_ep);
    body
}

#[test]
fn keepalive_roundtrip_then_rekey_reanchors_fresh_epoch() {
    let hub = VpnHub::start(vantablack::ghost::net::vpn::VpnConfig {
        role: vantablack::ghost::net::vpn::VpnRole::Hub,
        allowed_fingerprints: vec![FP.to_string()],
        ..Default::default()
    });
    let ep1: SocketAddr = "198.51.100.21:41001".parse().unwrap();
    hub.on_handshake(FP, ep1);
    let phone = ClientState::new(FP, KEY);

    // ── 1. Idle client sends the keepalive echo; hub answers; TUN gets it. ──
    let mut tun = FakeTun::new();
    tun.push_inbound(build_keepalive(HUB_OVERLAY.0.into(), CLIENT_IP.0.into()));
    push_from_client(&mut tun, &phone, &hub, ep1, 2);

    let u = (0..500)
        .find_map(|_| hub.poll_egress())
        .expect("keepalive answered");
    let reply_frame = tunnel_frame(
        &KEY,
        SH,
        1001,
        NonceDirection::ResponderToInitiator,
        &u.wire,
    );
    let reply =
        receiver_open(&reply_frame, reply_frame.len(), &KEY, SH, 1001).expect("sealed reply");
    let tun2 = FakeTun::new();
    let (accepted, _) = open_to_tun(&phone, &reply, &tun2);
    assert!(accepted, "keepalive reply must open on the phone");
    let out = tun2.drain_outbound();
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0][20], 0,
        "echo REPLY — tunnel proven bidirectionally alive"
    );

    // Burn a few hub-side tx counters so the reset is observable (hub→client
    // ICMP replies already consumed some; force more via another keepalive).
    tun.push_inbound(build_keepalive(HUB_OVERLAY.0.into(), CLIENT_IP.0.into()));
    push_from_client(&mut tun, &phone, &hub, ep1, 3);
    let u2 = (0..500)
        .find_map(|_| hub.poll_egress())
        .expect("second reply");
    let pre_ctr = u64::from_be_bytes(u2.wire[4..12].try_into().unwrap());
    assert!(pre_ctr > 1, "hub counter advanced before re-handshake");

    // ── 2. Reconnect: fresh handshake → client rotates, hub re-anchors. ──
    let ep2: SocketAddr = "198.51.100.22:41002".parse().unwrap(); // e.g. LTE now
    let new_epoch = phone.rotate_epoch(); // the ctr==1 fix's rotation
    assert_eq!(new_epoch, 2);
    hub.on_handshake(FP, ep2); // resets lease + hub tx_counters

    // Client speaks under the NEW epoch from the NEW endpoint: adopted.
    tun.push_inbound(build_keepalive(HUB_OVERLAY.0.into(), CLIENT_IP.0.into()));
    push_from_client(&mut tun, &phone, &hub, ep2, 2);
    let u3 = (0..500)
        .find_map(|_| hub.poll_egress())
        .expect("reply after re-key");
    assert_eq!(u3.endpoint, ep2, "lease re-anchored to the new endpoint");
    // Hub restarted its counter space for this client: next seal is ctr 1.
    let post_ctr = u64::from_be_bytes(u3.wire[4..12].try_into().unwrap());
    assert_eq!(post_ctr, 1, "hub tx counters reset on fresh handshake");
    // The reply was sealed under the client's NEW epoch (hub mirror adopted).
    let hdr_epoch = u32::from_be_bytes([u3.wire[0], u3.wire[1], u3.wire[2], u3.wire[3]]);
    assert_eq!(
        hdr_epoch, new_epoch,
        "hub seals under the client's adopted epoch"
    );
    // And the phone still opens it.
    let reply3 = receiver_open(
        &tunnel_frame(
            &KEY,
            SH,
            1002,
            NonceDirection::ResponderToInitiator,
            &u3.wire,
        ),
        1400,
        &KEY,
        SH,
        1002,
    )
    .expect("post-re-key reply intact");
    let tun3 = FakeTun::new();
    let (ok, _) = open_to_tun(&phone, &reply3, &tun3);
    assert!(ok, "re-keyed client accepts hub traffic");
}

#[test]
fn unauthenticated_future_epoch_cannot_poison_mobility_state() {
    let hub = VpnHub::start(vantablack::ghost::net::vpn::VpnConfig {
        role: vantablack::ghost::net::vpn::VpnRole::Hub,
        allowed_fingerprints: vec![FP.to_string()],
        ..Default::default()
    });
    let endpoint: SocketAddr = "198.51.100.30:41030".parse().unwrap();
    hub.on_handshake(FP, endpoint);

    let packet = vec![0x45u8; 40];
    let valid = seal_datagram(&KEY, 1, 1, &packet);
    hub.handle_tunnel_payload(FP, &KEY, SH, &valid, endpoint);
    assert_eq!(hub.lease_views()[0].epoch, 1);

    // Rewriting only the clear epoch header invalidates the AEAD nonce. It
    // must not advance the lease or evict epoch-1 replay state.
    let mut forged = valid.clone();
    forged[..4].copy_from_slice(&99u32.to_be_bytes());
    hub.handle_tunnel_payload(FP, &KEY, SH, &forged, endpoint);
    assert_eq!(hub.lease_views()[0].epoch, 1);

    // The original epoch remains usable after the failed future-epoch probe.
    let next = seal_datagram(&KEY, 1, 2, &packet);
    hub.handle_tunnel_payload(FP, &KEY, SH, &next, endpoint);
    assert_eq!(hub.lease_views()[0].epoch, 1);
}
